// Copyright 2024 Omni Cyber Solutions LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Agent enrollment — one-time token → mTLS certificate + initial policy

use anyhow::Result;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tracing::info;

use crate::config::AgentConfig;

#[derive(Serialize)]
struct EnrollmentRequest {
    token: String,
    hostname: String,
    os_platform: String,
    os_version: String,
    os_arch: String,
    agent_version: String,
    csr_pem: String,
}

#[derive(Deserialize)]
pub struct EnrollmentResponse {
    pub agent_id: String,
    pub tenant_id: String,
    pub client_cert_pem: String,
    pub ca_cert_pem: String,
    pub cert_valid_seconds: u64,
    pub policy: serde_json::Value,
}

pub struct EnrollmentClient {
    client: Client,
    platform_url: String,
    data_dir: PathBuf,
    hostname: String,
}

impl EnrollmentClient {
    pub fn new(cfg: &AgentConfig) -> Result<Self> {
        let client = Client::builder()
            .danger_accept_invalid_certs(false)
            .timeout(std::time::Duration::from_secs(30))
            .build()?;

        let hostname = std::env::var("COMPUTERNAME")
            .or_else(|_| std::env::var("HOSTNAME"))
            .unwrap_or_else(|_| "unknown".to_string());

        Ok(Self {
            client,
            platform_url: cfg.platform.url.clone(),
            data_dir: cfg.storage.data_dir.clone(),
            hostname,
        })
    }

    pub async fn enroll(&self, token: &str) -> Result<EnrollmentResponse> {
        info!("Starting enrollment with platform at {}", self.platform_url);

        // Generate a proper ECDSA P-256 CSR and save the private key
        let (csr_pem, key_pem) = self.generate_csr()?;

        let request = EnrollmentRequest {
            token: token.to_string(),
            hostname: self.hostname.clone(),
            os_platform: std::env::consts::OS.to_string(),
            os_version: os_version(),
            os_arch: std::env::consts::ARCH.to_string(),
            agent_version: env!("CARGO_PKG_VERSION").to_string(),
            csr_pem,
        };

        let response = self
            .client
            .post(format!("{}/api/v1/agents/enroll", self.platform_url))
            .json(&request)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!("Enrollment failed ({}): {}", status, body);
        }

        let enrollment: EnrollmentResponse = response.json().await?;

        // Persist certificates and key to disk
        self.save_certs(&enrollment.client_cert_pem, &enrollment.ca_cert_pem, &key_pem)?;

        // Persist initial policy if returned as a string
        if let Some(policy_str) = enrollment.policy.as_str() {
            let policy_path = self.data_dir.join("policy.toml");
            std::fs::write(&policy_path, policy_str)?;
            info!("Initial policy written to {:?}", policy_path);
        }

        info!(
            agent_id = %enrollment.agent_id,
            tenant_id = %enrollment.tenant_id,
            cert_valid_secs = enrollment.cert_valid_seconds,
            "Enrollment successful"
        );
        Ok(enrollment)
    }

    /// Generate an ECDSA P-256 CSR using rcgen.
    /// Returns (csr_pem, private_key_pem).
    fn generate_csr(&self) -> Result<(String, String)> {
        use rcgen::{Certificate, CertificateParams, DistinguishedName, DnType, SanType};

        let mut params = CertificateParams::new(vec![self.hostname.clone()]);
        let mut dn = DistinguishedName::new();
        dn.push(DnType::OrganizationName, "OpenClaw Agent");
        dn.push(DnType::CommonName, &self.hostname);
        params.distinguished_name = dn;
        params.subject_alt_names = vec![SanType::DnsName(self.hostname.clone())];
        params.is_ca = rcgen::IsCa::ExplicitNoCa;
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];

        let cert = Certificate::from_params(params)?;
        let csr_pem = cert.serialize_request_pem()?;
        let key_pem = cert.serialize_private_key_pem();

        Ok((csr_pem, key_pem))
    }

    fn save_certs(&self, client_cert: &str, ca_cert: &str, client_key: &str) -> Result<()> {
        let certs_dir = self.data_dir.join("certs");
        std::fs::create_dir_all(&certs_dir)?;

        std::fs::write(certs_dir.join("client.pem"), client_cert)?;
        std::fs::write(certs_dir.join("ca.pem"), ca_cert)?;

        // Key file: restrict permissions on Unix
        let key_path = certs_dir.join("client.key");
        std::fs::write(&key_path, client_key)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))?;
        }

        info!("Certificates and key saved to {:?}", certs_dir);
        Ok(())
    }
}

/// Best-effort OS version string.
fn os_version() -> String {
    #[cfg(target_os = "windows")]
    {
        // Use RtlGetVersion via windows crate if available; fallback to env
        std::env::var("OS").unwrap_or_else(|_| "Windows".to_string())
    }
    #[cfg(not(target_os = "windows"))]
    {
        // Read from /etc/os-release or uname
        std::fs::read_to_string("/etc/os-release")
            .ok()
            .and_then(|s| {
                s.lines()
                    .find(|l| l.starts_with("PRETTY_NAME="))
                    .map(|l| l.trim_start_matches("PRETTY_NAME=").trim_matches('"').to_string())
            })
            .unwrap_or_else(|| std::env::consts::OS.to_string())
    }
}
