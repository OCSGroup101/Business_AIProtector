// Copyright 2026 Omni Cyber Solutions LLC. Apache License 2.0.
//
// Certificate renewal — generate a new CSR, request a fresh 72-hour cert
// from the platform, and atomically replace the cert files on disk.

use anyhow::Result;
use rcgen::{Certificate, CertificateParams, DistinguishedName, DnType, SanType};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tracing::info;

use crate::platform_connector::client::build_platform_client_from_dir;

#[derive(Serialize)]
struct CertRenewalRequest {
    csr_pem: String,
}

#[derive(Deserialize)]
struct CertRenewalResponse {
    client_cert_pem: String,
    ca_cert_pem: String,
    cert_valid_seconds: u64,
}

pub struct CertRenewalClient {
    data_dir: PathBuf,
    platform_url: String,
}

impl CertRenewalClient {
    pub fn new(data_dir: &Path, platform_url: &str) -> Self {
        Self {
            data_dir: data_dir.to_path_buf(),
            platform_url: platform_url.to_string(),
        }
    }

    pub async fn renew(&self, agent_id: &str) -> Result<()> {
        let hostname = std::env::var("COMPUTERNAME")
            .or_else(|_| std::env::var("HOSTNAME"))
            .unwrap_or_else(|_| "unknown".to_string());

        // Generate a new key + CSR (the old key is replaced on success).
        let (csr_pem, key_pem) = generate_csr(&hostname)?;

        // Use the existing mTLS cert for the renewal request itself.
        let client =
            build_platform_client_from_dir(&self.data_dir, std::time::Duration::from_secs(30))?;

        let resp = client
            .post(format!(
                "{}/api/v1/agents/{}/renew-cert",
                self.platform_url, agent_id
            ))
            .json(&CertRenewalRequest { csr_pem })
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("Cert renewal failed ({}): {}", status, body);
        }

        let renewal: CertRenewalResponse = resp.json().await?;

        // Atomically replace cert files.
        let certs_dir = self.data_dir.join("certs");
        std::fs::create_dir_all(&certs_dir)?;

        // Write to .new files first, then rename for atomicity.
        let cert_new = certs_dir.join("client.pem.new");
        let ca_new = certs_dir.join("ca.pem.new");
        let key_new = certs_dir.join("client.key.new");

        std::fs::write(&cert_new, &renewal.client_cert_pem)?;
        std::fs::write(&ca_new, &renewal.ca_cert_pem)?;
        std::fs::write(&key_new, &key_pem)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key_new, std::fs::Permissions::from_mode(0o600))?;
        }

        std::fs::rename(&cert_new, certs_dir.join("client.pem"))?;
        std::fs::rename(&ca_new, certs_dir.join("ca.pem"))?;
        std::fs::rename(&key_new, certs_dir.join("client.key"))?;

        info!(
            agent_id = %agent_id,
            cert_valid_seconds = renewal.cert_valid_seconds,
            "Certificate renewed and persisted to disk"
        );
        Ok(())
    }
}

fn generate_csr(hostname: &str) -> Result<(String, String)> {
    let mut params = CertificateParams::new(vec![hostname.to_string()]);
    let mut dn = DistinguishedName::new();
    dn.push(DnType::OrganizationName, "OpenClaw Agent");
    dn.push(DnType::CommonName, hostname);
    params.distinguished_name = dn;
    params.subject_alt_names = vec![SanType::DnsName(hostname.to_string())];
    params.is_ca = rcgen::IsCa::ExplicitNoCa;
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];

    let cert = Certificate::from_params(params)?;
    let csr_pem = cert.serialize_request_pem()?;
    let key_pem = cert.serialize_private_key_pem();
    Ok((csr_pem, key_pem))
}
