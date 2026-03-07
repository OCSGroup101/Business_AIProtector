// Copyright 2026 Omni Cyber Solutions LLC. Apache License 2.0.
//
// Shared reqwest::Client factory with mutual TLS support.
//
// After enrollment, the agent stores a client certificate, private key, and
// the platform CA certificate under data_dir/certs/.  All outbound platform
// connector calls (heartbeat, telemetry, alerts, intel) should use the mTLS
// client returned by this module so that every request is authenticated at the
// transport layer.
//
// Fallback: if the cert files are absent (dev mode or pre-enrollment), a plain
// HTTP client with no client identity is returned.  The same code path handles
// both cases — no separate dev branch is needed.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;
use reqwest::{Certificate, Client, Identity};
use tracing::{debug, info, warn};

use crate::config::AgentConfig;

/// Build a `reqwest::Client` configured with mTLS from stored agent certificates.
///
/// Resolution order for cert files:
/// 1. `cfg.platform.client_cert` / `client_key` / `ca_cert` (explicit config)
/// 2. `cfg.storage.data_dir/certs/client.pem` etc. (post-enrollment defaults)
///
/// If any required file is absent, returns a plain HTTP client (no error).
pub fn build_platform_client(cfg: &AgentConfig, timeout: Duration) -> Result<Client> {
    let (cert_path, key_path, ca_path) = resolve_cert_paths(cfg);

    if !cert_path.exists() || !key_path.exists() || !ca_path.exists() {
        debug!(
            cert = %cert_path.display(),
            "mTLS certs not present — using plain HTTP client"
        );
        return Ok(Client::builder().timeout(timeout).build()?);
    }

    // reqwest Identity::from_pem requires a single PEM bundle: certificate then private key.
    let mut pem_bundle = std::fs::read(&cert_path)?;
    pem_bundle.extend_from_slice(&std::fs::read(&key_path)?);

    let identity = match Identity::from_pem(&pem_bundle) {
        Ok(id) => id,
        Err(e) => {
            warn!(
                "mTLS identity load failed ({}); falling back to plain HTTP",
                e
            );
            return Ok(Client::builder().timeout(timeout).build()?);
        }
    };

    let ca_pem = std::fs::read(&ca_path)?;
    let ca_cert = Certificate::from_pem(&ca_pem)?;

    let client = Client::builder()
        .timeout(timeout)
        .identity(identity)
        .add_root_certificate(ca_cert)
        .build()?;

    info!("mTLS platform client built from {}", cert_path.display());
    Ok(client)
}

/// Build a platform client using certs directly from a `certs/` subdirectory.
/// Used by cert_renewal, which doesn't have access to AgentConfig.
pub fn build_platform_client_from_dir(
    data_dir: &std::path::Path,
    timeout: Duration,
) -> Result<Client> {
    let certs_dir = data_dir.join("certs");
    let cert_path = certs_dir.join("client.pem");
    let key_path = certs_dir.join("client.key");
    let ca_path = certs_dir.join("ca.pem");

    if !cert_path.exists() || !key_path.exists() || !ca_path.exists() {
        return Ok(Client::builder().timeout(timeout).build()?);
    }

    let mut pem_bundle = std::fs::read(&cert_path)?;
    pem_bundle.extend_from_slice(&std::fs::read(&key_path)?);

    let identity = match Identity::from_pem(&pem_bundle) {
        Ok(id) => id,
        Err(e) => {
            warn!(
                "mTLS identity load failed ({}); falling back to plain HTTP",
                e
            );
            return Ok(Client::builder().timeout(timeout).build()?);
        }
    };

    let ca_pem = std::fs::read(&ca_path)?;
    let ca_cert = Certificate::from_pem(&ca_pem)?;

    Ok(Client::builder()
        .timeout(timeout)
        .identity(identity)
        .add_root_certificate(ca_cert)
        .build()?)
}

fn resolve_cert_paths(cfg: &AgentConfig) -> (PathBuf, PathBuf, PathBuf) {
    let default_dir = cfg.storage.data_dir.join("certs");

    let cert = cfg
        .platform
        .client_cert
        .clone()
        .unwrap_or_else(|| default_dir.join("client.pem"));
    let key = cfg
        .platform
        .client_key
        .clone()
        .unwrap_or_else(|| default_dir.join("client.key"));
    let ca = cfg
        .platform
        .ca_cert
        .clone()
        .unwrap_or_else(|| default_dir.join("ca.pem"));

    (cert, key, ca)
}
