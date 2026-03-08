// Copyright 2026 Omni Cyber Solutions LLC. Apache License 2.0.
//
// Policy sync — pull the current policy bundle from the platform when
// the heartbeat signals that a newer version is available.
//
// The heartbeat handler sends the new version number over a tokio channel;
// this module fetches, verifies the Ed25519 minisign signature, and
// hot-reloads the TOML policy.
//
// Signature verification:
//   The platform signs the policy TOML bytes with its Ed25519 private key.
//   The response includes `signature_b64` (base64 of the raw 64-byte signature).
//   The agent verifies using the public key configured in platform.update_signing_pubkey
//   (minisign format: "untrusted comment: ...\n<base64 blob>").
//   If the signature is present and the configured pubkey exists, verification
//   is mandatory — a bad signature aborts the policy update.

use anyhow::Result;
use base64::Engine;
use reqwest::Client;
use ring::signature::{self, UnparsedPublicKey};
use serde::Deserialize;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tracing::{info, warn};

use crate::config::AgentConfig;
use crate::platform_connector::client::build_platform_client;

// ─── Shared policy state ──────────────────────────────────────────────────────

/// The live policy data shared across agent subsystems.
#[derive(Clone, Default)]
pub struct LivePolicy {
    pub version: u64,
    pub raw_toml: String,
}

/// A cheap cloneable handle to the live policy.
#[derive(Clone)]
pub struct PolicyHandle {
    inner: Arc<RwLock<LivePolicy>>,
}

impl Default for PolicyHandle {
    fn default() -> Self {
        Self::new()
    }
}

impl PolicyHandle {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(LivePolicy::default())),
        }
    }

    pub async fn current(&self) -> LivePolicy {
        self.inner.read().await.clone()
    }

    pub async fn version(&self) -> u64 {
        self.inner.read().await.version
    }

    async fn update(&self, policy: LivePolicy) {
        *self.inner.write().await = policy;
    }
}

// ─── Platform response ────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct AgentPolicyResponse {
    version: u64,
    content_toml: String,
    /// Base64-encoded raw 64-byte Ed25519 signature over the UTF-8 bytes of content_toml.
    /// Present when the platform is configured for signed policy distribution.
    signature_b64: Option<String>,
}

// ─── Policy sync service ──────────────────────────────────────────────────────

/// Receives version-change signals from the heartbeat and fetches new policy.
pub struct PolicySync {
    client: Client,
    platform_url: String,
    agent_id: String,
    handle: PolicyHandle,
    trigger_rx: mpsc::Receiver<u64>,
    /// Minisign public key for verifying policy signatures (optional).
    signing_pubkey: Option<String>,
}

/// Sender half — given to the heartbeat service so it can signal version changes.
pub type PolicyTrigger = mpsc::Sender<u64>;

impl PolicySync {
    pub fn new(cfg: &AgentConfig, agent_id: &str) -> Result<(Self, PolicyTrigger)> {
        let (trigger_tx, trigger_rx) = mpsc::channel(8);
        let client = build_platform_client(cfg, std::time::Duration::from_secs(30))?;

        let sync = Self {
            client,
            platform_url: cfg.platform.url.clone(),
            agent_id: agent_id.to_string(),
            handle: PolicyHandle::new(),
            trigger_rx,
            signing_pubkey: cfg.platform.update_signing_pubkey.clone(),
        };

        Ok((sync, trigger_tx))
    }

    pub fn policy_handle(&self) -> PolicyHandle {
        self.handle.clone()
    }

    /// Run the policy sync loop — blocks until shutdown.
    pub async fn run(mut self) -> Result<()> {
        info!("PolicySync: waiting for heartbeat triggers");
        while let Some(new_version) = self.trigger_rx.recv().await {
            let current = self.handle.version().await;
            if new_version <= current {
                continue; // Already up to date (or spurious signal).
            }
            info!(new_version, current, "Policy update signalled — fetching");
            if let Err(e) = self.fetch_and_apply(new_version).await {
                warn!(error = %e, "Policy fetch failed — will retry on next signal");
            }
        }
        Ok(())
    }

    async fn fetch_and_apply(&self, _expected_version: u64) -> Result<()> {
        let url = format!(
            "{}/api/v1/agents/{}/policy",
            self.platform_url, self.agent_id
        );

        let resp = self.client.get(&url).send().await?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("Policy fetch failed ({}): {}", status, body);
        }

        let bundle: AgentPolicyResponse = resp.json().await?;

        // ── Ed25519 signature verification ────────────────────────────────────
        //
        // If the platform provides a signature AND we have a signing public key
        // configured, verification is mandatory.  If the pubkey is absent, we
        // skip (supports dev deployments without signing configured).
        // If the signature is absent but a pubkey is configured, we warn.
        match (&bundle.signature_b64, &self.signing_pubkey) {
            (Some(sig_b64), Some(pubkey_str)) => {
                verify_policy_signature(
                    bundle.content_toml.as_bytes(),
                    sig_b64,
                    pubkey_str,
                    bundle.version,
                )?;
            }
            (None, Some(_)) => {
                warn!(
                    version = bundle.version,
                    "Policy bundle has no signature but signing pubkey is configured — \
                     accepting for now; configure the platform to sign policy bundles"
                );
            }
            (Some(_), None) => {
                // Signature present but we have no key to verify it — skip silently.
                // This allows agents to be deployed before the operator configures signing.
            }
            (None, None) => {
                // Neither signature nor pubkey — unsigned policy, dev mode.
                #[cfg(debug_assertions)]
                tracing::debug!(
                    version = bundle.version,
                    "Policy signature verification skipped (no pubkey configured)"
                );
            }
        }

        self.handle
            .update(LivePolicy {
                version: bundle.version,
                raw_toml: bundle.content_toml,
            })
            .await;

        info!(version = bundle.version, "Policy applied successfully");
        Ok(())
    }
}

// ─── Signature helpers ────────────────────────────────────────────────────────

/// Verify a policy bundle's Ed25519 signature.
///
/// `sig_b64`   — base64-encoded raw 64-byte Ed25519 signature over `content`.
/// `pubkey_str` — minisign public key string (two lines: comment + base64 blob).
fn verify_policy_signature(
    content: &[u8],
    sig_b64: &str,
    pubkey_str: &str,
    version: u64,
) -> Result<()> {
    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(sig_b64.trim())
        .map_err(|e| anyhow::anyhow!("Policy sig base64 decode failed: {}", e))?;

    if sig_bytes.len() != 64 {
        anyhow::bail!(
            "Policy signature length {} != 64 bytes",
            sig_bytes.len()
        );
    }

    let pubkey_bytes = parse_minisign_pubkey(pubkey_str)
        .map_err(|e| anyhow::anyhow!("Failed to parse policy signing pubkey: {}", e))?;

    let pk = UnparsedPublicKey::new(&signature::ED25519, pubkey_bytes);
    pk.verify(content, &sig_bytes).map_err(|_| {
        anyhow::anyhow!(
            "Policy Ed25519 signature verification FAILED for version {} — aborting update",
            version
        )
    })?;

    info!(version, "Policy Ed25519 signature verified");
    Ok(())
}

/// Parse a minisign public key string and return the 32-byte Ed25519 key.
///
/// Format:
///   Line 0: "untrusted comment: ..."
///   Line 1: base64 blob where bytes 10–41 are the 32-byte Ed25519 public key.
fn parse_minisign_pubkey(pubkey_str: &str) -> Result<Vec<u8>> {
    let line = pubkey_str
        .lines()
        .find(|l| !l.starts_with("untrusted comment:"))
        .ok_or_else(|| anyhow::anyhow!("pubkey: no key line found"))?;

    let blob = base64::engine::general_purpose::STANDARD.decode(line.trim())?;
    if blob.len() < 42 {
        anyhow::bail!("pubkey blob too short: {} bytes", blob.len());
    }
    // Skip 2-byte algorithm + 8-byte key ID → public key at bytes 10–41
    Ok(blob[10..42].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair};

    fn make_test_minisign_pubkey(pubkey_bytes: &[u8]) -> String {
        // Build a minimal minisign public key string
        let mut blob = Vec::new();
        blob.extend_from_slice(b"Ed"); // algorithm
        blob.extend_from_slice(&[0u8; 8]); // key ID placeholder
        blob.extend_from_slice(pubkey_bytes);
        let b64 = base64::engine::general_purpose::STANDARD.encode(&blob);
        format!("untrusted comment: test key\n{}\n", b64)
    }

    #[test]
    fn test_policy_signature_roundtrip() {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();

        let content = b"[detection]\nrules_enabled = true\n";
        let signature = key_pair.sign(content);
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(signature.as_ref());

        let pubkey_str = make_test_minisign_pubkey(key_pair.public_key().as_ref());
        verify_policy_signature(content, &sig_b64, &pubkey_str, 1).unwrap();
    }

    #[test]
    fn test_policy_signature_bad_sig_rejected() {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();

        let content = b"[detection]\nrules_enabled = true\n";
        let mut sig_bytes = key_pair.sign(content).as_ref().to_vec();
        sig_bytes[0] ^= 0xFF; // corrupt first byte
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(&sig_bytes);

        let pubkey_str = make_test_minisign_pubkey(key_pair.public_key().as_ref());
        assert!(verify_policy_signature(content, &sig_b64, &pubkey_str, 1).is_err());
    }
}
