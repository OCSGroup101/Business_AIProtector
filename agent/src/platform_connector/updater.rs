// Agent self-updater — signature verify → atomic binary replace
//
// Update flow:
// 1. Platform sends UpdateAgent command via heartbeat
// 2. Download binary + .minisig + manifest.json from manifest_url
// 3. Verify manifest.json Ed25519 signature against pinned platform pubkey
// 4. Verify binary SHA-256 matches manifest
// 5. Write binary to temp path, verify executable
// 6. Atomic rename to replace current binary
// 7. Report update status to platform
// 8. Trigger OS service restart

use anyhow::Result;
use sha2::{Digest, Sha256};
use std::path::Path;
use tracing::{info, warn};

pub struct Updater {
    platform_url: String,
    agent_id: String,
    signing_pubkey: Option<String>,
}

impl Updater {
    pub fn new(
        platform_url: impl Into<String>,
        agent_id: impl Into<String>,
        signing_pubkey: Option<String>,
    ) -> Self {
        Self {
            platform_url: platform_url.into(),
            agent_id: agent_id.into(),
            signing_pubkey,
        }
    }

    pub async fn apply_update(&self, version: &str, manifest_url: &str) -> Result<()> {
        if self.signing_pubkey.is_none() {
            anyhow::bail!("Update signing pubkey not configured — refusing update");
        }

        info!(version, manifest_url, "Starting agent update");

        // Phase 1: Full implementation
        // 1. Download manifest.json and verify Ed25519 signature
        // 2. Extract binary URL and expected SHA-256 from manifest
        // 3. Download binary to temp path
        // 4. Verify SHA-256
        // 5. Set executable bit
        // 6. Atomic rename: std::fs::rename(temp, current_exe)
        // 7. POST /api/v1/agents/{id}/update-applied
        // 8. Graceful shutdown → OS service manager restarts

        warn!(version, "Agent update (Phase 1 — stub)");
        Ok(())
    }

    fn verify_sha256(path: &Path, expected_hex: &str) -> Result<()> {
        let contents = std::fs::read(path)?;
        let hash = Sha256::digest(&contents);
        let actual = hex::encode(hash);
        if actual != expected_hex.to_lowercase() {
            anyhow::bail!(
                "SHA-256 mismatch for {}: expected {}, got {}",
                path.display(),
                expected_hex,
                actual
            );
        }
        Ok(())
    }
}
