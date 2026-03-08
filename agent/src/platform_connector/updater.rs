// Copyright 2026 Omni Cyber Solutions LLC. Apache License 2.0.
//
// Agent self-updater — Ed25519 signature verify → atomic binary replace
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
use base64::Engine;
use ring::signature::{self, UnparsedPublicKey};
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
        let pubkey_str = self.signing_pubkey.as_deref().ok_or_else(|| {
            anyhow::anyhow!("Update signing pubkey not configured — refusing update")
        })?;

        info!(version, manifest_url, "Starting agent update");

        let client = reqwest::Client::new();

        // ── Step 1: Download manifest.json ────────────────────────────────
        let manifest_json = client
            .get(manifest_url)
            .send()
            .await?
            .error_for_status()?
            .bytes()
            .await?;

        // ── Step 2: Download manifest.json.minisig ────────────────────────
        let sig_url = format!("{}.minisig", manifest_url);
        let sig_bytes = client
            .get(&sig_url)
            .send()
            .await?
            .error_for_status()?
            .bytes()
            .await?;

        // ── Step 3: Verify Ed25519 signature ─────────────────────────────
        let sig = parse_minisig(&sig_bytes)
            .map_err(|e| anyhow::anyhow!("Failed to parse minisig: {}", e))?;
        let pubkey_bytes = parse_minisign_pubkey(pubkey_str)
            .map_err(|e| anyhow::anyhow!("Failed to parse pubkey: {}", e))?;

        let pk = UnparsedPublicKey::new(&signature::ED25519, pubkey_bytes);
        pk.verify(&manifest_json, &sig).map_err(|_| {
            anyhow::anyhow!("Manifest signature verification FAILED — aborting update")
        })?;
        info!(version, "Manifest Ed25519 signature verified");

        // ── Step 4: Parse manifest JSON ───────────────────────────────────
        let manifest: serde_json::Value = serde_json::from_slice(&manifest_json)?;
        let binary_url = manifest["binary_url"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("manifest missing binary_url"))?;
        let expected_sha256 = manifest["sha256"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("manifest missing sha256"))?;

        // ── Step 5: Download binary to temp path ─────────────────────────
        let binary_bytes = client
            .get(binary_url)
            .send()
            .await?
            .error_for_status()?
            .bytes()
            .await?;

        let current_exe = std::env::current_exe()?;
        let tmp_path = current_exe.with_extension("update.tmp");
        std::fs::write(&tmp_path, &binary_bytes)?;

        // ── Step 6: Verify SHA-256 ────────────────────────────────────────
        Self::verify_sha256(&tmp_path, expected_sha256).map_err(|e| {
            let _ = std::fs::remove_file(&tmp_path);
            e
        })?;
        info!(version, "Binary SHA-256 verified");

        // ── Step 7: Set executable bit (Unix only) ────────────────────────
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&tmp_path)?.permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&tmp_path, perms)?;
        }

        // ── Step 8: Atomic rename ─────────────────────────────────────────
        std::fs::rename(&tmp_path, &current_exe)?;
        info!(
            version,
            path = %current_exe.display(),
            "Agent binary replaced — initiating graceful restart"
        );

        // ── Step 9: Report success to platform ───────────────────────────
        let report_url = format!(
            "{}/api/v1/agents/{}/update-applied",
            self.platform_url, self.agent_id
        );
        if let Err(e) = client
            .post(&report_url)
            .json(&serde_json::json!({ "version": version }))
            .send()
            .await
        {
            warn!(error = %e, "Failed to report update status — continuing with restart");
        }

        // ── Step 10: Graceful shutdown (service manager will restart) ─────
        // Exit 0 — systemd/launchd/SCM will restart the process.
        std::process::exit(0);
    }

    pub fn verify_sha256(path: &Path, expected_hex: &str) -> Result<()> {
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

/// Parse a .minisig file and return the 64-byte Ed25519 signature.
///
/// minisig format:
///   Line 0: comment (starts with "untrusted comment:")
///   Line 1: base64-encoded blob
///     bytes 0-1: algorithm ("Ed")
///     bytes 2-9: key ID (8 bytes)
///     bytes 10-73: 64-byte Ed25519 signature
fn parse_minisig(data: &[u8]) -> Result<Vec<u8>> {
    let text = std::str::from_utf8(data)?;
    let line = text
        .lines()
        .find(|l| !l.starts_with("untrusted comment:"))
        .ok_or_else(|| anyhow::anyhow!("minisig: no signature line found"))?;

    let blob = base64::engine::general_purpose::STANDARD.decode(line.trim())?;
    if blob.len() < 74 {
        anyhow::bail!("minisig blob too short: {} bytes", blob.len());
    }
    // Skip 2-byte algorithm + 8-byte key ID → signature starts at byte 10
    Ok(blob[10..74].to_vec())
}

/// Parse a minisign public key string and return the 32-byte Ed25519 key.
///
/// Public key format:
///   Line 0: comment (starts with "untrusted comment:")
///   Line 1: base64-encoded blob
///     bytes 0-1: algorithm ("Ed")
///     bytes 2-9: key ID (8 bytes)
///     bytes 10-41: 32-byte Ed25519 public key
fn parse_minisign_pubkey(pubkey_str: &str) -> Result<Vec<u8>> {
    let line = pubkey_str
        .lines()
        .find(|l| !l.starts_with("untrusted comment:"))
        .ok_or_else(|| anyhow::anyhow!("pubkey: no key line found"))?;

    let blob = base64::engine::general_purpose::STANDARD.decode(line.trim())?;
    if blob.len() < 42 {
        anyhow::bail!("pubkey blob too short: {} bytes", blob.len());
    }
    // Skip 2-byte algorithm + 8-byte key ID → public key starts at byte 10
    Ok(blob[10..42].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use tempfile::TempDir;

    #[test]
    fn test_verify_sha256_pass() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("test.bin");
        let data = b"OpenClaw update payload";
        std::fs::write(&path, data).unwrap();
        let expected = hex::encode(Sha256::digest(data));
        Updater::verify_sha256(&path, &expected).unwrap();
    }

    #[test]
    fn test_verify_sha256_fail() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("test.bin");
        std::fs::write(&path, b"legit content").unwrap();
        let result = Updater::verify_sha256(&path, "deadbeef");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_minisig_structure() {
        // Craft a minimal .minisig with known content
        let algorithm = b"Ed";
        let key_id = b"12345678"; // 8 bytes
        let fake_sig = [0xABu8; 64]; // 64-byte signature
        let mut blob = Vec::new();
        blob.extend_from_slice(algorithm);
        blob.extend_from_slice(key_id);
        blob.extend_from_slice(&fake_sig);

        let b64 = base64::engine::general_purpose::STANDARD.encode(&blob);
        let minisig = format!("untrusted comment: test\n{}\n", b64);

        let sig = parse_minisig(minisig.as_bytes()).unwrap();
        assert_eq!(sig, fake_sig);
    }

    #[test]
    fn test_ed25519_roundtrip() {
        let rng = SystemRandom::new();
        // Generate an Ed25519 keypair using PKCS#8 DER
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();

        let message = b"test update manifest content";
        let signature = key_pair.sign(message);

        let pub_key = UnparsedPublicKey::new(
            &signature::ED25519,
            key_pair.public_key().as_ref().to_vec(),
        );
        assert!(pub_key.verify(message, signature.as_ref()).is_ok());

        // Mutate signature → should fail
        let mut bad_sig = signature.as_ref().to_vec();
        bad_sig[0] ^= 0xFF;
        assert!(pub_key.verify(message, &bad_sig).is_err());
    }
}
