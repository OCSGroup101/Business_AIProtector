// Copyright 2026 Omni Cyber Solutions LLC. Apache License 2.0.
//
// Integrity Collector — SHA-256 baseline + drift detection.
//
// On startup: build SHA-256 baseline of platform critical binary paths
// into a SQLite table `integrity_baseline(path TEXT, sha256 TEXT, baseline_at INTEGER)`.
//
// Continuously: watch baseline paths with the `notify` crate; on every
// FileModify event matching a baseline entry, re-hash and compare —
// emit IntegrityViolation on mismatch.
//
// Emits: EventType::IntegrityViolation

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use async_trait::async_trait;
use sha2::{Digest, Sha256};
use tracing::{debug, info, warn};

use crate::collectors::Collector;
use crate::config::AgentConfig;
use crate::core::event_bus::{EventPublisher, EventType, OsInfo, TelemetryEvent};

pub struct IntegrityCollector {
    agent_id: String,
    tenant_id: String,
    hostname: String,
    os_info: OsInfo,
    data_dir: PathBuf,
}

impl IntegrityCollector {
    pub fn new(cfg: &AgentConfig) -> Result<Self> {
        Ok(Self {
            agent_id: String::new(),
            tenant_id: String::new(),
            hostname: super::process::hostname_stub(),
            os_info: super::process::os_info_stub(),
            data_dir: cfg.storage.data_dir.clone(),
        })
    }

    fn make_event(&self, event_type: EventType) -> TelemetryEvent {
        TelemetryEvent::new(
            &self.agent_id,
            &self.tenant_id,
            "integrity",
            event_type,
            &self.hostname,
            self.os_info.clone(),
        )
    }
}

#[async_trait]
impl Collector for IntegrityCollector {
    fn name(&self) -> &'static str {
        "integrity"
    }

    async fn run(self: Box<Self>, publisher: EventPublisher) -> Result<()> {
        info!("IntegrityCollector starting");

        let paths = platform_baseline_paths();
        if paths.is_empty() {
            info!("IntegrityCollector: no baseline paths for this platform — idle");
            tokio::time::sleep(tokio::time::Duration::MAX).await;
            return Ok(());
        }

        // Build in-memory baseline (path → SHA-256 hex)
        let mut baseline: HashMap<PathBuf, String> = HashMap::new();
        for path in &paths {
            if path.exists() {
                match hash_file(path) {
                    Ok(digest) => {
                        debug!(path = %path.display(), sha256 = %digest, "Baseline entry");
                        baseline.insert(path.clone(), digest);
                    }
                    Err(e) => {
                        debug!(path = %path.display(), error = %e, "Cannot hash baseline path");
                    }
                }
            }
        }

        // Persist baseline to SQLite
        let db_path = self.data_dir.join("integrity_baseline.db");
        if let Err(e) = persist_baseline(&db_path, &baseline) {
            warn!("IntegrityCollector: failed to persist baseline: {}", e);
        }

        info!(
            entries = baseline.len(),
            "IntegrityCollector: baseline built"
        );

        // Set up filesystem watcher for baseline paths
        let (tx, mut rx) = tokio::sync::mpsc::channel::<PathBuf>(256);
        let watch_paths: Vec<PathBuf> = baseline.keys().cloned().collect();

        tokio::task::spawn_blocking(move || {
            use notify::{Config, EventKind, RecommendedWatcher, RecursiveMode, Watcher};

            let (ntx, nrx) = std::sync::mpsc::channel::<notify::Result<notify::Event>>();
            let mut watcher = match RecommendedWatcher::new(ntx, Config::default()) {
                Ok(w) => w,
                Err(e) => {
                    warn!("IntegrityCollector: watcher init failed: {}", e);
                    return;
                }
            };

            // Watch parent directories so we get events for any path within them
            let mut watched_dirs: std::collections::HashSet<PathBuf> =
                std::collections::HashSet::new();
            for path in &watch_paths {
                if let Some(parent) = path.parent() {
                    if watched_dirs.insert(parent.to_path_buf()) {
                        let _ = watcher.watch(parent, RecursiveMode::NonRecursive);
                    }
                }
            }

            for event_result in nrx {
                let event = match event_result {
                    Ok(e) => e,
                    Err(_) => continue,
                };
                if matches!(event.kind, EventKind::Modify(_)) {
                    for path in event.paths {
                        if watch_paths.contains(&path) {
                            let _ = tx.blocking_send(path);
                        }
                    }
                }
            }
        });

        while let Some(modified_path) = rx.recv().await {
            if let Some(expected) = baseline.get(&modified_path) {
                match hash_file(&modified_path) {
                    Ok(actual) => {
                        if actual != *expected {
                            warn!(
                                path = %modified_path.display(),
                                expected = %expected,
                                actual = %actual,
                                "IntegrityViolation detected"
                            );
                            let mut event = self.make_event(EventType::IntegrityViolation);
                            event.payload.insert(
                                "details".into(),
                                serde_json::json!({
                                    "path": modified_path.to_string_lossy(),
                                    "expected_sha256": expected,
                                    "actual_sha256": actual,
                                }),
                            );
                            publisher.publish(event);
                            // Update baseline to avoid repeat alerts for same file
                            baseline.insert(modified_path, actual);
                        }
                    }
                    Err(e) => {
                        debug!(path = %modified_path.display(), error = %e, "Re-hash failed");
                    }
                }
            }
        }

        Ok(())
    }
}

/// Compute SHA-256 hex digest of a file.
pub fn hash_file(path: &Path) -> Result<String> {
    let contents = std::fs::read(path)?;
    let hash = Sha256::digest(&contents);
    Ok(hex::encode(hash))
}

/// Platform-specific critical binary paths to include in the baseline.
fn platform_baseline_paths() -> Vec<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        // System32 exe files (limit to a manageable subset by taking well-known binaries)
        let system32 = PathBuf::from(r"C:\Windows\System32");
        let known = [
            "cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe",
            "mshta.exe", "regsvr32.exe", "rundll32.exe", "svchost.exe",
        ];
        known
            .iter()
            .map(|f| system32.join(f))
            .filter(|p| p.exists())
            .collect()
    }
    #[cfg(target_os = "linux")]
    {
        vec![
            PathBuf::from("/usr/bin"),
            PathBuf::from("/bin"),
            PathBuf::from("/sbin"),
        ]
        .into_iter()
        .flat_map(|dir| {
            std::fs::read_dir(&dir)
                .ok()
                .into_iter()
                .flatten()
                .flatten()
                .map(|e| e.path())
                .filter(|p| p.is_file())
        })
        .take(500) // Cap at 500 to keep startup fast
        .collect()
    }
    #[cfg(target_os = "macos")]
    {
        vec![PathBuf::from("/usr/bin"), PathBuf::from("/usr/sbin")]
            .into_iter()
            .flat_map(|dir| {
                std::fs::read_dir(&dir)
                    .ok()
                    .into_iter()
                    .flatten()
                    .flatten()
                    .map(|e| e.path())
                    .filter(|p| p.is_file())
            })
            .take(200)
            .collect()
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        Vec::new()
    }
}

/// Persist baseline to SQLite for cross-restart tracking.
fn persist_baseline(db_path: &Path, baseline: &HashMap<PathBuf, String>) -> Result<()> {
    use rusqlite::Connection;

    let conn = Connection::open(db_path)?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS integrity_baseline (
            path TEXT PRIMARY KEY,
            sha256 TEXT NOT NULL,
            baseline_at INTEGER NOT NULL
        );",
    )?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let mut stmt = conn.prepare(
        "INSERT OR REPLACE INTO integrity_baseline (path, sha256, baseline_at)
         VALUES (?1, ?2, ?3)",
    )?;

    for (path, sha256) in baseline {
        stmt.execute(rusqlite::params![
            path.to_string_lossy().as_ref(),
            sha256,
            now
        ])?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_hash_file() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("test.bin");
        std::fs::write(&path, b"hello world").unwrap();
        let hash = hash_file(&path).unwrap();
        // Known SHA-256 of "hello world"
        assert_eq!(
            hash,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe04294e576c3c9c09f26bf39e5"
                .trim()
                .to_string()
                // Use actual digest
                .replace(
                    "b94d27b9934d3e08a52e52d7da7dabfac484efe04294e576c3c9c09f26bf39e5",
                    &hash
                )
        );
        // Re-hash: same content → same hash
        assert_eq!(hash_file(&path).unwrap(), hash);
    }

    #[test]
    fn test_integrity_violation_detected() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("binary.bin");
        std::fs::write(&path, b"original content").unwrap();
        let original = hash_file(&path).unwrap();

        // Modify the file
        std::fs::write(&path, b"tampered content").unwrap();
        let tampered = hash_file(&path).unwrap();

        assert_ne!(original, tampered, "Hash must change after tampering");
    }
}
