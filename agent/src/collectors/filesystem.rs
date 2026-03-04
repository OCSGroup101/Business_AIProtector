// Copyright 2026 Omni Cyber Solutions LLC. Apache License 2.0.
// Filesystem Collector
//
// Uses the `notify` crate for cross-platform file-system event watching.
// On Windows this delegates to ReadDirectoryChangesW; on macOS to FSEvents;
// on Linux to inotify. All platform backends share the same event-processing path.
//
// For each create or modify event, the file is SHA-256 hashed in a blocking
// Tokio thread so the async runtime is not stalled.
//
// Emits: EventType::FileCreate, FileModify, FileDelete, FileRename

use anyhow::Result;
use async_trait::async_trait;
use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Duration;
use tracing::{debug, info, warn};

use crate::collectors::Collector;
use crate::config::AgentConfig;
use crate::core::event_bus::{EventPublisher, EventType, OsInfo, TelemetryEvent};

pub struct FilesystemCollector {
    watch_paths: Vec<PathBuf>,
    agent_id: String,
    tenant_id: String,
    hostname: String,
    os_info: OsInfo,
}

impl FilesystemCollector {
    pub fn new(cfg: &AgentConfig, agent_id: &str, tenant_id: &str) -> Result<Self> {
        Ok(Self {
            watch_paths: cfg.collectors.filesystem_watch_paths.clone(),
            agent_id: agent_id.to_string(),
            tenant_id: tenant_id.to_string(),
            hostname: super::process::hostname(),
            os_info: super::process::current_os_info(),
        })
    }

    fn make_event(&self, event_type: EventType) -> TelemetryEvent {
        TelemetryEvent::new(
            &self.agent_id,
            &self.tenant_id,
            "filesystem",
            event_type,
            &self.hostname,
            self.os_info.clone(),
        )
    }
}

#[async_trait]
impl Collector for FilesystemCollector {
    fn name(&self) -> &'static str {
        "filesystem"
    }

    async fn run(self: Box<Self>, publisher: EventPublisher) -> Result<()> {
        info!(paths = ?self.watch_paths, "FilesystemCollector starting");

        if self.watch_paths.is_empty() {
            warn!("FilesystemCollector: no watch_paths configured — collector idle");
            std::future::pending::<()>().await;
            return Ok(());
        }

        // notify uses a synchronous mpsc channel; bridge it to the async publisher
        let (tx, rx) = mpsc::channel::<notify::Result<Event>>();

        let mut watcher = RecommendedWatcher::new(
            tx,
            Config::default().with_poll_interval(Duration::from_secs(2)),
        )?;

        for path in &self.watch_paths {
            if path.exists() {
                watcher.watch(path, RecursiveMode::Recursive)?;
                info!("Watching path: {:?}", path);
            } else {
                warn!("Watch path does not exist, skipping: {:?}", path);
            }
        }

        // Drain notify events in a blocking thread; publish to async bus via mpsc bridge
        let (event_tx, mut event_rx) = tokio::sync::mpsc::channel::<TelemetryEvent>(512);

        let collector_ref = std::sync::Arc::new(self);
        let bridge_ref = collector_ref.clone();

        // Spawn a blocking thread to receive from the synchronous watcher channel
        tokio::task::spawn_blocking(move || {
            for result in rx {
                match result {
                    Ok(event) => {
                        let events = bridge_ref.translate_event(event);
                        for ev in events {
                            if event_tx.blocking_send(ev).is_err() {
                                return; // channel closed — shut down
                            }
                        }
                    }
                    Err(e) => {
                        warn!(error = %e, "Filesystem watcher error");
                    }
                }
            }
        });

        // Forward translated events to the event bus
        while let Some(event) = event_rx.recv().await {
            debug!(
                event_type = ?event.event_type,
                path = ?event.payload.get("path"),
                "Filesystem event"
            );
            publisher.publish(event);
        }

        Ok(())
    }
}

impl FilesystemCollector {
    /// Translate a `notify` event into zero or more `TelemetryEvent`s.
    fn translate_event(&self, event: Event) -> Vec<TelemetryEvent> {
        let paths = event.paths;

        match event.kind {
            EventKind::Create(_) => paths
                .into_iter()
                .map(|p| self.file_event(EventType::FileCreate, &p))
                .collect(),

            EventKind::Modify(_) => paths
                .into_iter()
                .map(|p| self.file_event(EventType::FileModify, &p))
                .collect(),

            EventKind::Remove(_) => paths
                .into_iter()
                .map(|p| {
                    let mut ev = self.make_event(EventType::FileDelete);
                    ev.payload
                        .insert("path".into(), json!(p.to_string_lossy().as_ref()));
                    ev
                })
                .collect(),

            EventKind::Other => {
                // Rename shows as two events on most backends; treat as modify
                paths
                    .into_iter()
                    .map(|p| self.file_event(EventType::FileModify, &p))
                    .collect()
            }

            _ => vec![],
        }
    }

    /// Build a file event with path and optional SHA-256 hash.
    fn file_event(&self, event_type: EventType, path: &Path) -> TelemetryEvent {
        let mut ev = self.make_event(event_type);
        ev.payload
            .insert("path".into(), json!(path.to_string_lossy().as_ref()));

        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();
        ev.payload.insert("extension".into(), json!(ext));

        // Hash the file synchronously (we're already in a blocking thread context)
        if path.is_file() {
            if let Ok(meta) = std::fs::metadata(path) {
                ev.payload.insert("size_bytes".into(), json!(meta.len()));
            }
            // Only hash files up to 50 MB to avoid stalling on large media
            if let Some(hash) = hash_file_if_small(path, 50 * 1024 * 1024) {
                ev.payload.insert("hash_sha256".into(), json!(hash));
            }
        }

        ev
    }
}

/// SHA-256 hash a file if it is smaller than `max_bytes`. Returns hex string or None.
fn hash_file_if_small(path: &Path, max_bytes: u64) -> Option<String> {
    let meta = std::fs::metadata(path).ok()?;
    if meta.len() > max_bytes {
        return None;
    }
    let bytes = std::fs::read(path).ok()?;
    let digest = Sha256::digest(&bytes);
    Some(hex::encode(digest))
}
