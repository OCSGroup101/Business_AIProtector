// Filesystem Collector
//
// Windows: ReadDirectoryChangesW on configured watch paths
// macOS:   FSEvents — Phase 3
// Linux:   inotify — Phase 3
//
// Emits: EventType::FileCreate, FileModify, FileDelete, FileRename

use anyhow::Result;
use async_trait::async_trait;
use serde_json::json;
use std::path::PathBuf;
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
    pub fn new(cfg: &AgentConfig) -> Result<Self> {
        Ok(Self {
            watch_paths: cfg.collectors.filesystem_watch_paths.clone(),
            agent_id: String::new(),
            tenant_id: String::new(),
            hostname: super::process::hostname_stub(),
            os_info: super::process::os_info_stub(),
        })
    }

    fn make_event(&self, event_type: EventType) -> TelemetryEvent {
        TelemetryEvent::new(
            &self.agent_id, &self.tenant_id, "filesystem",
            event_type, &self.hostname, self.os_info.clone(),
        )
    }
}

#[async_trait]
impl Collector for FilesystemCollector {
    fn name(&self) -> &'static str { "filesystem" }

    async fn run(self: Box<Self>, publisher: EventPublisher) -> Result<()> {
        info!(paths = ?self.watch_paths, "FilesystemCollector starting");
        #[cfg(target_os = "windows")]
        { run_windows(*self, publisher).await }
        #[cfg(not(target_os = "windows"))]
        { run_stub(*self, publisher).await }
    }
}

#[cfg(target_os = "windows")]
async fn run_windows(collector: FilesystemCollector, publisher: EventPublisher) -> Result<()> {
    // Phase 1: Implement ReadDirectoryChangesW per watch path.
    // Use FILE_NOTIFY_INFORMATION to detect create/modify/delete/rename.
    // Hash new/modified files with SHA-256 in a background thread.
    info!("Windows filesystem collector (Phase 1 implementation pending)");
    run_stub(collector, publisher).await
}

async fn run_stub(collector: FilesystemCollector, publisher: EventPublisher) -> Result<()> {
    use tokio::time::{sleep, Duration};
    loop {
        sleep(Duration::from_secs(45)).await;
        let mut event = collector.make_event(EventType::FileCreate);
        event.payload.insert("path".into(), json!("C:\\Users\\test\\Downloads\\suspicious.exe"));
        event.payload.insert("hash_sha256".into(), json!("0000000000000000000000000000000000000000000000000000000000000000"));
        event.payload.insert("size_bytes".into(), json!(102400u64));
        event.payload.insert("process_pid".into(), json!(1234u32));
        debug!("FilesystemCollector (stub): emitting synthetic file.create");
        publisher.publish(event);
    }
}
