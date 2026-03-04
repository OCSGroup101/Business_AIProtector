// Integrity Collector — Phase 2
//
// Maintains SHA-256 baseline of critical system binaries.
// On startup: build baseline if not present; otherwise verify.
// Continuously: re-verify on file modification events.
//
// Emits: EventType::IntegrityViolation

use anyhow::Result;
use async_trait::async_trait;
use tracing::info;

use crate::collectors::Collector;
use crate::config::AgentConfig;
use crate::core::event_bus::{EventPublisher, EventType, OsInfo, TelemetryEvent};

pub struct IntegrityCollector {
    agent_id: String,
    tenant_id: String,
    hostname: String,
    os_info: OsInfo,
}

impl IntegrityCollector {
    pub fn new(cfg: &AgentConfig) -> Result<Self> {
        Ok(Self {
            agent_id: String::new(),
            tenant_id: String::new(),
            hostname: super::process::hostname_stub(),
            os_info: super::process::os_info_stub(),
        })
    }
}

#[async_trait]
impl Collector for IntegrityCollector {
    fn name(&self) -> &'static str { "integrity" }

    async fn run(self: Box<Self>, publisher: EventPublisher) -> Result<()> {
        info!("IntegrityCollector starting (Phase 2 — stub mode)");
        // Phase 2: Build baseline of system32/*.exe SHA-256 hashes on first run.
        // Store in SQLite. On file modification events from FilesystemCollector,
        // re-hash and compare — emit IntegrityViolation if mismatch.
        tokio::time::sleep(tokio::time::Duration::MAX).await;
        Ok(())
    }
}
