// Persistence Collector — Phase 2
//
// Monitors: Registry Run keys, Scheduled Tasks, Windows Services, DLL hijack paths
// Emits: EventType::PersistenceCreate, PersistenceModify

use anyhow::Result;
use async_trait::async_trait;
use serde_json::json;
use tracing::{debug, info};

use crate::collectors::Collector;
use crate::config::AgentConfig;
use crate::core::event_bus::{EventPublisher, EventType, OsInfo, TelemetryEvent};

pub struct PersistenceCollector {
    agent_id: String,
    tenant_id: String,
    hostname: String,
    os_info: OsInfo,
}

impl PersistenceCollector {
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
impl Collector for PersistenceCollector {
    fn name(&self) -> &'static str { "persistence" }

    async fn run(self: Box<Self>, publisher: EventPublisher) -> Result<()> {
        info!("PersistenceCollector starting (Phase 2 — stub mode)");
        // Phase 2: Implement registry change monitoring (RegNotifyChangeKeyValue),
        // scheduled task watcher (Task Scheduler COM API), and service creation
        // (SCM event log monitoring).
        tokio::time::sleep(tokio::time::Duration::MAX).await;
        Ok(())
    }
}
