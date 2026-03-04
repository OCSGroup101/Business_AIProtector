// Authentication Collector — Phase 2
//
// Source: Windows Security Event Log
// Event IDs: 4624 (logon), 4625 (logon failure), 4648 (explicit creds),
//             4672 (special privileges), 4688 (process create with subject),
//             4697 (service installed), 4698 (scheduled task created)
//
// Emits: EventType::AuthLogon, AuthLogonFailure, AuthPrivilegeEscalation

use anyhow::Result;
use async_trait::async_trait;
use tracing::info;

use crate::collectors::Collector;
use crate::config::AgentConfig;
use crate::core::event_bus::{EventPublisher, EventType, OsInfo, TelemetryEvent};

pub struct AuthCollector {
    event_ids: Vec<u32>,
    agent_id: String,
    tenant_id: String,
    hostname: String,
    os_info: OsInfo,
}

impl AuthCollector {
    pub fn new(cfg: &AgentConfig) -> Result<Self> {
        Ok(Self {
            event_ids: cfg.collectors.auth_event_ids.clone(),
            agent_id: String::new(),
            tenant_id: String::new(),
            hostname: super::process::hostname_stub(),
            os_info: super::process::os_info_stub(),
        })
    }
}

#[async_trait]
impl Collector for AuthCollector {
    fn name(&self) -> &'static str { "auth" }

    async fn run(self: Box<Self>, publisher: EventPublisher) -> Result<()> {
        info!(event_ids = ?self.event_ids, "AuthCollector starting (Phase 2 — stub mode)");
        // Phase 2: Open Windows Security event log channel with EvtSubscribe,
        // filter on configured event IDs, parse XML fields into TelemetryEvent payload.
        tokio::time::sleep(tokio::time::Duration::MAX).await;
        Ok(())
    }
}
