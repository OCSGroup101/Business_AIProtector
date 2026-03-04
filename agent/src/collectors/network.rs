// Network Collector
//
// Windows: WSAEventSelect + DNS cache monitoring
// macOS:   libpcap / nettop — Phase 3
// Linux:   netlink — Phase 3
//
// Emits: EventType::NetworkConnect, NetworkListen, NetworkDnsQuery

use anyhow::Result;
use async_trait::async_trait;
use serde_json::json;
use tracing::{debug, info};

use crate::collectors::Collector;
use crate::config::AgentConfig;
use crate::core::event_bus::{EventPublisher, EventType, OsInfo, TelemetryEvent};

pub struct NetworkCollector {
    capture_dns: bool,
    agent_id: String,
    tenant_id: String,
    hostname: String,
    os_info: OsInfo,
}

impl NetworkCollector {
    pub fn new(cfg: &AgentConfig) -> Result<Self> {
        Ok(Self {
            capture_dns: cfg.collectors.network_capture_dns,
            agent_id: String::new(),
            tenant_id: String::new(),
            hostname: super::process::hostname_stub(),
            os_info: super::process::os_info_stub(),
        })
    }

    fn make_event(&self, event_type: EventType) -> TelemetryEvent {
        TelemetryEvent::new(
            &self.agent_id, &self.tenant_id, "network",
            event_type, &self.hostname, self.os_info.clone(),
        )
    }
}

#[async_trait]
impl Collector for NetworkCollector {
    fn name(&self) -> &'static str { "network" }

    async fn run(self: Box<Self>, publisher: EventPublisher) -> Result<()> {
        info!(capture_dns = self.capture_dns, "NetworkCollector starting");
        run_stub(*self, publisher).await
    }
}

async fn run_stub(collector: NetworkCollector, publisher: EventPublisher) -> Result<()> {
    use tokio::time::{sleep, Duration};
    loop {
        sleep(Duration::from_secs(60)).await;
        let mut event = collector.make_event(EventType::NetworkConnect);
        event.payload.insert("dst_ip".into(), json!("203.0.113.42"));
        event.payload.insert("dst_port".into(), json!(443u16));
        event.payload.insert("src_ip".into(), json!("10.0.0.5"));
        event.payload.insert("src_port".into(), json!(54321u16));
        event.payload.insert("protocol".into(), json!("TCP"));
        event.payload.insert("process_pid".into(), json!(1234u32));
        event.payload.insert("process_name".into(), json!("stub.exe"));
        debug!("NetworkCollector (stub): emitting synthetic network.connect");
        publisher.publish(event);
    }
}
