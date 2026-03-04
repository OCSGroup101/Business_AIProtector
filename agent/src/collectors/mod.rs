// Collector trait and CollectorSet aggregator.
// Each collector runs in its own tokio task, publishing TelemetryEvents to the EventBus.

use anyhow::Result;
use async_trait::async_trait;
use tokio::task::JoinHandle;
use tracing::info;

use crate::config::AgentConfig;
use crate::core::event_bus::{EventPublisher, TelemetryEvent};

pub mod auth;
pub mod filesystem;
pub mod integrity;
pub mod network;
pub mod persistence;
pub mod process;

/// All collectors implement this trait.
#[async_trait]
pub trait Collector: Send + 'static {
    fn name(&self) -> &'static str;

    /// Run the collector loop indefinitely, publishing events via the publisher.
    /// Should only return on shutdown or fatal error.
    async fn run(self: Box<Self>, publisher: EventPublisher) -> Result<()>;
}

/// Aggregates all enabled collectors and launches them as concurrent tasks.
pub struct CollectorSet {
    collectors: Vec<Box<dyn Collector>>,
    publisher: EventPublisher,
}

impl CollectorSet {
    pub fn new(
        cfg: &AgentConfig,
        publisher: EventPublisher,
        agent_id: &str,
        tenant_id: &str,
    ) -> Result<Self> {
        let mut collectors: Vec<Box<dyn Collector>> = Vec::new();

        if cfg.collectors.process_enabled {
            collectors.push(Box::new(process::ProcessCollector::new(cfg, agent_id, tenant_id)?));
        }
        if cfg.collectors.filesystem_enabled {
            collectors.push(Box::new(filesystem::FilesystemCollector::new(cfg, agent_id, tenant_id)?));
        }
        if cfg.collectors.network_enabled {
            collectors.push(Box::new(network::NetworkCollector::new(cfg)?));
        }
        if cfg.collectors.persistence_enabled {
            collectors.push(Box::new(persistence::PersistenceCollector::new(cfg)?));
        }
        if cfg.collectors.auth_enabled {
            collectors.push(Box::new(auth::AuthCollector::new(cfg)?));
        }
        if cfg.collectors.integrity_enabled {
            collectors.push(Box::new(integrity::IntegrityCollector::new(cfg)?));
        }

        info!(count = collectors.len(), "Collectors initialized");
        Ok(Self { collectors, publisher })
    }

    /// Run all collectors concurrently. Returns when any collector exits.
    pub async fn run(self) -> Result<()> {
        let mut handles: Vec<JoinHandle<Result<()>>> = Vec::new();

        for collector in self.collectors {
            let name = collector.name();
            let publisher = self.publisher.clone();
            info!(collector = name, "Starting collector");
            let handle = tokio::spawn(async move {
                collector.run(publisher).await
            });
            handles.push(handle);
        }

        // Wait for any collector to finish (they shouldn't in normal operation)
        let (result, _, _) = futures::future::select_all(handles).await;
        match result {
            Ok(inner) => inner,
            Err(e) => Err(anyhow::anyhow!("Collector task panicked: {}", e)),
        }
    }
}
