// Policy sync — pull latest policy bundle from platform, verify signature

use anyhow::Result;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};

use crate::config::AgentConfig;

/// The live policy data shared across agent subsystems
#[derive(Clone, Default)]
pub struct LivePolicy {
    pub version: u64,
    pub raw_toml: String,
}

/// A cheap cloneable handle to the live policy
#[derive(Clone)]
pub struct PolicyHandle {
    inner: Arc<RwLock<LivePolicy>>,
}

impl PolicyHandle {
    pub async fn current(&self) -> LivePolicy {
        self.inner.read().await.clone()
    }

    pub async fn version(&self) -> u64 {
        self.inner.read().await.version
    }
}

pub struct PolicySync {
    platform_url: String,
    agent_id: String,
    handle: PolicyHandle,
}

impl PolicySync {
    pub fn new(cfg: &AgentConfig, agent_id: &str) -> Result<Self> {
        Ok(Self {
            platform_url: cfg.platform.url.clone(),
            agent_id: agent_id.to_string(),
            handle: PolicyHandle {
                inner: Arc::new(RwLock::new(LivePolicy::default())),
            },
        })
    }

    pub fn policy_handle(&self) -> PolicyHandle {
        self.handle.clone()
    }

    /// Run the policy sync loop — polls on heartbeat triggers.
    pub async fn run(self) -> Result<()> {
        // Phase 1: Triggered by heartbeat when platform indicates version change
        info!("PolicySync: waiting for heartbeat triggers (Phase 1)");
        tokio::time::sleep(tokio::time::Duration::MAX).await;
        Ok(())
    }

    async fn fetch_and_apply(&self, version: u64) -> Result<()> {
        // Phase 1: Fetch signed policy bundle, verify minisign signature,
        // parse TOML, update live policy, notify subscribers
        info!(version, "Applying policy update");
        Ok(())
    }
}
