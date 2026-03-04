// Copyright 2026 Omni Cyber Solutions LLC. Apache License 2.0.
//
// Policy sync — pull the current policy bundle from the platform when
// the heartbeat signals that a newer version is available.
//
// The heartbeat handler sends the new version number over a tokio channel;
// this module fetches, verifies (Phase 2: minisign), and hot-reloads the TOML.

use anyhow::Result;
use reqwest::Client;
use serde::Deserialize;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tracing::{info, warn};

use crate::config::AgentConfig;
use crate::platform_connector::client::build_platform_client;

// ─── Shared policy state ──────────────────────────────────────────────────────

/// The live policy data shared across agent subsystems.
#[derive(Clone, Default)]
pub struct LivePolicy {
    pub version: u64,
    pub raw_toml: String,
}

/// A cheap cloneable handle to the live policy.
#[derive(Clone)]
pub struct PolicyHandle {
    inner: Arc<RwLock<LivePolicy>>,
}

impl PolicyHandle {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(LivePolicy::default())),
        }
    }

    pub async fn current(&self) -> LivePolicy {
        self.inner.read().await.clone()
    }

    pub async fn version(&self) -> u64 {
        self.inner.read().await.version
    }

    async fn update(&self, policy: LivePolicy) {
        *self.inner.write().await = policy;
    }
}

// ─── Platform response ────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct AgentPolicyResponse {
    version: u64,
    content_toml: String,
}

// ─── Policy sync service ──────────────────────────────────────────────────────

/// Receives version-change signals from the heartbeat and fetches new policy.
pub struct PolicySync {
    client: Client,
    platform_url: String,
    agent_id: String,
    handle: PolicyHandle,
    trigger_rx: mpsc::Receiver<u64>,
}

/// Sender half — given to the heartbeat service so it can signal version changes.
pub type PolicyTrigger = mpsc::Sender<u64>;

impl PolicySync {
    pub fn new(cfg: &AgentConfig, agent_id: &str) -> Result<(Self, PolicyTrigger)> {
        let (trigger_tx, trigger_rx) = mpsc::channel(8);
        let client = build_platform_client(cfg, std::time::Duration::from_secs(30))?;

        let sync = Self {
            client,
            platform_url: cfg.platform.url.clone(),
            agent_id: agent_id.to_string(),
            handle: PolicyHandle::new(),
            trigger_rx,
        };

        Ok((sync, trigger_tx))
    }

    pub fn policy_handle(&self) -> PolicyHandle {
        self.handle.clone()
    }

    /// Run the policy sync loop — blocks until shutdown.
    pub async fn run(mut self) -> Result<()> {
        info!("PolicySync: waiting for heartbeat triggers");
        while let Some(new_version) = self.trigger_rx.recv().await {
            let current = self.handle.version().await;
            if new_version <= current {
                continue; // Already up to date (or spurious signal).
            }
            info!(new_version, current, "Policy update signalled — fetching");
            if let Err(e) = self.fetch_and_apply(new_version).await {
                warn!(error = %e, "Policy fetch failed — will retry on next signal");
            }
        }
        Ok(())
    }

    async fn fetch_and_apply(&self, expected_version: u64) -> Result<()> {
        let url = format!(
            "{}/api/v1/agents/{}/policy",
            self.platform_url, self.agent_id
        );

        let resp = self.client.get(&url).send().await?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("Policy fetch failed ({}): {}", status, body);
        }

        let bundle: AgentPolicyResponse = resp.json().await?;

        // Phase 2: verify minisign Ed25519 signature before applying.
        // For now, log a warning in debug builds and proceed.
        #[cfg(debug_assertions)]
        tracing::debug!(version = bundle.version, "Policy signature verification skipped in debug build");

        self.handle
            .update(LivePolicy {
                version: bundle.version,
                raw_toml: bundle.content_toml,
            })
            .await;

        info!(version = bundle.version, "Policy applied successfully");
        Ok(())
    }
}
