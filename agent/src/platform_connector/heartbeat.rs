// 60-second heartbeat — reports health metrics, receives push commands

use anyhow::Result;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::{debug, info, warn};

use crate::config::AgentConfig;
use crate::core::state::AgentStateManager;

#[derive(Serialize)]
struct HeartbeatRequest {
    agent_id: String,
    agent_version: String,
    state: String,
    policy_version: u64,
    metrics: HealthMetrics,
}

#[derive(Serialize)]
struct HealthMetrics {
    cpu_percent: f32,
    ram_mb: u32,
    ring_buffer_fill_pct: u8,
    events_processed_since_last_heartbeat: u64,
}

#[derive(Deserialize)]
struct HeartbeatResponse {
    /// If set, the agent should pull this policy version
    policy_update_version: Option<u64>,
    /// Commands for the agent to execute
    #[serde(default)]
    commands: Vec<PlatformCommand>,
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum PlatformCommand {
    Isolate,
    LiftIsolation,
    UpdateAgent { version: String, manifest_url: String },
    PullIntelBundle { bundle_id: String },
}

pub struct HeartbeatService {
    client: Client,
    agent_id: String,
    platform_url: String,
    interval: Duration,
    state_manager: AgentStateManager,
}

impl HeartbeatService {
    pub fn new(cfg: &AgentConfig, agent_id: &str, state_manager: AgentStateManager) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(15))
            .build()?;
        Ok(Self {
            client,
            agent_id: agent_id.to_string(),
            platform_url: cfg.platform.url.clone(),
            interval: Duration::from_secs(cfg.platform.heartbeat_interval_secs),
            state_manager,
        })
    }

    pub async fn run(self) -> Result<()> {
        info!(interval_secs = self.interval.as_secs(), "Heartbeat service starting");
        let mut ticker = tokio::time::interval(self.interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            ticker.tick().await;
            if let Err(e) = self.send_heartbeat().await {
                warn!(error = %e, "Heartbeat failed — will retry next interval");
            }
        }
    }

    async fn send_heartbeat(&self) -> Result<()> {
        let request = HeartbeatRequest {
            agent_id: self.agent_id.clone(),
            agent_version: env!("CARGO_PKG_VERSION").to_string(),
            state: self.state_manager.current_state().to_string(),
            policy_version: self.state_manager.policy_version(),
            metrics: HealthMetrics {
                cpu_percent: 0.0,  // Phase 1: read from /proc/stat or GetSystemTimes
                ram_mb: 0,         // Phase 1: read from /proc/self/status or GetProcessMemoryInfo
                ring_buffer_fill_pct: 0,
                events_processed_since_last_heartbeat: 0,
            },
        };

        let response = self.client
            .post(format!("{}/api/v1/agents/{}/heartbeat", self.platform_url, self.agent_id))
            .json(&request)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            anyhow::bail!("Heartbeat rejected by platform: {}", status);
        }

        let hb_response: HeartbeatResponse = response.json().await?;
        debug!("Heartbeat acknowledged");

        // Process any commands from the platform
        for command in hb_response.commands {
            self.handle_command(command).await;
        }

        Ok(())
    }

    async fn handle_command(&self, command: PlatformCommand) {
        match command {
            PlatformCommand::Isolate => {
                info!("Platform command: ISOLATE");
                if let Err(e) = crate::containment::isolation::isolate_host().await {
                    warn!(error = %e, "Host isolation failed");
                }
            }
            PlatformCommand::LiftIsolation => {
                info!("Platform command: LIFT_ISOLATION");
                if let Err(e) = crate::containment::isolation::lift_isolation().await {
                    warn!(error = %e, "Lift isolation failed");
                }
            }
            PlatformCommand::UpdateAgent { version, manifest_url } => {
                info!(version = %version, "Platform command: UPDATE_AGENT");
                // Delegate to updater — Phase 1
            }
            PlatformCommand::PullIntelBundle { bundle_id } => {
                info!(bundle_id = %bundle_id, "Platform command: PULL_INTEL_BUNDLE");
                // Delegate to intel_receiver — Phase 1
            }
        }
    }
}
