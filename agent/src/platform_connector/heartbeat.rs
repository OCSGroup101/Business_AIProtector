// Copyright 2026 Omni Cyber Solutions LLC. Apache License 2.0.
//
// 60-second heartbeat — reports health metrics, receives push commands,
// triggers policy sync and certificate renewal when the platform requests it.

use anyhow::Result;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;
use tracing::{debug, info, warn};

use crate::config::AgentConfig;
use crate::core::metrics;
use crate::core::state::AgentStateManager;
use crate::platform_connector::cert_renewal::CertRenewalClient;
use crate::platform_connector::client::build_platform_client;
use crate::platform_connector::policy_sync::PolicyTrigger;

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
    /// If set, the agent should pull this policy version.
    policy_update_version: Option<u64>,
    /// Commands for the agent to execute.
    #[serde(default)]
    commands: Vec<PlatformCommand>,
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum PlatformCommand {
    Isolate,
    LiftIsolation,
    RenewCert,
    UpdateAgent {
        version: String,
        manifest_url: String,
    },
    PullIntelBundle {
        bundle_id: String,
    },
}

pub struct HeartbeatService {
    client: Client,
    agent_id: String,
    platform_url: String,
    interval: Duration,
    state_manager: AgentStateManager,
    policy_trigger: PolicyTrigger,
    data_dir: PathBuf,
}

impl HeartbeatService {
    pub fn new(
        cfg: &AgentConfig,
        agent_id: &str,
        state_manager: AgentStateManager,
        policy_trigger: PolicyTrigger,
    ) -> Result<Self> {
        let client = build_platform_client(cfg, Duration::from_secs(15))?;
        Ok(Self {
            client,
            agent_id: agent_id.to_string(),
            platform_url: cfg.platform.url.clone(),
            interval: Duration::from_secs(cfg.platform.heartbeat_interval_secs),
            state_manager,
            policy_trigger,
            data_dir: cfg.storage.data_dir.clone(),
        })
    }

    pub async fn run(self) -> Result<()> {
        info!(
            interval_secs = self.interval.as_secs(),
            "Heartbeat service starting"
        );
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
        let resource = metrics::sample();
        let policy_version = self.state_manager.policy_version();

        let request = HeartbeatRequest {
            agent_id: self.agent_id.clone(),
            agent_version: env!("CARGO_PKG_VERSION").to_string(),
            state: self.state_manager.current_state().to_string(),
            policy_version,
            metrics: HealthMetrics {
                cpu_percent: resource.cpu_percent,
                ram_mb: resource.ram_mb,
                ring_buffer_fill_pct: 0,
                events_processed_since_last_heartbeat: 0,
            },
        };

        let response = self
            .client
            .post(format!(
                "{}/api/v1/agents/{}/heartbeat",
                self.platform_url, self.agent_id
            ))
            .json(&request)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            anyhow::bail!("Heartbeat rejected by platform: {}", status);
        }

        let hb_response: HeartbeatResponse = response.json().await?;
        debug!("Heartbeat acknowledged");

        // Trigger policy sync if the platform signals a newer version.
        if let Some(new_version) = hb_response.policy_update_version {
            if new_version > policy_version {
                let _ = self.policy_trigger.try_send(new_version);
            }
        }

        // Process commands from the platform.
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
            PlatformCommand::RenewCert => {
                info!("Platform command: RENEW_CERT");
                let renewal = CertRenewalClient::new(&self.data_dir, &self.platform_url);
                if let Err(e) = renewal.renew(&self.agent_id).await {
                    warn!(error = %e, "Certificate renewal failed");
                }
            }
            PlatformCommand::UpdateAgent {
                version,
                manifest_url: _,
            } => {
                info!(version = %version, "Platform command: UPDATE_AGENT");
            }
            PlatformCommand::PullIntelBundle { bundle_id } => {
                info!(bundle_id = %bundle_id, "Platform command: PULL_INTEL_BUNDLE");
            }
        }
    }
}
