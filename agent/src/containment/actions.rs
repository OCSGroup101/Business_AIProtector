// Containment action dispatcher
//
// Maps action names from detection rules to concrete containment implementations.
// All actions are logged and reported to the platform.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::config::AgentConfig;
use crate::core::event_bus::TelemetryEvent;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ContainmentAction {
    TerminateProcess,
    QuarantineFile,
    BlockNetwork,
    DisablePersistence,
    IsolateHost,
}

impl std::fmt::Display for ContainmentAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::TerminateProcess => "terminate_process",
            Self::QuarantineFile => "quarantine_file",
            Self::BlockNetwork => "block_network",
            Self::DisablePersistence => "disable_persistence",
            Self::IsolateHost => "isolate_host",
        };
        write!(f, "{}", s)
    }
}

impl ContainmentAction {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "terminate_process" => Some(Self::TerminateProcess),
            "quarantine_file" => Some(Self::QuarantineFile),
            "block_network" => Some(Self::BlockNetwork),
            "disable_persistence" => Some(Self::DisablePersistence),
            "isolate_host" => Some(Self::IsolateHost),
            _ => None,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ContainmentResult {
    pub action: ContainmentAction,
    pub success: bool,
    pub message: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Dispatches containment actions based on rule response configuration.
pub struct ContainmentDispatcher {
    auto_contain_max_severity: String,
    require_approval_for_isolation: bool,
}

impl ContainmentDispatcher {
    pub fn new(cfg: &AgentConfig) -> Result<Self> {
        Ok(Self {
            auto_contain_max_severity: cfg.detection.auto_contain_max_severity.clone(),
            require_approval_for_isolation: cfg.detection.require_approval_for_isolation,
        })
    }

    /// Dispatch a single containment action by name.
    pub async fn dispatch(&self, action_name: &str, event: &TelemetryEvent) -> Result<ContainmentResult> {
        let action = match ContainmentAction::from_str(action_name) {
            Some(a) => a,
            None => {
                warn!(action = %action_name, "Unknown containment action — skipping");
                return Ok(ContainmentResult {
                    action: ContainmentAction::TerminateProcess, // placeholder
                    success: false,
                    message: format!("Unknown action: {}", action_name),
                    timestamp: chrono::Utc::now(),
                });
            }
        };

        // IsolateHost requires approval unless overridden
        if action == ContainmentAction::IsolateHost && self.require_approval_for_isolation {
            info!("Host isolation requires platform approval — queuing for review");
            return Ok(ContainmentResult {
                action,
                success: false,
                message: "Isolation queued — awaiting platform approval".to_string(),
                timestamp: chrono::Utc::now(),
            });
        }

        info!(action = %action, event_id = %event.event_id, "Dispatching containment action");

        let result = match &action {
            ContainmentAction::TerminateProcess => {
                use crate::containment::process_kill::terminate_process;
                let pid = event.payload.get("pid")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0) as u32;
                terminate_process(pid).await
            }
            ContainmentAction::QuarantineFile => {
                use crate::containment::file_quarantine::quarantine_file;
                let path = event.payload.get("path")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                quarantine_file(&path).await
            }
            ContainmentAction::BlockNetwork => {
                use crate::containment::network_block::block_network;
                let ip = event.payload.get("dst_ip")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                block_network(&ip).await
            }
            ContainmentAction::DisablePersistence => {
                use crate::containment::persistence_disable::disable_persistence;
                disable_persistence(event).await
            }
            ContainmentAction::IsolateHost => {
                use crate::containment::isolation::isolate_host;
                isolate_host().await
            }
        };

        Ok(ContainmentResult {
            action,
            success: result.is_ok(),
            message: result.err().map(|e| e.to_string()).unwrap_or_else(|| "Success".to_string()),
            timestamp: chrono::Utc::now(),
        })
    }
}
