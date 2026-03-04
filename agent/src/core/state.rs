// Agent state machine: Enrolling → Active → Isolated / Updating

use anyhow::Result;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tracing::{info, warn};

use crate::config::AgentConfig;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AgentState {
    /// No mTLS certificate yet — must run --enroll
    Enrolling,
    /// Normal operation
    Active,
    /// Network blocked to loopback only (containment order)
    Isolated,
    /// Binary update in progress
    Updating,
}

impl std::fmt::Display for AgentState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AgentState::Enrolling => write!(f, "ENROLLING"),
            AgentState::Active => write!(f, "ACTIVE"),
            AgentState::Isolated => write!(f, "ISOLATED"),
            AgentState::Updating => write!(f, "UPDATING"),
        }
    }
}

/// Persistent agent state stored in SQLite.
/// Also holds the agent ID and policy version.
#[derive(Clone)]
pub struct AgentStateManager {
    inner: Arc<Mutex<AgentStateInner>>,
}

struct AgentStateInner {
    conn: Connection,
}

impl AgentStateManager {
    pub fn new(cfg: &AgentConfig) -> Result<Self> {
        let db_path = cfg.storage.data_dir.join("agent-state.db");
        std::fs::create_dir_all(&cfg.storage.data_dir)?;

        let conn = Connection::open(&db_path)?;
        init_schema(&conn)?;

        Ok(Self {
            inner: Arc::new(Mutex::new(AgentStateInner { conn })),
        })
    }

    /// Get the current agent state.
    pub fn current_state(&self) -> AgentState {
        let inner = self.inner.lock().unwrap();
        get_kv(&inner.conn, "state")
            .and_then(|s| serde_json::from_str(&format!("\"{}\"", s)).ok())
            .unwrap_or(AgentState::Enrolling)
    }

    /// Transition to a new state (validates allowed transitions).
    pub fn transition(&self, next: AgentState) -> Result<()> {
        let current = self.current_state();
        if !is_valid_transition(&current, &next) {
            anyhow::bail!("Invalid state transition: {} → {}", current, next);
        }
        let inner = self.inner.lock().unwrap();
        set_kv(&inner.conn, "state", &next.to_string())?;
        info!(from = %current, to = %next, "Agent state transition");
        Ok(())
    }

    /// Get the enrolled agent ID (e.g. "agt_01JRXXXXXX")
    pub fn agent_id(&self) -> Result<String> {
        let inner = self.inner.lock().unwrap();
        get_kv(&inner.conn, "agent_id")
            .ok_or_else(|| anyhow::anyhow!("Agent ID not set — run --enroll first"))
    }

    /// Set the agent ID after successful enrollment.
    pub fn set_agent_id(&self, id: &str) -> Result<()> {
        let inner = self.inner.lock().unwrap();
        set_kv(&inner.conn, "agent_id", id)
    }

    /// Get the tenant ID assigned during enrollment.
    pub fn tenant_id(&self) -> Option<String> {
        let inner = self.inner.lock().unwrap();
        get_kv(&inner.conn, "tenant_id").filter(|s| !s.is_empty())
    }

    /// Store the tenant ID after successful enrollment.
    pub fn set_tenant_id(&self, id: &str) -> Result<()> {
        let inner = self.inner.lock().unwrap();
        set_kv(&inner.conn, "tenant_id", id)
    }

    /// Get the current policy version (0 if never synced).
    pub fn policy_version(&self) -> u64 {
        let inner = self.inner.lock().unwrap();
        get_kv(&inner.conn, "policy_version")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0)
    }

    /// Update the stored policy version after a successful sync.
    pub fn set_policy_version(&self, version: u64) -> Result<()> {
        let inner = self.inner.lock().unwrap();
        set_kv(&inner.conn, "policy_version", &version.to_string())
    }

    /// Store mTLS cert path after enrollment
    pub fn set_cert_paths(&self, cert: &PathBuf, key: &PathBuf) -> Result<()> {
        let inner = self.inner.lock().unwrap();
        set_kv(&inner.conn, "client_cert", &cert.to_string_lossy())?;
        set_kv(&inner.conn, "client_key", &key.to_string_lossy())?;
        Ok(())
    }

    pub fn cert_paths(&self) -> Option<(PathBuf, PathBuf)> {
        let inner = self.inner.lock().unwrap();
        let cert = get_kv(&inner.conn, "client_cert")?;
        let key = get_kv(&inner.conn, "client_key")?;
        Some((PathBuf::from(cert), PathBuf::from(key)))
    }
}

fn is_valid_transition(from: &AgentState, to: &AgentState) -> bool {
    matches!(
        (from, to),
        (AgentState::Enrolling, AgentState::Active)
            | (AgentState::Active, AgentState::Isolated)
            | (AgentState::Active, AgentState::Updating)
            | (AgentState::Isolated, AgentState::Active)
            | (AgentState::Updating, AgentState::Active)
            | (AgentState::Updating, AgentState::Enrolling) // rollback
    )
}

fn init_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS kv (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        PRAGMA journal_mode = WAL;
        PRAGMA synchronous = NORMAL;",
    )?;
    Ok(())
}

fn get_kv(conn: &Connection, key: &str) -> Option<String> {
    conn.query_row("SELECT value FROM kv WHERE key = ?1", params![key], |row| {
        row.get(0)
    })
    .ok()
}

fn set_kv(conn: &Connection, key: &str, value: &str) -> Result<()> {
    conn.execute(
        "INSERT INTO kv (key, value) VALUES (?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![key, value],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn make_cfg(dir: &TempDir) -> AgentConfig {
        AgentConfig {
            log_level: "info".into(),
            log_format: "text".into(),
            platform: crate::config::PlatformConfig {
                url: "https://test".into(),
                client_cert: None,
                client_key: None,
                ca_cert: None,
                heartbeat_interval_secs: 60,
                telemetry_upload_interval_secs: 300,
                buffer_upload_threshold_pct: 50,
                update_signing_pubkey: None,
            },
            storage: crate::config::StorageConfig {
                data_dir: dir.path().to_path_buf(),
                ring_buffer_capacity: 1000,
            },
            collectors: Default::default(),
            detection: Default::default(),
            assistant: Default::default(),
        }
    }

    #[test]
    fn test_initial_state_is_enrolling() {
        let dir = TempDir::new().unwrap();
        let mgr = AgentStateManager::new(&make_cfg(&dir)).unwrap();
        assert_eq!(mgr.current_state(), AgentState::Enrolling);
    }

    #[test]
    fn test_valid_transition() {
        let dir = TempDir::new().unwrap();
        let mgr = AgentStateManager::new(&make_cfg(&dir)).unwrap();
        mgr.transition(AgentState::Active).unwrap();
        assert_eq!(mgr.current_state(), AgentState::Active);
    }

    #[test]
    fn test_invalid_transition() {
        let dir = TempDir::new().unwrap();
        let mgr = AgentStateManager::new(&make_cfg(&dir)).unwrap();
        let result = mgr.transition(AgentState::Isolated); // Enrolling → Isolated invalid
        assert!(result.is_err());
    }

    #[test]
    fn test_agent_id_roundtrip() {
        let dir = TempDir::new().unwrap();
        let mgr = AgentStateManager::new(&make_cfg(&dir)).unwrap();
        mgr.set_agent_id("agt_test_123").unwrap();
        assert_eq!(mgr.agent_id().unwrap(), "agt_test_123");
    }
}
