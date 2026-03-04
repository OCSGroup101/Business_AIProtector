// Agent configuration — loaded from TOML file + environment overrides

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Top-level agent configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AgentConfig {
    /// Log level: trace | debug | info | warn | error
    #[serde(default = "default_log_level")]
    pub log_level: String,

    /// Log format: text | json
    #[serde(default = "default_log_format")]
    pub log_format: String,

    /// Platform connection settings
    pub platform: PlatformConfig,

    /// Local storage paths
    #[serde(default)]
    pub storage: StorageConfig,

    /// Collector enablement and settings
    #[serde(default)]
    pub collectors: CollectorsConfig,

    /// Detection engine settings
    #[serde(default)]
    pub detection: DetectionConfig,

    /// Assistant / TTS settings
    #[serde(default)]
    pub assistant: AssistantConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PlatformConfig {
    /// Base URL of the platform API (e.g. https://api.openclaw.example.com)
    pub url: String,

    /// Path to the mTLS client certificate (PEM)
    pub client_cert: Option<PathBuf>,

    /// Path to the mTLS client key (PEM)
    pub client_key: Option<PathBuf>,

    /// Path to the platform CA certificate for server verification (PEM)
    pub ca_cert: Option<PathBuf>,

    /// Heartbeat interval in seconds (default: 60)
    #[serde(default = "default_heartbeat_interval")]
    pub heartbeat_interval_secs: u64,

    /// Telemetry upload interval in seconds (default: 300 = 5 min)
    #[serde(default = "default_telemetry_interval")]
    pub telemetry_upload_interval_secs: u64,

    /// Upload when ring buffer reaches this percentage full (default: 50)
    #[serde(default = "default_buffer_upload_threshold")]
    pub buffer_upload_threshold_pct: u8,

    /// Platform Ed25519 public key (minisign format) for update verification
    pub update_signing_pubkey: Option<String>,

    /// IOC bundle poll interval in seconds (default: 300 = 5 min)
    pub ioc_poll_interval_secs: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct StorageConfig {
    /// Directory for SQLite database and LMDB IOC store
    #[serde(default = "default_data_dir")]
    pub data_dir: PathBuf,

    /// SQLite ring buffer maximum event count (default: 100,000)
    #[serde(default = "default_ring_buffer_capacity")]
    pub ring_buffer_capacity: usize,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct CollectorsConfig {
    #[serde(default = "default_true")]
    pub process_enabled: bool,

    #[serde(default = "default_true")]
    pub filesystem_enabled: bool,

    /// Filesystem paths to watch
    #[serde(default = "default_watch_paths")]
    pub filesystem_watch_paths: Vec<PathBuf>,

    #[serde(default = "default_true")]
    pub network_enabled: bool,

    #[serde(default = "default_true")]
    pub network_capture_dns: bool,

    #[serde(default = "default_true")]
    pub persistence_enabled: bool,

    #[serde(default = "default_true")]
    pub auth_enabled: bool,

    /// Windows Security event IDs to collect
    #[serde(default = "default_auth_event_ids")]
    pub auth_event_ids: Vec<u32>,

    #[serde(default = "default_true")]
    pub integrity_enabled: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct DetectionConfig {
    /// Rule packs to load (names match directories under intelligence/rule-packs/)
    #[serde(default = "default_rule_packs")]
    pub rule_packs: Vec<String>,

    /// Override the directory that contains rule-pack subdirectories.
    /// Defaults to <data_dir>/rules if not set.
    /// In development, point this at intelligence/rule-packs/ in the repo root.
    pub rules_dir: Option<PathBuf>,

    /// Detection sensitivity: conservative | balanced | aggressive
    #[serde(default = "default_sensitivity")]
    pub sensitivity: String,

    /// Maximum auto-containment severity (CRITICAL/HIGH/MEDIUM/LOW/NONE)
    #[serde(default = "default_auto_contain_severity")]
    pub auto_contain_max_severity: String,

    /// Require analyst approval before full network isolation
    #[serde(default = "default_true")]
    pub require_approval_for_isolation: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct AssistantConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,

    #[serde(default = "default_true")]
    pub tts_enabled: bool,

    /// Minimum severity for TTS alerts: CRITICAL | HIGH | MEDIUM | LOW
    #[serde(default = "default_tts_min_severity")]
    pub tts_min_severity: String,

    /// Enable whisper.cpp STT (opt-in, requires feature flag)
    #[serde(default)]
    pub stt_enabled: bool,

    /// Anthropic API key (falls back to ANTHROPIC_API_KEY env var)
    pub anthropic_api_key: Option<String>,
}

impl AgentConfig {
    /// Load configuration from a TOML file, with environment variable overrides.
    pub fn load(path: &str) -> Result<Self> {
        use config::{Config, Environment, File};

        let cfg = Config::builder()
            .add_source(File::with_name(path).required(false))
            .add_source(
                Environment::with_prefix("OPENCLAW")
                    .separator("__")
                    .try_parsing(true),
            )
            .build()?;

        let agent_config: Self = cfg.try_deserialize()?;
        agent_config.validate()?;
        Ok(agent_config)
    }

    fn validate(&self) -> Result<()> {
        if self.platform.url.is_empty() {
            anyhow::bail!("platform.url must be set");
        }
        Ok(())
    }
}

// ─── Default value functions ──────────────────────────────────────────────────

fn default_log_level() -> String { "info".to_string() }
fn default_log_format() -> String { "text".to_string() }
fn default_heartbeat_interval() -> u64 { 60 }
fn default_telemetry_interval() -> u64 { 300 }
fn default_buffer_upload_threshold() -> u8 { 50 }
fn default_ring_buffer_capacity() -> usize { 100_000 }
fn default_true() -> bool { true }
fn default_sensitivity() -> String { "balanced".to_string() }
fn default_auto_contain_severity() -> String { "HIGH".to_string() }
fn default_tts_min_severity() -> String { "HIGH".to_string() }

fn default_data_dir() -> PathBuf {
    #[cfg(target_os = "windows")]
    { PathBuf::from("C:\\ProgramData\\OpenClaw") }
    #[cfg(target_os = "macos")]
    { PathBuf::from("/Library/Application Support/OpenClaw") }
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    { PathBuf::from("/var/lib/openclaw") }
}

fn default_watch_paths() -> Vec<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        vec![
            PathBuf::from("C:\\Users"),
            PathBuf::from("C:\\Windows\\Temp"),
            PathBuf::from("C:\\Windows\\System32"),
        ]
    }
    #[cfg(not(target_os = "windows"))]
    {
        vec![
            PathBuf::from("/home"),
            PathBuf::from("/tmp"),
            PathBuf::from("/usr/bin"),
        ]
    }
}

fn default_auth_event_ids() -> Vec<u32> {
    vec![4624, 4625, 4648, 4672, 4688, 4697, 4698, 4720, 4728]
}

fn default_rule_packs() -> Vec<String> {
    vec!["openclaw-core-v1".to_string()]
}

/// Generate an example config file (useful for first-run documentation)
pub fn example_config() -> &'static str {
    r#"
# OpenClaw Agent Configuration
# Platform connection is required; all other settings have sensible defaults.

log_level = "info"
log_format = "text"  # "text" or "json"

[platform]
url = "https://api.openclaw.example.com"
# client_cert = "/etc/openclaw/certs/client.pem"
# client_key  = "/etc/openclaw/certs/client.key"
# ca_cert     = "/etc/openclaw/certs/ca.pem"
heartbeat_interval_secs       = 60
telemetry_upload_interval_secs = 300
buffer_upload_threshold_pct   = 50

[storage]
# data_dir = "C:\\ProgramData\\OpenClaw"  # Windows default
ring_buffer_capacity = 100000

[collectors]
process_enabled    = true
filesystem_enabled = true
network_enabled    = true
persistence_enabled = true
auth_enabled       = true
integrity_enabled  = true

[detection]
rule_packs             = ["openclaw-core-v1"]
sensitivity            = "balanced"
auto_contain_max_severity = "HIGH"
require_approval_for_isolation = true
# rules_dir = "intelligence/rule-packs"  # dev: override default <data_dir>/rules path

[assistant]
enabled          = true
tts_enabled      = true
tts_min_severity = "HIGH"
stt_enabled      = false
"#
}
