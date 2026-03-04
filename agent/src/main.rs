// OpenClaw Agent — Entry Point
// Copyright 2026 Omni Cyber Solutions LLC. Apache License 2.0.

use anyhow::Result;
use clap::Parser;
use tracing::{error, info};

mod assistant;
mod collectors;
mod config;
mod containment;
mod core;
mod detection;
mod platform_connector;
mod voice;

use crate::config::AgentConfig;
use crate::core::state::{AgentState, AgentStateManager};

/// OpenClaw endpoint security agent
#[derive(Parser, Debug)]
#[command(name = "openclaw-agent", version, about)]
struct Cli {
    /// Path to configuration file
    #[arg(short, long, default_value = "openclaw-agent.toml", env = "OPENCLAW_CONFIG")]
    config: String,

    /// Override log level (trace/debug/info/warn/error)
    #[arg(long, env = "OPENCLAW_LOG_LEVEL")]
    log_level: Option<String>,

    /// Run enrollment with the provided one-time token
    #[arg(long, env = "OPENCLAW_ENROLL_TOKEN")]
    enroll: Option<String>,

    /// Print version and exit
    #[arg(long)]
    version_info: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    if cli.version_info {
        println!(
            "openclaw-agent {} ({} {})",
            env!("CARGO_PKG_VERSION"),
            std::env::consts::OS,
            std::env::consts::ARCH
        );
        return Ok(());
    }

    // Load configuration
    let cfg = AgentConfig::load(&cli.config)?;

    // Initialize structured logging
    let log_level = cli
        .log_level
        .as_deref()
        .unwrap_or(&cfg.log_level)
        .to_string();

    init_tracing(&log_level, &cfg.log_format)?;

    info!(
        version = env!("CARGO_PKG_VERSION"),
        os = std::env::consts::OS,
        arch = std::env::consts::ARCH,
        config = %cli.config,
        "OpenClaw agent starting"
    );

    // Handle enrollment mode
    if let Some(token) = cli.enroll {
        info!("Running enrollment with one-time token");
        return run_enrollment(&cfg, &token).await;
    }

    // Normal agent operation
    run_agent(cfg).await
}

async fn run_enrollment(cfg: &AgentConfig, token: &str) -> Result<()> {
    use crate::platform_connector::enrollment::EnrollmentClient;

    let state = AgentStateManager::new(cfg)?;
    let client = EnrollmentClient::new(cfg)?;
    let result = client.enroll(token).await?;

    // Persist enrollment results to local state DB
    state.set_agent_id(&result.agent_id)?;
    state.set_tenant_id(&result.tenant_id)?;

    let certs_dir = cfg.storage.data_dir.join("certs");
    state.set_cert_paths(&certs_dir.join("client.pem"), &certs_dir.join("client.key"))?;
    state.transition(AgentState::Active)?;

    info!(
        agent_id = %result.agent_id,
        tenant_id = %result.tenant_id,
        "Enrollment successful. Agent ID assigned."
    );
    info!("Restart the agent without --enroll to begin monitoring.");
    Ok(())
}

async fn run_agent(cfg: AgentConfig) -> Result<()> {
    use std::sync::Arc;
    use crate::core::event_bus::EventBus;
    use crate::core::scheduler::Scheduler;
    use crate::collectors::CollectorSet;
    use crate::detection::engine::DetectionEngine;
    use crate::detection::ioc_store::IocStore;
    use crate::platform_connector::alert_uploader::AlertUploader;
    use crate::platform_connector::heartbeat::HeartbeatService;
    use crate::platform_connector::intel_receiver::IntelReceiver;
    use crate::platform_connector::telemetry_uploader::TelemetryUploader;
    use crate::platform_connector::policy_sync::PolicySync;

    // Initialize state manager
    let state_manager = AgentStateManager::new(&cfg)?;
    let agent_id = state_manager.agent_id()?;

    info!(%agent_id, "Agent initialized");

    // Verify we're enrolled before starting
    if state_manager.current_state() == AgentState::Enrolling {
        error!("Agent not enrolled. Run with --enroll <token> first.");
        anyhow::bail!("Agent not enrolled");
    }

    let tenant_id = state_manager.tenant_id().unwrap_or_default();

    // Open shared IOC store (LMDB) — shared by DetectionEngine (reader) and IntelReceiver (writer)
    let ioc_store = Arc::new(IocStore::open(&cfg.storage.data_dir)?);

    // Create central event bus (tokio::broadcast, capacity 10,000)
    let event_bus = EventBus::new(10_000);

    // Alert channel: DetectionEngine → AlertUploader (capacity 1000 alerts)
    let (alert_tx, alert_rx) = tokio::sync::mpsc::channel(1_000);

    // Initialize platform connector components
    let heartbeat = HeartbeatService::new(&cfg, &agent_id, state_manager.clone())?;
    let uploader = TelemetryUploader::new(&cfg, &agent_id, &tenant_id, event_bus.subscribe())?;
    let alert_uploader = AlertUploader::new(&cfg, &agent_id, &tenant_id, alert_rx)?;
    let policy_sync = PolicySync::new(&cfg, &agent_id)?;
    let intel_receiver = IntelReceiver::new(&cfg, &agent_id, &tenant_id, Arc::clone(&ioc_store))?;

    // Initialize detection engine (subscribes to event bus, reads from shared IOC store)
    let detection_engine = DetectionEngine::new(
        &cfg,
        event_bus.subscribe(),
        policy_sync.policy_handle(),
        Arc::clone(&ioc_store),
        alert_tx,
    )?;

    // Initialize collectors (publish to event bus)
    let collectors = CollectorSet::new(&cfg, event_bus.publisher(), &agent_id, &tenant_id)?;

    info!("Starting all subsystems");

    // Launch all tasks concurrently
    tokio::select! {
        result = collectors.run() => {
            error!(?result, "Collectors exited unexpectedly");
        }
        result = detection_engine.run() => {
            error!(?result, "Detection engine exited unexpectedly");
        }
        result = heartbeat.run() => {
            error!(?result, "Heartbeat service exited unexpectedly");
        }
        result = uploader.run() => {
            error!(?result, "Telemetry uploader exited unexpectedly");
        }
        result = alert_uploader.run() => {
            error!(?result, "Alert uploader exited unexpectedly");
        }
        result = policy_sync.run() => {
            error!(?result, "Policy sync exited unexpectedly");
        }
        result = intel_receiver.run() => {
            error!(?result, "Intel receiver exited unexpectedly");
        }
        _ = tokio::signal::ctrl_c() => {
            info!("Received shutdown signal");
        }
    }

    info!("Agent shutting down");
    Ok(())
}

fn init_tracing(level: &str, format: &str) -> Result<()> {
    use tracing_subscriber::{EnvFilter, fmt, prelude::*};

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(level));

    match format {
        "json" => {
            tracing_subscriber::registry()
                .with(filter)
                .with(fmt::layer().json())
                .init();
        }
        _ => {
            tracing_subscriber::registry()
                .with(filter)
                .with(fmt::layer().compact())
                .init();
        }
    }

    Ok(())
}
