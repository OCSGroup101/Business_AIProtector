// Copyright 2026 Omni Cyber Solutions LLC. Apache License 2.0.
//
// macOS Endpoint Security Framework (ESF) dispatcher.
//
// Two modes:
//   Approach A (default, no entitlement): spawns `eslogger` (macOS 13+) and
//     parses NDJSON output.  Gate: cfg(not(feature = "macos-esf")).
//   Approach B (full ESF FFI, requires entitlement): links EndpointSecurity.framework
//     directly.  Gate: cfg(feature = "macos-esf").  All unsafe blocks carry
//     // SAFETY: comments and require Security Architect sign-off per CLAUDE.md.
//
// Emits: ProcessCreate, FileCreate/Modify/Delete/Rename, AuthLogon,
//         AuthPrivilegeEscalation, PersistenceCreate/Modify

pub mod auth;
pub mod file;
pub mod persistence;
pub mod process;

#[cfg(feature = "macos-esf")]
pub mod esf_ffi;

use anyhow::Result;
use tokio::io::{AsyncBufReadExt, BufReader};
use tracing::{info, warn};

use crate::core::event_bus::{EventPublisher, TelemetryEvent};

/// Dispatch event type strings from eslogger NDJSON to typed TelemetryEvents.
/// Returns Some(event) if the line is a relevant, parseable event.
pub fn dispatch_eslogger_line(
    line: &str,
    agent_id: &str,
    tenant_id: &str,
    hostname: &str,
    os_info: &crate::core::event_bus::OsInfo,
) -> Option<TelemetryEvent> {
    let v: serde_json::Value = serde_json::from_str(line).ok()?;
    let event_type_str = v["event_type"].as_str()?;

    match event_type_str {
        s if s.contains("EXEC") => {
            process::parse_exec_event(&v, agent_id, tenant_id, hostname, os_info)
        }
        s if s.contains("CREATE") || s.contains("WRITE") || s.contains("RENAME")
            || s.contains("UNLINK") =>
        {
            file::parse_file_event(&v, event_type_str, agent_id, tenant_id, hostname, os_info)
        }
        s if s.contains("AUTHENTICATION") || s.contains("SETUID") => {
            auth::parse_auth_event(&v, event_type_str, agent_id, tenant_id, hostname, os_info)
        }
        s if s.contains("CREATE") && {
            // LaunchAgent/LaunchDaemon writes count as persistence
            let path = v["event"]["create"]["destination"]["existing_file"]["path"]
                .as_str()
                .unwrap_or("");
            path.contains("LaunchAgent") || path.contains("LaunchDaemon")
        } =>
        {
            persistence::parse_persistence_event(&v, agent_id, tenant_id, hostname, os_info)
        }
        _ => None,
    }
}

/// Start eslogger subprocess and forward parsed events to the publisher.
pub async fn run_eslogger(
    agent_id: String,
    tenant_id: String,
    hostname: String,
    os_info: crate::core::event_bus::OsInfo,
    publisher: EventPublisher,
    event_types: &[&str],
) -> Result<()> {
    let child = tokio::process::Command::new("eslogger")
        .args(event_types)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn();

    match child {
        Ok(mut c) => {
            let stdout = c.stdout.take().expect("eslogger stdout piped");
            let reader = BufReader::new(stdout);
            let mut lines = reader.lines();

            info!(
                events = ?event_types,
                "ESF eslogger dispatcher started"
            );

            while let Ok(Some(line)) = lines.next_line().await {
                if let Some(event) =
                    dispatch_eslogger_line(&line, &agent_id, &tenant_id, &hostname, &os_info)
                {
                    publisher.publish(event);
                }
            }
            Ok(())
        }
        Err(e) => {
            warn!(
                "eslogger unavailable ({}); macOS ESF events will not be collected",
                e
            );
            tokio::time::sleep(tokio::time::Duration::MAX).await;
            Ok(())
        }
    }
}
