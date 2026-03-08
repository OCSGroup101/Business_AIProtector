// Copyright 2026 Omni Cyber Solutions LLC. Apache License 2.0.
//
// ESF persistence event parser — writes to LaunchDaemons/LaunchAgents paths

use crate::core::event_bus::{EventType, OsInfo, TelemetryEvent};

pub fn parse_persistence_event(
    v: &serde_json::Value,
    agent_id: &str,
    tenant_id: &str,
    hostname: &str,
    os_info: &OsInfo,
) -> Option<TelemetryEvent> {
    // Extract path from create event
    let path = v["event"]["create"]["destination"]["existing_file"]["path"]
        .as_str()
        .or_else(|| {
            v["event"]["create"]["destination"]["new_path"]["dir"]["path"]
                .as_str()
        })
        .unwrap_or("")
        .to_string();

    if path.is_empty() {
        return None;
    }

    let is_persistence = path.contains("LaunchAgent") || path.contains("LaunchDaemon");
    if !is_persistence {
        return None;
    }

    let mut event = TelemetryEvent::new(
        agent_id,
        tenant_id,
        "esf_persistence",
        EventType::PersistenceCreate,
        hostname,
        os_info.clone(),
    );
    event.payload.insert("path".into(), serde_json::json!(path));
    event
        .payload
        .insert("mechanism".into(), serde_json::json!("launchd"));
    Some(event)
}
