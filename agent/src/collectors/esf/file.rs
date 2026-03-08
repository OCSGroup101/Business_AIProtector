// Copyright 2026 Omni Cyber Solutions LLC. Apache License 2.0.
//
// ESF file event parser — NOTIFY_CREATE/WRITE/RENAME/UNLINK → file events

use crate::core::event_bus::{EventType, OsInfo, TelemetryEvent};

pub fn parse_file_event(
    v: &serde_json::Value,
    event_type_str: &str,
    agent_id: &str,
    tenant_id: &str,
    hostname: &str,
    os_info: &OsInfo,
) -> Option<TelemetryEvent> {
    let (event_type, path) = if event_type_str.contains("CREATE") {
        let path = v["event"]["create"]["destination"]["new_path"]["dir"]["path"]
            .as_str()
            .and_then(|dir| {
                v["event"]["create"]["destination"]["new_path"]["filename"]
                    .as_str()
                    .map(|f| format!("{}/{}", dir, f))
            })
            .unwrap_or_default();
        (EventType::FileCreate, path)
    } else if event_type_str.contains("WRITE") {
        let path = v["event"]["write"]["target"]["path"]
            .as_str()
            .unwrap_or("")
            .to_string();
        (EventType::FileModify, path)
    } else if event_type_str.contains("RENAME") {
        let path = v["event"]["rename"]["destination"]["existing_file"]["path"]
            .as_str()
            .or_else(|| {
                v["event"]["rename"]["destination"]["new_path"]["dir"]["path"].as_str()
            })
            .unwrap_or("")
            .to_string();
        (EventType::FileRename, path)
    } else if event_type_str.contains("UNLINK") {
        let path = v["event"]["unlink"]["target"]["path"]
            .as_str()
            .unwrap_or("")
            .to_string();
        (EventType::FileDelete, path)
    } else {
        return None;
    };

    if path.is_empty() {
        return None;
    }

    let mut event = TelemetryEvent::new(
        agent_id,
        tenant_id,
        "esf_file",
        event_type,
        hostname,
        os_info.clone(),
    );
    event.payload.insert("path".into(), serde_json::json!(path));
    Some(event)
}
