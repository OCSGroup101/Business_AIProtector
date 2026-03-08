// Copyright 2026 Omni Cyber Solutions LLC. Apache License 2.0.
//
// ESF process event parser — ES_EVENT_TYPE_NOTIFY_EXEC → ProcessCreate

use crate::core::event_bus::{EventPublisher, EventType, OsInfo, TelemetryEvent};

pub fn parse_exec_event(
    v: &serde_json::Value,
    agent_id: &str,
    tenant_id: &str,
    hostname: &str,
    os_info: &OsInfo,
) -> Option<TelemetryEvent> {
    let exec = &v["event"]["exec"];
    let target = &exec["target"];

    let image_path = target["executable"]["path"]
        .as_str()
        .unwrap_or("")
        .to_string();
    let pid = target["audit_token"]["pid"].as_u64().unwrap_or(0);
    let ppid = target["parent_audit_token"]["pid"].as_u64().unwrap_or(0);
    let user = target["audit_token"]["euid"].as_u64().map(|u| u.to_string());

    let mut event = TelemetryEvent::new(
        agent_id,
        tenant_id,
        "esf_process",
        EventType::ProcessCreate,
        hostname,
        os_info.clone(),
    );

    let process_name = std::path::Path::new(&image_path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_string();

    event.payload.insert("process_name".into(), serde_json::json!(process_name));
    event.payload.insert("image_path".into(), serde_json::json!(image_path));
    event.payload.insert("pid".into(), serde_json::json!(pid));
    event.payload.insert("ppid".into(), serde_json::json!(ppid));

    if let Some(user) = user {
        event.principal = Some(crate::core::event_bus::Principal {
            user,
            sid: None,
            elevated: false,
        });
    }

    Some(event)
}
