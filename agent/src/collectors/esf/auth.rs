// Copyright 2026 Omni Cyber Solutions LLC. Apache License 2.0.
//
// ESF auth event parser — NOTIFY_SETUID/NOTIFY_AUTHENTICATION → auth events

use crate::core::event_bus::{EventType, OsInfo, Principal, TelemetryEvent};

pub fn parse_auth_event(
    v: &serde_json::Value,
    event_type_str: &str,
    agent_id: &str,
    tenant_id: &str,
    hostname: &str,
    os_info: &OsInfo,
) -> Option<TelemetryEvent> {
    let (event_type, user, elevated) = if event_type_str.contains("AUTHENTICATION") {
        let success = v["event"]["authentication"]["success"]
            .as_bool()
            .unwrap_or(false);
        let et = if success {
            EventType::AuthLogon
        } else {
            EventType::AuthLogonFailure
        };
        let user = v["event"]["authentication"]["target"]["name"]
            .as_str()
            .unwrap_or("")
            .to_string();
        (et, user, false)
    } else if event_type_str.contains("SETUID") {
        let user = v["process"]["audit_token"]["euid"]
            .as_u64()
            .map(|u| u.to_string())
            .unwrap_or_default();
        (EventType::AuthPrivilegeEscalation, user, true)
    } else {
        return None;
    };

    let mut event = TelemetryEvent::new(
        agent_id,
        tenant_id,
        "esf_auth",
        event_type,
        hostname,
        os_info.clone(),
    );

    if !user.is_empty() {
        event.principal = Some(Principal {
            user: user.clone(),
            sid: None,
            elevated,
        });
    }
    event
        .payload
        .insert("details".into(), serde_json::json!({ "user": user }));
    Some(event)
}
