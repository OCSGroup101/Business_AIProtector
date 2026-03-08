// Copyright 2026 Omni Cyber Solutions LLC. Apache License 2.0.
//
// Authentication Collector — monitors authentication and privilege events.
//
// Platform implementations:
//   Linux   — watches /var/log/auth.log (Debian/Ubuntu) or /var/log/secure
//             (RHEL/CentOS/Fedora) using the `notify` crate; tails new lines on
//             each modification event and parses sshd, sudo, su, PAM patterns.
//   Windows — Phase 2: subscribe to Windows Security Event Log via EvtSubscribe,
//             filter on event IDs 4624/4625/4648/4672 and render XML fields.
//             Stub currently sleeps to avoid holding a collector slot.
//   macOS   — Phase 3 stub.
//
// Emits: EventType::AuthLogon, AuthLogonFailure, AuthPrivilegeEscalation

use anyhow::Result;
use async_trait::async_trait;
use tracing::info;

use crate::collectors::Collector;
use crate::config::AgentConfig;
#[cfg(target_os = "linux")]
use crate::core::event_bus::Principal;
use crate::core::event_bus::{EventPublisher, EventType, OsInfo, TelemetryEvent};

pub struct AuthCollector {
    event_ids: Vec<u32>,
    agent_id: String,
    tenant_id: String,
    hostname: String,
    os_info: OsInfo,
}

impl AuthCollector {
    pub fn new(cfg: &AgentConfig, agent_id: &str, tenant_id: &str) -> Result<Self> {
        Ok(Self {
            event_ids: cfg.collectors.auth_event_ids.clone(),
            agent_id: agent_id.to_string(),
            tenant_id: tenant_id.to_string(),
            hostname: super::process::hostname_stub(),
            os_info: super::process::os_info_stub(),
        })
    }

    fn make_event(&self, event_type: EventType) -> TelemetryEvent {
        TelemetryEvent::new(
            &self.agent_id,
            &self.tenant_id,
            "auth",
            event_type,
            &self.hostname,
            self.os_info.clone(),
        )
    }
}

#[async_trait]
impl Collector for AuthCollector {
    fn name(&self) -> &'static str {
        "auth"
    }

    async fn run(self: Box<Self>, publisher: EventPublisher) -> Result<()> {
        info!(event_ids = ?self.event_ids, "AuthCollector starting");

        #[cfg(target_os = "linux")]
        return linux::run(*self, publisher).await;

        #[cfg(target_os = "windows")]
        return windows::run(*self, publisher).await;

        #[cfg(target_os = "macos")]
        return macos::run(*self, publisher).await;

        #[allow(unreachable_code)]
        {
            info!("AuthCollector: platform not supported — idle");
            tokio::time::sleep(tokio::time::Duration::MAX).await;
            Ok(())
        }
    }
}

// ─── Linux (/var/log/auth.log or /var/log/secure) ─────────────────────────────

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::io::{BufRead, BufReader, Seek, SeekFrom};
    use tracing::{debug, warn};

    /// Candidate log paths in preference order.
    const LOG_CANDIDATES: &[&str] = &["/var/log/auth.log", "/var/log/secure"];

    pub async fn run(collector: AuthCollector, publisher: EventPublisher) -> Result<()> {
        let log_path = LOG_CANDIDATES
            .iter()
            .copied()
            .find(|&p| std::path::Path::new(p).exists());

        let log_path = match log_path {
            Some(p) => p,
            None => {
                info!(
                    "AuthCollector: no auth log found ({:?}) — idle",
                    LOG_CANDIDATES
                );
                tokio::time::sleep(tokio::time::Duration::MAX).await;
                return Ok(());
            }
        };

        info!("AuthCollector: tailing {}", log_path);

        // Seek to EOF to avoid replaying historical entries on startup
        let file = std::fs::File::open(log_path)?;
        let mut reader = BufReader::new(file);
        reader.seek(SeekFrom::End(0))?;

        // Async channel: notify watcher (blocking thread) → async event loop
        let (ntx, mut nrx) = tokio::sync::mpsc::channel::<()>(32);
        let log_path_owned = log_path.to_string();

        tokio::task::spawn_blocking(move || {
            use notify::{Config, EventKind, RecommendedWatcher, RecursiveMode, Watcher};

            let (tx, rx) = std::sync::mpsc::channel::<notify::Result<notify::Event>>();
            let mut watcher = match RecommendedWatcher::new(tx, Config::default()) {
                Ok(w) => w,
                Err(e) => {
                    warn!("AuthCollector: watcher init failed: {}", e);
                    return;
                }
            };
            let _ = watcher.watch(
                std::path::Path::new(&log_path_owned),
                RecursiveMode::NonRecursive,
            );
            for event in rx.into_iter().flatten() {
                if matches!(event.kind, EventKind::Modify(_)) {
                    // Signal the async reader that new data may be available
                    if ntx.blocking_send(()).is_err() {
                        break;
                    }
                }
            }
        });

        let mut line_buf = String::new();

        loop {
            // Drain all newly appended lines
            loop {
                line_buf.clear();
                match reader.read_line(&mut line_buf) {
                    Ok(0) => break, // No more data — wait for next notify signal
                    Ok(_) => {
                        let trimmed = line_buf.trim_end();
                        if !trimmed.is_empty() {
                            parse_and_publish(&collector, &publisher, trimmed);
                        }
                    }
                    Err(e) => {
                        warn!("AuthCollector: read error: {}", e);
                        break;
                    }
                }
            }

            // Block until file is modified again
            if nrx.recv().await.is_none() {
                break;
            }
        }

        Ok(())
    }

    /// Parse a single syslog auth line and emit the appropriate TelemetryEvent.
    fn parse_and_publish(collector: &AuthCollector, publisher: &EventPublisher, line: &str) {
        let (event_type, user, src_ip, details) = classify_line(line);

        let event_type = match event_type {
            Some(et) => et,
            None => return, // line not relevant
        };

        let mut event = collector.make_event(event_type.clone());

        if !user.is_empty() {
            event.principal = Some(Principal {
                user: user.clone(),
                sid: None,
                elevated: matches!(event_type, EventType::AuthPrivilegeEscalation),
            });
        }

        event.payload.insert(
            "details".into(),
            serde_json::json!({
                "user": user,
                "src_ip": src_ip,
                "raw_line": &line[..line.len().min(256)],
            }),
        );

        debug!(user = %user, "Auth event parsed");
        publisher.publish(event);
    }

    /// Returns (event_type, username, source_ip, _) for recognisable auth log patterns.
    fn classify_line(line: &str) -> (Option<EventType>, String, String, ()) {
        let src_ip = extract_after(line, "from ").unwrap_or_default();

        if line.contains("Failed password")
            || line.contains("authentication failure")
            || line.contains("FAILED LOGIN")
        {
            let user = extract_user_field(line).unwrap_or_default();
            (Some(EventType::AuthLogonFailure), user, src_ip, ())
        } else if line.contains("Accepted password")
            || line.contains("Accepted publickey")
            || (line.contains("session opened") && line.contains("for user"))
        {
            let user = extract_user_field(line).unwrap_or_default();
            (Some(EventType::AuthLogon), user, src_ip, ())
        } else if line.contains("sudo:") || line.contains(" su:") || line.contains(" su[") {
            let user = extract_user_field(line).unwrap_or_default();
            (Some(EventType::AuthPrivilegeEscalation), user, src_ip, ())
        } else {
            (None, String::new(), String::new(), ())
        }
    }

    /// Extract a username from common syslog field patterns.
    fn extract_user_field(line: &str) -> Option<String> {
        for prefix in &["for user ", "for ", "user=", "USER="] {
            if let Some(u) = extract_after(line, prefix) {
                if !u.is_empty() {
                    return Some(u);
                }
            }
        }
        None
    }

    /// Return the first whitespace-delimited token after `prefix` in `line`.
    fn extract_after(line: &str, prefix: &str) -> Option<String> {
        let start = line.find(prefix)? + prefix.len();
        let rest = &line[start..];
        let end = rest
            .find(|c: char| c.is_whitespace() || c == ',' || c == ';')
            .unwrap_or(rest.len());
        let token = rest[..end].trim_matches(|c: char| c == '\'' || c == '"');
        if token.is_empty() {
            None
        } else {
            Some(token.to_string())
        }
    }
}

// ─── Windows (Security Event Log) ─────────────────────────────────────────────

#[cfg(target_os = "windows")]
mod windows {
    use super::*;
    use tracing::{debug, warn};
    use windows::Win32::System::EventLog::{
        EvtClose, EvtNext, EvtQuery, EvtRender, EvtRenderEventXml,
        EVT_HANDLE, EVT_QUERY_FLAGS, EvtQueryChannelPath, EvtQueryReverseDirection,
    };
    use windows::core::{HSTRING, PCWSTR};

    const SECURITY_CHANNEL: &str = "Security";
    // XPath query for logon / privilege events
    const XPATH_QUERY: &str =
        "*[System/EventID=4624 or System/EventID=4625 or System/EventID=4648 or System/EventID=4672]";

    pub async fn run(collector: AuthCollector, publisher: EventPublisher) -> Result<()> {
        info!("AuthCollector: Windows Security Event Log monitoring starting");

        let (tx, mut rx) = tokio::sync::mpsc::channel::<(u32, String, String)>(256);

        // Blocking thread: EvtQuery + EvtNext loop
        tokio::task::spawn_blocking(move || {
            let channel = HSTRING::from(SECURITY_CHANNEL);
            let query = HSTRING::from(XPATH_QUERY);

            let handle = unsafe {
                EvtQuery(
                    None,
                    PCWSTR(channel.as_ptr()),
                    PCWSTR(query.as_ptr()),
                    (EvtQueryChannelPath.0 | EvtQueryReverseDirection.0) as u32,
                )
            };
            let handle = match handle {
                Ok(h) => h,
                Err(e) => {
                    warn!("AuthCollector: EvtQuery failed: {:?}", e);
                    return;
                }
            };

            loop {
                let mut events: [EVT_HANDLE; 32] = [EVT_HANDLE::default(); 32];
                let mut returned: u32 = 0;
                let ok = unsafe {
                    EvtNext(handle, &mut events, 500, 0, &mut returned).is_ok()
                };
                if !ok || returned == 0 {
                    // No new events; wait a bit then retry
                    std::thread::sleep(std::time::Duration::from_millis(500));
                    continue;
                }

                for i in 0..returned as usize {
                    let evt = events[i];
                    if let Some((event_id, user, src_ip)) = render_event(evt) {
                        let _ = tx.blocking_send((event_id, user, src_ip));
                    }
                    unsafe { let _ = EvtClose(evt); }
                }
            }
        });

        while let Some((event_id, user, src_ip)) = rx.recv().await {
            let event_type = match event_id {
                4624 => EventType::AuthLogon,
                4625 => EventType::AuthLogonFailure,
                4648 => EventType::AuthLogon,
                4672 => EventType::AuthPrivilegeEscalation,
                _ => continue,
            };

            debug!(event_id, user = %user, "Windows auth event");
            let mut event = collector.make_event(event_type.clone());
            event.principal = Some(crate::core::event_bus::Principal {
                user: user.clone(),
                sid: None,
                elevated: matches!(event_type, EventType::AuthPrivilegeEscalation),
            });
            event.payload.insert(
                "details".into(),
                serde_json::json!({ "event_id": event_id, "user": user, "src_ip": src_ip }),
            );
            publisher.publish(event);
        }

        Ok(())
    }

    /// Render a Security event to XML and extract (event_id, user, src_ip).
    fn render_event(evt: EVT_HANDLE) -> Option<(u32, String, String)> {
        let mut buf_used: u32 = 0;
        let mut buf: Vec<u16> = vec![0u16; 4096];

        let ok = unsafe {
            EvtRender(
                None,
                evt,
                EvtRenderEventXml.0,
                buf.len() as u32 * 2,
                Some(buf.as_mut_ptr() as *mut core::ffi::c_void),
                &mut buf_used,
                &mut 0u32,
            )
            .is_ok()
        };

        if !ok {
            return None;
        }

        let xml = String::from_utf16_lossy(&buf[..buf_used as usize / 2]);
        parse_security_xml(&xml)
    }

    /// Parse Security event XML to extract (event_id, username, source_ip).
    fn parse_security_xml(xml: &str) -> Option<(u32, String, String)> {
        use quick_xml::events::Event;
        use quick_xml::Reader;

        let mut reader = Reader::from_str(xml);
        reader.config_mut().trim_text(true);

        let mut event_id: u32 = 0;
        let mut user = String::new();
        let mut src_ip = String::new();
        let mut in_event_id = false;
        let mut current_name = String::new();
        let mut in_data = false;

        loop {
            match reader.read_event() {
                Ok(Event::Start(ref e)) => {
                    let tag = String::from_utf8_lossy(e.name().as_ref()).to_string();
                    match tag.as_str() {
                        "EventID" => in_event_id = true,
                        "Data" => {
                            in_data = true;
                            current_name = e
                                .attributes()
                                .flatten()
                                .find(|a| a.key.as_ref() == b"Name")
                                .and_then(|a| String::from_utf8(a.value.to_vec()).ok())
                                .unwrap_or_default();
                        }
                        _ => {}
                    }
                }
                Ok(Event::End(_)) => {
                    in_event_id = false;
                    in_data = false;
                }
                Ok(Event::Text(e)) => {
                    let text = e.unescape().unwrap_or_default().to_string();
                    if in_event_id {
                        event_id = text.parse().unwrap_or(0);
                    } else if in_data {
                        match current_name.as_str() {
                            "SubjectUserName" | "TargetUserName" if user.is_empty() => {
                                user = text;
                            }
                            "IpAddress" if src_ip.is_empty() => {
                                src_ip = text;
                            }
                            _ => {}
                        }
                    }
                }
                Ok(Event::Eof) => break,
                Err(_) => break,
                _ => {}
            }
        }

        if event_id != 0 {
            Some((event_id, user, src_ip))
        } else {
            None
        }
    }
}

// ─── macOS (eslogger / OpenBSM tail) ─────────────────────────────────────────
//
// Uses `eslogger` (macOS 13+, ships with XProtect) to stream security events
// as NDJSON without requiring the ESF entitlement.
// Gate: cfg(not(feature = "macos-esf")) — no special entitlement needed.

#[cfg(target_os = "macos")]
mod macos {
    use super::*;
    use tokio::io::{AsyncBufReadExt, BufReader};
    use tracing::{debug, warn};

    pub async fn run(collector: AuthCollector, publisher: EventPublisher) -> Result<()> {
        info!("AuthCollector: macOS eslogger authentication monitoring starting");

        // eslogger requires root; if it fails, fall back to OpenBSM log tail.
        let child = tokio::process::Command::new("eslogger")
            .args(["authentication"])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn();

        match child {
            Ok(mut c) => {
                let stdout = c.stdout.take().expect("stdout piped");
                let reader = BufReader::new(stdout);
                let mut lines = reader.lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    if let Some(event) = parse_eslogger_auth(&collector, &line) {
                        debug!("macOS auth event from eslogger");
                        publisher.publish(event);
                    }
                }
            }
            Err(e) => {
                warn!("eslogger not available ({}); macOS auth monitoring degraded", e);
                // Idle rather than spin-loop
                tokio::time::sleep(tokio::time::Duration::MAX).await;
            }
        }
        Ok(())
    }

    /// Parse an eslogger NDJSON line for authentication events.
    fn parse_eslogger_auth(
        collector: &AuthCollector,
        line: &str,
    ) -> Option<crate::core::event_bus::TelemetryEvent> {
        let v: serde_json::Value = serde_json::from_str(line).ok()?;
        let event_type_str = v["event_type"].as_str()?;

        let (event_type, elevated) = match event_type_str {
            "ES_EVENT_TYPE_NOTIFY_AUTHENTICATION" => {
                let success = v["event"]["authentication"]["success"].as_bool().unwrap_or(false);
                if success {
                    (EventType::AuthLogon, false)
                } else {
                    (EventType::AuthLogonFailure, false)
                }
            }
            "ES_EVENT_TYPE_NOTIFY_SETUID" => (EventType::AuthPrivilegeEscalation, true),
            _ => return None,
        };

        let user = v["event"]["authentication"]["target"]["name"]
            .as_str()
            .unwrap_or("")
            .to_string();

        let mut event = collector.make_event(event_type.clone());
        event.principal = Some(crate::core::event_bus::Principal {
            user: user.clone(),
            sid: None,
            elevated,
        });
        event.payload.insert(
            "details".into(),
            serde_json::json!({ "user": user, "event_type": event_type_str }),
        );
        Some(event)
    }
}
