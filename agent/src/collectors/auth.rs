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
use crate::core::event_bus::{EventPublisher, EventType, OsInfo, Principal, TelemetryEvent};

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
            &self.agent_id, &self.tenant_id, "auth",
            event_type, &self.hostname, self.os_info.clone(),
        )
    }
}

#[async_trait]
impl Collector for AuthCollector {
    fn name(&self) -> &'static str { "auth" }

    async fn run(self: Box<Self>, publisher: EventPublisher) -> Result<()> {
        info!(event_ids = ?self.event_ids, "AuthCollector starting");

        #[cfg(target_os = "linux")]
        return linux::run(*self, publisher).await;

        #[cfg(target_os = "windows")]
        return windows::run(*self, publisher).await;

        #[allow(unreachable_code)]
        {
            info!("AuthCollector: platform not supported — idle (Phase 3)");
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
                Err(e) => { warn!("AuthCollector: watcher init failed: {}", e); return; }
            };
            let _ = watcher.watch(
                std::path::Path::new(&log_path_owned),
                RecursiveMode::NonRecursive,
            );
            for event in rx.into_iter().flatten() {
                if matches!(event.kind, EventKind::Modify(_)) {
                    // Signal the async reader that new data may be available
                    if ntx.blocking_send(()).is_err() { break; }
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
    fn parse_and_publish(
        collector: &AuthCollector,
        publisher: &EventPublisher,
        line: &str,
    ) {
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
        if token.is_empty() { None } else { Some(token.to_string()) }
    }
}

// ─── Windows (Security Event Log) ─────────────────────────────────────────────
//
// Phase 2 — implement EvtSubscribe with XML rendering to extract user, source
// IP, logon type from event IDs 4624 (logon), 4625 (logon failure),
// 4648 (explicit credentials), 4672 (special privileges).

#[cfg(target_os = "windows")]
mod windows {
    use super::*;

    pub async fn run(_collector: AuthCollector, _publisher: EventPublisher) -> Result<()> {
        info!("AuthCollector: Windows Security Event Log monitoring (Phase 2 — stub)");
        tokio::time::sleep(tokio::time::Duration::MAX).await;
        Ok(())
    }
}
