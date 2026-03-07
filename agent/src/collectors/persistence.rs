// Copyright 2026 Omni Cyber Solutions LLC. Apache License 2.0.
//
// Persistence Collector — watches filesystem-based persistence mechanisms.
//
// Uses the `notify` crate (cross-platform: inotify on Linux, ReadDirectoryChangesW
// on Windows, kqueue on macOS) to watch the directories and files that attackers
// most commonly abuse for persistence.
//
// Watched locations by platform:
//   Linux   — /etc/cron.d, /etc/cron.daily, /etc/cron.weekly, /var/spool/cron,
//              /etc/systemd/system, /usr/lib/systemd/system, /etc/init.d
//   Windows — C:\Windows\System32\Tasks, C:\Windows\SysWOW64\Tasks,
//              %APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup,
//              C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup
//
// Note: Windows Registry Run key monitoring requires RegNotifyChangeKeyValue and
// is scheduled for Phase 2.
//
// Emits: EventType::PersistenceCreate, EventType::PersistenceModify

use std::path::PathBuf;

use anyhow::Result;
use async_trait::async_trait;
use serde_json::json;
use tracing::{debug, info, warn};

use crate::collectors::Collector;
use crate::config::AgentConfig;
use crate::core::event_bus::{EventPublisher, EventType, OsInfo, TelemetryEvent};

pub struct PersistenceCollector {
    agent_id: String,
    tenant_id: String,
    hostname: String,
    os_info: OsInfo,
}

impl PersistenceCollector {
    pub fn new(_cfg: &AgentConfig, agent_id: &str, tenant_id: &str) -> Result<Self> {
        Ok(Self {
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
            "persistence",
            event_type,
            &self.hostname,
            self.os_info.clone(),
        )
    }
}

#[async_trait]
impl Collector for PersistenceCollector {
    fn name(&self) -> &'static str {
        "persistence"
    }

    async fn run(self: Box<Self>, publisher: EventPublisher) -> Result<()> {
        info!("PersistenceCollector starting");

        let watch_paths = platform_persistence_paths();

        if watch_paths.is_empty() {
            info!("PersistenceCollector: no paths for this platform — idle (Phase 3)");
            tokio::time::sleep(tokio::time::Duration::MAX).await;
            return Ok(());
        }

        // Bridge: sync notify channel → async tokio mpsc
        // Each message: (path, event_kind_str)
        let (tx, mut rx) = tokio::sync::mpsc::channel::<(PathBuf, &'static str)>(256);

        let watch_paths_for_thread = watch_paths.clone();

        tokio::task::spawn_blocking(move || {
            use notify::{Config, EventKind, RecommendedWatcher, RecursiveMode, Watcher};

            let (ntx, nrx) = std::sync::mpsc::channel::<notify::Result<notify::Event>>();
            let mut watcher = match RecommendedWatcher::new(ntx, Config::default()) {
                Ok(w) => w,
                Err(e) => {
                    warn!("PersistenceCollector: watcher init failed: {}", e);
                    return;
                }
            };

            let mut watching = 0usize;
            for path in &watch_paths_for_thread {
                if path.exists() {
                    match watcher.watch(path, RecursiveMode::Recursive) {
                        Ok(_) => {
                            debug!("PersistenceCollector: watching {:?}", path);
                            watching += 1;
                        }
                        Err(e) => debug!("PersistenceCollector: cannot watch {:?}: {}", path, e),
                    }
                } else {
                    debug!("PersistenceCollector: path absent, skipping: {:?}", path);
                }
            }

            if watching == 0 {
                info!("PersistenceCollector: no persistence paths accessible — idle");
                return;
            }

            info!(watching, "PersistenceCollector: filesystem watches active");

            for event_result in nrx {
                let event = match event_result {
                    Ok(e) => e,
                    Err(e) => {
                        warn!("PersistenceCollector watch error: {}", e);
                        continue;
                    }
                };

                let kind_str: &'static str = match event.kind {
                    EventKind::Create(_) => "create",
                    EventKind::Modify(_) => "modify",
                    EventKind::Remove(_) => "delete",
                    _ => continue,
                };

                for path in event.paths {
                    // Ignore editor temp files and OS metadata
                    if is_noise_path(&path) {
                        continue;
                    }
                    let _ = tx.blocking_send((path, kind_str));
                }
            }
        });

        while let Some((path, event_kind)) = rx.recv().await {
            let event_type = if event_kind == "create" {
                EventType::PersistenceCreate
            } else {
                EventType::PersistenceModify
            };

            let mechanism = classify_mechanism(&path);
            let mut event = self.make_event(event_type);
            event
                .payload
                .insert("path".into(), json!(path.to_string_lossy().as_ref()));
            event.payload.insert("event_kind".into(), json!(event_kind));
            event.payload.insert("mechanism".into(), json!(mechanism));

            debug!(
                path = %path.display(),
                kind = event_kind,
                mechanism,
                "Persistence activity"
            );
            publisher.publish(event);
        }

        Ok(())
    }
}

/// Platform-specific persistence paths to watch.
fn platform_persistence_paths() -> Vec<PathBuf> {
    #[cfg(target_os = "linux")]
    return vec![
        PathBuf::from("/etc/cron.d"),
        PathBuf::from("/etc/cron.daily"),
        PathBuf::from("/etc/cron.weekly"),
        PathBuf::from("/var/spool/cron"),
        PathBuf::from("/etc/systemd/system"),
        PathBuf::from("/usr/lib/systemd/system"),
        PathBuf::from("/etc/init.d"),
    ];

    #[cfg(target_os = "windows")]
    return {
        let mut paths = vec![
            PathBuf::from(r"C:\Windows\System32\Tasks"),
            PathBuf::from(r"C:\Windows\SysWOW64\Tasks"),
            PathBuf::from(r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"),
        ];
        // Per-user startup folder
        if let Ok(appdata) = std::env::var("APPDATA") {
            paths.push(PathBuf::from(format!(
                r"{}\Microsoft\Windows\Start Menu\Programs\Startup",
                appdata
            )));
        }
        paths
    };

    #[allow(unreachable_code)]
    Vec::new()
}

/// Returns true for filesystem noise that should not produce events.
fn is_noise_path(path: &std::path::Path) -> bool {
    path.to_string_lossy().ends_with(['~', '#'])
        || path.extension().is_some_and(|e| e == "swp" || e == "tmp")
}

/// Classify the persistence mechanism from the path for event context.
fn classify_mechanism(path: &std::path::Path) -> &'static str {
    let s = path.to_string_lossy();
    if s.contains("cron") {
        "cron"
    } else if s.contains("systemd") {
        "systemd_unit"
    } else if s.contains("init.d") {
        "sysvinit"
    } else if s.contains("Tasks") {
        "scheduled_task"
    } else if s.contains("Startup") {
        "startup_folder"
    } else {
        "unknown"
    }
}
