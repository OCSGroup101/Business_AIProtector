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
#[cfg(target_os = "macos")]
fn platform_persistence_paths() -> Vec<PathBuf> {
    let mut paths = vec![
        PathBuf::from("/Library/LaunchDaemons"),
        PathBuf::from("/Library/LaunchAgents"),
        PathBuf::from("/System/Library/LaunchDaemons"),
        PathBuf::from("/System/Library/LaunchAgents"),
    ];
    if let Ok(home) = std::env::var("HOME") {
        paths.push(PathBuf::from(format!("{}/Library/LaunchAgents", home)));
    }
    paths
}

#[cfg(not(target_os = "macos"))]
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
    } else if s.contains("LaunchDaemon") || s.contains("LaunchAgent") {
        "launchd"
    } else if s.contains("Run") || s.contains("SOFTWARE\\Microsoft\\Windows\\CurrentVersion") {
        "registry_run_key"
    } else {
        "unknown"
    }
}

// ─── Windows Registry Run Key Watcher ─────────────────────────────────────────

#[cfg(target_os = "windows")]
pub mod registry {
    use super::*;
    use std::collections::HashMap;
    use windows::Win32::System::Registry::{
        RegCloseKey, RegEnumValueW, RegNotifyChangeKeyValue, RegOpenKeyExW,
        HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE,
        KEY_NOTIFY, KEY_READ, REG_NOTIFY_CHANGE_LAST_SET, REG_SZ,
    };
    use windows::core::PCWSTR;
    use tracing::{debug, warn};

    const RUN_KEYS: &[(&str, &str)] = &[
        (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKLM"),
        (r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM"),
        (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKCU"),
        (r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU"),
    ];

    /// Snapshot of a single registry key (value_name → value_data).
    type KeySnapshot = HashMap<String, String>;

    pub async fn watch_run_keys(
        collector: PersistenceCollector,
        publisher: EventPublisher,
    ) -> Result<()> {
        info!("Registry Run key watcher starting");
        let (tx, mut rx) =
            tokio::sync::mpsc::channel::<(String, String, &'static str)>(64);

        tokio::task::spawn_blocking(move || {
            // Take initial snapshot for each key and then watch for changes
            let mut snapshots: HashMap<(&str, &str), KeySnapshot> = HashMap::new();

            for (key_path, hive) in RUN_KEYS {
                let hkey = if *hive == "HKLM" {
                    HKEY_LOCAL_MACHINE
                } else {
                    HKEY_CURRENT_USER
                };
                if let Some(snapshot) = read_run_key(hkey, key_path) {
                    snapshots.insert((key_path, hive), snapshot);
                }
            }

            loop {
                // Open each key for notification
                for (key_path, hive) in RUN_KEYS {
                    let hkey = if *hive == "HKLM" {
                        HKEY_LOCAL_MACHINE
                    } else {
                        HKEY_CURRENT_USER
                    };
                    let path_wide: Vec<u16> = key_path.encode_utf16().chain(Some(0)).collect();

                    let mut hkey_open = HKEY::default();
                    let open_ok = unsafe {
                        RegOpenKeyExW(
                            hkey,
                            PCWSTR(path_wide.as_ptr()),
                            0,
                            KEY_READ | KEY_NOTIFY,
                            &mut hkey_open,
                        )
                    };
                    if open_ok.is_err() {
                        continue;
                    }

                    // Block up to 5s for changes; then poll
                    let _ = unsafe {
                        RegNotifyChangeKeyValue(
                            hkey_open,
                            false,
                            REG_NOTIFY_CHANGE_LAST_SET,
                            None,
                            false,
                        )
                    };
                    unsafe { let _ = RegCloseKey(hkey_open); }

                    // Compare new snapshot vs old
                    let new_snap = match read_run_key(hkey, key_path) {
                        Some(s) => s,
                        None => continue,
                    };
                    let old_snap = snapshots
                        .entry((key_path, hive))
                        .or_default();

                    for (name, data) in &new_snap {
                        let kind = if old_snap.contains_key(name) {
                            if old_snap.get(name) != Some(data) {
                                "modify"
                            } else {
                                continue;
                            }
                        } else {
                            "create"
                        };
                        let full_path = format!(
                            "{}\\{}\\{}",
                            hive, key_path, name
                        );
                        debug!(path = %full_path, kind, "Registry run key change detected");
                        let _ = tx.blocking_send((full_path, data.clone(), kind));
                    }
                    *old_snap = new_snap;
                }
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
        });

        while let Some((path, data, kind)) = rx.recv().await {
            let event_type = if kind == "create" {
                EventType::PersistenceCreate
            } else {
                EventType::PersistenceModify
            };
            let mut event = collector.make_event(event_type);
            event.payload.insert("path".into(), json!(path));
            event.payload.insert("data".into(), json!(data));
            event.payload.insert("mechanism".into(), json!("registry_run_key"));
            publisher.publish(event);
        }

        Ok(())
    }

    /// Read all string values from a registry run key into a HashMap.
    fn read_run_key(hive: HKEY, key_path: &str) -> Option<KeySnapshot> {
        let path_wide: Vec<u16> = key_path.encode_utf16().chain(Some(0)).collect();
        let mut hkey_open = HKEY::default();

        unsafe {
            RegOpenKeyExW(
                hive,
                PCWSTR(path_wide.as_ptr()),
                0,
                KEY_READ,
                &mut hkey_open,
            )
        }.ok()?;

        let mut result = HashMap::new();
        let mut index: u32 = 0;
        loop {
            let mut name_buf = vec![0u16; 256];
            let mut name_len = name_buf.len() as u32;
            let mut data_buf = vec![0u8; 1024];
            let mut data_len = data_buf.len() as u32;
            let mut value_type = 0u32;

            let status = unsafe {
                RegEnumValueW(
                    hkey_open,
                    index,
                    windows::core::PWSTR(name_buf.as_mut_ptr()),
                    &mut name_len,
                    None,
                    Some(&mut value_type),
                    Some(data_buf.as_mut_ptr()),
                    Some(&mut data_len),
                )
            };
            if status.is_err() {
                break;
            }
            if value_type == REG_SZ.0 {
                let name = String::from_utf16_lossy(&name_buf[..name_len as usize]);
                let data_u16: Vec<u16> = data_buf[..data_len as usize]
                    .chunks_exact(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .collect();
                let data = String::from_utf16_lossy(&data_u16)
                    .trim_end_matches('\0')
                    .to_string();
                result.insert(name, data);
            }
            index += 1;
        }

        unsafe { let _ = RegCloseKey(hkey_open); }
        Some(result)
    }
}
