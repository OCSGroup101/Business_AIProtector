// Copyright 2026 Omni Cyber Solutions LLC. Apache License 2.0.
//
// Persistence disable containment — removes or neutralises active persistence
// mechanisms detected by the PersistenceCollector.
//
// Mechanism dispatch table:
//   registry_run_key  → delete registry value (Windows only)
//   scheduled_task    → schtasks /delete (Windows) or delete cron file (Linux)
//   service           → sc stop + sc delete (Windows) / systemctl (Linux)
//   cron              → delete the cron file (Linux / macOS)
//   systemd_unit      → systemctl disable + stop + remove unit file (Linux)
//   startup_folder    → delete startup entry file (Windows / macOS)
//   launchd           → launchctl unload + delete plist (macOS)
//   unknown           → log and skip

use anyhow::Result;
use tracing::{info, warn};

use crate::core::event_bus::TelemetryEvent;

pub async fn disable_persistence(event: &TelemetryEvent) -> Result<()> {
    let mechanism = event
        .payload
        .get("mechanism")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    let path = event
        .payload
        .get("path")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    info!(
        event_id = %event.event_id,
        mechanism,
        path,
        "Disabling persistence mechanism"
    );

    let result = match mechanism {
        "registry_run_key" => disable_registry_run_key(path).await,
        "scheduled_task" => disable_scheduled_task(path).await,
        "service" => disable_service(path).await,
        "cron" => delete_file(path, "cron entry").await,
        "systemd_unit" => disable_systemd_unit(path).await,
        "startup_folder" => delete_file(path, "startup entry").await,
        "launchd" => disable_launchd(path).await,
        other => {
            warn!(mechanism = other, path, "Unknown persistence mechanism — skipping");
            return Ok(());
        }
    };

    if let Err(ref e) = result {
        warn!(
            event_id = %event.event_id,
            mechanism,
            path,
            error = %e,
            "Persistence disable failed"
        );
    }

    result
}

// ─── Registry Run Key ─────────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
async fn disable_registry_run_key(path: &str) -> Result<()> {
    // Path format from PersistenceCollector registry watcher:
    //   "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\ValueName"
    // Split on first backslash to separate hive from the rest.
    let (hive_str, rest) = path
        .split_once('\\')
        .ok_or_else(|| anyhow::anyhow!("Malformed registry path: {}", path))?;

    let (key_path, value_name) = rest
        .rsplit_once('\\')
        .ok_or_else(|| anyhow::anyhow!("Cannot split key/value from: {}", rest))?;

    use windows::Win32::System::Registry::{
        RegCloseKey, RegDeleteValueW, RegOpenKeyExW, HKEY, HKEY_CURRENT_USER,
        HKEY_LOCAL_MACHINE, KEY_SET_VALUE,
    };
    use windows::core::PCWSTR;

    let hive = if hive_str.eq_ignore_ascii_case("HKLM")
        || hive_str.eq_ignore_ascii_case("HKEY_LOCAL_MACHINE")
    {
        HKEY_LOCAL_MACHINE
    } else if hive_str.eq_ignore_ascii_case("HKCU")
        || hive_str.eq_ignore_ascii_case("HKEY_CURRENT_USER")
    {
        HKEY_CURRENT_USER
    } else {
        anyhow::bail!("Unsupported registry hive: {}", hive_str);
    };

    let path_wide: Vec<u16> = key_path.encode_utf16().chain(Some(0)).collect();
    let value_wide: Vec<u16> = value_name.encode_utf16().chain(Some(0)).collect();
    let mut hkey = HKEY::default();

    unsafe {
        RegOpenKeyExW(
            hive,
            PCWSTR(path_wide.as_ptr()),
            0,
            KEY_SET_VALUE,
            &mut hkey,
        )
    }
    .map_err(|e| anyhow::anyhow!("RegOpenKeyExW failed for '{}': {:?}", path, e))?;

    let del_result = unsafe { RegDeleteValueW(hkey, PCWSTR(value_wide.as_ptr())) };
    unsafe { let _ = RegCloseKey(hkey); }

    del_result.map_err(|e| {
        anyhow::anyhow!("RegDeleteValueW failed for '{}': {:?}", value_name, e)
    })?;

    info!(path, "Registry run key value deleted");
    Ok(())
}

#[cfg(not(target_os = "windows"))]
async fn disable_registry_run_key(path: &str) -> Result<()> {
    warn!(path, "Registry run key disable not supported on this platform");
    Ok(())
}

// ─── Scheduled Task ───────────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
async fn disable_scheduled_task(path: &str) -> Result<()> {
    // Extract task name from path: C:\Windows\System32\Tasks\SomeName
    let task_name = {
        let mut name = path.to_string();
        for prefix in &[
            r"C:\Windows\System32\Tasks",
            r"C:\Windows\SysWOW64\Tasks",
        ] {
            if let Some(rel) = path.strip_prefix(prefix) {
                name = rel.replace('/', "\\");
                break;
            }
        }
        name
    };

    let output = tokio::process::Command::new("schtasks")
        .args(["/delete", "/tn", &task_name, "/f"])
        .output()
        .await
        .map_err(|e| anyhow::anyhow!("schtasks exec failed: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("schtasks /delete failed for '{}': {}", task_name, stderr);
    }
    info!(task_name, "Scheduled task deleted");
    Ok(())
}

#[cfg(target_os = "linux")]
async fn disable_scheduled_task(path: &str) -> Result<()> {
    // On Linux, scheduled tasks are cron entries — delete the file.
    delete_file(path, "scheduled task (cron)").await
}

#[cfg(not(any(target_os = "windows", target_os = "linux")))]
async fn disable_scheduled_task(path: &str) -> Result<()> {
    warn!(path, "Scheduled task disable not supported on this platform");
    Ok(())
}

// ─── Service ──────────────────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
async fn disable_service(path: &str) -> Result<()> {
    let service_name = std::path::Path::new(path)
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| path.to_string());

    let stop = tokio::process::Command::new("sc")
        .args(["stop", &service_name])
        .output()
        .await
        .map_err(|e| anyhow::anyhow!("sc stop exec failed: {}", e))?;
    if !stop.status.success() {
        let stderr = String::from_utf8_lossy(&stop.stderr);
        warn!(service_name, stderr = %stderr, "sc stop failed (service may already be stopped)");
    }

    let del = tokio::process::Command::new("sc")
        .args(["delete", &service_name])
        .output()
        .await
        .map_err(|e| anyhow::anyhow!("sc delete exec failed: {}", e))?;
    if !del.status.success() {
        let stderr = String::from_utf8_lossy(&del.stderr);
        anyhow::bail!("sc delete failed for '{}': {}", service_name, stderr);
    }
    info!(service_name, "Windows service stopped and deleted");
    Ok(())
}

#[cfg(target_os = "linux")]
async fn disable_service(path: &str) -> Result<()> {
    let service_name = std::path::Path::new(path)
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| path.to_string());

    let _ = tokio::process::Command::new("systemctl")
        .args(["stop", &service_name])
        .output()
        .await;
    let disable = tokio::process::Command::new("systemctl")
        .args(["disable", "--now", &service_name])
        .output()
        .await
        .map_err(|e| anyhow::anyhow!("systemctl disable exec failed: {}", e))?;
    if !disable.status.success() {
        let stderr = String::from_utf8_lossy(&disable.stderr);
        warn!(service_name, stderr = %stderr, "systemctl disable returned non-zero");
    }
    info!(service_name, "systemd service disabled");
    Ok(())
}

#[cfg(not(any(target_os = "windows", target_os = "linux")))]
async fn disable_service(path: &str) -> Result<()> {
    warn!(path, "Service disable not supported on this platform");
    Ok(())
}

// ─── Systemd Unit ─────────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
async fn disable_systemd_unit(path: &str) -> Result<()> {
    let unit_name = std::path::Path::new(path)
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| path.to_string());

    let _ = tokio::process::Command::new("systemctl")
        .args(["stop", &unit_name])
        .output()
        .await;
    let _ = tokio::process::Command::new("systemctl")
        .args(["disable", &unit_name])
        .output()
        .await;

    if std::path::Path::new(path).exists() {
        std::fs::remove_file(path)
            .map_err(|e| anyhow::anyhow!("Failed to remove unit file '{}': {}", path, e))?;
        info!(path, "systemd unit file removed");
    }

    let _ = tokio::process::Command::new("systemctl")
        .args(["daemon-reload"])
        .output()
        .await;

    Ok(())
}

#[cfg(not(target_os = "linux"))]
async fn disable_systemd_unit(path: &str) -> Result<()> {
    warn!(path, "systemd unit disable not supported on this platform");
    Ok(())
}

// ─── launchd (macOS) ──────────────────────────────────────────────────────────

#[cfg(target_os = "macos")]
async fn disable_launchd(path: &str) -> Result<()> {
    let unload = tokio::process::Command::new("launchctl")
        .args(["unload", "-w", path])
        .output()
        .await
        .map_err(|e| anyhow::anyhow!("launchctl unload exec failed: {}", e))?;

    if !unload.status.success() {
        let stderr = String::from_utf8_lossy(&unload.stderr);
        warn!(path, stderr = %stderr, "launchctl unload returned non-zero (may already be unloaded)");
    }

    delete_file(path, "launchd plist").await
}

#[cfg(not(target_os = "macos"))]
async fn disable_launchd(path: &str) -> Result<()> {
    warn!(path, "launchd disable not supported on this platform");
    Ok(())
}

// ─── Shared helpers ───────────────────────────────────────────────────────────

async fn delete_file(path: &str, label: &str) -> Result<()> {
    if path.is_empty() {
        anyhow::bail!("{} path is empty", label);
    }
    if !std::path::Path::new(path).exists() {
        warn!(path, label, "Persistence file already absent");
        return Ok(());
    }
    std::fs::remove_file(path)
        .map_err(|e| anyhow::anyhow!("Failed to remove {} at '{}': {}", label, path, e))?;
    info!(path, label, "Persistence file removed");
    Ok(())
}
