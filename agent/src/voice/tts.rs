// OS-native Text-to-Speech for security alerts
//
// Windows: Windows SAPI 5 (ISpVoice COM interface)
// macOS:   AVSpeechSynthesizer via shell (say command)
// Linux:   espeak-ng (system package, optional)
//
// Zero download, zero idle memory overhead.
// Mandatory for HIGH/CRITICAL alerts per policy.

use anyhow::Result;
use tracing::{debug, warn};

use crate::core::event_bus::Severity;

/// Speak a message using the OS TTS engine.
pub async fn speak(text: &str) -> Result<()> {
    if text.is_empty() {
        return Ok(());
    }

    debug!(chars = text.len(), "TTS speak requested");

    #[cfg(target_os = "windows")]
    {
        speak_windows(text)
    }
    #[cfg(target_os = "macos")]
    {
        speak_macos(text).await
    }
    #[cfg(target_os = "linux")]
    {
        speak_linux(text).await
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        warn!("TTS not available on this platform");
        Ok(())
    }
}

/// Check if TTS should trigger for the given severity and minimum threshold.
pub fn should_speak(event_severity: &Severity, min_severity: &str) -> bool {
    let min = parse_severity(min_severity);
    event_severity >= &min
}

fn parse_severity(s: &str) -> Severity {
    match s.to_uppercase().as_str() {
        "CRITICAL" => Severity::Critical,
        "HIGH" => Severity::High,
        "MEDIUM" => Severity::Medium,
        "LOW" => Severity::Low,
        _ => Severity::Info,
    }
}

// ─── Windows SAPI 5 ──────────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
fn speak_windows(text: &str) -> Result<()> {
    // Phase 2: Implement via ISpVoice COM interface.
    // For Phase 0/1: use PowerShell as a quick bootstrap.
    use std::process::Command;
    let script = format!(
        "Add-Type -AssemblyName System.Speech; \
         $s = New-Object System.Speech.Synthesis.SpeechSynthesizer; \
         $s.Speak('{}');",
        text.replace('\'', "''")
    );
    Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .status()?;
    Ok(())
}

// ─── macOS AVSpeech (via `say` command) ──────────────────────────────────────

#[cfg(target_os = "macos")]
async fn speak_macos(text: &str) -> Result<()> {
    tokio::process::Command::new("say")
        .arg(text)
        .status()
        .await?;
    Ok(())
}

// ─── Linux espeak-ng ─────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
async fn speak_linux(text: &str) -> Result<()> {
    let result = tokio::process::Command::new("espeak-ng")
        .arg(text)
        .status()
        .await;
    match result {
        Ok(_) => Ok(()),
        Err(_) => {
            warn!("espeak-ng not found — TTS unavailable on this Linux system");
            Ok(()) // Non-fatal
        }
    }
}
