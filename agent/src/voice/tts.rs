// OS-native Text-to-Speech for security alerts
//
// Windows: Windows SAPI 5 (ISpVoice COM interface)
// macOS:   AVSpeechSynthesizer via shell (say command)
// Linux:   espeak-ng (system package, optional)
//
// Zero download, zero idle memory overhead.
// Mandatory for HIGH/CRITICAL alerts per policy.

use anyhow::Result;
use tracing::debug;
#[cfg(target_os = "linux")]
use tracing::warn;

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

// ─── Windows SAPI 5 (ISpVoice COM) ───────────────────────────────────────────

#[cfg(target_os = "windows")]
fn speak_windows(text: &str) -> Result<()> {
    use windows::Win32::Media::Speech::{ISpVoice, SpVoice, SPEI_END_INPUT_STREAM};
    use windows::Win32::System::Com::{
        CoCreateInstance, CoInitializeEx, CoUninitialize, CLSCTX_ALL,
        COINIT_MULTITHREADED,
    };
    use windows::core::HSTRING;

    // SAFETY: CoInitializeEx is safe to call from any thread. We always pair
    // it with CoUninitialize via the guard below. COINIT_MULTITHREADED is the
    // correct flag for async agent code; nested calls (already-initialized
    // threads) return S_FALSE which we tolerate.
    let hr_init = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
    let com_initialized = hr_init.is_ok();

    struct ComGuard(bool);
    impl Drop for ComGuard {
        fn drop(&mut self) {
            if self.0 {
                // SAFETY: CoUninitialize must be called exactly once per
                // successful CoInitializeEx — the guard ensures this pairing.
                unsafe { CoUninitialize() };
            }
        }
    }
    let _guard = ComGuard(com_initialized);

    // SAFETY: CoCreateInstance is safe when COM is initialized (ensured above).
    // SpVoice is a well-known CLSID documented by Microsoft; CLSCTX_ALL is the
    // standard context for in-process COM servers. The returned interface pointer
    // is reference-counted and released automatically when `voice` is dropped.
    let voice: ISpVoice = unsafe {
        CoCreateInstance(&SpVoice, None, CLSCTX_ALL)
            .map_err(|e| anyhow::anyhow!("CoCreateInstance(SpVoice) failed: {:?}", e))?
    };

    let wide = HSTRING::from(text);

    // SAFETY: Speak is a COM method on a valid ISpVoice interface. The HSTRING
    // outlives the Speak call. SPF_DEFAULT (0) requests synchronous speech.
    // The SPEI_END_INPUT_STREAM flag (unused here) would be for async mode.
    let _ = SPEI_END_INPUT_STREAM; // suppress unused import warning
    unsafe {
        voice
            .Speak(wide.as_ptr(), 0, None)
            .map_err(|e| anyhow::anyhow!("ISpVoice::Speak failed: {:?}", e))?
    };

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
