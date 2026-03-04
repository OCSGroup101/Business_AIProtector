// Speech-to-Text — whisper.cpp integration (opt-in, feature-flagged)
//
// Enabled via: cargo build --features stt
// Model: whisper tiny.en (39 MB) — downloaded on first enable
//
// This feature is off by default and must be explicitly enabled via policy.

use anyhow::Result;
use tracing::warn;

/// Start listening for voice commands (returns transcribed text).
/// Only available when compiled with --features stt and enabled in policy.
#[cfg(feature = "stt")]
pub async fn listen_once() -> Result<String> {
    use whisper_rs::{FullParams, SamplingStrategy, WhisperContext, WhisperContextParameters};
    // Phase 3: Full implementation with microphone capture via cpal crate
    // and whisper.cpp inference.
    todo!("STT implementation — Phase 3")
}

#[cfg(not(feature = "stt"))]
pub async fn listen_once() -> Result<String> {
    warn!("STT feature not compiled in — enable with --features stt");
    Err(anyhow::anyhow!("STT not available in this build"))
}

pub fn is_available() -> bool {
    cfg!(feature = "stt")
}
