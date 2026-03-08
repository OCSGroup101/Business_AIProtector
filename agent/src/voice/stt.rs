// Copyright 2026 Omni Cyber Solutions LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Speech-to-text using whisper.cpp via whisper-rs bindings.
// Feature-gated: only compiled when the `stt` feature is enabled.
// Policy-gated:  only active when AgentConfig.assistant.stt_enabled == true.
//
// Model: whisper-tiny (39 MB) — downloaded to agent data dir on first use.
// Sampling: 16 kHz mono PCM via cpal (OS audio API).
//
// Usage:
//   let recognizer = SpeechRecognizer::new(Path::new("/var/lib/openclaw/whisper-tiny.bin"))?;
//   let text = recognizer.transcribe_wav(&wav_bytes)?;

#[cfg(feature = "stt")]
mod inner {
    use anyhow::{Context, Result};
    use std::path::Path;
    use tracing::{debug, info};
    use whisper_rs::{FullParams, SamplingStrategy, WhisperContext, WhisperContextParameters};

    // ─── WAV header constants ──────────────────────────────────────────────────

    /// Expected PCM sample rate (16 kHz) required by whisper.cpp.
    const WHISPER_SAMPLE_RATE: u32 = 16_000;

    /// Byte offset of the "data" chunk's sample payload within a minimal WAV file.
    /// 44 = RIFF(4) + size(4) + WAVE(4) + fmt (4+4+16) + data(4+4)
    const WAV_DATA_OFFSET: usize = 44;

    // ─── SpeechRecognizer ─────────────────────────────────────────────────────

    /// Wraps a loaded whisper.cpp model and exposes synchronous transcription.
    ///
    /// `SpeechRecognizer` is `Send` but not `Sync`; wrap in `Arc<Mutex<_>>` for
    /// multi-threaded use, or confine to a single `spawn_blocking` task.
    pub struct SpeechRecognizer {
        ctx: WhisperContext,
    }

    impl SpeechRecognizer {
        /// Load a whisper model from `model_path` (e.g. whisper-tiny.bin).
        ///
        /// This is CPU-bound and may take 100–500 ms on first call; call from a
        /// `tokio::task::spawn_blocking` context.
        pub fn new(model_path: &Path) -> Result<Self> {
            let path_str = model_path
                .to_str()
                .context("model path is not valid UTF-8")?;

            info!(model = path_str, "Loading whisper model");

            let ctx = WhisperContext::new_with_params(path_str, WhisperContextParameters::default())
                .map_err(|e| anyhow::anyhow!("failed to load whisper model '{}': {:?}", path_str, e))?;

            Ok(Self { ctx })
        }

        /// Transcribe a 16 kHz mono PCM WAV file supplied as raw bytes.
        ///
        /// The WAV must be:
        ///   - PCM (format code 1), 16-bit signed little-endian
        ///   - 1 channel (mono)
        ///   - 16000 Hz sample rate
        ///
        /// Returns the transcribed text with leading/trailing whitespace trimmed.
        pub fn transcribe_wav(&self, wav_bytes: &[u8]) -> Result<String> {
            // ── Decode WAV header ──────────────────────────────────────────────
            let samples = decode_wav_to_f32(wav_bytes)
                .context("WAV decode failed — expected 16 kHz mono PCM")?;

            if samples.is_empty() {
                return Ok(String::new());
            }

            debug!(
                sample_count = samples.len(),
                duration_secs = samples.len() as f32 / WHISPER_SAMPLE_RATE as f32,
                "Transcribing audio"
            );

            // ── Whisper inference ──────────────────────────────────────────────
            let mut params = FullParams::new(SamplingStrategy::Greedy { best_of: 1 });
            params.set_language(Some("en"));
            params.set_print_special(false);
            params.set_print_progress(false);
            params.set_print_realtime(false);
            params.set_print_timestamps(false);
            // Single-threaded inference — agent must stay ≤4% CPU steady state
            params.set_n_threads(1);

            let mut state = self
                .ctx
                .create_state()
                .map_err(|e| anyhow::anyhow!("failed to create whisper state: {:?}", e))?;

            state
                .full(params, &samples)
                .map_err(|e| anyhow::anyhow!("whisper inference failed: {:?}", e))?;

            // ── Collect segments ───────────────────────────────────────────────
            let n_segments = state
                .full_n_segments()
                .map_err(|e| anyhow::anyhow!("full_n_segments failed: {:?}", e))?;

            let mut text = String::new();
            for i in 0..n_segments {
                let segment = state
                    .full_get_segment_text(i)
                    .map_err(|e| anyhow::anyhow!("full_get_segment_text({}) failed: {:?}", i, e))?;
                text.push_str(&segment);
            }

            Ok(text.trim().to_string())
        }
    }

    // ─── WAV decoder ──────────────────────────────────────────────────────────

    /// Decode a minimal 44-byte-header PCM WAV into normalised f32 samples.
    ///
    /// Validates:
    ///   - "RIFF" / "WAVE" magic bytes
    ///   - PCM format (audio format code 1)
    ///   - Mono channel count
    ///   - 16000 Hz sample rate
    ///   - 16-bit bit depth
    fn decode_wav_to_f32(wav_bytes: &[u8]) -> Result<Vec<f32>> {
        if wav_bytes.len() < WAV_DATA_OFFSET {
            anyhow::bail!(
                "WAV too short ({} bytes, need at least {})",
                wav_bytes.len(),
                WAV_DATA_OFFSET
            );
        }

        // RIFF magic
        if &wav_bytes[0..4] != b"RIFF" {
            anyhow::bail!("not a RIFF file");
        }
        if &wav_bytes[8..12] != b"WAVE" {
            anyhow::bail!("RIFF container is not WAVE");
        }

        // fmt chunk at offset 12
        let audio_format = u16::from_le_bytes([wav_bytes[20], wav_bytes[21]]);
        if audio_format != 1 {
            anyhow::bail!("unsupported audio format {} (expected PCM = 1)", audio_format);
        }

        let channels = u16::from_le_bytes([wav_bytes[22], wav_bytes[23]]);
        if channels != 1 {
            anyhow::bail!("expected mono (1 channel), got {}", channels);
        }

        let sample_rate = u32::from_le_bytes([wav_bytes[24], wav_bytes[25], wav_bytes[26], wav_bytes[27]]);
        if sample_rate != WHISPER_SAMPLE_RATE {
            anyhow::bail!(
                "expected {} Hz sample rate, got {} Hz",
                WHISPER_SAMPLE_RATE,
                sample_rate
            );
        }

        let bits_per_sample = u16::from_le_bytes([wav_bytes[34], wav_bytes[35]]);
        if bits_per_sample != 16 {
            anyhow::bail!("expected 16-bit PCM, got {} bits", bits_per_sample);
        }

        // PCM data starts at offset 44 (assumes no extra fmt fields)
        let pcm = &wav_bytes[WAV_DATA_OFFSET..];
        if pcm.len() % 2 != 0 {
            anyhow::bail!("PCM data byte count {} is odd", pcm.len());
        }

        // Convert i16 samples to f32 in [-1.0, 1.0]
        let samples: Vec<f32> = pcm
            .chunks_exact(2)
            .map(|c| {
                let s = i16::from_le_bytes([c[0], c[1]]);
                s as f32 / 32768.0_f32
            })
            .collect();

        Ok(samples)
    }

    // ─── Async helper ─────────────────────────────────────────────────────────

    /// Listen for a single voice command from the default microphone and return
    /// the transcribed text.
    ///
    /// Blocks a `spawn_blocking` thread during audio capture and inference.
    /// Requires `model_path` to point at a downloaded whisper-tiny model.
    pub async fn listen_once(model_path: std::path::PathBuf) -> Result<String> {
        use std::sync::Arc;

        let recognizer = tokio::task::spawn_blocking(move || SpeechRecognizer::new(&model_path))
            .await
            .context("spawn_blocking panicked")??;

        let recognizer = Arc::new(std::sync::Mutex::new(recognizer));

        // Capture ~5 seconds of microphone audio via cpal
        let wav_bytes = tokio::task::spawn_blocking(move || capture_microphone_wav(5))
            .await
            .context("microphone capture task panicked")??;

        let result = tokio::task::spawn_blocking(move || {
            recognizer
                .lock()
                .expect("recognizer mutex poisoned")
                .transcribe_wav(&wav_bytes)
        })
        .await
        .context("transcription task panicked")??;

        Ok(result)
    }

    // ─── Microphone capture ───────────────────────────────────────────────────

    /// Capture `duration_secs` of audio from the default input device at 16 kHz
    /// mono 16-bit PCM and return the raw bytes as a minimal WAV.
    ///
    /// This is a synchronous (blocking) function — always call via
    /// `tokio::task::spawn_blocking`.
    fn capture_microphone_wav(duration_secs: u64) -> Result<Vec<u8>> {
        use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
        use cpal::{BufferSize, SampleFormat, StreamConfig};
        use std::sync::{Arc, Mutex};
        use std::time::Duration;

        let host = cpal::default_host();
        let device = host
            .default_input_device()
            .context("no default audio input device found")?;

        let config = StreamConfig {
            channels: 1,
            sample_rate: cpal::SampleRate(WHISPER_SAMPLE_RATE),
            buffer_size: BufferSize::Default,
        };

        let pcm: Arc<Mutex<Vec<i16>>> = Arc::new(Mutex::new(Vec::new()));
        let pcm_clone = Arc::clone(&pcm);
        let error_holder: Arc<Mutex<Option<cpal::StreamError>>> = Arc::new(Mutex::new(None));
        let error_clone = Arc::clone(&error_holder);

        let stream = device
            .build_input_stream(
                &config,
                move |data: &[i16], _: &cpal::InputCallbackInfo| {
                    let mut guard = pcm_clone.lock().expect("pcm mutex poisoned");
                    guard.extend_from_slice(data);
                },
                move |err| {
                    let mut guard = error_clone.lock().expect("error mutex poisoned");
                    *guard = Some(err);
                },
                None,
            )
            .context("failed to build audio input stream")?;

        stream.play().context("failed to start audio stream")?;
        std::thread::sleep(Duration::from_secs(duration_secs));
        drop(stream);

        if let Some(err) = error_holder.lock().unwrap().take() {
            anyhow::bail!("audio stream error: {:?}", err);
        }

        let samples = Arc::try_unwrap(pcm)
            .map_err(|_| anyhow::anyhow!("pcm arc still referenced"))?
            .into_inner()
            .unwrap();

        encode_wav(&samples)
    }

    /// Encode a slice of 16-bit signed mono PCM samples into a minimal WAV.
    fn encode_wav(samples: &[i16]) -> Result<Vec<u8>> {
        let data_len = (samples.len() * 2) as u32;
        let file_len = 36 + data_len;

        let mut out = Vec::with_capacity(WAV_DATA_OFFSET + samples.len() * 2);

        // RIFF header
        out.extend_from_slice(b"RIFF");
        out.extend_from_slice(&file_len.to_le_bytes());
        out.extend_from_slice(b"WAVE");

        // fmt chunk
        out.extend_from_slice(b"fmt ");
        out.extend_from_slice(&16u32.to_le_bytes());           // chunk size
        out.extend_from_slice(&1u16.to_le_bytes());            // PCM
        out.extend_from_slice(&1u16.to_le_bytes());            // mono
        out.extend_from_slice(&WHISPER_SAMPLE_RATE.to_le_bytes()); // sample rate
        out.extend_from_slice(&(WHISPER_SAMPLE_RATE * 2).to_le_bytes()); // byte rate
        out.extend_from_slice(&2u16.to_le_bytes());            // block align
        out.extend_from_slice(&16u16.to_le_bytes());           // bits per sample

        // data chunk
        out.extend_from_slice(b"data");
        out.extend_from_slice(&data_len.to_le_bytes());
        for s in samples {
            out.extend_from_slice(&s.to_le_bytes());
        }

        Ok(out)
    }
} // mod inner

// ─── Public re-exports ────────────────────────────────────────────────────────

#[cfg(feature = "stt")]
pub use inner::{listen_once, SpeechRecognizer};

/// Returns true when the `stt` feature is compiled in.
pub fn is_available() -> bool {
    cfg!(feature = "stt")
}

// ─── Stub (no stt feature) ────────────────────────────────────────────────────

#[cfg(not(feature = "stt"))]
pub async fn listen_once(_model_path: std::path::PathBuf) -> anyhow::Result<String> {
    use tracing::warn;
    warn!("STT feature not compiled in — enable with --features stt");
    Err(anyhow::anyhow!("STT not available in this build"))
}
