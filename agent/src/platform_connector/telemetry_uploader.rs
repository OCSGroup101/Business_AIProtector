// Telemetry uploader — batches ring buffer events and uploads to platform
//
// Upload triggers:
//   1. Timer: every N seconds (default 300 = 5 min)
//   2. Buffer threshold: when ring buffer reaches X% full (default 50%)

use anyhow::Result;
use reqwest::Client;
use std::time::Duration;
use tokio::sync::broadcast;
use tracing::{debug, info, warn};

use crate::config::AgentConfig;
use crate::core::event_bus::TelemetryEvent;
use crate::core::ring_buffer::RingBuffer;
use crate::platform_connector::client::build_platform_client;

pub struct TelemetryUploader {
    client: Client,
    agent_id: String,
    tenant_id: String,
    platform_url: String,
    upload_interval: Duration,
    buffer_threshold_pct: u8,
    ring_buffer: RingBuffer,
    receiver: broadcast::Receiver<TelemetryEvent>,
}

impl TelemetryUploader {
    pub fn new(
        cfg: &AgentConfig,
        agent_id: &str,
        tenant_id: &str,
        receiver: broadcast::Receiver<TelemetryEvent>,
    ) -> Result<Self> {
        let client = build_platform_client(cfg, Duration::from_secs(60))?;

        let ring_buffer =
            RingBuffer::open(&cfg.storage.data_dir, cfg.storage.ring_buffer_capacity)?;

        Ok(Self {
            client,
            agent_id: agent_id.to_string(),
            tenant_id: tenant_id.to_string(),
            platform_url: cfg.platform.url.clone(),
            upload_interval: Duration::from_secs(cfg.platform.telemetry_upload_interval_secs),
            buffer_threshold_pct: cfg.platform.buffer_upload_threshold_pct,
            ring_buffer,
            receiver,
        })
    }

    pub async fn run(mut self) -> Result<()> {
        info!(
            interval_secs = self.upload_interval.as_secs(),
            threshold_pct = self.buffer_threshold_pct,
            "Telemetry uploader starting"
        );

        let mut upload_ticker = tokio::time::interval(self.upload_interval);
        upload_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                // Drain events from bus into ring buffer
                event = self.receiver.recv() => {
                    match event {
                        Ok(e) => {
                            if let Err(err) = self.ring_buffer.push(&e) {
                                warn!(error = %err, "Failed to push event to ring buffer");
                            }
                            // Check threshold trigger
                            if self.ring_buffer.fill_pct() >= self.buffer_threshold_pct {
                                debug!("Ring buffer threshold reached — uploading");
                                self.upload_batch().await;
                            }
                        }
                        Err(broadcast::error::RecvError::Lagged(n)) => {
                            warn!(dropped = n, "Telemetry uploader lagged");
                        }
                        Err(broadcast::error::RecvError::Closed) => {
                            // Flush remaining events before shutdown
                            self.upload_batch().await;
                            return Ok(());
                        }
                    }
                }
                // Timer trigger
                _ = upload_ticker.tick() => {
                    if self.ring_buffer.pending_count() > 0 {
                        self.upload_batch().await;
                    }
                }
            }
        }
    }

    async fn upload_batch(&self) {
        const BATCH_SIZE: usize = 500;

        let events = match self.ring_buffer.pending_batch(BATCH_SIZE) {
            Ok(e) => e,
            Err(err) => {
                warn!(error = %err, "Failed to read ring buffer batch");
                return;
            }
        };

        if events.is_empty() {
            return;
        }

        let count = events.len();
        let event_ids: Vec<String> = events.iter().map(|e| e.event_id.clone()).collect();

        // Serialize as NDJSON
        let ndjson: String = events
            .iter()
            .filter_map(|e| serde_json::to_string(e).ok())
            .collect::<Vec<_>>()
            .join("\n");

        let result = self
            .client
            .post(format!("{}/api/v1/telemetry/batch", self.platform_url))
            .header("Content-Type", "application/x-ndjson")
            .header("X-Agent-ID", &self.agent_id)
            .header("X-Tenant-ID", &self.tenant_id)
            .body(ndjson)
            .send()
            .await;

        match result {
            Ok(resp) if resp.status().is_success() => {
                debug!(count, "Telemetry batch uploaded successfully");
                if let Err(e) = self.ring_buffer.mark_uploaded(&event_ids) {
                    warn!(error = %e, "Failed to mark events as uploaded");
                }
                let _ = self.ring_buffer.purge_uploaded();
            }
            Ok(resp) => {
                warn!(status = %resp.status(), count, "Telemetry upload rejected — will retry");
            }
            Err(e) => {
                warn!(error = %e, count, "Telemetry upload failed — events remain in buffer");
            }
        }
    }
}
