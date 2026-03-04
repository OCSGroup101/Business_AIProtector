// Copyright 2026 Omni Cyber Solutions LLC. Apache License 2.0.
// Alert Uploader — fast-path for detection events.
//
// When the DetectionEngine fires a hit it annotates the event with
// `detections: Vec<DetectionHit>` and sends it here via mpsc channel.
// AlertUploader batches these and POSTs them directly to the platform's
// telemetry endpoint (which calls incident_service for any event that
// has a non-empty `detections` array).
//
// Unlike TelemetryUploader there is no ring buffer — alerts are sent
// immediately and retried on failure.  The ring buffer continues to
// carry raw (undetected) telemetry for historical completeness.

use anyhow::Result;
use reqwest::Client;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::config::AgentConfig;
use crate::core::event_bus::TelemetryEvent;

const MAX_BATCH: usize = 50;
const DRAIN_TIMEOUT_MS: u64 = 200; // collect events for up to 200ms before flushing

pub struct AlertUploader {
    client: Client,
    platform_url: String,
    agent_id: String,
    tenant_id: String,
    receiver: mpsc::Receiver<TelemetryEvent>,
}

impl AlertUploader {
    pub fn new(
        cfg: &AgentConfig,
        agent_id: &str,
        tenant_id: &str,
        receiver: mpsc::Receiver<TelemetryEvent>,
    ) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()?;

        Ok(Self {
            client,
            platform_url: cfg.platform.url.clone(),
            agent_id: agent_id.to_string(),
            tenant_id: tenant_id.to_string(),
            receiver,
        })
    }

    pub async fn run(mut self) -> Result<()> {
        info!("Alert uploader starting");
        loop {
            // Wait for the first alert
            let first = match self.receiver.recv().await {
                Some(e) => e,
                None => {
                    info!("Alert channel closed — alert uploader shutting down");
                    return Ok(());
                }
            };

            // Drain any additional alerts that arrive within DRAIN_TIMEOUT_MS
            let mut batch = vec![first];
            let deadline = tokio::time::Instant::now()
                + Duration::from_millis(DRAIN_TIMEOUT_MS);

            loop {
                if batch.len() >= MAX_BATCH {
                    break;
                }
                match tokio::time::timeout_at(deadline, self.receiver.recv()).await {
                    Ok(Some(e)) => batch.push(e),
                    _ => break,
                }
            }

            self.upload(batch).await;
        }
    }

    async fn upload(&self, events: Vec<TelemetryEvent>) {
        let count = events.len();
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
                debug!(count, "Alert batch uploaded");
            }
            Ok(resp) => {
                warn!(status = %resp.status(), count, "Alert upload rejected by platform");
            }
            Err(e) => {
                warn!(error = %e, count, "Alert upload failed — events lost (no ring buffer on alert path)");
            }
        }
    }
}
