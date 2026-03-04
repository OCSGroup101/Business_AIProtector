// Copyright 2026 Omni Cyber Solutions LLC. Apache License 2.0.
// Intel receiver — polls platform IOC bundle endpoint and applies updates to LMDB.
//
// Poll interval: 5 minutes (configurable via cfg.platform.ioc_poll_interval_secs).
// Delta fetches: sends X-Last-Bundle-Time header so the platform returns only new/changed IOCs.
// Bundle format: NDJSON, one record per line:
//   {"action":"upsert","type":"file_hash","value":"abc...","score":0.90,"metadata":{...}}
//   {"action":"delete","type":"file_hash","value":"def..."}

use anyhow::Result;
use chrono::{DateTime, Utc};
use reqwest::Client;
use serde::Deserialize;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info, warn};

use crate::config::AgentConfig;
use crate::detection::ioc_store::IocStore;

const DEFAULT_POLL_INTERVAL_SECS: u64 = 300; // 5 minutes

#[derive(Deserialize)]
struct BundleRecord {
    action: String,         // "upsert" | "delete"
    #[serde(rename = "type")]
    ioc_type: String,
    value: String,
    score: Option<f64>,
    metadata: Option<serde_json::Value>,
}

pub struct IntelReceiver {
    client: Client,
    platform_url: String,
    agent_id: String,
    tenant_id: String,
    ioc_store: Arc<IocStore>,
    poll_interval: Duration,
}

impl IntelReceiver {
    pub fn new(
        cfg: &AgentConfig,
        agent_id: &str,
        tenant_id: &str,
        ioc_store: Arc<IocStore>,
    ) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(60))
            .build()?;

        let poll_secs = cfg
            .platform
            .ioc_poll_interval_secs
            .unwrap_or(DEFAULT_POLL_INTERVAL_SECS);

        Ok(Self {
            client,
            platform_url: cfg.platform.url.clone(),
            agent_id: agent_id.to_string(),
            tenant_id: tenant_id.to_string(),
            ioc_store,
            poll_interval: Duration::from_secs(poll_secs),
        })
    }

    pub async fn run(self) -> Result<()> {
        info!(
            poll_secs = self.poll_interval.as_secs(),
            "Intel receiver starting"
        );

        let mut last_fetch: Option<DateTime<Utc>> = None;
        let mut ticker = tokio::time::interval(self.poll_interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            ticker.tick().await;
            match self.fetch_and_apply(last_fetch).await {
                Ok(count) => {
                    if count > 0 {
                        info!(count, "IOC bundle applied to LMDB");
                    } else {
                        debug!("IOC bundle: no updates");
                    }
                    last_fetch = Some(Utc::now());
                }
                Err(e) => {
                    warn!(error = %e, "IOC bundle fetch failed — will retry next cycle");
                }
            }
        }
    }

    async fn fetch_and_apply(&self, since: Option<DateTime<Utc>>) -> Result<usize> {
        let mut req = self
            .client
            .get(format!("{}/api/v1/intel/ioc-bundle", self.platform_url))
            .header("X-Agent-ID", &self.agent_id)
            .header("X-Tenant-ID", &self.tenant_id);

        if let Some(ts) = since {
            req = req.query(&[("since", ts.to_rfc3339())]);
        }

        let response = req.send().await?;

        if !response.status().is_success() {
            anyhow::bail!(
                "IOC bundle request failed: HTTP {}",
                response.status()
            );
        }

        let body = response.text().await?;
        let mut upserts: Vec<(String, String, String)> = Vec::new();
        let mut delete_count = 0usize;

        for line in body.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let record: BundleRecord = match serde_json::from_str(line) {
                Ok(r) => r,
                Err(e) => {
                    warn!(error = %e, "Malformed IOC bundle line — skipping");
                    continue;
                }
            };

            match record.action.as_str() {
                "upsert" => {
                    let meta = serde_json::json!({
                        "score": record.score.unwrap_or(0.5),
                        "source": "platform_bundle",
                        "metadata": record.metadata,
                    });
                    // Collect owned strings; borrow them below
                    upserts.push((
                        record.ioc_type,
                        record.value,
                        meta.to_string(),
                    ));
                }
                "delete" => {
                    if let Err(e) = self.ioc_store.remove(&record.ioc_type, &record.value) {
                        warn!(error = %e, "Failed to remove IOC");
                    } else {
                        delete_count += 1;
                    }
                }
                other => {
                    warn!(action = other, "Unknown IOC bundle action");
                }
            }
        }

        let upsert_count = if !upserts.is_empty() {
            // Build iterator of (&str, &str, &str) from owned strings
            let refs: Vec<(&str, &str, &str)> = upserts
                .iter()
                .map(|(t, v, m)| (t.as_str(), v.as_str(), m.as_str()))
                .collect();
            self.ioc_store.bulk_insert(refs.into_iter())?
        } else {
            0
        };

        debug!(
            upserted = upsert_count,
            deleted = delete_count,
            "IOC bundle processed"
        );

        Ok(upsert_count + delete_count)
    }
}
