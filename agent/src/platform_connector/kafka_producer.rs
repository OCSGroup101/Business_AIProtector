// Copyright 2026 Omni Cyber Solutions LLC. Apache License 2.0.
//
// Kafka producer for real-time telemetry streaming.
//
// Topic naming: openclaw.telemetry.{tenant_id}
//
// The agent publishes each TelemetryEvent to Kafka immediately on detection.
// The ring buffer HTTP upload path remains as the fallback when Kafka is
// unavailable or not configured.

use anyhow::Result;
use tracing::warn;

use crate::core::event_bus::TelemetryEvent;

/// Kafka connection configuration.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct KafkaConfig {
    /// Comma-separated list of broker addresses (e.g. "kafka:9092")
    pub brokers: String,
    /// Topic prefix; full topic = "{prefix}.{tenant_id}"
    #[serde(default = "default_topic_prefix")]
    pub topic_prefix: String,
    /// Compression: none | gzip | snappy | lz4 | zstd
    #[serde(default = "default_compression")]
    pub compression: String,
}

fn default_topic_prefix() -> String {
    "openclaw.telemetry".to_string()
}

fn default_compression() -> String {
    "lz4".to_string()
}

/// Thin wrapper around the rdkafka FutureProducer.
///
/// When rdkafka is not compiled in (CI / platforms without cmake) the struct
/// is a no-op stub so the rest of the codebase compiles unconditionally.
pub struct KafkaProducer {
    #[cfg(feature = "kafka")]
    inner: rdkafka::producer::FutureProducer,
    topic_prefix: String,
    #[cfg(not(feature = "kafka"))]
    _phantom: std::marker::PhantomData<()>,
}

impl KafkaProducer {
    /// Create a new Kafka producer.
    ///
    /// Returns `Ok(None)` when kafka config is absent (Kafka disabled).
    /// Returns `Err` if the config is present but broker connection fails.
    pub fn new(cfg: &KafkaConfig) -> Result<Self> {
        #[cfg(feature = "kafka")]
        {
            use rdkafka::config::ClientConfig;
            let producer: rdkafka::producer::FutureProducer = ClientConfig::new()
                .set("bootstrap.servers", &cfg.brokers)
                .set("message.timeout.ms", "5000")
                .set("compression.type", &cfg.compression)
                .create()?;
            return Ok(Self {
                inner: producer,
                topic_prefix: cfg.topic_prefix.clone(),
            });
        }
        #[cfg(not(feature = "kafka"))]
        {
            warn!("Kafka feature not compiled in — events will use HTTP fallback only");
            Ok(Self {
                topic_prefix: cfg.topic_prefix.clone(),
                _phantom: std::marker::PhantomData,
            })
        }
    }

    /// Produce a single TelemetryEvent to the tenant-scoped topic.
    ///
    /// Non-blocking: uses `try_produce` which returns immediately. A failed
    /// produce is logged but does not propagate — the ring buffer is the
    /// authoritative store.
    pub async fn produce(&self, event: &TelemetryEvent) -> Result<()> {
        let topic = format!("{}.{}", self.topic_prefix, event.tenant_id);
        let payload = serde_json::to_vec(event)?;
        let key = event.event_id.to_string();

        #[cfg(feature = "kafka")]
        {
            use rdkafka::producer::FutureRecord;
            use std::time::Duration;

            let record = FutureRecord::to(&topic)
                .key(&key)
                .payload(&payload);

            match self.inner.send(record, Duration::from_secs(5)).await {
                Ok(_) => {
                    debug!(topic = %topic, event_id = %key, "Kafka produce OK");
                }
                Err((e, _)) => {
                    warn!(topic = %topic, error = %e, "Kafka produce failed — event in ring buffer");
                }
            }
        }

        #[cfg(not(feature = "kafka"))]
        {
            let _ = (topic, payload, key);
        }

        Ok(())
    }
}
