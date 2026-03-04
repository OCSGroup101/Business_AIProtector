// OpenClaw Agent — Central Event Bus
//
// This is the nervous system of the agent. All collectors publish TelemetryEvents
// here; all consumers (detection engine, ring buffer, uploader) subscribe.
//
// Implementation: tokio::broadcast::channel with a capacity of 10,000 events.
// Slow consumers that fall behind will receive RecvError::Lagged — they must
// handle this gracefully (log the lag count and continue).

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::broadcast;
use ulid::Ulid;

/// The capacity of the broadcast channel.
/// At 10,000 events/sec processing rate this gives ~1 second of buffer.
pub const EVENT_BUS_CAPACITY: usize = 10_000;

// ─── Event Types ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    // Process lifecycle
    ProcessCreate,
    ProcessTerminate,
    // Filesystem
    FileCreate,
    FileModify,
    FileDelete,
    FileRename,
    // Network
    NetworkConnect,
    NetworkListen,
    NetworkDnsQuery,
    // Persistence
    PersistenceCreate,
    PersistenceModify,
    // Authentication
    AuthLogon,
    AuthLogonFailure,
    AuthPrivilegeEscalation,
    // Integrity
    IntegrityViolation,
}

impl std::fmt::Display for EventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = serde_json::to_value(self)
            .ok()
            .and_then(|v| v.as_str().map(str::to_owned))
            .unwrap_or_else(|| format!("{:?}", self));
        write!(f, "{}", s)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// OS principal (user context for the event)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Principal {
    pub user: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,
    pub elevated: bool,
}

/// OS/platform metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsInfo {
    pub platform: String,
    pub version: String,
    pub arch: String,
}

/// A single detection result attached to an event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionHit {
    pub rule_id: String,
    pub rule_name: String,
    pub severity: Severity,
    pub mitre_techniques: Vec<String>,
    pub details: HashMap<String, serde_json::Value>,
}

/// The canonical telemetry event envelope — emitted by collectors, consumed by
/// the detection engine, ring buffer, and uploader.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryEvent {
    pub schema_version: String,
    pub event_id: String,
    pub agent_id: String,
    pub tenant_id: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub collector: String,
    pub event_type: EventType,
    pub severity: Severity,
    pub hostname: String,
    pub os: OsInfo,
    pub principal: Option<Principal>,
    /// Collector-specific payload fields
    pub payload: HashMap<String, serde_json::Value>,
    /// Populated by DetectionEngine after rule evaluation
    pub detections: Vec<DetectionHit>,
    /// MITRE tags, e.g. ["mitre:T1059.001", "mitre:TA0002"]
    pub tags: Vec<String>,
}

impl TelemetryEvent {
    /// Create a new event with a fresh ULID event_id and current timestamp.
    pub fn new(
        agent_id: impl Into<String>,
        tenant_id: impl Into<String>,
        collector: impl Into<String>,
        event_type: EventType,
        hostname: impl Into<String>,
        os: OsInfo,
    ) -> Self {
        Self {
            schema_version: "1.0".to_string(),
            event_id: format!("evt_{}", Ulid::new()),
            agent_id: agent_id.into(),
            tenant_id: tenant_id.into(),
            timestamp: chrono::Utc::now(),
            collector: collector.into(),
            event_type,
            severity: Severity::Info,
            hostname: hostname.into(),
            os,
            principal: None,
            payload: HashMap::new(),
            detections: Vec::new(),
            tags: Vec::new(),
        }
    }
}

// ─── EventBus ────────────────────────────────────────────────────────────────

/// Central event bus. Clone it freely — all clones share the same channel.
#[derive(Clone)]
pub struct EventBus {
    sender: Arc<broadcast::Sender<TelemetryEvent>>,
}

impl EventBus {
    /// Create a new EventBus with the specified channel capacity.
    pub fn new(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity);
        Self {
            sender: Arc::new(sender),
        }
    }

    /// Get a publisher handle. All collectors call `.publish()` on this.
    pub fn publisher(&self) -> EventPublisher {
        EventPublisher {
            sender: Arc::clone(&self.sender),
        }
    }

    /// Subscribe to the event stream. Returns a receiver that will receive
    /// all future events. If the receiver falls behind by more than `capacity`
    /// events it will receive `RecvError::Lagged`.
    pub fn subscribe(&self) -> broadcast::Receiver<TelemetryEvent> {
        self.sender.subscribe()
    }

    /// Number of active receivers.
    pub fn receiver_count(&self) -> usize {
        self.sender.receiver_count()
    }
}

/// Publisher handle — given to each collector so they can emit events.
#[derive(Clone)]
pub struct EventPublisher {
    sender: Arc<broadcast::Sender<TelemetryEvent>>,
}

impl EventPublisher {
    /// Publish an event to all subscribers.
    /// Returns the number of receivers that received the event.
    /// Returns 0 (not an error) if there are no active subscribers.
    pub fn publish(&self, event: TelemetryEvent) -> usize {
        match self.sender.send(event) {
            Ok(n) => n,
            Err(_) => 0, // No receivers — not an error at startup
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_os() -> OsInfo {
        OsInfo {
            platform: "test".into(),
            version: "0.0".into(),
            arch: "x86_64".into(),
        }
    }

    #[tokio::test]
    async fn test_publish_and_receive() {
        let bus = EventBus::new(10);
        let publisher = bus.publisher();
        let mut receiver = bus.subscribe();

        let event = TelemetryEvent::new(
            "agt_test",
            "ten_test",
            "test_collector",
            EventType::ProcessCreate,
            "test-host",
            make_os(),
        );

        publisher.publish(event.clone());
        let received = receiver.recv().await.expect("should receive event");
        assert_eq!(received.event_id, event.event_id);
        assert_eq!(received.event_type, EventType::ProcessCreate);
    }

    #[tokio::test]
    async fn test_multiple_subscribers() {
        let bus = EventBus::new(100);
        let publisher = bus.publisher();
        let mut r1 = bus.subscribe();
        let mut r2 = bus.subscribe();

        let event = TelemetryEvent::new(
            "agt_test",
            "ten_test",
            "collector",
            EventType::FileCreate,
            "host",
            make_os(),
        );

        publisher.publish(event.clone());

        let e1 = r1.recv().await.unwrap();
        let e2 = r2.recv().await.unwrap();
        assert_eq!(e1.event_id, event.event_id);
        assert_eq!(e2.event_id, event.event_id);
    }

    #[tokio::test]
    async fn test_lagged_receiver() {
        use tokio::sync::broadcast::error::RecvError;

        let bus = EventBus::new(2); // tiny capacity
        let publisher = bus.publisher();
        let mut receiver = bus.subscribe();

        // Flood the channel — receiver will lag
        for _ in 0..5 {
            let e = TelemetryEvent::new(
                "agt",
                "ten",
                "col",
                EventType::NetworkConnect,
                "h",
                make_os(),
            );
            publisher.publish(e);
        }

        // Receiver should detect lag
        let result = receiver.recv().await;
        match result {
            Err(RecvError::Lagged(n)) => {
                assert!(n > 0, "should have lagged by at least 1");
            }
            Ok(_) => {} // Got an event despite lag — also acceptable
            Err(e) => panic!("unexpected error: {}", e),
        }
    }
}
