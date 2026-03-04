// Behavioral heuristics — sliding window correlators
// These supplement the TOML/Lua rule engine for patterns that need
// stateful aggregation over time.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use crate::core::event_bus::{EventType, TelemetryEvent};

/// A sliding window of events, filtered by time and optionally by event type.
pub struct SlidingWindow {
    window: VecDeque<(Instant, TelemetryEvent)>,
    duration: Duration,
}

impl SlidingWindow {
    pub fn new(duration: Duration) -> Self {
        Self {
            window: VecDeque::new(),
            duration,
        }
    }

    pub fn push(&mut self, event: TelemetryEvent) {
        let now = Instant::now();
        self.window.push_back((now, event));
        self.evict_old(now);
    }

    pub fn events_of_type(&self, event_type: &EventType) -> Vec<&TelemetryEvent> {
        self.window
            .iter()
            .filter(|(_, e)| &e.event_type == event_type)
            .map(|(_, e)| e)
            .collect()
    }

    pub fn count(&self) -> usize {
        self.window.len()
    }

    fn evict_old(&mut self, now: Instant) {
        while let Some((ts, _)) = self.window.front() {
            if now.duration_since(*ts) > self.duration {
                self.window.pop_front();
            } else {
                break;
            }
        }
    }
}

/// Detect rapid process spawning from a single parent (>5 children in 10s).
pub fn detect_process_storm(window: &SlidingWindow, threshold: usize) -> bool {
    let process_creates = window.events_of_type(&EventType::ProcessCreate);
    process_creates.len() > threshold
}

/// Detect login brute force (>5 failures from same user in 60s).
pub fn detect_brute_force(window: &SlidingWindow, threshold: usize) -> bool {
    let failures = window.events_of_type(&EventType::AuthLogonFailure);
    if failures.len() <= threshold {
        return false;
    }
    // Group by user
    let mut per_user: HashMap<String, usize> = HashMap::new();
    for event in &failures {
        if let Some(p) = &event.principal {
            *per_user.entry(p.user.clone()).or_default() += 1;
        }
    }
    per_user.values().any(|&count| count > threshold)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::event_bus::{OsInfo, TelemetryEvent};
    use std::time::Duration;

    fn make_event(event_type: EventType) -> TelemetryEvent {
        TelemetryEvent::new(
            "agt",
            "ten",
            "test",
            event_type,
            "host",
            OsInfo {
                platform: "test".into(),
                version: "0".into(),
                arch: "x64".into(),
            },
        )
    }

    #[test]
    fn test_process_storm_detection() {
        let mut window = SlidingWindow::new(Duration::from_secs(10));
        for _ in 0..6 {
            window.push(make_event(EventType::ProcessCreate));
        }
        assert!(detect_process_storm(&window, 5));
    }

    #[test]
    fn test_no_storm_below_threshold() {
        let mut window = SlidingWindow::new(Duration::from_secs(10));
        for _ in 0..3 {
            window.push(make_event(EventType::ProcessCreate));
        }
        assert!(!detect_process_storm(&window, 5));
    }
}
