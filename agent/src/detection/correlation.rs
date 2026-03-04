// Behavioral correlation engine — Phase 2 multi-event detection
//
// Implements two stateful detection strategies:
//   Sequence  — ordered sequence of event-type steps within a time window,
//               correlated per entity (user, host, pid, …).
//   Threshold — N matching events for the same entity within a time window.
//
// State is maintained in-memory and keyed by (rule_id, entity_value).
// Stale entries are pruned every 500 events to bound memory usage.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::core::event_bus::TelemetryEvent;
use crate::detection::rule_loader::{Condition, CompiledRule, MatchType, SequenceStep};

// ─── Internal state types ─────────────────────────────────────────────────────

/// Unique state key: (rule_id, correlated entity value).
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
struct CorrelationKey {
    rule_id: String,
    entity: String,
}

/// Per-entity progress state for a sequence rule.
struct SequenceState {
    /// How many times each step has been satisfied (indexed by step position).
    step_counts: Vec<usize>,
    /// Timestamp of the first event that advanced any step — used for window expiry.
    first_seen: Instant,
}

impl SequenceState {
    fn new(step_count: usize) -> Self {
        Self {
            step_counts: vec![0; step_count],
            first_seen: Instant::now(),
        }
    }

    fn is_expired(&self, window: Duration) -> bool {
        self.first_seen.elapsed() > window
    }

    fn is_complete(&self, steps: &[SequenceStep]) -> bool {
        steps.iter().enumerate().all(|(i, step)| {
            self.step_counts.get(i).copied().unwrap_or(0)
                >= step.count_threshold.unwrap_or(1)
        })
    }
}

/// Per-entity sliding count state for a threshold rule.
struct ThresholdState {
    timestamps: Vec<Instant>,
}

impl ThresholdState {
    fn new() -> Self {
        Self { timestamps: Vec::new() }
    }

    /// Record a new matching event; prune timestamps outside `window`.
    fn record(&mut self, window: Duration) {
        let now = Instant::now();
        self.timestamps.retain(|t| now.duration_since(*t) <= window);
        self.timestamps.push(now);
    }

    fn count(&self) -> usize {
        self.timestamps.len()
    }
}

// ─── CorrelationTracker ───────────────────────────────────────────────────────

/// Maintains stateful multi-event correlation for sequence and threshold rules.
/// Called once per incoming event from the detection engine.
pub struct CorrelationTracker {
    sequence_states: HashMap<CorrelationKey, SequenceState>,
    threshold_states: HashMap<CorrelationKey, ThresholdState>,
    event_count: u64,
}

impl CorrelationTracker {
    pub fn new() -> Self {
        Self {
            sequence_states: HashMap::new(),
            threshold_states: HashMap::new(),
            event_count: 0,
        }
    }

    /// Feed one event through all sequence/threshold rules.
    /// Returns the rule IDs that fired on this event.
    pub fn process_event(
        &mut self,
        event: &TelemetryEvent,
        rules: &HashMap<String, CompiledRule>,
    ) -> Vec<String> {
        self.event_count += 1;
        let mut fired = Vec::new();

        for (rule_id, compiled) in rules {
            match compiled.rule.match_block.match_type {
                MatchType::Sequence => {
                    if self.check_sequence(rule_id, compiled, event) {
                        fired.push(rule_id.clone());
                    }
                }
                MatchType::Threshold => {
                    if self.check_threshold(rule_id, compiled, event) {
                        fired.push(rule_id.clone());
                    }
                }
                _ => {}
            }
        }

        // Prune stale state every 500 events to bound memory usage
        if self.event_count % 500 == 0 {
            self.prune(rules);
        }

        fired
    }

    // ─── Sequence ────────────────────────────────────────────────────────────

    fn check_sequence(
        &mut self,
        rule_id: &str,
        compiled: &CompiledRule,
        event: &TelemetryEvent,
    ) -> bool {
        let rule = &compiled.rule;
        let steps = match rule.match_block.sequence.as_deref() {
            Some(s) if !s.is_empty() => s,
            _ => return false,
        };
        let window = Duration::from_secs(rule.match_block.window_seconds as u64);
        let entity = extract_entity(event, rule.match_block.correlation_key.as_deref());
        let key = CorrelationKey { rule_id: rule_id.to_owned(), entity };

        // Ensure state exists; reset it if the window has expired.
        // We do this before computing current_idx so the idx always reflects
        // the post-reset state (avoids stale idx after expiry).
        if !self.sequence_states.contains_key(&key) {
            self.sequence_states.insert(key.clone(), SequenceState::new(steps.len()));
        }
        {
            let state = self.sequence_states.get_mut(&key).unwrap();
            if state.is_expired(window) {
                *state = SequenceState::new(steps.len());
            }
        }

        // Find the index of the first step not yet fully satisfied.
        let current_idx = {
            let state = self.sequence_states.get(&key).unwrap();
            steps.iter().enumerate().find_map(|(i, step)| {
                if state.step_counts.get(i).copied().unwrap_or(0)
                    < step.count_threshold.unwrap_or(1)
                {
                    Some(i)
                } else {
                    None
                }
            })
        };

        let Some(idx) = current_idx else {
            // All steps already satisfied — state cleanup anomaly; remove and skip.
            self.sequence_states.remove(&key);
            return false;
        };

        // Does this event advance the current step?
        if !step_matches(event, &steps[idx]) {
            return false;
        }

        // Advance the step counter.
        let state = self.sequence_states.get_mut(&key).unwrap();
        state.step_counts[idx] += 1;
        let complete = state.is_complete(steps);
        // `state` (mutable borrow) last used above — NLL ends the borrow here.

        if complete {
            self.sequence_states.remove(&key);
            true
        } else {
            false
        }
    }

    // ─── Threshold ───────────────────────────────────────────────────────────

    fn check_threshold(
        &mut self,
        rule_id: &str,
        compiled: &CompiledRule,
        event: &TelemetryEvent,
    ) -> bool {
        let rule = &compiled.rule;
        let threshold = match rule.match_block.threshold {
            Some(t) if t > 0 => t,
            _ => return false,
        };
        let window = Duration::from_secs(rule.match_block.window_seconds as u64);

        // Event type filter
        if !rule.match_block.event_types.is_empty() {
            let et = event.event_type.to_string();
            if !rule.match_block.event_types.iter().any(|t| {
                t == &et || t.replace('.', "_") == et
            }) {
                return false;
            }
        }

        // Additional field conditions
        if !rule.match_block.conditions.iter().all(|c| condition_matches(c, event)) {
            return false;
        }

        let entity = extract_entity(event, rule.match_block.correlation_key.as_deref());
        let key = CorrelationKey { rule_id: rule_id.to_owned(), entity };

        let state = self.threshold_states
            .entry(key.clone())
            .or_insert_with(ThresholdState::new);

        state.record(window);

        if state.count() >= threshold {
            // Reset so the rule can fire again after another full threshold accumulation
            self.threshold_states.remove(&key);
            true
        } else {
            false
        }
    }

    // ─── Maintenance ─────────────────────────────────────────────────────────

    fn prune(&mut self, rules: &HashMap<String, CompiledRule>) {
        self.sequence_states.retain(|key, state| {
            rules.get(&key.rule_id)
                .map(|c| {
                    let window = Duration::from_secs(c.rule.match_block.window_seconds as u64);
                    !state.is_expired(window)
                })
                .unwrap_or(false)
        });
        // Threshold state self-prunes on record(); just drop empty entries
        self.threshold_states.retain(|_, state| !state.timestamps.is_empty());
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Extract the correlated entity value from an event using a dot-notation path.
/// Falls back to "global" if no key is configured or the field is absent.
fn extract_entity(event: &TelemetryEvent, key: Option<&str>) -> String {
    match key {
        None => "global".to_owned(),
        Some("hostname") => event.hostname.clone(),
        Some("principal.user") => event.principal.as_ref()
            .map(|p| p.user.clone())
            .unwrap_or_else(|| "unknown".to_owned()),
        Some(field) if field.starts_with("payload.") => {
            let k = &field["payload.".len()..];
            event.payload.get(k)
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_owned()
        }
        Some(other) => other.to_owned(),
    }
}

/// Check whether an event satisfies a sequence step's event_type and conditions.
fn step_matches(event: &TelemetryEvent, step: &SequenceStep) -> bool {
    let et = event.event_type.to_string();
    if step.event_type != et && step.event_type.replace('.', "_") != et {
        return false;
    }
    step.conditions.iter().all(|c| condition_matches(c, event))
}

/// Evaluate a single field condition against an event (shared with engine.rs).
pub fn condition_matches(condition: &Condition, event: &TelemetryEvent) -> bool {
    let value = match get_field_value(event, &condition.field) {
        Some(v) => v,
        None => return false,
    };
    match condition.operator.as_str() {
        "in" => condition.values.iter().any(|v| v.eq_ignore_ascii_case(&value)),
        "eq" => condition.values.first()
            .map(|v| v.eq_ignore_ascii_case(&value))
            .unwrap_or(false),
        "contains" => condition.values.iter().any(|v| {
            value.to_lowercase().contains(&v.to_lowercase())
        }),
        "starts_with" => condition.values.iter().any(|v| {
            value.to_lowercase().starts_with(&v.to_lowercase())
        }),
        "ends_with" => condition.values.iter().any(|v| {
            value.to_lowercase().ends_with(&v.to_lowercase())
        }),
        "gt" => condition.values.first()
            .and_then(|v| v.parse::<f64>().ok())
            .zip(value.parse::<f64>().ok())
            .map(|(threshold, val)| val > threshold)
            .unwrap_or(false),
        _ => false,
    }
}

fn get_field_value(event: &TelemetryEvent, field: &str) -> Option<String> {
    let parts: Vec<&str> = field.splitn(2, '.').collect();
    match parts.as_slice() {
        ["payload", key] => event.payload.get(*key)?.as_str().map(str::to_owned),
        ["principal", "user"] => event.principal.as_ref().map(|p| p.user.clone()),
        ["event_type"] => Some(event.event_type.to_string()),
        ["hostname"] => Some(event.hostname.clone()),
        _ => None,
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::event_bus::{EventType, OsInfo, TelemetryEvent};
    use crate::detection::rule_loader::{
        CompiledRule, DetectionRule, MatchBlock, MatchType, ResponseBlock, SequenceStep,
    };

    fn base_event(event_type: EventType) -> TelemetryEvent {
        TelemetryEvent::new(
            "agent1", "tenant1", "test",
            event_type, "host-01",
            OsInfo { platform: "linux".into(), version: "22.04".into(), arch: "x86_64".into() },
        )
    }

    fn seq_rule(id: &str, steps: Vec<SequenceStep>, window_secs: u32) -> (String, CompiledRule) {
        let compiled = CompiledRule {
            rule: DetectionRule {
                id: id.to_owned(),
                name: id.to_owned(),
                enabled: true,
                mitre: None,
                match_block: MatchBlock {
                    match_type: MatchType::Sequence,
                    event_types: vec![],
                    conditions: vec![],
                    window_seconds: window_secs,
                    lua_script: String::new(),
                    correlation_key: Some("hostname".to_owned()),
                    threshold: None,
                    sequence: Some(steps),
                },
                response: ResponseBlock {
                    severity: "HIGH".to_owned(),
                    auto_contain: vec![],
                    notify: true,
                },
            },
            lua_fn: None,
        };
        (id.to_owned(), compiled)
    }

    fn thr_rule(id: &str, event_type: &str, threshold: usize, window_secs: u32) -> (String, CompiledRule) {
        let compiled = CompiledRule {
            rule: DetectionRule {
                id: id.to_owned(),
                name: id.to_owned(),
                enabled: true,
                mitre: None,
                match_block: MatchBlock {
                    match_type: MatchType::Threshold,
                    event_types: vec![event_type.to_owned()],
                    conditions: vec![],
                    window_seconds: window_secs,
                    lua_script: String::new(),
                    correlation_key: Some("hostname".to_owned()),
                    threshold: Some(threshold),
                    sequence: None,
                },
                response: ResponseBlock {
                    severity: "HIGH".to_owned(),
                    auto_contain: vec![],
                    notify: true,
                },
            },
            lua_fn: None,
        };
        (id.to_owned(), compiled)
    }

    #[test]
    fn threshold_fires_at_count() {
        let mut tracker = CorrelationTracker::new();
        let mut rules = HashMap::new();
        let (id, rule) = thr_rule("THR-001", "auth_logon_failure", 3, 60);
        rules.insert(id, rule);

        let ev = base_event(EventType::AuthLogonFailure);
        assert!(tracker.process_event(&ev, &rules).is_empty());
        assert!(tracker.process_event(&ev, &rules).is_empty());
        assert_eq!(tracker.process_event(&ev, &rules), vec!["THR-001"]);
    }

    #[test]
    fn threshold_resets_after_fire() {
        let mut tracker = CorrelationTracker::new();
        let mut rules = HashMap::new();
        let (id, rule) = thr_rule("THR-002", "auth_logon_failure", 2, 60);
        rules.insert(id, rule);

        let ev = base_event(EventType::AuthLogonFailure);
        tracker.process_event(&ev, &rules);
        assert!(tracker.process_event(&ev, &rules).contains(&"THR-002".to_owned()));
        // Resets; needs 2 more to fire again
        assert!(tracker.process_event(&ev, &rules).is_empty());
        assert!(tracker.process_event(&ev, &rules).contains(&"THR-002".to_owned()));
    }

    #[test]
    fn sequence_fires_in_order() {
        let mut tracker = CorrelationTracker::new();
        let steps = vec![
            SequenceStep { event_type: "process_create".into(), conditions: vec![], count_threshold: None },
            SequenceStep { event_type: "network_connect".into(), conditions: vec![], count_threshold: None },
        ];
        let mut rules = HashMap::new();
        let (id, rule) = seq_rule("SEQ-001", steps, 60);
        rules.insert(id, rule);

        let proc_ev = base_event(EventType::ProcessCreate);
        let net_ev = base_event(EventType::NetworkConnect);

        assert!(tracker.process_event(&proc_ev, &rules).is_empty(), "step 1 alone should not fire");
        assert_eq!(tracker.process_event(&net_ev, &rules), vec!["SEQ-001"]);
    }

    #[test]
    fn sequence_requires_step_order() {
        let mut tracker = CorrelationTracker::new();
        let steps = vec![
            SequenceStep { event_type: "process_create".into(), conditions: vec![], count_threshold: None },
            SequenceStep { event_type: "network_connect".into(), conditions: vec![], count_threshold: None },
        ];
        let mut rules = HashMap::new();
        let (id, rule) = seq_rule("SEQ-002", steps, 60);
        rules.insert(id, rule);

        let net_ev = base_event(EventType::NetworkConnect);
        let proc_ev = base_event(EventType::ProcessCreate);

        // Network first — doesn't advance step 0 (expects ProcessCreate)
        assert!(tracker.process_event(&net_ev, &rules).is_empty());
        // Process — advances step 0
        assert!(tracker.process_event(&proc_ev, &rules).is_empty());
        // Network — advances step 1 and fires
        assert_eq!(tracker.process_event(&net_ev, &rules), vec!["SEQ-002"]);
    }

    #[test]
    fn sequence_resets_after_fire() {
        let mut tracker = CorrelationTracker::new();
        let steps = vec![
            SequenceStep { event_type: "process_create".into(), conditions: vec![], count_threshold: None },
            SequenceStep { event_type: "file_modify".into(), conditions: vec![], count_threshold: None },
        ];
        let mut rules = HashMap::new();
        let (id, rule) = seq_rule("SEQ-003", steps, 60);
        rules.insert(id, rule);

        let proc_ev = base_event(EventType::ProcessCreate);
        let file_ev = base_event(EventType::FileModify);

        tracker.process_event(&proc_ev, &rules);
        assert!(tracker.process_event(&file_ev, &rules).contains(&"SEQ-003".to_owned()));

        // After reset, step 1 alone should not re-fire the rule
        assert!(tracker.process_event(&file_ev, &rules).is_empty());
    }
}
