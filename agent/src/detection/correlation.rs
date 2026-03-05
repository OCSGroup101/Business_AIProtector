// Copyright 2026 Omni Cyber Solutions LLC. Apache License 2.0.
//
// Correlation Tracker — multi-event sequence and threshold rule evaluation.
//
// Phase 1: stub (returns no hits; single-event rules cover Phase 1 detection).
// Phase 2: implement sequence automata and per-entity sliding-window counters.

use std::collections::HashMap;

use crate::core::event_bus::TelemetryEvent;
use crate::detection::rule_loader::CompiledRule;

/// Tracks multi-event correlation state for sequence and threshold rules.
///
/// Phase 2 will maintain per-entity automaton state for sequence rules and
/// rolling event counts for threshold rules, keyed by entity (hostname/PID).
pub struct CorrelationTracker {
    // Phase 2: per-entity state maps go here.
    _placeholder: (),
}

impl CorrelationTracker {
    pub fn new() -> Self {
        Self {
            _placeholder: (),
        }
    }

    /// Evaluate multi-event rules against `event`.
    ///
    /// Returns the IDs of any correlation rules that fired.
    /// Phase 1: always returns empty — correlation rules fire in Phase 2.
    pub fn process_event(
        &mut self,
        _event: &TelemetryEvent,
        _rules: &HashMap<String, CompiledRule>,
    ) -> Vec<String> {
        Vec::new()
    }
}
