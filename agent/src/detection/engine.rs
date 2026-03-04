// Detection Engine — main detection loop
//
// Subscribes to the event bus and evaluates each event against:
//   Phase 1 (single-event):
//     1. IOC match rules  (LMDB lookup, O(1))
//     2. Behavioral rules (field condition matching, AND logic)
//     3. Lua heuristics   (sliding window correlation, Phase 2)
//   Phase 2 (multi-event correlation):
//     4. Sequence rules   (ordered steps per entity within a time window)
//     5. Threshold rules  (N matching events per entity within a time window)
//
// Detected events are augmented with DetectionHit records and dispatched
// to the containment module and alert uploader.

use anyhow::Result;
use std::collections::VecDeque;
use std::sync::Arc;
use tokio::sync::{broadcast, mpsc, RwLock};
use tracing::{debug, info, warn};

use crate::config::AgentConfig;
use crate::containment::actions::ContainmentDispatcher;
use crate::core::event_bus::{DetectionHit, Severity, TelemetryEvent};
use crate::detection::correlation::CorrelationTracker;
use crate::detection::ioc_store::IocStore;
use crate::detection::rule_loader::{CompiledRule, DetectionRule, MatchType, RuleLoader};
use crate::platform_connector::policy_sync::PolicyHandle;

/// A recent-event window kept for heuristic rules (Lua evaluation in Phase 2).
type EventWindow = VecDeque<TelemetryEvent>;

pub struct DetectionEngine {
    receiver: broadcast::Receiver<TelemetryEvent>,
    ioc_store: Arc<IocStore>,
    rule_loader: Arc<RwLock<RuleLoader>>,
    containment: ContainmentDispatcher,
    event_window: EventWindow,
    window_size: usize,
    /// Multi-event correlation tracker (sequence + threshold rules).
    tracker: CorrelationTracker,
    /// Sends annotated events (with detections populated) to AlertUploader fast-path.
    alert_sender: mpsc::Sender<TelemetryEvent>,
}

impl DetectionEngine {
    pub fn new(
        cfg: &AgentConfig,
        receiver: broadcast::Receiver<TelemetryEvent>,
        _policy: PolicyHandle,
        ioc_store: Arc<IocStore>,
        alert_sender: mpsc::Sender<TelemetryEvent>,
    ) -> Result<Self> {
        let mut rule_loader = RuleLoader::new()?;
        let rules_dir = cfg
            .detection
            .rules_dir
            .clone()
            .unwrap_or_else(|| cfg.storage.data_dir.join("rules"));
        if rules_dir.exists() {
            rule_loader.load_packs(&rules_dir, &cfg.detection.rule_packs)?;
        }
        info!(
            rules = rule_loader.rule_count(),
            "Detection engine initialized"
        );

        Ok(Self {
            receiver,
            ioc_store,
            rule_loader: Arc::new(RwLock::new(rule_loader)),
            containment: ContainmentDispatcher::new(cfg)?,
            event_window: VecDeque::with_capacity(1000),
            window_size: 1000,
            tracker: CorrelationTracker::new(),
            alert_sender,
        })
    }

    /// Main detection loop — runs until the broadcast channel is closed.
    pub async fn run(mut self) -> Result<()> {
        info!("Detection engine running");
        loop {
            match self.receiver.recv().await {
                Ok(event) => {
                    self.process_event(event).await;
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    warn!(lagged = n, "Detection engine lagged — {} events dropped", n);
                }
                Err(broadcast::error::RecvError::Closed) => {
                    info!("Event bus closed — detection engine shutting down");
                    return Ok(());
                }
            }
        }
    }

    async fn process_event(&mut self, mut event: TelemetryEvent) {
        let mut hits: Vec<DetectionHit> = Vec::new();

        // Clone the Arc so the read-lock guard doesn't borrow `self`, allowing
        // self.tracker to be mutably borrowed in the same scope.
        let rule_loader = Arc::clone(&self.rule_loader);
        let rules = rule_loader.read().await;

        // ── Phase 1: single-event rules (IOC / behavioral / heuristic) ──────
        for (rule_id, compiled) in &rules.rules {
            if let Some(hit) = self.evaluate_rule(compiled, &event) {
                debug!(
                    rule = %rule_id,
                    event_id = %event.event_id,
                    severity = ?hit.severity,
                    "Detection hit (single-event)"
                );
                hits.push(hit);
            }
        }

        // ── Phase 2: multi-event correlation (sequence / threshold) ──────────
        // rules borrows rule_loader (the local Arc clone), not self.rule_loader,
        // so self.tracker can be mutably borrowed without conflict.
        let fired = self.tracker.process_event(&event, &rules.rules);
        for rule_id in fired {
            if let Some(compiled) = rules.rules.get(&rule_id) {
                debug!(
                    rule = %rule_id,
                    event_id = %event.event_id,
                    "Detection hit (correlation)"
                );
                hits.push(make_detection_hit(&compiled.rule));
            }
        }

        drop(rules);

        if !hits.is_empty() {
            // Attach MITRE tags to the event
            for hit in &hits {
                for technique in &hit.mitre_techniques {
                    event.tags.push(format!("mitre:{}", technique));
                }
            }
            event.detections = hits.clone();

            // Fast-path: send annotated event to AlertUploader
            if let Err(e) = self.alert_sender.try_send(event.clone()) {
                warn!(error = %e, "Alert channel full — detection event dropped from alert path");
            }

            // Dispatch containment for the highest-severity hit
            let max_hit = hits.iter().max_by_key(|h| &h.severity);
            if let Some(hit) = max_hit {
                self.dispatch_containment(&event, hit).await;
            }
        }

        // Maintain sliding window for heuristic rules
        self.event_window.push_back(event);
        if self.event_window.len() > self.window_size {
            self.event_window.pop_front();
        }
    }

    /// Evaluate a single-event rule (IOC / behavioral / heuristic).
    /// Synchronous — none of the evaluators block or need async I/O.
    fn evaluate_rule(
        &self,
        compiled: &CompiledRule,
        event: &TelemetryEvent,
    ) -> Option<DetectionHit> {
        let rule = &compiled.rule;

        // Check event type filter
        if !rule.match_block.event_types.is_empty() {
            let event_type_str = event.event_type.to_string();
            if !rule
                .match_block
                .event_types
                .iter()
                .any(|t| t == &event_type_str || t.replace('.', "_") == event_type_str)
            {
                return None;
            }
        }

        let matched = match rule.match_block.match_type {
            MatchType::Ioc => self.evaluate_ioc_rule(rule, event),
            MatchType::Behavioral => evaluate_behavioral_rule(rule, event),
            MatchType::Heuristic => self
                .evaluate_heuristic_rule(compiled, event)
                .unwrap_or(false),
            // Sequence and Threshold are handled by the CorrelationTracker; skip here.
            MatchType::Sequence | MatchType::Threshold => return None,
        };

        if matched {
            Some(make_detection_hit(rule))
        } else {
            None
        }
    }

    fn evaluate_ioc_rule(&self, rule: &DetectionRule, event: &TelemetryEvent) -> bool {
        for condition in &rule.match_block.conditions {
            if condition.operator == "in_ioc_set" {
                let ioc_type = condition.ioc_type.as_deref().unwrap_or("file_hash");
                if let Some(v) = get_field_value(event, &condition.field) {
                    if self.ioc_store.contains(ioc_type, &v) {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn evaluate_heuristic_rule(
        &self,
        _compiled: &CompiledRule,
        _event: &TelemetryEvent,
    ) -> Result<bool> {
        // Full Lua heuristic evaluation planned for Phase 2 milestone 2.
        // Will call compiled.lua_fn with (event, context{recent_events}).
        Ok(false)
    }

    async fn dispatch_containment(&self, event: &TelemetryEvent, hit: &DetectionHit) {
        // Look up the containment actions from the rule definition
        let rules = self.rule_loader.read().await;
        let auto_contain = rules
            .rules
            .get(&hit.rule_id)
            .map(|c| c.rule.response.auto_contain.as_slice())
            .unwrap_or(&[]);

        for action_name in auto_contain {
            if let Err(e) = self.containment.dispatch(action_name, event).await {
                warn!(action = %action_name, error = %e, "Containment dispatch failed");
            }
        }
    }
}

// ─── Free functions ───────────────────────────────────────────────────────────

/// Build a DetectionHit from a rule's metadata.
fn make_detection_hit(rule: &DetectionRule) -> DetectionHit {
    DetectionHit {
        rule_id: rule.id.clone(),
        rule_name: rule.name.clone(),
        severity: parse_severity(&rule.response.severity),
        mitre_techniques: rule
            .mitre
            .as_ref()
            .map(|m| m.techniques.clone())
            .unwrap_or_default(),
        details: std::collections::HashMap::new(),
    }
}

/// Evaluate behavioral rule conditions against a single event (AND logic).
fn evaluate_behavioral_rule(rule: &DetectionRule, event: &TelemetryEvent) -> bool {
    rule.match_block.conditions.iter().all(|condition| {
        let value = match get_field_value(event, &condition.field) {
            Some(v) => v,
            None => return false,
        };
        match condition.operator.as_str() {
            "in" => condition
                .values
                .iter()
                .any(|v| v.eq_ignore_ascii_case(&value)),
            "eq" => condition
                .values
                .first()
                .map(|v| v.eq_ignore_ascii_case(&value))
                .unwrap_or(false),
            "contains" => condition
                .values
                .iter()
                .any(|v| value.to_lowercase().contains(&v.to_lowercase())),
            "starts_with" => condition
                .values
                .iter()
                .any(|v| value.to_lowercase().starts_with(&v.to_lowercase())),
            "ends_with" => condition
                .values
                .iter()
                .any(|v| value.to_lowercase().ends_with(&v.to_lowercase())),
            _ => false,
        }
    })
}

/// Extract a field value from a TelemetryEvent using dot notation.
/// e.g. "payload.process_name" → event.payload["process_name"]
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

fn parse_severity(s: &str) -> Severity {
    match s.to_uppercase().as_str() {
        "CRITICAL" => Severity::Critical,
        "HIGH" => Severity::High,
        "MEDIUM" => Severity::Medium,
        "LOW" => Severity::Low,
        _ => Severity::Info,
    }
}
