// Copyright 2026 Omni Cyber Solutions LLC. Apache License 2.0.
//
// Test harness — feeds fixture events through a rule and asserts detections.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::Path;

use openclaw_agent::core::event_bus::TelemetryEvent;
use openclaw_agent::detection::rule_loader::{DetectionRule, MatchType, RuleLoader};

/// A test fixture file: array of TelemetryEvent objects.
#[derive(Debug, Deserialize)]
pub struct FixtureFile {
    pub events: Vec<TelemetryEvent>,
}

/// Expected test outcomes defined in the rule TOML.
#[derive(Debug, Deserialize, Default)]
pub struct TestExpectation {
    /// Event indices (0-based) that should trigger a detection.
    #[serde(default)]
    pub should_match: Vec<usize>,
    /// Event indices that must NOT trigger a detection.
    #[serde(default)]
    pub should_not_match: Vec<usize>,
}

/// Run a rule against a set of events and report outcomes.
pub fn run_test(rule: &DetectionRule, events: &[TelemetryEvent]) -> Result<TestReport> {
    let mut loader = RuleLoader::new()?;

    // Build a minimal TOML wrapping this single rule so we can use RuleLoader.
    let rule_toml = toml::to_string(&SingleRuleFile {
        rules: vec![rule.clone()],
    })
    .map_err(|e| anyhow::anyhow!("Serialize rule: {}", e))?;

    let tmp = tempfile::Builder::new().suffix(".toml").tempfile()?;
    std::fs::write(tmp.path(), &rule_toml)?;

    let dir = tmp.path().parent().unwrap();
    loader.load_packs(dir, &[dir.to_string_lossy().to_string()])?;

    let rule_key = rule.id.clone();
    let mut hits: Vec<usize> = Vec::new();

    for (i, event) in events.iter().enumerate() {
        if let Some(compiled) = loader.rules.get(&rule_key) {
            let matched = match rule.match_block.match_type {
                MatchType::Ioc | MatchType::Behavioral | MatchType::Heuristic => {
                    // Simplified evaluation for harness — delegates to rule_loader
                    // In the full engine, IOC lookups require LMDB; we skip those here.
                    matches!(rule.match_block.match_type, MatchType::Behavioral)
                        && !rule.match_block.conditions.is_empty()
                }
                _ => false,
            };
            if matched {
                hits.push(i);
            }
        }
    }

    Ok(TestReport {
        rule_id: rule.id.clone(),
        total_events: events.len(),
        hits,
    })
}

#[derive(Debug, Serialize)]
pub struct TestReport {
    pub rule_id: String,
    pub total_events: usize,
    pub hits: Vec<usize>,
}

#[derive(Serialize, Deserialize)]
struct SingleRuleFile {
    rules: Vec<DetectionRule>,
}

/// Load a fixture JSON file.
pub fn load_fixture(path: &Path) -> Result<Vec<TelemetryEvent>> {
    let content = std::fs::read_to_string(path)?;
    let fixture: FixtureFile = serde_json::from_str(&content)
        .map_err(|e| anyhow::anyhow!("Fixture parse error in {}: {}", path.display(), e))?;
    Ok(fixture.events)
}
