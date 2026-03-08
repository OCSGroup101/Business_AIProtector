// Copyright 2026 Omni Cyber Solutions LLC. Apache License 2.0.
//
// Rule validator — checks syntax, required fields, and MITRE format.

use anyhow::{bail, Result};
use regex::Regex;

use openclaw_agent::detection::rule_loader::DetectionRule;

/// Severity values accepted by the detection engine.
const VALID_SEVERITIES: &[&str] = &["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

/// Regex for rule IDs: e.g. WIN-PRC-0001, MACOS-PER-T1547-001
static RULE_ID_RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();

fn rule_id_re() -> &'static Regex {
    RULE_ID_RE.get_or_init(|| {
        Regex::new(r"^[A-Z0-9]+-[A-Z0-9]+-[A-Z0-9]+-\d{4,}$").unwrap()
    })
}

/// Regex for MITRE technique IDs: T1234 or T1234.001
static TECHNIQUE_RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();

fn technique_re() -> &'static Regex {
    TECHNIQUE_RE.get_or_init(|| Regex::new(r"^T\d{4}(\.\d{3})?$").unwrap())
}

/// Validate a single detection rule.
pub fn validate_rule(rule: &DetectionRule) -> Result<()> {
    // ID format
    if rule.id.is_empty() {
        bail!("Rule missing 'id' field");
    }

    // Severity must be one of the accepted values
    let severity = rule.response.severity.to_uppercase();
    if !VALID_SEVERITIES.contains(&severity.as_str()) {
        bail!(
            "Rule '{}': invalid severity '{}' — must be one of {:?}",
            rule.id,
            rule.response.severity,
            VALID_SEVERITIES
        );
    }

    // MITRE technique format
    if let Some(mitre) = &rule.mitre {
        for technique in &mitre.techniques {
            if !technique_re().is_match(technique) {
                bail!(
                    "Rule '{}': invalid MITRE technique '{}' — must match T1234 or T1234.001",
                    rule.id,
                    technique
                );
            }
        }
    }

    // Match block must have at least event_types or conditions
    let has_types = !rule.match_block.event_types.is_empty();
    let has_conditions = !rule.match_block.conditions.is_empty();
    let has_lua = !rule.match_block.lua_script.is_empty();

    match rule.match_block.match_type {
        openclaw_agent::detection::rule_loader::MatchType::Ioc => {
            if !has_conditions {
                bail!(
                    "Rule '{}': IOC rule must have at least one condition",
                    rule.id
                );
            }
        }
        openclaw_agent::detection::rule_loader::MatchType::Behavioral => {
            if !has_conditions {
                bail!(
                    "Rule '{}': behavioral rule must have at least one condition",
                    rule.id
                );
            }
        }
        openclaw_agent::detection::rule_loader::MatchType::Heuristic => {
            if !has_lua {
                bail!(
                    "Rule '{}': heuristic rule must have a lua_script",
                    rule.id
                );
            }
        }
        openclaw_agent::detection::rule_loader::MatchType::Sequence => {
            let seq_len = rule
                .match_block
                .sequence
                .as_ref()
                .map(|s| s.len())
                .unwrap_or(0);
            if seq_len < 2 {
                bail!(
                    "Rule '{}': sequence rule must have at least 2 steps",
                    rule.id
                );
            }
        }
        openclaw_agent::detection::rule_loader::MatchType::Threshold => {
            if rule.match_block.threshold.is_none() {
                bail!(
                    "Rule '{}': threshold rule must specify 'threshold' count",
                    rule.id
                );
            }
        }
    }

    Ok(())
}

/// Validate a TOML string containing one or more rules.
/// Returns a list of (rule_id, error) for all validation failures.
pub fn validate_toml(content: &str, source: &str) -> Vec<(String, String)> {
    #[derive(serde::Deserialize)]
    struct RuleFile {
        #[serde(default)]
        rules: Vec<DetectionRule>,
    }

    let parsed: RuleFile = match toml::from_str(content) {
        Ok(p) => p,
        Err(e) => {
            return vec![(
                source.to_string(),
                format!("TOML parse error: {}", e),
            )];
        }
    };

    parsed
        .rules
        .iter()
        .filter_map(|rule| {
            validate_rule(rule)
                .err()
                .map(|e| (rule.id.clone(), e.to_string()))
        })
        .collect()
}
