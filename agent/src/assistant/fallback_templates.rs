// Static fallback templates for when the Claude API is unavailable.

use crate::core::event_bus::Severity;

pub fn explain_detection(rule_name: &str, severity: &Severity) -> String {
    let severity_str = match severity {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
        Severity::Info => "informational",
    };
    format!(
        "A {} severity security detection '{}' has fired on this endpoint. \
         Please contact your IT security team for assistance.",
        severity_str, rule_name
    )
}

pub fn tts_alert(rule_name: &str, severity: &Severity) -> String {
    match severity {
        Severity::Critical => format!(
            "Critical security alert. {}. Immediate action required. \
             Contact your security team now.",
            rule_name
        ),
        Severity::High => format!(
            "High severity security alert. {}. \
             Please contact your IT security team.",
            rule_name
        ),
        _ => format!("Security alert: {}", rule_name),
    }
}
