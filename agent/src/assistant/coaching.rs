// Risk behavior explanation and coaching for end users.
// Uses Claude API with fallback to static templates.

use anyhow::Result;
use tracing::warn;

use crate::assistant::claude_client::ClaudeClient;
use crate::core::event_bus::{Severity, TelemetryEvent};

pub struct CoachingEngine {
    claude: Option<ClaudeClient>,
}

impl CoachingEngine {
    pub fn new(api_key: Option<String>) -> Self {
        let claude = api_key
            .filter(|k| !k.is_empty())
            .and_then(|key| ClaudeClient::new(key).ok());
        if claude.is_none() {
            warn!("Claude API key not configured — using fallback templates for coaching");
        }
        Self { claude }
    }

    pub async fn explain(
        &self,
        event: &TelemetryEvent,
        rule_name: &str,
        severity: &Severity,
    ) -> String {
        if let Some(client) = &self.claude {
            let summary = format!(
                "Process: {:?}, Type: {}, Host: {}",
                event.payload.get("process_name"),
                event.event_type,
                event.hostname
            );
            match client
                .explain_detection(rule_name, &summary, &format!("{:?}", severity))
                .await
            {
                Ok(text) => return text,
                Err(e) => warn!(error = %e, "Claude API call failed — using fallback"),
            }
        }
        crate::assistant::fallback_templates::explain_detection(rule_name, severity)
    }
}
