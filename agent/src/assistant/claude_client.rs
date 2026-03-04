// Async Claude API client for agent-side assistant features.
// Used for: alert explanations, risk behavior coaching, local Q&A.
// Falls back to static templates if API is unreachable or key not configured.

use anyhow::Result;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

const CLAUDE_API_URL: &str = "https://api.anthropic.com/v1/messages";
const DEFAULT_MODEL: &str = "claude-haiku-4-5-20251001"; // fast, low-cost for agent use
const MAX_TOKENS: u32 = 512;

#[derive(Serialize)]
struct ClaudeRequest<'a> {
    model: &'a str,
    max_tokens: u32,
    system: &'a str,
    messages: Vec<ClaudeMessage<'a>>,
}

#[derive(Serialize)]
struct ClaudeMessage<'a> {
    role: &'a str,
    content: &'a str,
}

#[derive(Deserialize)]
struct ClaudeResponse {
    content: Vec<ClaudeContent>,
}

#[derive(Deserialize)]
struct ClaudeContent {
    text: String,
}

pub struct ClaudeClient {
    client: Client,
    api_key: String,
    model: String,
}

impl ClaudeClient {
    pub fn new(api_key: impl Into<String>) -> Result<Self> {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()?;
        Ok(Self {
            client,
            api_key: api_key.into(),
            model: DEFAULT_MODEL.to_string(),
        })
    }

    /// Ask Claude to explain a security detection in plain English.
    pub async fn explain_detection(
        &self,
        rule_name: &str,
        event_summary: &str,
        severity: &str,
    ) -> Result<String> {
        let prompt = format!(
            "A security detection fired on this endpoint.\n\
             Rule: {}\nSeverity: {}\nEvent: {}\n\n\
             Explain in 2-3 plain English sentences what happened and \
             why it may be concerning. Do not include technical jargon.",
            rule_name, severity, event_summary
        );
        self.complete(&prompt).await
    }

    /// Ask Claude to provide risk coaching for a user behavior.
    pub async fn coach_behavior(
        &self,
        behavior: &str,
    ) -> Result<String> {
        let prompt = format!(
            "An endpoint user performed the following action: {}\n\
             Explain in 1-2 friendly sentences why this could be risky \
             and what safer alternatives exist.",
            behavior
        );
        self.complete(&prompt).await
    }

    async fn complete(&self, user_prompt: &str) -> Result<String> {
        let request = ClaudeRequest {
            model: &self.model,
            max_tokens: MAX_TOKENS,
            system: "You are a concise endpoint security assistant. \
                     Explain security events in plain language suitable for \
                     non-technical users. Be brief, clear, and non-alarmist.",
            messages: vec![ClaudeMessage {
                role: "user",
                content: user_prompt,
            }],
        };

        let response = self.client
            .post(CLAUDE_API_URL)
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", "2023-06-01")
            .header("content-type", "application/json")
            .json(&request)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!("Claude API error {}: {}", status, body);
        }

        let claude_response: ClaudeResponse = response.json().await?;
        let text = claude_response.content
            .into_iter()
            .next()
            .map(|c| c.text)
            .unwrap_or_else(|| "No explanation available.".to_string());

        debug!("Claude response length: {} chars", text.len());
        Ok(text)
    }
}
