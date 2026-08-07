// Claude authentication helpers.
//
// Replaces the old `llm.rs` after we removed local-LLM (Ollama) support.
// The desktop no longer drives an LLM loop directly — that responsibility
// belongs to the `claude` CLI running inside the Kali container. This
// module exists to support the Settings page when a user pastes their
// Anthropic API key (BYO Key mode) and we want to validate it before
// persisting to the macOS Keychain.

use std::time::Duration;

use reqwest::Client;
use tracing::info;

use crate::error::{AppError, Result};

const ANTHROPIC_API_URL: &str = "https://api.anthropic.com/v1/messages";
// Cheapest call we can make to validate a key — Haiku, 1 token of output.
const VALIDATION_MODEL: &str = "claude-haiku-4-5-20251001";

/// Send a single 1-token request to verify an Anthropic API key works.
/// Returns `Ok(true)` on 2xx, `Err` with the API's error body otherwise.
pub async fn test_anthropic_api_key(api_key: &str) -> Result<bool> {
    if !api_key.starts_with("sk-ant-") {
        return Err(AppError::Validation(
            "Invalid Anthropic API key format (expected sk-ant-…)".into(),
        ));
    }

    let client = Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(AppError::Http)?;

    let body = serde_json::json!({
        "model": VALIDATION_MODEL,
        "max_tokens": 1,
        "messages": [{"role": "user", "content": "hi"}]
    });

    let resp = client
        .post(ANTHROPIC_API_URL)
        .header("x-api-key", api_key)
        .header("anthropic-version", "2023-06-01")
        .header("content-type", "application/json")
        .json(&body)
        .send()
        .await
        .map_err(AppError::Http)?;

    if resp.status().is_success() {
        info!("Anthropic API key validated successfully");
        Ok(true)
    } else {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        Err(AppError::Other(format!(
            "Anthropic API rejected key ({}): {}",
            status, text
        )))
    }
}
