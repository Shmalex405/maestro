// Codex (OpenAI) authentication helpers.
//
// Mirrors claude_auth.rs. Used by the Settings page when a user pastes their
// OpenAI API key (BYO Key mode) and we want to validate it before persisting
// to the macOS Keychain. The actual LLM loop is driven by the `codex` CLI
// running inside the Kali container; this module is only for preflight key
// validation.

use std::time::Duration;

use reqwest::Client;
use tracing::info;

use crate::error::{AppError, Result};

const OPENAI_API_URL: &str = "https://api.openai.com/v1/chat/completions";
// Cheapest call we can make to validate a key. `gpt-4o-mini` is a stable,
// universally-available cheap model — we use it here only to confirm the
// key is shaped correctly and accepted by OpenAI; it has nothing to do with
// the model Codex CLI actually uses for assessments.
const VALIDATION_MODEL: &str = "gpt-4o-mini";

/// Send a single 1-token request to verify an OpenAI API key works.
/// Returns `Ok(true)` on 2xx, `Err` with the API's error body otherwise.
pub async fn test_openai_api_key(api_key: &str) -> Result<bool> {
    // OpenAI keys come in several shapes: `sk-...` (legacy user keys),
    // `sk-proj-...` (project keys), `sk-svcacct-...` (service account).
    // All start with `sk-` so we keep the prefix check loose; the live
    // request below is the binding check.
    if !api_key.starts_with("sk-") {
        return Err(AppError::Validation(
            "Invalid OpenAI API key format (expected sk-…)".into(),
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
        .post(OPENAI_API_URL)
        .bearer_auth(api_key)
        .header("content-type", "application/json")
        .json(&body)
        .send()
        .await
        .map_err(AppError::Http)?;

    if resp.status().is_success() {
        info!("OpenAI API key validated successfully");
        Ok(true)
    } else {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        Err(AppError::Other(format!(
            "OpenAI API rejected key ({}): {}",
            status, text
        )))
    }
}
