//! JWKS cache shared between Cognito and OIDC JWT verification.
//!
//! Keys are fetched on demand and retained for 10 minutes. The Python
//! backend re-fetches JWKS on every request (see
//! `backend/app/core/security.py:verify_cognito_token`) — we're intentionally
//! faster here without changing observable behavior.

use std::time::Duration;

use moka::future::Cache;
use serde::Deserialize;

use crate::error::{AppError, AppResult};

#[derive(Debug, Clone, Deserialize)]
pub struct Jwks {
    pub keys: Vec<serde_json::Value>,
}

#[derive(Clone)]
pub struct JwksCache {
    cache: Cache<String, Jwks>,
    http: reqwest::Client,
}

impl JwksCache {
    pub fn new() -> Self {
        Self {
            cache: Cache::builder()
                .time_to_live(Duration::from_secs(600))
                .max_capacity(16)
                .build(),
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .expect("reqwest client"),
        }
    }

    pub async fn fetch(&self, url: &str) -> AppResult<Jwks> {
        if let Some(cached) = self.cache.get(url).await {
            return Ok(cached);
        }
        let resp = self
            .http
            .get(url)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("JWKS fetch failed: {e}")))?;
        if !resp.status().is_success() {
            return Err(AppError::Internal(format!(
                "JWKS fetch returned {}",
                resp.status()
            )));
        }
        let jwks: Jwks = resp
            .json()
            .await
            .map_err(|e| AppError::Internal(format!("JWKS parse failed: {e}")))?;
        self.cache.insert(url.to_string(), jwks.clone()).await;
        Ok(jwks)
    }

    pub async fn fetch_oidc_discovery(&self, issuer: &str) -> AppResult<String> {
        // OIDC discovery → returns the jwks_uri. Cached under a synthetic key.
        let discovery_url = format!("{}/.well-known/openid-configuration", issuer.trim_end_matches('/'));
        let cache_key = format!("@oidc-jwks-uri:{issuer}");
        if let Some(cached) = self.cache.get(&cache_key).await {
            // We stash the jwks_uri as a single-key Jwks for reuse.
            if let Some(first) = cached.keys.first().and_then(|v| v.as_str()) {
                return Ok(first.to_string());
            }
        }
        let resp = self
            .http
            .get(&discovery_url)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("OIDC discovery failed: {e}")))?;
        let doc: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| AppError::Internal(format!("OIDC discovery parse: {e}")))?;
        let jwks_uri = doc
            .get("jwks_uri")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AppError::Internal("OIDC discovery missing jwks_uri".into()))?
            .to_string();
        self.cache
            .insert(
                cache_key,
                Jwks {
                    keys: vec![serde_json::Value::String(jwks_uri.clone())],
                },
            )
            .await;
        Ok(jwks_uri)
    }
}

impl Default for JwksCache {
    fn default() -> Self {
        Self::new()
    }
}
