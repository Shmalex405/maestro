// Cloud sync module - handles communication with the self-hosted backend

use crate::error::AppError;
use chrono::{DateTime, Utc};
use reqwest::{Client, header};
use serde::{Deserialize, Serialize};
use std::time::Duration;

pub use maestro_types::{
    AssessmentSync, AuthProvidersResponse, FindingSync, ProviderInfo, ReportSync, SyncRequest,
    SyncResponse, TokenResponse,
};

/// Cloud configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CloudConfig {
    pub enabled: bool,
    pub api_url: String,
    pub auth_provider: AuthProvider,

    // Local auth
    pub email: Option<String>,
    #[serde(skip_serializing)]
    pub password: Option<String>,

    // Cognito
    pub cognito_region: Option<String>,
    pub cognito_user_pool_id: Option<String>,
    pub cognito_client_id: Option<String>,

    // OIDC
    pub oidc_issuer: Option<String>,
    pub oidc_client_id: Option<String>,

    // Sync settings
    pub auto_sync: bool,
    pub sync_interval_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum AuthProvider {
    #[default]
    Local,
    Cognito,
    Oidc,
}

/// Authentication tokens
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AuthTokens {
    pub access_token: String,
    pub token_type: String,
    pub expires_at: Option<DateTime<Utc>>,
    pub refresh_token: Option<String>,
}

/// Sync status
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SyncStatus {
    pub connected: bool,
    pub last_sync_at: Option<DateTime<Utc>>,
    pub pending_changes: u32,
    pub sync_in_progress: bool,
    pub last_error: Option<String>,
}

/// Cloud API client
pub struct CloudClient {
    client: Client,
    config: CloudConfig,
    tokens: Option<AuthTokens>,
}

// Wire types live in the shared `maestro-types` crate so both the Tauri
// desktop shell and the Rust backend stay in lockstep. Re-exported above.

impl CloudClient {
    pub fn new(config: CloudConfig) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("Failed to create HTTP client");

        Self {
            client,
            config,
            tokens: None,
        }
    }

    pub fn with_tokens(mut self, tokens: AuthTokens) -> Self {
        self.tokens = Some(tokens);
        self
    }

    pub fn is_authenticated(&self) -> bool {
        if let Some(tokens) = &self.tokens {
            if let Some(expires_at) = tokens.expires_at {
                return Utc::now() < expires_at;
            }
            return !tokens.access_token.is_empty();
        }
        false
    }

    fn api_url(&self, path: &str) -> String {
        format!("{}/api/v1{}", self.config.api_url.trim_end_matches('/'), path)
    }

    fn auth_headers(&self) -> Result<header::HeaderMap, AppError> {
        let mut headers = header::HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            header::HeaderValue::from_static("application/json"),
        );

        if let Some(tokens) = &self.tokens {
            let auth_value = format!("{} {}", tokens.token_type, tokens.access_token);
            headers.insert(
                header::AUTHORIZATION,
                header::HeaderValue::from_str(&auth_value)
                    .map_err(|e| AppError::Config(format!("Invalid auth header: {}", e)))?,
            );
        }

        Ok(headers)
    }

    /// Test connection to the cloud backend
    pub async fn test_connection(&self) -> Result<bool, AppError> {
        let url = format!("{}/health", self.config.api_url.trim_end_matches('/'));

        let response = self.client
            .get(&url)
            .timeout(Duration::from_secs(10))
            .send()
            .await
            .map_err(|e| AppError::Cloud(format!("Connection failed: {}", e)))?;

        Ok(response.status().is_success())
    }

    /// Get available auth providers from the backend
    pub async fn get_auth_providers(&self) -> Result<AuthProvidersResponse, AppError> {
        let url = self.api_url("/auth/providers");

        let response = self.client
            .get(&url)
            .send()
            .await
            .map_err(|e| AppError::Cloud(format!("Failed to get providers: {}", e)))?;

        if !response.status().is_success() {
            return Err(AppError::Cloud(format!(
                "Failed to get auth providers: {}",
                response.status()
            )));
        }

        response
            .json()
            .await
            .map_err(|e| AppError::Cloud(format!("Failed to parse providers: {}", e)))
    }

    /// Login with email and password (local auth)
    pub async fn login(&mut self, email: &str, password: &str) -> Result<AuthTokens, AppError> {
        let url = self.api_url("/auth/login");

        let body = serde_json::json!({
            "email": email,
            "password": password
        });

        let response = self.client
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(|e| AppError::Cloud(format!("Login failed: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            return Err(AppError::Auth(format!(
                "Login failed ({}): {}",
                status, error_text
            )));
        }

        let token_response: TokenResponse = response
            .json()
            .await
            .map_err(|e| AppError::Cloud(format!("Failed to parse login response: {}", e)))?;

        let tokens = AuthTokens {
            access_token: token_response.access_token,
            token_type: token_response.token_type,
            expires_at: Some(Utc::now() + chrono::Duration::seconds(token_response.expires_in)),
            refresh_token: None,
        };

        self.tokens = Some(tokens.clone());
        Ok(tokens)
    }

    /// Sync data with the cloud backend
    pub async fn sync(&self, request: SyncRequest) -> Result<SyncResponse, AppError> {
        if !self.is_authenticated() {
            return Err(AppError::Auth("Not authenticated".into()));
        }

        let url = self.api_url("/sync");
        let headers = self.auth_headers()?;

        let response = self.client
            .post(&url)
            .headers(headers)
            .json(&request)
            .send()
            .await
            .map_err(|e| AppError::Cloud(format!("Sync failed: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            return Err(AppError::Cloud(format!(
                "Sync failed ({}): {}",
                status, error_text
            )));
        }

        response
            .json()
            .await
            .map_err(|e| AppError::Cloud(format!("Failed to parse sync response: {}", e)))
    }

    /// Get sync status from the backend
    pub async fn get_sync_status(&self) -> Result<serde_json::Value, AppError> {
        if !self.is_authenticated() {
            return Err(AppError::Auth("Not authenticated".into()));
        }

        let url = self.api_url("/sync/status");
        let headers = self.auth_headers()?;

        let response = self.client
            .get(&url)
            .headers(headers)
            .send()
            .await
            .map_err(|e| AppError::Cloud(format!("Failed to get sync status: {}", e)))?;

        if !response.status().is_success() {
            return Err(AppError::Cloud(format!(
                "Failed to get sync status: {}",
                response.status()
            )));
        }

        response
            .json()
            .await
            .map_err(|e| AppError::Cloud(format!("Failed to parse sync status: {}", e)))
    }

    /// Get current user info
    pub async fn get_current_user(&self) -> Result<serde_json::Value, AppError> {
        if !self.is_authenticated() {
            return Err(AppError::Auth("Not authenticated".into()));
        }

        let url = self.api_url("/auth/me");
        let headers = self.auth_headers()?;

        let response = self.client
            .get(&url)
            .headers(headers)
            .send()
            .await
            .map_err(|e| AppError::Cloud(format!("Failed to get user: {}", e)))?;

        if !response.status().is_success() {
            return Err(AppError::Cloud(format!(
                "Failed to get user: {}",
                response.status()
            )));
        }

        response
            .json()
            .await
            .map_err(|e| AppError::Cloud(format!("Failed to parse user: {}", e)))
    }

    /// Post a delta to `/cache-stats`. Backend upserts on (org_id, assessment_id)
    /// and adds the deltas to the running totals. See
    /// `backend-rs/src/routes/cache_stats.rs` for the full request shape.
    pub async fn record_cache_stats(
        &self,
        delta: serde_json::Value,
    ) -> Result<serde_json::Value, AppError> {
        if !self.is_authenticated() {
            return Err(AppError::Auth("Not authenticated".into()));
        }

        let url = self.api_url("/cache-stats");
        let headers = self.auth_headers()?;

        let response = self
            .client
            .post(&url)
            .headers(headers)
            .json(&delta)
            .send()
            .await
            .map_err(|e| AppError::Cloud(format!("record_cache_stats POST failed: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(AppError::Cloud(format!(
                "record_cache_stats failed ({}): {}",
                status, body
            )));
        }

        response
            .json()
            .await
            .map_err(|e| AppError::Cloud(format!("record_cache_stats parse failed: {}", e)))
    }

    /// Fetch cache stats for one assessment. Returns `None` if no row exists
    /// yet (i.e., no LLM activity has been recorded against this assessment).
    pub async fn get_cache_stats(
        &self,
        assessment_id: &str,
    ) -> Result<Option<serde_json::Value>, AppError> {
        if !self.is_authenticated() {
            return Err(AppError::Auth("Not authenticated".into()));
        }

        let url = self.api_url(&format!("/cache-stats/{}", assessment_id));
        let headers = self.auth_headers()?;

        let response = self
            .client
            .get(&url)
            .headers(headers)
            .send()
            .await
            .map_err(|e| AppError::Cloud(format!("get_cache_stats GET failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(AppError::Cloud(format!(
                "get_cache_stats failed: {}",
                response.status()
            )));
        }

        // The backend returns `Option<CacheStatsResponse>` serialized as
        // either `null` or the object — both deserialize cleanly to
        // `Option<serde_json::Value>`.
        response
            .json()
            .await
            .map_err(|e| AppError::Cloud(format!("get_cache_stats parse failed: {}", e)))
    }

    /// Fetch the baseline-aware findings response for a target. Used by
    /// the team lead at Phase 1.5 of an assessment to decide whether to
    /// reuse prior validation results.
    ///
    /// `target_id` must be a UUID resolved via the targets canonicalization
    /// helper. The backend returns the prior findings (last_seen_at, severity,
    /// file_path, evidence excerpt), the org's revalidation cadence state,
    /// and the master `caching_enabled` switch.
    pub async fn get_baseline_findings(
        &self,
        target_id: &str,
        max_age_days: Option<i32>,
    ) -> Result<serde_json::Value, AppError> {
        if !self.is_authenticated() {
            return Err(AppError::Auth("Not authenticated".into()));
        }

        let mut url = self.api_url(&format!("/findings/baseline?target_id={}", target_id));
        if let Some(d) = max_age_days {
            url.push_str(&format!("&max_age_days={}", d));
        }
        let headers = self.auth_headers()?;

        let response = self
            .client
            .get(&url)
            .headers(headers)
            .send()
            .await
            .map_err(|e| AppError::Cloud(format!("get_baseline_findings GET failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(AppError::Cloud(format!(
                "get_baseline_findings failed: {}",
                response.status()
            )));
        }

        response
            .json()
            .await
            .map_err(|e| AppError::Cloud(format!("get_baseline_findings parse failed: {}", e)))
    }

    // ── SAST cache (Phase 4) ──────────────────────────────────────────

    /// Look up a cached SAST scan result by full cache key. Returns
    /// `{ cached: false }` if no entry exists or the entry has expired.
    pub async fn sast_cache_lookup(
        &self,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, AppError> {
        if !self.is_authenticated() {
            return Err(AppError::Auth("Not authenticated".into()));
        }
        // params is a map of cache-key fields; serialize to query string.
        let obj = params.as_object().ok_or_else(|| {
            AppError::Cloud("sast_cache_lookup params must be an object".into())
        })?;
        let mut qs: Vec<String> = Vec::new();
        for (k, v) in obj.iter() {
            if let Some(s) = v.as_str() {
                qs.push(format!("{}={}", k, urlencode(s)));
            }
        }
        let url = self.api_url(&format!("/sast-cache/lookup?{}", qs.join("&")));
        let headers = self.auth_headers()?;
        let response = self
            .client
            .get(&url)
            .headers(headers)
            .send()
            .await
            .map_err(|e| AppError::Cloud(format!("sast_cache_lookup failed: {}", e)))?;
        if !response.status().is_success() {
            return Err(AppError::Cloud(format!(
                "sast_cache_lookup failed: {}",
                response.status()
            )));
        }
        response
            .json()
            .await
            .map_err(|e| AppError::Cloud(format!("sast_cache_lookup parse failed: {}", e)))
    }

    /// Upsert a SAST cache entry. Caller MUST provide the full cache key.
    /// On conflict (same key), the payload + scan timestamps are refreshed.
    pub async fn sast_cache_upsert(
        &self,
        body: serde_json::Value,
    ) -> Result<serde_json::Value, AppError> {
        self.post_json("/sast-cache", body, "sast_cache_upsert").await
    }

    // ── Recon cache (Phase 5) ─────────────────────────────────────────

    /// Look up a cached recon snapshot by (target_id, scan_type). Returns
    /// `{ cached: false }` on miss or expiry.
    pub async fn recon_cache_lookup(
        &self,
        target_id: &str,
        scan_type: &str,
    ) -> Result<serde_json::Value, AppError> {
        if !self.is_authenticated() {
            return Err(AppError::Auth("Not authenticated".into()));
        }
        let url = self.api_url(&format!(
            "/recon-cache/lookup?target_id={}&scan_type={}",
            urlencode(target_id),
            urlencode(scan_type)
        ));
        let headers = self.auth_headers()?;
        let response = self
            .client
            .get(&url)
            .headers(headers)
            .send()
            .await
            .map_err(|e| AppError::Cloud(format!("recon_cache_lookup failed: {}", e)))?;
        if !response.status().is_success() {
            return Err(AppError::Cloud(format!(
                "recon_cache_lookup failed: {}",
                response.status()
            )));
        }
        response
            .json()
            .await
            .map_err(|e| AppError::Cloud(format!("recon_cache_lookup parse failed: {}", e)))
    }

    /// Upsert a recon cache entry.
    pub async fn recon_cache_upsert(
        &self,
        body: serde_json::Value,
    ) -> Result<serde_json::Value, AppError> {
        self.post_json("/recon-cache", body, "recon_cache_upsert").await
    }

    /// Internal helper for the cache upsert endpoints — both Phase 4
    /// and Phase 5 do the same POST-JSON shape against different paths.
    async fn post_json(
        &self,
        path: &str,
        body: serde_json::Value,
        label: &str,
    ) -> Result<serde_json::Value, AppError> {
        if !self.is_authenticated() {
            return Err(AppError::Auth("Not authenticated".into()));
        }
        let url = self.api_url(path);
        let headers = self.auth_headers()?;
        let response = self
            .client
            .post(&url)
            .headers(headers)
            .json(&body)
            .send()
            .await
            .map_err(|e| AppError::Cloud(format!("{} POST failed: {}", label, e)))?;
        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(AppError::Cloud(format!(
                "{} failed ({}): {}",
                label, status, body
            )));
        }
        response
            .json()
            .await
            .map_err(|e| AppError::Cloud(format!("{} parse failed: {}", label, e)))
    }

    // ── Org settings (Phase 6) ────────────────────────────────────────

    /// Read the caller's org cache settings. Backend bootstraps a row
    /// with defaults if none exists yet.
    pub async fn get_org_settings(&self) -> Result<serde_json::Value, AppError> {
        if !self.is_authenticated() {
            return Err(AppError::Auth("Not authenticated".into()));
        }
        let url = self.api_url("/org-settings");
        let headers = self.auth_headers()?;
        let response = self
            .client
            .get(&url)
            .headers(headers)
            .send()
            .await
            .map_err(|e| AppError::Cloud(format!("get_org_settings failed: {}", e)))?;
        if !response.status().is_success() {
            return Err(AppError::Cloud(format!(
                "get_org_settings failed: {}",
                response.status()
            )));
        }
        response
            .json()
            .await
            .map_err(|e| AppError::Cloud(format!("get_org_settings parse failed: {}", e)))
    }

    /// Partial-update org cache settings. The backend uses COALESCE
    /// internally, so omitted fields stay at their current value.
    pub async fn update_org_settings(
        &self,
        body: serde_json::Value,
    ) -> Result<serde_json::Value, AppError> {
        if !self.is_authenticated() {
            return Err(AppError::Auth("Not authenticated".into()));
        }
        let url = self.api_url("/org-settings");
        let headers = self.auth_headers()?;
        let response = self
            .client
            .put(&url)
            .headers(headers)
            .json(&body)
            .send()
            .await
            .map_err(|e| AppError::Cloud(format!("update_org_settings failed: {}", e)))?;
        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(AppError::Cloud(format!(
                "update_org_settings failed ({}): {}",
                status, body
            )));
        }
        response
            .json()
            .await
            .map_err(|e| AppError::Cloud(format!("update_org_settings parse failed: {}", e)))
    }

    /// Drift alerts summary (rolling 30-day count + threshold breach).
    pub async fn get_drift_alerts_summary(&self) -> Result<serde_json::Value, AppError> {
        if !self.is_authenticated() {
            return Err(AppError::Auth("Not authenticated".into()));
        }
        let url = self.api_url("/cache-drift-alerts/summary");
        let headers = self.auth_headers()?;
        let response = self
            .client
            .get(&url)
            .headers(headers)
            .send()
            .await
            .map_err(|e| AppError::Cloud(format!("get_drift_alerts_summary failed: {}", e)))?;
        if !response.status().is_success() {
            return Err(AppError::Cloud(format!(
                "get_drift_alerts_summary failed: {}",
                response.status()
            )));
        }
        response
            .json()
            .await
            .map_err(|e| AppError::Cloud(format!("get_drift_alerts_summary parse failed: {}", e)))
    }
}

/// Tiny URL-encoder for the cache lookup query strings. We only need
/// to handle the characters actually present in target IDs and scan
/// types (UUIDs + ASCII identifiers), so this stays small and
/// dependency-free.
fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                out.push_str(&format!("%{:02X}", b));
            }
        }
    }
    out
}

// =============================================================================
// MULTI-ACCOUNT STORAGE
// =============================================================================
//
// The desktop can hold N saved cloud connections (Groovy Security, customer
// X, customer Y, …) and switch which one is active without re-entering
// credentials. On-disk layout:
//
//   <config_dir>/cloud-accounts.json   — list of accounts + active_id
//   <config_dir>/cloud-tokens/<id>.json — per-account AuthTokens (0600)
//
// Migration: the first call to load_accounts() detects a legacy
// `cloud.json` (single-account world) and folds it into a one-entry
// `cloud-accounts.json` named "Groovy Security" (id = "groovy"). Tokens
// from `.tokens` are moved to `cloud-tokens/groovy.json`. The legacy files
// are left in place untouched as a safety net (single migration run is
// idempotent: if cloud-accounts.json already exists, legacy files are
// ignored).
//
// The shim functions at the bottom (`load_cloud_config`,
// `save_cloud_config`, `load_auth_tokens`, `save_auth_tokens`,
// `clear_auth_tokens`) preserve the pre-multi-account API so every existing
// caller (codex_credentials, credentials, sync_with_cloud, etc.) keeps
// working unchanged — they just transparently read/write the active
// account's slot.

/// One saved cloud connection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudAccount {
    pub id: String,
    pub name: String,
    #[serde(flatten)]
    pub config: CloudConfig,
}

/// The full multi-account registry persisted to disk.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CloudAccountList {
    pub active_id: Option<String>,
    #[serde(default)]
    pub accounts: Vec<CloudAccount>,
}

impl CloudAccountList {
    pub fn active(&self) -> Option<&CloudAccount> {
        let id = self.active_id.as_ref()?;
        self.accounts.iter().find(|a| &a.id == id)
    }

    pub fn active_mut(&mut self) -> Option<&mut CloudAccount> {
        let id = self.active_id.clone()?;
        self.accounts.iter_mut().find(|a| a.id == id)
    }
}

fn accounts_path(config_dir: &std::path::Path) -> std::path::PathBuf {
    config_dir.join("cloud-accounts.json")
}

fn tokens_dir(config_dir: &std::path::Path) -> std::path::PathBuf {
    config_dir.join("cloud-tokens")
}

fn token_path_for(config_dir: &std::path::Path, account_id: &str) -> std::path::PathBuf {
    tokens_dir(config_dir).join(format!("{}.json", account_id))
}

/// Load the multi-account registry. Auto-migrates from the legacy
/// single-account `cloud.json` + `.tokens` layout on first call.
pub fn load_accounts(config_dir: &std::path::Path) -> Result<CloudAccountList, AppError> {
    let path = accounts_path(config_dir);

    if path.exists() {
        let content = std::fs::read_to_string(&path)
            .map_err(|e| AppError::Config(format!("Failed to read cloud accounts: {}", e)))?;
        return serde_json::from_str(&content)
            .map_err(|e| AppError::Config(format!("Failed to parse cloud accounts: {}", e)));
    }

    // No accounts file yet — try to migrate from legacy single-account layout.
    let legacy_config = config_dir.join("cloud.json");
    if legacy_config.exists() {
        let content = std::fs::read_to_string(&legacy_config)
            .map_err(|e| AppError::Config(format!("Failed to read legacy cloud config: {}", e)))?;
        let config: CloudConfig = serde_json::from_str(&content).map_err(|e| {
            AppError::Config(format!("Failed to parse legacy cloud config: {}", e))
        })?;

        let account = CloudAccount {
            id: "groovy".to_string(),
            name: "Groovy Security".to_string(),
            config,
        };
        let list = CloudAccountList {
            active_id: Some("groovy".to_string()),
            accounts: vec![account],
        };
        save_accounts(config_dir, &list)?;

        // Move legacy tokens into the per-account slot, best-effort.
        let legacy_tokens = config_dir.join(".tokens");
        if legacy_tokens.exists() {
            if let Ok(content) = std::fs::read_to_string(&legacy_tokens) {
                if let Ok(tokens) = serde_json::from_str::<AuthTokens>(&content) {
                    let _ = save_auth_tokens_for(config_dir, "groovy", &tokens);
                }
            }
        }

        return Ok(list);
    }

    Ok(CloudAccountList::default())
}

/// Persist the multi-account registry. Passwords are scrubbed before write.
pub fn save_accounts(
    config_dir: &std::path::Path,
    accounts: &CloudAccountList,
) -> Result<(), AppError> {
    let path = accounts_path(config_dir);

    let mut to_save = accounts.clone();
    for acc in to_save.accounts.iter_mut() {
        acc.config.password = None;
    }

    let content = serde_json::to_string_pretty(&to_save)
        .map_err(|e| AppError::Config(format!("Failed to serialize cloud accounts: {}", e)))?;

    std::fs::write(&path, content)
        .map_err(|e| AppError::Config(format!("Failed to write cloud accounts: {}", e)))?;

    Ok(())
}

/// Generate a short, URL-safe ID for a new account.
pub fn generate_account_id() -> String {
    let nanos = Utc::now().timestamp_nanos_opt().unwrap_or(0);
    format!("acc_{:x}", nanos as u64)
}

/// Load auth tokens for a specific account. Returns None (and removes the
/// file) if the stored tokens are expired.
pub fn load_auth_tokens_for(
    config_dir: &std::path::Path,
    account_id: &str,
) -> Result<Option<AuthTokens>, AppError> {
    let token_path = token_path_for(config_dir, account_id);

    if !token_path.exists() {
        return Ok(None);
    }

    let content = std::fs::read_to_string(&token_path)
        .map_err(|e| AppError::Config(format!("Failed to read tokens: {}", e)))?;

    let tokens: AuthTokens = serde_json::from_str(&content)
        .map_err(|e| AppError::Config(format!("Failed to parse tokens: {}", e)))?;

    if let Some(expires_at) = tokens.expires_at {
        if Utc::now() >= expires_at {
            let _ = std::fs::remove_file(&token_path);
            return Ok(None);
        }
    }

    Ok(Some(tokens))
}

/// Save auth tokens for a specific account, 0600 on Unix.
pub fn save_auth_tokens_for(
    config_dir: &std::path::Path,
    account_id: &str,
    tokens: &AuthTokens,
) -> Result<(), AppError> {
    let dir = tokens_dir(config_dir);
    std::fs::create_dir_all(&dir)
        .map_err(|e| AppError::Config(format!("Failed to create token dir: {}", e)))?;

    let token_path = token_path_for(config_dir, account_id);

    let content = serde_json::to_string(tokens)
        .map_err(|e| AppError::Config(format!("Failed to serialize tokens: {}", e)))?;

    std::fs::write(&token_path, content)
        .map_err(|e| AppError::Config(format!("Failed to write tokens: {}", e)))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&token_path)
            .map_err(|e| AppError::Config(format!("Failed to get permissions: {}", e)))?
            .permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(&token_path, perms)
            .map_err(|e| AppError::Config(format!("Failed to set permissions: {}", e)))?;
    }

    Ok(())
}

/// Clear stored tokens for a specific account.
pub fn clear_auth_tokens_for(
    config_dir: &std::path::Path,
    account_id: &str,
) -> Result<(), AppError> {
    let token_path = token_path_for(config_dir, account_id);
    if token_path.exists() {
        std::fs::remove_file(&token_path)
            .map_err(|e| AppError::Config(format!("Failed to remove tokens: {}", e)))?;
    }
    Ok(())
}

// =============================================================================
// SHIMS — preserve the pre-multi-account API. Every existing caller
// (commands/cloud.rs, codex_credentials, credentials, …) reads/writes "the
// active account" through these without knowing accounts exist.

/// Load the active account's cloud config (default if no active account).
pub fn load_cloud_config(config_dir: &std::path::Path) -> Result<CloudConfig, AppError> {
    let list = load_accounts(config_dir)?;
    Ok(list.active().map(|a| a.config.clone()).unwrap_or_default())
}

/// Save the given config to the active account. If no active account
/// exists, creates one (id = "default", name = "Default") so single-account
/// behaviour still works for pre-existing callers that don't know about
/// accounts.
pub fn save_cloud_config(
    config_dir: &std::path::Path,
    config: &CloudConfig,
) -> Result<(), AppError> {
    let mut list = load_accounts(config_dir)?;

    if let Some(active) = list.active_mut() {
        active.config = config.clone();
    } else {
        let id = "default".to_string();
        list.active_id = Some(id.clone());
        list.accounts.push(CloudAccount {
            id,
            name: "Default".to_string(),
            config: config.clone(),
        });
    }

    save_accounts(config_dir, &list)
}

/// Load tokens for the active account.
pub fn load_auth_tokens(config_dir: &std::path::Path) -> Result<Option<AuthTokens>, AppError> {
    let list = load_accounts(config_dir)?;
    let Some(id) = list.active_id.as_deref() else {
        return Ok(None);
    };
    load_auth_tokens_for(config_dir, id)
}

/// Save tokens for the active account.
pub fn save_auth_tokens(config_dir: &std::path::Path, tokens: &AuthTokens) -> Result<(), AppError> {
    let list = load_accounts(config_dir)?;
    let Some(id) = list.active_id.as_deref() else {
        return Err(AppError::Cloud(
            "No active cloud account — cannot save tokens".into(),
        ));
    };
    save_auth_tokens_for(config_dir, id, tokens)
}

/// Clear tokens for the active account.
pub fn clear_auth_tokens(config_dir: &std::path::Path) -> Result<(), AppError> {
    let list = load_accounts(config_dir)?;
    let Some(id) = list.active_id.as_deref() else {
        return Ok(());
    };
    clear_auth_tokens_for(config_dir, id)
}
