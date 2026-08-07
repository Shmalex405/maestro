// Cloud sync commands

use crate::cloud::{
    AuthProvider, AuthTokens, CloudAccount, CloudClient, CloudConfig, SyncRequest,
    clear_auth_tokens, clear_auth_tokens_for, generate_account_id, load_accounts,
    load_auth_tokens, load_cloud_config, save_accounts, save_auth_tokens, save_cloud_config,
};
use crate::database::Database;
use crate::error::{AppError, Result};
use crate::state::AppState;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tauri::State;
use tokio::sync::RwLock;

#[derive(Debug, Serialize, Deserialize)]
pub struct CloudConfigResponse {
    pub enabled: bool,
    pub api_url: String,
    pub auth_provider: String,
    pub email: Option<String>,
    pub cognito_region: Option<String>,
    pub cognito_user_pool_id: Option<String>,
    pub cognito_client_id: Option<String>,
    pub oidc_issuer: Option<String>,
    pub oidc_client_id: Option<String>,
    pub auto_sync: bool,
    pub sync_interval_seconds: u64,
}

impl From<CloudConfig> for CloudConfigResponse {
    fn from(config: CloudConfig) -> Self {
        Self {
            enabled: config.enabled,
            api_url: config.api_url,
            auth_provider: match config.auth_provider {
                AuthProvider::Local => "local".to_string(),
                AuthProvider::Cognito => "cognito".to_string(),
                AuthProvider::Oidc => "oidc".to_string(),
            },
            email: config.email,
            cognito_region: config.cognito_region,
            cognito_user_pool_id: config.cognito_user_pool_id,
            cognito_client_id: config.cognito_client_id,
            oidc_issuer: config.oidc_issuer,
            oidc_client_id: config.oidc_client_id,
            auto_sync: config.auto_sync,
            sync_interval_seconds: config.sync_interval_seconds,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CloudStatusResponse {
    pub enabled: bool,
    pub connected: bool,
    pub authenticated: bool,
    pub user_email: Option<String>,
    pub last_sync_at: Option<String>,
    pub pending_changes: u32,
    pub sync_in_progress: bool,
    pub last_error: Option<String>,
}

/// Get cloud configuration
#[tauri::command(rename_all = "snake_case")]
pub async fn get_cloud_config(
    state: State<'_, Arc<RwLock<AppState>>>,
) -> Result<CloudConfigResponse> {
    let state = state.read().await;
    let config_dir = state.get_config_dir()?;
    let config = load_cloud_config(&config_dir)?;
    Ok(config.into())
}

/// Save cloud configuration
#[tauri::command(rename_all = "snake_case")]
#[tracing::instrument(skip(state), fields(api_url = %api_url, auth_provider = %auth_provider))]
pub async fn save_cloud_config_cmd(
    enabled: bool,
    api_url: String,
    auth_provider: String,
    email: Option<String>,
    cognito_region: Option<String>,
    cognito_user_pool_id: Option<String>,
    cognito_client_id: Option<String>,
    oidc_issuer: Option<String>,
    oidc_client_id: Option<String>,
    auto_sync: bool,
    sync_interval_seconds: u64,
    state: State<'_, Arc<RwLock<AppState>>>,
) -> Result<()> {
    let state = state.read().await;
    let config_dir = state.get_config_dir()?;

    let config = CloudConfig {
        enabled,
        api_url,
        auth_provider: match auth_provider.as_str() {
            "cognito" => AuthProvider::Cognito,
            "oidc" => AuthProvider::Oidc,
            _ => AuthProvider::Local,
        },
        email,
        password: None,
        cognito_region,
        cognito_user_pool_id,
        cognito_client_id,
        oidc_issuer,
        oidc_client_id,
        auto_sync,
        sync_interval_seconds,
    };

    save_cloud_config(&config_dir, &config)?;
    Ok(())
}

/// Test cloud connection
#[tauri::command(rename_all = "snake_case")]
pub async fn test_cloud_connection(
    api_url: String,
) -> Result<bool> {
    tracing::info!(api_url = %api_url, "test_cloud_connection invoked");
    let config = CloudConfig {
        enabled: true,
        api_url: api_url.clone(),
        ..Default::default()
    };

    let client = CloudClient::new(config);
    match client.test_connection().await {
        Ok(ok) => {
            tracing::info!(api_url = %api_url, success = ok, "test_cloud_connection result");
            Ok(ok)
        }
        Err(e) => {
            tracing::error!(api_url = %api_url, error = %e, "test_cloud_connection failed");
            Err(e)
        }
    }
}

/// Get available auth providers from backend
#[tauri::command(rename_all = "snake_case")]
pub async fn get_cloud_auth_providers(
    api_url: String,
) -> Result<serde_json::Value> {
    let config = CloudConfig {
        enabled: true,
        api_url,
        ..Default::default()
    };

    let client = CloudClient::new(config);
    let providers = client.get_auth_providers().await?;
    Ok(serde_json::to_value(providers).unwrap_or_default())
}

/// Login with email and password
#[tauri::command(rename_all = "snake_case")]
pub async fn cloud_login(
    email: String,
    password: String,
    state: State<'_, Arc<RwLock<AppState>>>,
) -> Result<serde_json::Value> {
    tracing::info!(email = %email, "cloud_login invoked");
    let state = state.read().await;
    let config_dir = state.get_config_dir()?;
    let config = load_cloud_config(&config_dir)?;
    tracing::info!(
        enabled = config.enabled,
        api_url = %config.api_url,
        "cloud_login loaded config"
    );

    if !config.enabled {
        tracing::warn!("cloud_login: cloud sync not enabled — user must click Save Settings first");
        return Err(AppError::Cloud("Cloud sync is not enabled".into()));
    }

    let mut client = CloudClient::new(config);
    let tokens = client.login(&email, &password).await.map_err(|e| {
        tracing::error!(error = %e, "cloud_login: backend login failed");
        e
    })?;

    // Save tokens
    save_auth_tokens(&config_dir, &tokens)?;

    // Get user info
    let user = client.get_current_user().await?;

    Ok(serde_json::json!({
        "success": true,
        "user": user,
        "expires_at": tokens.expires_at
    }))
}

/// Logout (clear tokens)
#[tauri::command(rename_all = "snake_case")]
pub async fn cloud_logout(
    state: State<'_, Arc<RwLock<AppState>>>,
) -> Result<()> {
    let state = state.read().await;
    let config_dir = state.get_config_dir()?;
    clear_auth_tokens(&config_dir)?;
    Ok(())
}

/// Get cloud status
#[tauri::command(rename_all = "snake_case")]
pub async fn get_cloud_status(
    state: State<'_, Arc<RwLock<AppState>>>,
) -> Result<CloudStatusResponse> {
    let app_state = state.read().await;
    let config_dir = app_state.get_config_dir()?;
    let config = load_cloud_config(&config_dir)?;

    if !config.enabled {
        return Ok(CloudStatusResponse {
            enabled: false,
            connected: false,
            authenticated: false,
            user_email: None,
            last_sync_at: None,
            pending_changes: 0,
            sync_in_progress: false,
            last_error: None,
        });
    }

    let tokens = load_auth_tokens(&config_dir)?;
    let authenticated = tokens.is_some();

    let mut connected = false;
    let mut user_email = None;
    let mut last_error = None;

    if let Some(tokens) = tokens {
        let client = CloudClient::new(config.clone()).with_tokens(tokens);

        // Test connection
        match client.test_connection().await {
            Ok(true) => {
                connected = true;
                // Get user info
                if let Ok(user) = client.get_current_user().await {
                    user_email = user.get("email").and_then(|e| e.as_str()).map(|s| s.to_string());
                }
            }
            Ok(false) => {
                last_error = Some("Server returned error".into());
            }
            Err(e) => {
                last_error = Some(e.to_string());
            }
        }
    }

    // Get sync status from local state
    let sync_status = app_state.get_sync_status();

    Ok(CloudStatusResponse {
        enabled: config.enabled,
        connected,
        authenticated,
        user_email,
        last_sync_at: sync_status.last_sync_at.map(|t| t.to_rfc3339()),
        pending_changes: sync_status.pending_changes,
        sync_in_progress: sync_status.sync_in_progress,
        last_error: last_error.or(sync_status.last_error),
    })
}

/// Sync data with cloud
#[tauri::command(rename_all = "snake_case")]
pub async fn sync_with_cloud(
    state: State<'_, Arc<RwLock<AppState>>>,
) -> Result<serde_json::Value> {
    let config_dir = {
        let app_state = state.read().await;
        app_state.get_config_dir()?
    };

    let config = load_cloud_config(&config_dir)?;

    if !config.enabled {
        return Err(AppError::Cloud("Cloud sync is not enabled".into()));
    }

    let tokens = load_auth_tokens(&config_dir)?
        .ok_or_else(|| AppError::Auth("Not authenticated. Please login first.".into()))?;

    let client = CloudClient::new(config).with_tokens(tokens);

    // Create a new database connection for this operation
    let db = Database::new()?;

    // Get last sync time from state
    let last_sync = {
        let app_state = state.read().await;
        app_state.get_sync_status().last_sync_at
    };

    // Get assessments modified since last sync
    let assessments = db.get_assessments_for_sync(last_sync)?;
    let findings = db.get_findings_for_sync(last_sync)?;
    let reports = db.get_reports_for_sync(last_sync)?;

    let request = SyncRequest {
        assessments,
        findings,
        reports,
        last_sync_at: last_sync,
    };

    // Perform sync
    let response = client.sync(request).await?;

    // Update local database with server data
    let mut synced_count = 0;

    for assessment in &response.assessments {
        if db.upsert_assessment_from_sync(assessment).is_ok() {
            synced_count += 1;
        }
    }

    for finding in &response.findings {
        if db.upsert_finding_from_sync(finding).is_ok() {
            synced_count += 1;
        }
    }

    for report in &response.reports {
        if db.upsert_report_from_sync(report).is_ok() {
            synced_count += 1;
        }
    }

    // Update sync timestamp in state
    {
        let mut app_state = state.write().await;
        app_state.update_sync_status(response.sync_at, None);
    }

    Ok(serde_json::json!({
        "success": true,
        "synced_at": response.sync_at,
        "assessments_synced": response.assessments.len(),
        "findings_synced": response.findings.len(),
        "reports_synced": response.reports.len(),
        "total_synced": synced_count
    }))
}

/// Set Cognito/OIDC tokens (for external auth flows)
#[tauri::command(rename_all = "snake_case")]
pub async fn set_cloud_tokens(
    access_token: String,
    token_type: String,
    expires_in: i64,
    refresh_token: Option<String>,
    state: State<'_, Arc<RwLock<AppState>>>,
) -> Result<()> {
    let state = state.read().await;
    let config_dir = state.get_config_dir()?;

    let tokens = AuthTokens {
        access_token,
        token_type,
        expires_at: Some(chrono::Utc::now() + chrono::Duration::seconds(expires_in)),
        refresh_token,
    };

    save_auth_tokens(&config_dir, &tokens)?;
    Ok(())
}

/// Persist the active cloud session (backend URL + Cognito ID token) to a
/// well-known file the local MCP server can read. Writing this file is what
/// switches MCP-driven writes (create_finding, etc.) from local SQLite to the
/// org's cloud backend. The TS layer calls this whenever it refreshes the
/// JWT or signs the user in. The file is owner-only (0600) and replaced
/// atomically.
#[tauri::command(rename_all = "snake_case")]
pub async fn write_cloud_session_file(
    backend_url: String,
    id_token: String,
    token_expiry: i64,
) -> Result<()> {
    use std::io::Write;
    let dir = dirs::home_dir()
        .ok_or_else(|| AppError::Cloud("home dir not resolvable".into()))?
        .join(".kali-mcp-pentest");
    std::fs::create_dir_all(&dir)
        .map_err(|e| AppError::Cloud(format!("mkdir cloud-session dir: {e}")))?;
    let path = dir.join("cloud-session.json");
    // Per-call unique tmp suffix so concurrent persistCloudSession invocations
    // don't race on the same .tmp filename — without it, A renames the tmp
    // first and B's rename hits ENOENT. ID token refreshes can fire from
    // multiple cloudRequest calls simultaneously.
    let tmp = dir.join(format!(
        "cloud-session.json.tmp.{}.{}",
        std::process::id(),
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
    ));
    let body = serde_json::json!({
        "backendUrl": backend_url,
        "idToken": id_token,
        "tokenExpiry": token_expiry,
        "writtenAt": chrono::Utc::now().to_rfc3339(),
    });
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)
            .map_err(|e| AppError::Cloud(format!("open cloud-session.tmp: {e}")))?;
        f.write_all(serde_json::to_string(&body).unwrap().as_bytes())
            .map_err(|e| AppError::Cloud(format!("write cloud-session: {e}")))?;
        f.flush().ok();
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(&tmp, perms).ok();
    }
    std::fs::rename(&tmp, &path)
        .map_err(|e| AppError::Cloud(format!("rename cloud-session: {e}")))?;
    Ok(())
}

/// Persist the org's OAST listener config to a well-known file the local MCP
/// server reads (`verification/oast.ts`). Without this file the `oast` oracle
/// has no listener, reports `oast_unavailable`, and every blind finding —
/// blind SSRF, blind SQLi, XXE, blind SSTI — stays an unverified candidate.
///
/// A FILE rather than container env vars, for two reasons:
///   * changing the listener doesn't require recreating the Kali container;
///   * the polling token stays out of `docker inspect`, at 0600 on disk.
///
/// Values come from the org's discovery payload (`/api/discover` → the customer
/// registry secret), so the shared Groovy-operated listener needs no action from
/// the customer at all. An org running its own listener can still override with
/// MAESTRO_OAST_SERVER / MAESTRO_OAST_TOKEN in the container environment.
#[tauri::command(rename_all = "snake_case")]
pub async fn write_oast_config_file(server: String, token: Option<String>) -> Result<()> {
    use std::io::Write;
    let dir = dirs::home_dir()
        .ok_or_else(|| AppError::Cloud("home dir not resolvable".into()))?
        .join(".kali-mcp-pentest");
    std::fs::create_dir_all(&dir).map_err(|e| AppError::Cloud(format!("mkdir oast dir: {e}")))?;
    let path = dir.join("oast.json");
    let tmp = dir.join(format!(
        "oast.json.tmp.{}.{}",
        std::process::id(),
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
    ));
    let body = serde_json::json!({
        "server": server,
        "token": token,
        "writtenAt": chrono::Utc::now().to_rfc3339(),
    });
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)
            .map_err(|e| AppError::Cloud(format!("open oast.tmp: {e}")))?;
        f.write_all(serde_json::to_string(&body).unwrap().as_bytes())
            .map_err(|e| AppError::Cloud(format!("write oast config: {e}")))?;
        f.flush().ok();
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600)).ok();
    }
    std::fs::rename(&tmp, &path).map_err(|e| AppError::Cloud(format!("rename oast config: {e}")))?;
    Ok(())
}

/// Remove the OAST config. Called on sign-out alongside the cloud session, so a
/// signed-out app cannot keep polling a listener with a stale org token.
#[tauri::command(rename_all = "snake_case")]
pub async fn clear_oast_config_file() -> Result<()> {
    let path = dirs::home_dir()
        .ok_or_else(|| AppError::Cloud("home dir not resolvable".into()))?
        .join(".kali-mcp-pentest")
        .join("oast.json");
    if path.exists() {
        std::fs::remove_file(&path)
            .map_err(|e| AppError::Cloud(format!("remove oast config: {e}")))?;
    }
    Ok(())
}

/// Remove the cloud session file. Called on sign-out to ensure MCP writes
/// stop hitting the cloud immediately.
#[tauri::command(rename_all = "snake_case")]
pub async fn clear_cloud_session_file() -> Result<()> {
    let path = dirs::home_dir()
        .ok_or_else(|| AppError::Cloud("home dir not resolvable".into()))?
        .join(".kali-mcp-pentest")
        .join("cloud-session.json");
    if path.exists() {
        std::fs::remove_file(&path)
            .map_err(|e| AppError::Cloud(format!("remove cloud-session: {e}")))?;
    }
    Ok(())
}

/// Materialize the merged credentials config (cloud `org_configs.credentials`
/// shared metadata + per-user OS-keychain secrets, merged on the desktop) to
/// a host-side file the in-container MCP server reads via
/// MAESTRO_CREDENTIALS_PATH. The TS layer calls this whenever the user
/// updates credentials and at startup once auth is established. File is
/// owner-only (0600) and replaced atomically to avoid the MCP server
/// reading a half-written tree.
#[tauri::command(rename_all = "snake_case")]
pub async fn write_merged_credentials_file(value: serde_json::Value) -> Result<()> {
    use std::io::Write;
    let dir = dirs::home_dir()
        .ok_or_else(|| AppError::Cloud("home dir not resolvable".into()))?
        .join(".kali-mcp-pentest");
    std::fs::create_dir_all(&dir)
        .map_err(|e| AppError::Cloud(format!("mkdir credentials dir: {e}")))?;
    let path = dir.join("credentials-merged.json");
    // Per-call unique tmp suffix — same rationale as write_cloud_session_file.
    let tmp = dir.join(format!(
        "credentials-merged.json.tmp.{}.{}",
        std::process::id(),
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
    ));
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)
            .map_err(|e| AppError::Cloud(format!("open credentials.tmp: {e}")))?;
        f.write_all(serde_json::to_string(&value).unwrap().as_bytes())
            .map_err(|e| AppError::Cloud(format!("write credentials: {e}")))?;
        f.flush().ok();
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(&tmp, perms).ok();
    }
    std::fs::rename(&tmp, &path)
        .map_err(|e| AppError::Cloud(format!("rename credentials: {e}")))?;
    Ok(())
}

/// Remove the materialized credentials file. Called on sign-out alongside
/// clear_cloud_session_file so the container can no longer read the user's
/// secrets after they leave.
#[tauri::command(rename_all = "snake_case")]
pub async fn clear_merged_credentials_file() -> Result<()> {
    let path = dirs::home_dir()
        .ok_or_else(|| AppError::Cloud("home dir not resolvable".into()))?
        .join(".kali-mcp-pentest")
        .join("credentials-merged.json");
    if path.exists() {
        std::fs::remove_file(&path)
            .map_err(|e| AppError::Cloud(format!("remove credentials: {e}")))?;
    }
    Ok(())
}

/// Materialize the cloud scope (apps, repo paths, networks, domains) to
/// a host-side file the in-container Docker bind logic reads at
/// container-create time. The Maestro UI's Scope page writes scope to
/// the per-org cloud DB; this command snapshots that to disk so
/// docker.rs::expected_binds can derive RO mounts for in-scope repo
/// paths without an HTTP fetch (binds is sync, called before any
/// network operations).
///
/// Tier 2 (v0.1.54) needs this so the container's read view shrinks
/// from "everything in $HOME" to "only the user's authorized scope
/// repos plus the Maestro project". Same atomic-write pattern as
/// write_merged_credentials_file.
#[tauri::command(rename_all = "snake_case")]
pub async fn write_merged_scope_file(value: serde_json::Value) -> Result<()> {
    use std::io::Write;
    let dir = dirs::home_dir()
        .ok_or_else(|| AppError::Cloud("home dir not resolvable".into()))?
        .join(".kali-mcp-pentest");
    std::fs::create_dir_all(&dir)
        .map_err(|e| AppError::Cloud(format!("mkdir scope dir: {e}")))?;
    let path = dir.join("scope-merged.json");
    let tmp = dir.join(format!(
        "scope-merged.json.tmp.{}.{}",
        std::process::id(),
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
    ));
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)
            .map_err(|e| AppError::Cloud(format!("open scope.tmp: {e}")))?;
        f.write_all(serde_json::to_string(&value).unwrap().as_bytes())
            .map_err(|e| AppError::Cloud(format!("write scope: {e}")))?;
        f.flush().ok();
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o644);
        std::fs::set_permissions(&tmp, perms).ok();
    }
    std::fs::rename(&tmp, &path)
        .map_err(|e| AppError::Cloud(format!("rename scope: {e}")))?;
    Ok(())
}

/// Remove the materialized scope file. Called on sign-out so the next
/// container start can't see the user's previous engagement scope.
#[tauri::command(rename_all = "snake_case")]
pub async fn clear_merged_scope_file() -> Result<()> {
    let path = dirs::home_dir()
        .ok_or_else(|| AppError::Cloud("home dir not resolvable".into()))?
        .join(".kali-mcp-pentest")
        .join("scope-merged.json");
    if path.exists() {
        std::fs::remove_file(&path)
            .map_err(|e| AppError::Cloud(format!("remove scope: {e}")))?;
    }
    Ok(())
}

// =============================================================================
// MULTI-ACCOUNT COMMANDS
// =============================================================================
//
// Manage N saved cloud connections (Groovy Security, customer X, …) with
// one marked active. The existing single-account commands above keep
// working because they read/write via the shim layer in cloud.rs, which
// transparently targets the active account.

/// Lightweight summary returned by list_cloud_accounts — enough for the
/// list page to render rows without dragging the whole config blob around.
#[derive(Debug, Serialize, Deserialize)]
pub struct CloudAccountSummary {
    pub id: String,
    pub name: String,
    pub api_url: String,
    pub auth_provider: String,
    pub is_active: bool,
}

/// Full account view returned by get_cloud_account, used by the edit page.
#[derive(Debug, Serialize, Deserialize)]
pub struct CloudAccountResponse {
    pub id: String,
    pub name: String,
    pub is_active: bool,
    #[serde(flatten)]
    pub config: CloudConfigResponse,
}

/// Input struct used by add/update — mirrors CloudConfigResponse so the
/// frontend can hand its form state straight through.
#[derive(Debug, Deserialize)]
pub struct CloudAccountInput {
    pub name: String,
    pub enabled: bool,
    pub api_url: String,
    pub auth_provider: String,
    pub email: Option<String>,
    pub cognito_region: Option<String>,
    pub cognito_user_pool_id: Option<String>,
    pub cognito_client_id: Option<String>,
    pub oidc_issuer: Option<String>,
    pub oidc_client_id: Option<String>,
    pub auto_sync: bool,
    pub sync_interval_seconds: u64,
}

impl From<CloudAccountInput> for CloudConfig {
    fn from(input: CloudAccountInput) -> Self {
        CloudConfig {
            enabled: input.enabled,
            api_url: input.api_url,
            auth_provider: match input.auth_provider.as_str() {
                "cognito" => AuthProvider::Cognito,
                "oidc" => AuthProvider::Oidc,
                _ => AuthProvider::Local,
            },
            email: input.email,
            password: None,
            cognito_region: input.cognito_region,
            cognito_user_pool_id: input.cognito_user_pool_id,
            cognito_client_id: input.cognito_client_id,
            oidc_issuer: input.oidc_issuer,
            oidc_client_id: input.oidc_client_id,
            auto_sync: input.auto_sync,
            sync_interval_seconds: input.sync_interval_seconds,
        }
    }
}

fn summarize(account: &CloudAccount, active_id: Option<&str>) -> CloudAccountSummary {
    CloudAccountSummary {
        id: account.id.clone(),
        name: account.name.clone(),
        api_url: account.config.api_url.clone(),
        auth_provider: match account.config.auth_provider {
            AuthProvider::Local => "local".to_string(),
            AuthProvider::Cognito => "cognito".to_string(),
            AuthProvider::Oidc => "oidc".to_string(),
        },
        is_active: active_id == Some(account.id.as_str()),
    }
}

/// List all saved cloud accounts.
#[tauri::command(rename_all = "snake_case")]
pub async fn list_cloud_accounts(
    state: State<'_, Arc<RwLock<AppState>>>,
) -> Result<Vec<CloudAccountSummary>> {
    let state = state.read().await;
    let config_dir = state.get_config_dir()?;
    let list = load_accounts(&config_dir)?;
    let active = list.active_id.clone();
    Ok(list
        .accounts
        .iter()
        .map(|a| summarize(a, active.as_deref()))
        .collect())
}

/// Get a single account by id (for the edit page).
#[tauri::command(rename_all = "snake_case")]
pub async fn get_cloud_account(
    id: String,
    state: State<'_, Arc<RwLock<AppState>>>,
) -> Result<CloudAccountResponse> {
    let state = state.read().await;
    let config_dir = state.get_config_dir()?;
    let list = load_accounts(&config_dir)?;
    let active = list.active_id.clone();
    let account = list
        .accounts
        .into_iter()
        .find(|a| a.id == id)
        .ok_or_else(|| AppError::Cloud(format!("Cloud account '{}' not found", id)))?;
    let is_active = active.as_deref() == Some(account.id.as_str());
    Ok(CloudAccountResponse {
        id: account.id,
        name: account.name,
        is_active,
        config: account.config.into(),
    })
}

/// Create a new cloud account. Returns the generated id. The new account
/// becomes active automatically if no account is currently active (e.g.
/// first-time setup).
#[tauri::command(rename_all = "snake_case")]
pub async fn add_cloud_account(
    input: CloudAccountInput,
    state: State<'_, Arc<RwLock<AppState>>>,
) -> Result<String> {
    let state = state.read().await;
    let config_dir = state.get_config_dir()?;
    let mut list = load_accounts(&config_dir)?;

    if input.name.trim().is_empty() {
        return Err(AppError::Cloud("Account name cannot be empty".into()));
    }

    let id = generate_account_id();
    let name = input.name.clone();
    let config: CloudConfig = input.into();
    list.accounts.push(CloudAccount {
        id: id.clone(),
        name,
        config,
    });
    if list.active_id.is_none() {
        list.active_id = Some(id.clone());
    }
    save_accounts(&config_dir, &list)?;
    Ok(id)
}

/// Update an existing account's name + config in place.
#[tauri::command(rename_all = "snake_case")]
pub async fn update_cloud_account(
    id: String,
    input: CloudAccountInput,
    state: State<'_, Arc<RwLock<AppState>>>,
) -> Result<()> {
    let state = state.read().await;
    let config_dir = state.get_config_dir()?;
    let mut list = load_accounts(&config_dir)?;

    if input.name.trim().is_empty() {
        return Err(AppError::Cloud("Account name cannot be empty".into()));
    }

    let account = list
        .accounts
        .iter_mut()
        .find(|a| a.id == id)
        .ok_or_else(|| AppError::Cloud(format!("Cloud account '{}' not found", id)))?;
    account.name = input.name.clone();
    account.config = input.into();
    save_accounts(&config_dir, &list)?;
    Ok(())
}

/// Delete an account and its tokens. If the deleted account was active,
/// the first remaining account becomes active (or none, if the list is
/// now empty).
#[tauri::command(rename_all = "snake_case")]
pub async fn remove_cloud_account(
    id: String,
    state: State<'_, Arc<RwLock<AppState>>>,
) -> Result<()> {
    let state = state.read().await;
    let config_dir = state.get_config_dir()?;
    let mut list = load_accounts(&config_dir)?;

    let before = list.accounts.len();
    list.accounts.retain(|a| a.id != id);
    if list.accounts.len() == before {
        return Err(AppError::Cloud(format!(
            "Cloud account '{}' not found",
            id
        )));
    }

    if list.active_id.as_deref() == Some(id.as_str()) {
        list.active_id = list.accounts.first().map(|a| a.id.clone());
    }

    save_accounts(&config_dir, &list)?;
    let _ = clear_auth_tokens_for(&config_dir, &id);
    Ok(())
}

/// Switch which account is active. The caller (frontend) is responsible
/// for invalidating cached data and rewriting cloud-session.json after
/// this returns.
#[tauri::command(rename_all = "snake_case")]
pub async fn set_active_cloud_account(
    id: String,
    state: State<'_, Arc<RwLock<AppState>>>,
) -> Result<()> {
    let state = state.read().await;
    let config_dir = state.get_config_dir()?;
    let mut list = load_accounts(&config_dir)?;

    if !list.accounts.iter().any(|a| a.id == id) {
        return Err(AppError::Cloud(format!(
            "Cloud account '{}' not found",
            id
        )));
    }
    list.active_id = Some(id);
    save_accounts(&config_dir, &list)?;
    Ok(())
}

// =============================================================================
// CACHE STATS (Phase 0 of caching plan — 2026-05-22)
// =============================================================================
//
// LLM cost + cache hit telemetry per assessment. See
// `docs/caching-plan-2026-05-22.md` and
// `backend-rs/src/routes/cache_stats.rs` for the design.
//
// Data flow is desktop-driven: the assessment orchestrator records
// cache_read / cache_creation token counts as it sees them and these
// commands populate cache_stats on the per-customer backend directly.

/// Record a delta of token usage against an assessment. The backend
/// atomically adds these counts to the running totals for
/// (org_id, assessment_id) and recomputes cost figures. To overwrite
/// instead of add, the caller can set `"replace": true` in the delta.
///
/// `delta` shape (see `CacheStatsUpsert` in backend-rs/routes/cache_stats.rs):
/// {
///   "assessment_id": "...",
///   "provider": "anthropic" | "openai",
///   "model": "claude-opus-4-7",
///   "input_tokens": 1234,
///   "output_tokens": 567,
///   "cache_read_input_tokens": 890,
///   "cache_creation_input_tokens": 123,
///   "request_count": 1,
///   "requests_with_extended_ttl": 1,
///   "requests_without_cache_beta": 0,
///   "replace": false
/// }
#[tauri::command(rename_all = "snake_case")]
pub async fn record_cache_stats(
    delta: serde_json::Value,
    state: State<'_, Arc<RwLock<AppState>>>,
) -> Result<serde_json::Value> {
    let app_state = state.read().await;
    let config_dir = app_state.get_config_dir()?;
    let config = load_cloud_config(&config_dir)?;

    if !config.enabled {
        return Err(AppError::Cloud(
            "Cloud sync is disabled; cache stats are recorded against the cloud backend.".into(),
        ));
    }

    let tokens = load_auth_tokens(&config_dir)?
        .ok_or_else(|| AppError::Auth("Not authenticated to cloud".into()))?;

    let client = CloudClient::new(config).with_tokens(tokens);
    client.record_cache_stats(delta).await
}

/// Fetch cache stats for a specific assessment. Returns `null` if no
/// row exists yet (no LLM activity recorded). The shape matches
/// `CacheStatsResponse` from the backend route.
#[tauri::command(rename_all = "snake_case")]
pub async fn get_cache_stats_for_assessment(
    assessment_id: String,
    state: State<'_, Arc<RwLock<AppState>>>,
) -> Result<Option<serde_json::Value>> {
    let app_state = state.read().await;
    let config_dir = app_state.get_config_dir()?;
    let config = load_cloud_config(&config_dir)?;

    if !config.enabled {
        // Cloud disabled = no cache_stats data available. Return None
        // rather than erroring so the cost panel can render an empty state.
        return Ok(None);
    }

    let tokens = match load_auth_tokens(&config_dir)? {
        Some(t) => t,
        None => return Ok(None),
    };

    let client = CloudClient::new(config).with_tokens(tokens);
    client.get_cache_stats(&assessment_id).await
}

/// Fetch baseline findings + cadence state for a target. Used by the
/// team lead at Phase 1.5 of an assessment (see
/// `skills/team-assessment/SKILL.md` step 3.5) and by the frontend
/// "Baseline reuse" panel to surface the cadence counter to the user.
///
/// Returns the raw JSON response from `/findings/baseline` — the shape
/// matches `BaselineResponse` in backend-rs. Returns Ok(None) when
/// cloud isn't authenticated (so the UI can render an empty state).
#[tauri::command(rename_all = "snake_case")]
pub async fn get_baseline_findings_for_target(
    target_id: String,
    max_age_days: Option<i32>,
    state: State<'_, Arc<RwLock<AppState>>>,
) -> Result<Option<serde_json::Value>> {
    let app_state = state.read().await;
    let config_dir = app_state.get_config_dir()?;
    let config = load_cloud_config(&config_dir)?;

    if !config.enabled {
        return Ok(None);
    }

    let tokens = match load_auth_tokens(&config_dir)? {
        Some(t) => t,
        None => return Ok(None),
    };

    let client = CloudClient::new(config).with_tokens(tokens);
    Ok(Some(client.get_baseline_findings(&target_id, max_age_days).await?))
}

// =============================================================================
// SAST + RECON CACHE COMMANDS (Phase 4 + 5 of caching plan)
// =============================================================================
//
// These wrap the GET /sast-cache/lookup, POST /sast-cache,
// GET /recon-cache/lookup, POST /recon-cache endpoints so the MCP
// server (running in the Kali container) can call out via the
// Tauri-hosted desktop session. The MCP server itself doesn't have a
// cloud auth token; the desktop holds it and proxies on behalf of
// the assessment. See `docs/caching-cross-assessment-design.md` →
// "Cross-account proxy ingest" for the long-term plan.

async fn cache_client_or_err(
    state: &State<'_, Arc<RwLock<AppState>>>,
) -> Result<CloudClient> {
    let app_state = state.read().await;
    let config_dir = app_state.get_config_dir()?;
    let config = load_cloud_config(&config_dir)?;
    if !config.enabled {
        return Err(AppError::Cloud(
            "Cloud is disabled; cache endpoints are cloud-side only.".into(),
        ));
    }
    let tokens = load_auth_tokens(&config_dir)?
        .ok_or_else(|| AppError::Auth("Not authenticated to cloud".into()))?;
    Ok(CloudClient::new(config).with_tokens(tokens))
}

/// Look up a SAST cache entry. Params shape (all strings):
/// { target_id, commit_sha, scanner, scanner_version, rule_pack_hash,
///   dependency_lock_hash? }
#[tauri::command(rename_all = "snake_case")]
pub async fn sast_cache_lookup(
    params: serde_json::Value,
    state: State<'_, Arc<RwLock<AppState>>>,
) -> Result<serde_json::Value> {
    let client = cache_client_or_err(&state).await?;
    client.sast_cache_lookup(params).await
}

/// Upsert a SAST cache entry. Body shape matches the UpsertBody in
/// backend-rs/src/routes/sast_cache.rs.
#[tauri::command(rename_all = "snake_case")]
pub async fn sast_cache_upsert(
    body: serde_json::Value,
    state: State<'_, Arc<RwLock<AppState>>>,
) -> Result<serde_json::Value> {
    let client = cache_client_or_err(&state).await?;
    client.sast_cache_upsert(body).await
}

/// Look up a recon cache entry by (target_id, scan_type).
#[tauri::command(rename_all = "snake_case")]
pub async fn recon_cache_lookup(
    target_id: String,
    scan_type: String,
    state: State<'_, Arc<RwLock<AppState>>>,
) -> Result<serde_json::Value> {
    let client = cache_client_or_err(&state).await?;
    client.recon_cache_lookup(&target_id, &scan_type).await
}

/// Upsert a recon cache entry. Body matches UpsertBody in
/// backend-rs/src/routes/recon_cache.rs.
#[tauri::command(rename_all = "snake_case")]
pub async fn recon_cache_upsert(
    body: serde_json::Value,
    state: State<'_, Arc<RwLock<AppState>>>,
) -> Result<serde_json::Value> {
    let client = cache_client_or_err(&state).await?;
    client.recon_cache_upsert(body).await
}

/// Read org-level cache configuration (caching_enabled, TTLs, etc.).
/// Used by the cache settings page in the desktop UI.
#[tauri::command(rename_all = "snake_case")]
pub async fn get_org_settings(
    state: State<'_, Arc<RwLock<AppState>>>,
) -> Result<serde_json::Value> {
    let client = cache_client_or_err(&state).await?;
    client.get_org_settings().await
}

/// Update org cache settings. Body shape is partial — see backend-rs
/// UpdateBody. Any omitted field stays unchanged.
#[tauri::command(rename_all = "snake_case")]
pub async fn update_org_settings(
    body: serde_json::Value,
    state: State<'_, Arc<RwLock<AppState>>>,
) -> Result<serde_json::Value> {
    let client = cache_client_or_err(&state).await?;
    client.update_org_settings(body).await
}

/// Drift-alerts rolling-30-day summary. Drives the desktop's "needs
/// review" badge + the future auto-disable circuit.
#[tauri::command(rename_all = "snake_case")]
pub async fn get_drift_alerts_summary(
    state: State<'_, Arc<RwLock<AppState>>>,
) -> Result<serde_json::Value> {
    let client = cache_client_or_err(&state).await?;
    client.get_drift_alerts_summary().await
}
