// Claude credential management.
//
// Two modes, picked by the user in Settings → Claude:
//
//   OAuth   — default. Container's /root/.claude/.credentials.json is the
//             source of truth. No env vars get injected; `claude` reads its
//             own credential file. Each pentester signs into their own
//             Pro/Max account inside the container.
//
//   ApiKey  — BYO. The user pastes an Anthropic Console key into the
//             Settings page; we store it in the macOS Keychain and inject
//             ANTHROPIC_API_KEY=<value> on every `docker exec` that
//             launches `claude`.
//
// Storage:
//   - Active mode is a tiny `claude-auth.yml` next to the other configs in
//     ~/.kali-mcp-pentest/. We do NOT persist the API key here — it goes
//     to the platform keychain via the `keyring` crate.

use std::path::PathBuf;

use keyring::Entry;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::error::{AppError, Result};

const KEYRING_SERVICE: &str = "com.groovysec.maestro";
const KEYRING_USER_ANTHROPIC: &str = "anthropic_api_key";
const SETTINGS_FILE: &str = "claude-auth.yml";

fn config_dir() -> Result<PathBuf> {
    let dir = dirs::home_dir()
        .ok_or_else(|| AppError::Config("Home directory not resolvable".into()))?
        .join(".kali-mcp-pentest");
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn settings_path() -> Result<PathBuf> {
    Ok(config_dir()?.join(SETTINGS_FILE))
}

// =============================================================================
// Container credential reconciliation
// =============================================================================
//
// The container's `/root/.claude` is the bind-mounted `claude-home` dir (see
// `docker.rs::expected_binds` → `{config}/claude-home:/root/.claude`), so the
// OAuth login file lives on the host at
// `~/.kali-mcp-pentest/claude-home/.credentials.json`. We reconcile it here
// rather than via `docker exec` so it works even when the container is stopped.

/// Host path of the container's `/root/.claude` (the bind-mounted claude-home).
fn claude_home_dir() -> Result<PathBuf> {
    let dir = config_dir()?.join("claude-home");
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

const OAUTH_CREDS_FILE: &str = ".credentials.json";
const OAUTH_CREDS_BACKUP: &str = ".credentials.json.maestro-oauth-bak";

/// apiKeyHelper script filename in claude-home, plus its path *as seen from
/// inside the container* (claude-home is bind-mounted at /root/.claude).
const API_KEY_HELPER_FILE: &str = "api-key-helper.sh";
const API_KEY_HELPER_CONTAINER_PATH: &str = "/root/.claude/api-key-helper.sh";
/// Claude Code's user settings inside the container (claude-home/settings.json).
const CONTAINER_SETTINGS_FILE: &str = "settings.json";

/// Env var the apiKeyHelper script echoes. Deliberately **not**
/// `ANTHROPIC_API_KEY` — that exact name is what makes Claude Code show the
/// interactive "Detected a custom API key… use it?" confirmation on launch
/// (which stalls the automated assessment and collides with the auto-injected
/// first prompt). Keys obtained via apiKeyHelper are trusted with no prompt.
pub const KEY_ENV_VAR: &str = "MAESTRO_ANTHROPIC_KEY";

/// Write the apiKeyHelper script into claude-home (idempotent). Claude Code
/// runs it to obtain the key and trusts the result silently. The script just
/// echoes whatever we inject as `MAESTRO_ANTHROPIC_KEY` at `docker exec` time,
/// so the actual key never lives on disk — only this stub does.
fn ensure_api_key_helper_script() -> Result<()> {
    let path = claude_home_dir()?.join(API_KEY_HELPER_FILE);
    let script = "#!/bin/sh\n# Maestro-managed: returns the injected key for Claude Code's\n# apiKeyHelper so no interactive \"use this key?\" prompt appears.\nprintf '%s' \"${MAESTRO_ANTHROPIC_KEY:-}\"\n";
    std::fs::write(&path, script)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))?;
    }
    Ok(())
}

/// Set or clear `apiKeyHelper` in the container's Claude `settings.json`,
/// preserving every other field. Enabled for ApiKey (so the injected key is
/// used without a prompt); cleared for OAuth (so a stale helper can't
/// interfere with the subscription login).
fn set_api_key_helper(enabled: bool) -> Result<()> {
    let path = claude_home_dir()?.join(CONTAINER_SETTINGS_FILE);
    let mut root: serde_json::Value = if path.exists() {
        std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_else(|| serde_json::json!({}))
    } else {
        serde_json::json!({})
    };
    if !root.is_object() {
        root = serde_json::json!({});
    }
    let obj = root.as_object_mut().expect("json object");
    if enabled {
        obj.insert(
            "apiKeyHelper".to_string(),
            serde_json::Value::String(API_KEY_HELPER_CONTAINER_PATH.to_string()),
        );
    } else {
        obj.remove("apiKeyHelper");
    }
    let serialized = serde_json::to_string_pretty(&root)
        .map_err(|e| AppError::Config(format!("Failed to serialize claude settings.json: {}", e)))?;
    std::fs::write(&path, serialized)?;
    Ok(())
}

/// Ensure the **container-only** workflow-edit guard is present in the
/// container's Claude user settings (`claude-home/settings.json`, bind-mounted
/// at `/root/.claude/settings.json`).
///
/// This deny used to live in the committed project `.claude/settings.json`, but
/// that file is read by BOTH the in-container assessment claude AND host-side
/// development — so it also blocked legitimate host edits to the workflow
/// chunks. Moving it here scopes it to the container only (the host reads its
/// own `~/.claude`, never `claude-home`). The intent is unchanged: keep the
/// in-container assessment claude from rewriting its own orchestration mid-run.
/// Idempotent — safe to re-apply on every launch; merges into any existing
/// `permissions.deny` without clobbering other rules.
fn ensure_workflow_edit_guard() -> Result<()> {
    const RULES: [&str; 2] = ["Edit(.claude/workflows/**)", "Write(.claude/workflows/**)"];
    let path = claude_home_dir()?.join(CONTAINER_SETTINGS_FILE);
    let mut root: serde_json::Value = if path.exists() {
        std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_else(|| serde_json::json!({}))
    } else {
        serde_json::json!({})
    };
    if !root.is_object() {
        root = serde_json::json!({});
    }
    let perms = root
        .as_object_mut()
        .expect("json object")
        .entry("permissions")
        .or_insert_with(|| serde_json::json!({}));
    if !perms.is_object() {
        *perms = serde_json::json!({});
    }
    let deny = perms
        .as_object_mut()
        .expect("permissions object")
        .entry("deny")
        .or_insert_with(|| serde_json::json!([]));
    if !deny.is_array() {
        *deny = serde_json::json!([]);
    }
    let deny_arr = deny.as_array_mut().expect("deny array");
    for rule in RULES {
        if !deny_arr.iter().any(|v| v.as_str() == Some(rule)) {
            deny_arr.push(serde_json::Value::String(rule.to_string()));
        }
    }
    let serialized = serde_json::to_string_pretty(&root)
        .map_err(|e| AppError::Config(format!("Failed to serialize claude settings.json: {}", e)))?;
    std::fs::write(&path, serialized)?;
    Ok(())
}

/// Make the container's live credential state match the selected mode.
///
/// Two things must agree with the mode:
///   1. **OAuth login** (`.credentials.json`) — Claude Code prefers it over
///      env/helper auth, so for ApiKey we move it aside (and restore it for
///      OAuth). Moved, not deleted, so switching back needs no re-login.
///      Without this, ApiKey silently does nothing.
///   2. **apiKeyHelper** — for ApiKey we point Claude Code at our helper
///      script so the injected key is used WITHOUT the "Detected a custom
///      API key… use it?" prompt (which stalls the automated launch).
///      Cleared for OAuth.
fn reconcile_container_auth(mode: CredentialMode) -> Result<()> {
    let home = claude_home_dir()?;
    let live = home.join(OAUTH_CREDS_FILE);
    let bak = home.join(OAUTH_CREDS_BACKUP);

    // Container-only workflow-edit guard. Re-applied on every launch (idempotent)
    // so it self-heals if the settings file is recreated. Best-effort — a failure
    // here must not block the assessment from launching.
    if let Err(e) = ensure_workflow_edit_guard() {
        warn!("Could not write container workflow-edit guard: {}", e);
    }

    match mode {
        // Env/helper auth must be the only source → neutralize the OAuth login
        // and route the key through the (no-prompt) apiKeyHelper.
        CredentialMode::ApiKey => {
            if live.exists() {
                // The most-recent login becomes the restorable backup.
                let _ = std::fs::remove_file(&bak);
                std::fs::rename(&live, &bak)?;
                info!(
                    "Moved OAuth credentials aside for {:?} mode so env/helper auth is authoritative",
                    mode
                );
            }
            ensure_api_key_helper_script()?;
            set_api_key_helper(true)?;
        }
        // Restore a prior login (never clobber a fresh in-container `claude
        // login`) and drop the helper so the subscription login is used.
        CredentialMode::Oauth => {
            if !live.exists() && bak.exists() {
                std::fs::rename(&bak, &live)?;
                info!("Restored OAuth credentials for OAuth mode");
            }
            set_api_key_helper(false)?;
        }
    }
    Ok(())
}

// =============================================================================
// Active credential mode
// =============================================================================

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CredentialMode {
    Oauth,
    ApiKey,
}

impl Default for CredentialMode {
    fn default() -> Self {
        Self::Oauth
    }
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct PersistedSettings {
    #[serde(default)]
    mode: CredentialMode,
}

fn read_settings() -> PersistedSettings {
    let Ok(path) = settings_path() else {
        return PersistedSettings::default();
    };
    if !path.exists() {
        return PersistedSettings::default();
    }
    std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| serde_yaml::from_str(&s).ok())
        .unwrap_or_default()
}

fn write_settings(settings: &PersistedSettings) -> Result<()> {
    let path = settings_path()?;
    let yaml = serde_yaml::to_string(settings)
        .map_err(|e| AppError::Config(format!("Failed to serialize claude-auth: {}", e)))?;
    std::fs::write(&path, yaml)?;
    Ok(())
}

// =============================================================================
// API key (Keychain)
// =============================================================================

fn keyring_entry() -> Result<Entry> {
    Entry::new(KEYRING_SERVICE, KEYRING_USER_ANTHROPIC)
        .map_err(|e| AppError::Other(format!("Keyring init failed: {}", e)))
}

#[tauri::command]
pub async fn set_claude_api_key(key: String) -> Result<()> {
    if !key.starts_with("sk-ant-") {
        return Err(AppError::Validation(
            "Invalid Anthropic API key format (expected sk-ant-…)".into(),
        ));
    }
    keyring_entry()?
        .set_password(&key)
        .map_err(|e| AppError::Other(format!("Keyring write failed: {}", e)))?;
    info!("Stored Anthropic API key in keyring");
    Ok(())
}

/// Internal helper — returns the stored API key for env injection.
/// Not exposed as a Tauri command; we never want the frontend reading the
/// raw key after the user saves it.
fn read_stored_api_key() -> Option<String> {
    let entry = keyring_entry().ok()?;
    match entry.get_password() {
        Ok(p) => Some(p),
        Err(keyring::Error::NoEntry) => None,
        Err(e) => {
            warn!("Keyring read failed: {}", e);
            None
        }
    }
}

#[tauri::command]
pub async fn clear_claude_api_key() -> Result<()> {
    let entry = keyring_entry()?;
    match entry.delete_credential() {
        Ok(_) => Ok(()),
        Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(AppError::Other(format!("Keyring delete failed: {}", e))),
    }
}

/// Validate a key without persisting. Used by the Settings UI to preflight
/// a paste before the user clicks Save.
#[tauri::command]
pub async fn test_claude_api_key(key: String) -> Result<bool> {
    crate::claude_auth::test_anthropic_api_key(&key).await
}

// =============================================================================
// Auth state — what the Settings UI renders
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaudeAuthState {
    pub mode: CredentialMode,
    pub oauth_authenticated: bool,
    pub api_key_present: bool,
}

#[tauri::command]
pub async fn get_claude_auth_state() -> Result<ClaudeAuthState> {
    let mode = read_settings().mode;
    let oauth_authenticated = check_oauth_in_container().await;
    let api_key_present = read_stored_api_key().is_some();

    Ok(ClaudeAuthState {
        mode,
        oauth_authenticated,
        api_key_present,
    })
}

#[tauri::command]
pub async fn set_active_credential_mode(mode: CredentialMode) -> Result<()> {
    let mut settings = read_settings();
    settings.mode = mode;
    write_settings(&settings)?;
    info!("Active Claude credential mode set to {:?}", mode);

    // Reconcile the container's credential state to the new selection right
    // now — move OAuth creds aside for ApiKey, restore for OAuth — so the
    // toggle "takes effect" immediately rather than only on the next terminal
    // launch, and so `get_claude_auth_state` reports the true OAuth state.
    // Resolving via `get_claude_container_env` also handles the case where
    // ApiKey can't actually be used (it falls back to OAuth and restores the
    // creds accordingly). Non-fatal.
    if let Err(e) = get_claude_container_env().await {
        warn!("Could not reconcile container credentials after mode change: {}", e);
    }
    Ok(())
}

/// Check whether the in-container `claude` CLI has saved OAuth credentials
/// at the canonical path. Uses the bollard Docker daemon API (same as
/// `docker.rs`) instead of shelling out to the `docker` CLI — the macOS
/// Tauri GUI runs with a minimal PATH and `docker` isn't always
/// resolvable from there, which made this check return false even when
/// the credential file was present.
async fn check_oauth_in_container() -> bool {
    use bollard::exec::{CreateExecOptions, StartExecResults};
    use futures_util::StreamExt;

    let docker = match bollard::Docker::connect_with_local_defaults() {
        Ok(d) => d,
        Err(_) => return false,
    };

    let exec = match docker
        .create_exec(
            "kali-pentest",
            CreateExecOptions::<&str> {
                attach_stdout: Some(true),
                attach_stderr: Some(false),
                cmd: Some(vec!["test", "-f", "/root/.claude/.credentials.json"]),
                ..Default::default()
            },
        )
        .await
    {
        Ok(e) => e,
        Err(_) => return false,
    };

    // Drain the stream so the exec record is finalized, then inspect
    // exit code. `test -f` exits 0 on success, 1 on missing.
    if let Ok(StartExecResults::Attached { mut output, .. }) =
        docker.start_exec(&exec.id, None).await
    {
        while output.next().await.is_some() {}
    }
    docker
        .inspect_exec(&exec.id)
        .await
        .ok()
        .and_then(|r| r.exit_code)
        .map(|c| c == 0)
        .unwrap_or(false)
}

// =============================================================================
// Container env injection
// =============================================================================
//
// `terminal-view.tsx` calls this before each `docker exec ... claude` to
// figure out which env vars to forward via `-e KEY=VALUE`. The frontend
// turns the returned map into CLI flags; we don't render the values to
// the UI, so the API key path stays in process memory only.

/// The Claude model every assessment session runs on.
///
/// This is the single source of truth for "which Opus" Maestro drives. We
/// inject it as `ANTHROPIC_MODEL` into the container env for ALL auth modes
/// (OAuth/Max, BYO key) so the model is deterministic and decoupled
/// from whatever the containerized `claude` CLI happens to default to. The
/// model string is forwarded straight to the Anthropic API, so this pins the
/// model regardless of the bundled CLI version (an older CLI defaulting to a
/// previous Opus is overridden by this).
///
/// **To upgrade:** bump this constant after validating the new model doesn't
/// regress assessment findings/severity, then ship a release. Keep it roughly
/// in step with the CLI version pinned in `docker/Dockerfile.kali`. For an
/// ad-hoc override without a rebuild (testing a new model, per-deploy pin),
/// set the `MAESTRO_CLAUDE_MODEL` env var — `resolve_claude_model()` prefers it.
///
/// Note: the Dockerfile CLI pin also has a **Workflow floor** (≥ 2.1.162) —
/// `/assess` orchestrates via the built-in Workflow tool. When bumping the CLI
/// pin alongside this model, never drop below that floor (see the comment on
/// the `claude-code` `RUN` line in `docker/Dockerfile.kali`).
pub const DEFAULT_CLAUDE_MODEL: &str = "claude-opus-4-8";

/// Resolve the Claude model to pin for this session. Prefers the
/// `MAESTRO_CLAUDE_MODEL` env override (escape hatch for testing / per-deploy
/// pins without a rebuild); otherwise falls back to [`DEFAULT_CLAUDE_MODEL`].
fn resolve_claude_model() -> String {
    std::env::var("MAESTRO_CLAUDE_MODEL")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| DEFAULT_CLAUDE_MODEL.to_string())
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ClaudeContainerEnv {
    /// Mode that resolved — useful for telemetry / status badges.
    pub mode: CredentialMode,
    /// Map of env vars to inject. Always carries `ANTHROPIC_MODEL` (the pinned
    /// model); OAuth otherwise relies on the container .credentials.json for
    /// auth, BYO key adds the key via the apiKeyHelper.
    pub env: Vec<(String, String)>,
    /// Set when the resolved mode can't actually be used (e.g. user picked
    /// API-key mode but no key is saved). Falls back to OAuth in that case so
    /// the UI still launches — frontend should surface this as a non-blocking
    /// warning.
    pub fallback_reason: Option<String>,
}

#[tauri::command]
pub async fn get_claude_container_env() -> Result<ClaudeContainerEnv> {
    let requested = read_settings().mode;
    // Pin the model for every mode — see DEFAULT_CLAUDE_MODEL. `ANTHROPIC_MODEL`
    // is honored by the Claude Code CLI regardless of auth mode, so this
    // overrides the CLI's built-in default (which lags behind new Opus
    // releases until the bundled CLI is rebuilt).
    let model = resolve_claude_model();

    let result = match requested {
        CredentialMode::Oauth => ClaudeContainerEnv {
            mode: CredentialMode::Oauth,
            env: vec![("ANTHROPIC_MODEL".into(), model)],
            fallback_reason: None,
        },

        CredentialMode::ApiKey => {
            if let Some(key) = read_stored_api_key() {
                ClaudeContainerEnv {
                    mode: CredentialMode::ApiKey,
                    // Passed to the apiKeyHelper (NOT ANTHROPIC_API_KEY) so no
                    // "use this key?" prompt fires. See reconcile_container_auth.
                    env: vec![
                        (KEY_ENV_VAR.to_string(), key),
                        ("ANTHROPIC_MODEL".into(), model),
                    ],
                    fallback_reason: None,
                }
            } else {
                ClaudeContainerEnv {
                    mode: CredentialMode::Oauth,
                    env: vec![("ANTHROPIC_MODEL".into(), model)],
                    fallback_reason: Some(
                        "API key mode is selected but no key is saved — falling back to OAuth"
                            .into(),
                    ),
                }
            }
        }

    };

    // Reconcile the container's OAuth login to the mode that ACTUALLY runs
    // (`result.mode` already reflects any fallback to OAuth). This is what makes
    // ApiKey truly take effect: without moving `.credentials.json` aside,
    // `claude` ignores the env-var auth. Non-fatal — a filesystem hiccup
    // shouldn't block launching.
    if let Err(e) = reconcile_container_auth(result.mode) {
        warn!(
            "Could not reconcile container auth for {:?} mode: {}",
            result.mode, e
        );
    }

    Ok(result)
}

// =============================================================================
// One-time migration: drop legacy llm-config.yml from the Ollama era
// =============================================================================

/// Called once on app boot. If a legacy `llm-config.yml` exists from the
/// Ollama-supporting builds (≤ 0.1.19), delete it and log. We don't surface
/// a toast — users don't need to know, and the new auth flow renders the
/// right state regardless of whether the old file was there.
pub fn migrate_legacy_llm_config() {
    let Ok(dir) = config_dir() else { return };
    let path = dir.join("llm-config.yml");
    if path.exists() {
        match std::fs::remove_file(&path) {
            Ok(_) => info!(
                "Removed legacy llm-config.yml ({}) — local LLM support was removed in 0.1.20",
                path.display()
            ),
            Err(e) => warn!("Could not remove legacy llm-config.yml: {}", e),
        }
    }
    // Also clean up the project-config copy that the old save handler wrote.
    if let Some(proj_root) = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
    {
        let proj_path = proj_root.join("config").join("llm-config.yml");
        if proj_path.exists() {
            let _ = std::fs::remove_file(&proj_path);
        }
    }
}
