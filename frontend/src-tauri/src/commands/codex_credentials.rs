// Codex (OpenAI) credential management.
//
// Mirror of `credentials.rs` for the parallel Codex brain. Two modes,
// picked by the user in Settings → Codex:
//
//   OAuth   — default. Container's /root/.codex/auth.json is the source
//             of truth. The Codex CLI itself runs the device-code flow
//             inside the terminal pane (`codex login --device-auth`):
//             prints a URL + 8-digit code, the user enters the code in
//             their host browser, the container's auth.json gets
//             populated. Persisted across container restarts via the
//             /root/.codex bind mount.
//
//   ApiKey  — BYO. The user pastes an OpenAI API key into the Settings
//             page; we store it in the macOS Keychain and inject
//             OPENAI_API_KEY=<value> on every `docker exec` that
//             launches `codex`.
//
// Storage:
//   - Active mode is a tiny `codex-auth.yml` next to the other configs in
//     ~/.kali-mcp-pentest/. We do NOT persist the API key here — it goes
//     to the platform keychain via the `keyring` crate. The keychain
//     entry uses the same service ("com.groovysec.maestro") as the
//     Anthropic key but a distinct user ("openai_api_key") so the two
//     entries coexist cleanly.

use std::path::PathBuf;

use keyring::Entry;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::error::{AppError, Result};

const KEYRING_SERVICE: &str = "com.groovysec.maestro";
const KEYRING_USER_OPENAI: &str = "openai_api_key";
const SETTINGS_FILE: &str = "codex-auth.yml";

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
// Active credential mode
// =============================================================================

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CodexCredentialMode {
    Oauth,
    ApiKey,
}

impl Default for CodexCredentialMode {
    fn default() -> Self {
        Self::Oauth
    }
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct PersistedSettings {
    #[serde(default)]
    mode: CodexCredentialMode,
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
        .map_err(|e| AppError::Config(format!("Failed to serialize codex-auth: {}", e)))?;
    std::fs::write(&path, yaml)?;
    Ok(())
}

// =============================================================================
// API key (Keychain)
// =============================================================================

fn keyring_entry() -> Result<Entry> {
    Entry::new(KEYRING_SERVICE, KEYRING_USER_OPENAI)
        .map_err(|e| AppError::Other(format!("Keyring init failed: {}", e)))
}

#[tauri::command]
pub async fn set_codex_api_key(key: String) -> Result<()> {
    if !key.starts_with("sk-") {
        return Err(AppError::Validation(
            "Invalid OpenAI API key format (expected sk-…)".into(),
        ));
    }
    keyring_entry()?
        .set_password(&key)
        .map_err(|e| AppError::Other(format!("Keyring write failed: {}", e)))?;
    info!("Stored OpenAI API key in keyring");
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
pub async fn clear_codex_api_key() -> Result<()> {
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
pub async fn test_codex_api_key(key: String) -> Result<bool> {
    crate::codex_auth::test_openai_api_key(&key).await
}

// =============================================================================
// Auth state — what the Settings UI renders
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodexAuthState {
    pub mode: CodexCredentialMode,
    pub oauth_authenticated: bool,
    pub api_key_present: bool,
}

#[tauri::command]
pub async fn get_codex_auth_state() -> Result<CodexAuthState> {
    let mode = read_settings().mode;
    let oauth_authenticated = check_oauth_in_container().await;
    let api_key_present = read_stored_api_key().is_some();

    Ok(CodexAuthState {
        mode,
        oauth_authenticated,
        api_key_present,
    })
}

#[tauri::command]
pub async fn set_active_codex_credential_mode(mode: CodexCredentialMode) -> Result<()> {
    let mut settings = read_settings();
    settings.mode = mode;
    write_settings(&settings)?;
    info!("Active Codex credential mode set to {:?}", mode);
    Ok(())
}

/// Check whether the in-container `codex` CLI has saved auth credentials
/// at the canonical path. Mirrors the Claude check (which tests for
/// `/root/.claude/.credentials.json`); we test for `/root/.codex/auth.json`,
/// which Codex CLI writes after a successful `codex login` (browser or
/// device-code flow).
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
                cmd: Some(vec!["test", "-f", "/root/.codex/auth.json"]),
                ..Default::default()
            },
        )
        .await
    {
        Ok(e) => e,
        Err(_) => return false,
    };

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
// `codex-terminal-view.tsx` calls this before each `docker exec ... codex`
// to figure out which env vars to forward via `-e KEY=VALUE`. The frontend
// turns the returned map into CLI flags; we don't render the values to
// the UI, so the API key path stays in process memory only.

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CodexContainerEnv {
    /// Mode that resolved — useful for telemetry / status badges.
    pub mode: CodexCredentialMode,
    /// Map of env vars to inject. Empty for OAuth (container auth.json
    /// drives auth on its own).
    pub env: Vec<(String, String)>,
    /// Set when the resolved mode can't actually be used (e.g. user picked
    /// API-key mode but no key is saved). Falls back to OAuth in that case so
    /// the UI still launches — frontend should surface this as a non-blocking
    /// warning.
    pub fallback_reason: Option<String>,
}

#[tauri::command]
pub async fn get_codex_container_env() -> Result<CodexContainerEnv> {
    let requested = read_settings().mode;

    match requested {
        CodexCredentialMode::Oauth => Ok(CodexContainerEnv {
            mode: CodexCredentialMode::Oauth,
            env: vec![],
            fallback_reason: None,
        }),

        CodexCredentialMode::ApiKey => {
            if let Some(key) = read_stored_api_key() {
                Ok(CodexContainerEnv {
                    mode: CodexCredentialMode::ApiKey,
                    env: vec![("OPENAI_API_KEY".into(), key)],
                    fallback_reason: None,
                })
            } else {
                Ok(CodexContainerEnv {
                    mode: CodexCredentialMode::Oauth,
                    env: vec![],
                    fallback_reason: Some(
                        "API key mode is selected but no key is saved — falling back to OAuth"
                            .into(),
                    ),
                })
            }
        }
    }
}
