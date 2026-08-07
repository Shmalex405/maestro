//! Self-hosted deployment configuration.
//!
//! In the managed (subscription) arrangement the desktop app learns where its
//! backend lives by POSTing the user's email to Groovy's `/api/discover`, which
//! returns the backend URL plus the Cognito settings for that org. That endpoint
//! is part of the proprietary control plane and is not something a self-hoster
//! runs.
//!
//! A self-hosted deployment supplies the same values directly, from a local
//! file the operator writes once. Everything downstream is unchanged: the
//! frontend synthesizes the exact same `Bootstrap` object the discovery flow
//! would have produced, so Cognito auth, cloud routing, and the OAST oracle all
//! work through their normal code paths.
//!
//! Config sources, highest precedence first:
//!
//!   1. Environment variables (`MAESTRO_SELF_HOSTED=1` plus `MAESTRO_*`).
//!      Useful for CI and for `tauri dev`.
//!   2. `~/.kali-mcp-pentest/self-host.json`.
//!      The normal path — a GUI app launched from Finder or the Start menu does
//!      not inherit a shell environment, so a file is the only arrangement that
//!      reliably works for a desktop install.
//!
//! Absent both, `get_self_host_config` returns `None` and the app runs the
//! managed discovery flow exactly as before. Self-hosting is strictly additive:
//! no existing install changes behavior.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tracing::{info, warn};

use crate::error::{AppError, Result};

/// How this install stores its data.
///
/// The distinction is the whole shape of the product for a self-hoster:
///
///   - `Local`  — everything on this machine. Findings, assessments, and
///                reports live in the local SQLite DB. No AWS, no Cognito, no
///                terraform, nothing to provision before first launch. Single
///                operator. This is the default for someone who just cloned
///                the repo.
///   - `Team`   — a backend the operator deployed themselves (see
///                deploy/terraform/maestro-self-host). Multiple users sign in
///                against their own Cognito pool and see the same data.
///
/// A managed subscription install has no self-host config at all and resolves
/// its backend through discovery instead; that path is untouched.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum DeploymentMode {
    #[default]
    Local,
    Team,
}

/// Everything the desktop needs in order to talk to a self-hosted deployment.
///
/// Field names match the `/api/discover` response so the frontend can build a
/// `Bootstrap` from either source without a translation layer.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SelfHostConfig {
    /// `local` or `team`. Defaults to `local` so a hand-written config that
    /// omits it gets the no-infrastructure path rather than failing validation
    /// for missing Cognito fields it was never going to have.
    #[serde(default)]
    pub mode: DeploymentMode,

    /// Org slug. Cosmetic for a single-tenant self-host, but it flows into
    /// report metadata and the assessments table, so it should be stable.
    #[serde(default)]
    pub org_id: String,
    /// Display name shown in the UI.
    #[serde(default)]
    pub customer_name: String,
    /// Base URL of the operator's own backend-rs deployment, e.g.
    /// `https://maestro.security.example.com`. No trailing slash.
    #[serde(default)]
    pub backend_url: String,

    /// AWS region of the operator's own Cognito user pool.
    #[serde(default)]
    pub cognito_region: String,
    /// The operator's own Cognito user pool ID.
    #[serde(default)]
    pub cognito_user_pool_id: String,
    /// App client ID for the desktop app on that pool.
    #[serde(default)]
    pub cognito_client_id: String,
    /// Hosted UI domain host, no scheme, e.g. `login.security.example.com`.
    /// Empty disables browser sign-in; SRP password login still works.
    #[serde(default)]
    pub cognito_domain: String,

    /// OAST listener hostname for the blind-vulnerability oracle. Empty means
    /// the oracle reports `oast_unavailable` and blind findings stay honest
    /// unverified candidates — which is the correct behavior, not a failure.
    #[serde(default)]
    pub oast_server: String,
    /// Polling token for that listener.
    ///
    /// Unlike the managed path — where the token deliberately never rides the
    /// unauthenticated `/api/discover` response — a self-hoster's token can live
    /// here, because this file is on the operator's own machine at 0600 rather
    /// than being served to anyone who knows an email address.
    #[serde(default)]
    pub oast_token: String,
}

impl SelfHostConfig {
    /// Whether this config can actually be used.
    ///
    /// Local mode needs nothing — there is no backend to route to and no pool to
    /// authenticate against, so every routing field is legitimately absent.
    ///
    /// Team mode must be able to route AND authenticate. A partial team config
    /// (backend URL but no Cognito, say) would otherwise let the startup gate
    /// skip discovery and then leave every cloud request failing with "No cloud
    /// backend configured" — blank panels and no server-side error explaining
    /// them. Rejecting it here surfaces a real error instead of half-working.
    fn is_complete(&self) -> bool {
        if self.mode == DeploymentMode::Local {
            return true;
        }
        !self.backend_url.trim().is_empty()
            && !self.cognito_region.trim().is_empty()
            && !self.cognito_user_pool_id.trim().is_empty()
            && !self.cognito_client_id.trim().is_empty()
    }

    /// Names of the fields that are required but empty. Used to tell the
    /// operator exactly what to fix rather than "invalid config".
    fn missing_fields(&self) -> Vec<&'static str> {
        let mut missing = Vec::new();
        if self.mode == DeploymentMode::Local {
            return missing;
        }
        if self.backend_url.trim().is_empty() {
            missing.push("backendUrl");
        }
        if self.cognito_region.trim().is_empty() {
            missing.push("cognitoRegion");
        }
        if self.cognito_user_pool_id.trim().is_empty() {
            missing.push("cognitoUserPoolId");
        }
        if self.cognito_client_id.trim().is_empty() {
            missing.push("cognitoClientId");
        }
        missing
    }

    /// Normalize before handing to the frontend: strip trailing slashes off the
    /// backend URL (the frontend concatenates paths onto it) and strip any
    /// scheme off the Cognito domain (the OAuth path expects a bare host and
    /// would otherwise build `https://https://...`).
    fn normalize(mut self) -> Self {
        self.backend_url = self.backend_url.trim().trim_end_matches('/').to_string();
        self.cognito_domain = self
            .cognito_domain
            .trim()
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .trim_end_matches('/')
            .to_string();
        self.oast_server = self.oast_server.trim().to_string();
        if self.org_id.trim().is_empty() {
            self.org_id = "self-hosted".to_string();
        }
        if self.customer_name.trim().is_empty() {
            self.customer_name = "Self-Hosted".to_string();
        }
        self
    }
}

/// Build-time distribution flavor.
///
/// The open-core build sets `MAESTRO_DISTRIBUTION=self-host` (see
/// tauri.self-host.conf.json and SELF-HOSTING.md). That is what lets a fresh
/// clone come up in LOCAL mode with no config file, no AWS, and no first-run
/// questions — the single biggest thing standing between "cloned the repo" and
/// "running an assessment".
///
/// Managed builds leave it unset and keep the email-discovery flow untouched.
fn distribution() -> &'static str {
    option_env!("MAESTRO_DISTRIBUTION").unwrap_or("managed")
}

/// Path of the on-disk config. Same directory the container already
/// bind-mounts, so an operator managing one Maestro install has one place to
/// look.
fn config_path() -> Option<PathBuf> {
    dirs::home_dir().map(|h| h.join(".kali-mcp-pentest").join("self-host.json"))
}

/// Read config from environment variables. `MAESTRO_SELF_HOSTED=1` is the
/// opt-in; without it we do not look at the other vars at all, so a stray
/// `MAESTRO_BACKEND_URL` in someone's shell profile can never silently
/// redirect a managed install.
fn from_env() -> Option<SelfHostConfig> {
    if std::env::var("MAESTRO_SELF_HOSTED").as_deref() != Ok("1") {
        return None;
    }

    let get = |k: &str| std::env::var(k).unwrap_or_default();

    // Explicit MAESTRO_MODE wins. Absent it, infer from whether a backend URL
    // was supplied — setting one and getting local mode (silently ignoring it)
    // would be a confusing failure.
    let mode = match get("MAESTRO_MODE").to_ascii_lowercase().as_str() {
        "local" => DeploymentMode::Local,
        "team" => DeploymentMode::Team,
        _ if !get("MAESTRO_BACKEND_URL").is_empty() => DeploymentMode::Team,
        _ => DeploymentMode::Local,
    };

    Some(SelfHostConfig {
        mode,
        org_id: get("MAESTRO_ORG_ID"),
        customer_name: get("MAESTRO_ORG_NAME"),
        backend_url: get("MAESTRO_BACKEND_URL"),
        cognito_region: get("MAESTRO_COGNITO_REGION"),
        cognito_user_pool_id: get("MAESTRO_COGNITO_USER_POOL_ID"),
        cognito_client_id: get("MAESTRO_COGNITO_CLIENT_ID"),
        cognito_domain: get("MAESTRO_COGNITO_DOMAIN"),
        oast_server: get("MAESTRO_OAST_SERVER"),
        oast_token: get("MAESTRO_OAST_TOKEN"),
    })
}

/// Read config from `~/.kali-mcp-pentest/self-host.json`. A missing file is not
/// an error — it is the normal state of a managed install. A file that exists
/// but is malformed IS an error, surfaced to the operator, because silently
/// falling through to the managed flow would look like "self-hosting doesn't
/// work" with nothing to debug.
fn from_file() -> Result<Option<SelfHostConfig>> {
    let Some(path) = config_path() else {
        return Ok(None);
    };
    if !path.exists() {
        return Ok(None);
    }

    let raw = std::fs::read_to_string(&path)?;
    let cfg: SelfHostConfig = serde_json::from_str(&raw).map_err(|e| {
        AppError::Config(format!(
            "{} is not valid Maestro self-host config: {}. \
             Expected a JSON object with backendUrl, cognitoRegion, \
             cognitoUserPoolId, and cognitoClientId.",
            path.display(),
            e
        ))
    })?;

    Ok(Some(cfg))
}

/// Outcome of resolving self-hosted config.
///
/// Three states, reported structurally rather than as `Result`, because the
/// caller has to tell them apart and cannot do so from an error string:
///
///   - `enabled: false`                → managed install, run normal discovery
///   - `enabled: true, config: Some`   → self-hosted, use this
///   - `enabled: true, error: Some`    → self-hosted but broken, STOP
///
/// The last case must be fatal: falling through to managed discovery would aim
/// the operator at a Groovy endpoint they have no account on and report
/// "discovery failed" instead of the actual problem with their file.
///
/// Deliberately never returns `Err`. If this command *could* fail, the frontend
/// would have to treat a transport-level failure (command not registered in an
/// older build, IPC hiccup) the same as a bad config — and hard-blocking
/// startup on that would be a self-inflicted outage for managed installs, which
/// have no self-host config at all. An `invoke` rejection therefore means only
/// "this build can't answer", and the frontend falls through. Same reasoning as
/// `get_test_mode_flags`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SelfHostStatus {
    pub enabled: bool,
    pub config: Option<SelfHostConfig>,
    pub error: Option<String>,
}

impl SelfHostStatus {
    fn managed() -> Self {
        Self::default()
    }

    fn broken(msg: String) -> Self {
        Self {
            enabled: true,
            config: None,
            error: Some(msg),
        }
    }

    fn active(cfg: SelfHostConfig) -> Self {
        Self {
            enabled: true,
            config: Some(cfg),
            error: None,
        }
    }
}

/// Resolve the active self-hosted config. See [`SelfHostStatus`].
#[tauri::command(rename_all = "snake_case")]
pub async fn get_self_host_config() -> Result<SelfHostStatus> {
    // Env wins so CI and `tauri dev` can override a file without editing it.
    let (cfg, source) = match from_env() {
        Some(c) => (c, "environment"),
        None => match from_file() {
            Ok(Some(c)) => (c, "config file"),
            // No config file. An open-core build defaults to local mode — the
            // whole point is that nothing has to be provisioned or written
            // before first launch. A managed build falls through to discovery.
            Ok(None) if distribution() == "self-host" => (
                SelfHostConfig {
                    mode: DeploymentMode::Local,
                    org_id: "local".to_string(),
                    customer_name: "Local".to_string(),
                    ..Default::default()
                },
                "self-host build default",
            ),
            Ok(None) => return Ok(SelfHostStatus::managed()),
            // A file that exists but won't parse is an intended-but-broken
            // self-host, not a managed install.
            Err(e) => return Ok(SelfHostStatus::broken(e.to_string())),
        },
    };

    if !cfg.is_complete() {
        let missing = cfg.missing_fields().join(", ");
        return Ok(SelfHostStatus::broken(format!(
            "Self-hosted mode is enabled via {source} but the config is \
             incomplete — missing: {missing}. See SELF-HOSTING.md."
        )));
    }

    let cfg = cfg.normalize();
    match cfg.mode {
        DeploymentMode::Local => info!(
            "Local mode active (from {}): all data stays in the local SQLite DB; \
             no backend, no sign-in",
            source
        ),
        DeploymentMode::Team => info!(
            "Team mode active (from {}): org={} backend={}",
            source, cfg.org_id, cfg.backend_url
        ),
    }
    if cfg.oast_server.is_empty() {
        warn!(
            "No OAST listener configured — the blind-vulnerability oracle will \
             report oast_unavailable and blind findings will stay unverified \
             candidates."
        );
    }

    Ok(SelfHostStatus::active(cfg))
}

/// True when this install keeps its data on this machine.
///
/// Synchronous and cheap (one small file read) so call sites that must NOT
/// attempt a cloud round trip can check inline. Defaults to `false` — i.e.
/// "cloud" — on any doubt, matching the frontend's DEFAULT_MODE: a
/// misdetected cloud install fails visibly, whereas a misdetected local one
/// would silently skip promoting a completed assessment.
pub fn is_local_deployment() -> bool {
    if let Some(cfg) = from_env() {
        return cfg.mode == DeploymentMode::Local;
    }
    match from_file() {
        Ok(Some(cfg)) => cfg.mode == DeploymentMode::Local,
        // No config at all = managed install = cloud.
        Ok(None) => false,
        // Unreadable/!parsing config: treat as cloud so the failure surfaces
        // through the normal startup error path rather than here.
        Err(_) => false,
    }
}

/// Write a team-mode config from the terraform output.
///
/// `deploy/terraform/maestro-self-host` emits `desktop_self_host_json` — exactly
/// the shape of this file. Accepting it verbatim means an operator pastes one
/// blob instead of hand-transcribing a pool ID, a client ID, a region and a URL,
/// which is the step people get wrong.
///
/// Validated before writing: a config that would fail `is_complete` is rejected
/// here with the missing field names, rather than being written and then failing
/// at next launch when the context for fixing it is gone.
#[tauri::command(rename_all = "snake_case")]
pub async fn set_deployment_config(config_json: String) -> Result<SelfHostConfig> {
    let cfg: SelfHostConfig = serde_json::from_str(&config_json).map_err(|e| {
        AppError::Config(format!(
            "That is not a valid Maestro deployment config: {e}. Paste the \
             output of `terraform output -raw desktop_self_host_json`."
        ))
    })?;

    // A pasted terraform output has no `mode` field, so serde defaults it to
    // Local — which would be wrong for a blob that carries a backend URL. Infer
    // team from the payload instead of trusting the default.
    let mut cfg = cfg;
    if !cfg.backend_url.trim().is_empty() {
        cfg.mode = DeploymentMode::Team;
    }

    if !cfg.is_complete() {
        return Err(AppError::Config(format!(
            "Deployment config is incomplete — missing: {}. Re-run \
             `terraform output -raw desktop_self_host_json`.",
            cfg.missing_fields().join(", ")
        )));
    }

    let cfg = cfg.normalize();
    write_config(&cfg)?;
    info!(
        "Deployment config written: mode={:?} backend={}",
        cfg.mode, cfg.backend_url
    );
    Ok(cfg)
}

/// Serialize a config to `~/.kali-mcp-pentest/self-host.json` at 0600.
fn write_config(cfg: &SelfHostConfig) -> Result<()> {
    let Some(path) = config_path() else {
        return Err(AppError::Config(
            "Could not resolve the home directory to write self-host.json".into(),
        ));
    };
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&path, serde_json::to_string_pretty(cfg)?)?;

    // The team config can carry oast_token, so 0600 is not optional here.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

/// Persist the deployment mode chosen at first launch.
///
/// Writes `~/.kali-mcp-pentest/self-host.json`. Used by the first-run picker for
/// the local case, where there is nothing else to configure — the whole point is
/// that a user who just cloned the repo never edits a file or provisions AWS.
///
/// Team mode is deliberately NOT settable here: it needs a backend URL and
/// Cognito IDs that come from `terraform output desktop_self_host_json`, so
/// writing a half-formed team config from the UI would just produce the
/// incomplete-config error. The picker sends team users to that output instead.
#[tauri::command(rename_all = "snake_case")]
pub async fn set_local_mode() -> Result<()> {
    write_config(&SelfHostConfig {
        mode: DeploymentMode::Local,
        org_id: "local".to_string(),
        customer_name: "Local".to_string(),
        ..Default::default()
    })?;
    info!("Local mode persisted");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn complete() -> SelfHostConfig {
        SelfHostConfig {
            mode: DeploymentMode::Team,
            org_id: "acme".into(),
            customer_name: "Acme".into(),
            backend_url: "https://maestro.acme.test/".into(),
            cognito_region: "us-west-2".into(),
            cognito_user_pool_id: "us-west-2_abc123".into(),
            cognito_client_id: "client123".into(),
            cognito_domain: "https://login.acme.test/".into(),
            oast_server: " oast.acme.test ".into(),
            oast_token: "tok".into(),
        }
    }

    #[test]
    fn complete_config_is_accepted() {
        assert!(complete().is_complete());
        assert!(complete().missing_fields().is_empty());
    }

    #[test]
    fn missing_cognito_is_rejected_with_field_names() {
        let mut c = complete();
        c.cognito_client_id = "  ".into();
        c.cognito_region = String::new();
        assert!(!c.is_complete());
        let missing = c.missing_fields();
        assert!(missing.contains(&"cognitoClientId"));
        assert!(missing.contains(&"cognitoRegion"));
        assert!(!missing.contains(&"backendUrl"));
    }

    #[test]
    fn normalize_strips_trailing_slash_and_scheme() {
        let c = complete().normalize();
        assert_eq!(c.backend_url, "https://maestro.acme.test");
        assert_eq!(c.cognito_domain, "login.acme.test");
        assert_eq!(c.oast_server, "oast.acme.test");
    }

    #[test]
    fn normalize_fills_blank_identity_fields() {
        let mut c = complete();
        c.org_id = String::new();
        c.customer_name = "   ".into();
        let c = c.normalize();
        assert_eq!(c.org_id, "self-hosted");
        assert_eq!(c.customer_name, "Self-Hosted");
    }

    #[test]
    fn local_mode_needs_no_backend_or_cognito() {
        // The whole point of local mode: nothing to provision, so an otherwise
        // empty config must validate. If this regresses, a fresh clone gets an
        // incomplete-config error instead of a working app.
        let c = SelfHostConfig {
            mode: DeploymentMode::Local,
            ..Default::default()
        };
        assert!(c.is_complete());
        assert!(c.missing_fields().is_empty());
    }

    #[test]
    fn team_mode_still_requires_the_routing_fields() {
        let c = SelfHostConfig {
            mode: DeploymentMode::Team,
            ..Default::default()
        };
        assert!(!c.is_complete());
        assert_eq!(c.missing_fields().len(), 4);
    }

    #[test]
    fn mode_defaults_to_local_when_absent_from_json() {
        // A hand-written config omitting `mode` should get the
        // no-infrastructure path, not a validation failure for missing Cognito.
        let c: SelfHostConfig = serde_json::from_str("{}").expect("parses");
        assert_eq!(c.mode, DeploymentMode::Local);
        assert!(c.is_complete());
    }

    #[test]
    fn mode_serializes_lowercase_for_the_frontend() {
        let json = serde_json::to_string(&SelfHostConfig {
            mode: DeploymentMode::Team,
            ..Default::default()
        })
        .expect("serializes");
        assert!(json.contains("\"mode\":\"team\""), "got {json}");
    }

    #[test]
    fn managed_is_the_default_distribution() {
        // A managed build must never be silently repointed at local storage.
        // This asserts the compiled-in default rather than the resolution
        // (which touches the filesystem) — if MAESTRO_DISTRIBUTION ever gains a
        // build-script default, this catches it.
        assert_eq!(distribution(), "managed");
    }

    #[test]
    fn status_states_are_distinguishable_by_the_frontend() {
        // The frontend branches on these three shapes. If `managed` ever
        // reported enabled=true, or `broken` carried a config, a self-hoster's
        // bad file would silently route them at Groovy's platform instead of
        // stopping with the real error.
        let managed = SelfHostStatus::managed();
        assert!(!managed.enabled);
        assert!(managed.config.is_none());
        assert!(managed.error.is_none());

        let broken = SelfHostStatus::broken("missing: backendUrl".into());
        assert!(broken.enabled);
        assert!(broken.config.is_none());
        assert_eq!(broken.error.as_deref(), Some("missing: backendUrl"));

        let active = SelfHostStatus::active(complete().normalize());
        assert!(active.enabled);
        assert!(active.error.is_none());
        assert_eq!(
            active.config.expect("config present").backend_url,
            "https://maestro.acme.test"
        );
    }

    #[test]
    fn status_serializes_with_the_keys_the_frontend_reads() {
        let json = serde_json::to_string(&SelfHostStatus::managed()).expect("serializes");
        // A rename here makes `status?.enabled` undefined, which reads as
        // "managed" — silently disabling self-hosting rather than failing loudly.
        assert!(json.contains("\"enabled\":false"), "got {json}");
        assert!(json.contains("\"config\":null"), "got {json}");
        assert!(json.contains("\"error\":null"), "got {json}");
    }

    #[test]
    fn camel_case_json_round_trips() {
        // The frontend consumes these field names directly when building a
        // Bootstrap; a rename here silently breaks self-hosted startup.
        let json = r#"{
            "orgId": "acme",
            "customerName": "Acme",
            "backendUrl": "https://maestro.acme.test",
            "cognitoRegion": "us-west-2",
            "cognitoUserPoolId": "us-west-2_abc123",
            "cognitoClientId": "client123"
        }"#;
        let c: SelfHostConfig = serde_json::from_str(json).expect("parses");
        assert!(c.is_complete());
        // Omitted optional fields default rather than failing the parse.
        assert_eq!(c.cognito_domain, "");
        assert_eq!(c.oast_token, "");
    }
}
