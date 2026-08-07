//! Cloud credential validation — save-time probes.
//!
//! When a user adds a cloud account in the desktop UI, this module runs
//! a small non-mutating call against the credential they configured to
//! confirm it actually resolves before we persist the account. The form
//! gates its **Add Account** button on the probe returning ok=true.
//!
//! Architecture decision (2026-05-13):
//! Probes shell out to the existing cloud CLIs (`aws`, `az`, `gcloud`,
//! `kubectl`) inside the running Kali container rather than going
//! through pure-Rust SDKs. Three reasons:
//!  1. The same CLIs run when assessments actually execute, so the
//!     probe exercises the *real* credential resolution path — no
//!     "probe says ok, assessment says AccessDenied" surprises.
//!  2. We avoid pulling four heavyweight cloud SDKs (`aws-config`,
//!     `azure_identity`, `google-cloud-auth`, `kube`) into the desktop
//!     binary just for credential validation. The CLIs are already in
//!     the Kali image.
//!  3. Each CLI emits structured JSON via `--output json` (or HTTPS
//!     directly to OAuth endpoints), so error parsing stays clean.
//!
//! The probe is fast (typically 1–3 seconds per provider) because every
//! cell hits exactly one read-only API call.

use crate::commands::config::CloudAccountScope;
use crate::docker::DockerManager;
use crate::error::{AppError, Result};
use bollard::exec::{CreateExecOptions, StartExecResults};
use bollard::Docker;
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;
use tracing::{info, warn};

const CONTAINER_NAME: &str = "kali-pentest";

/// Result returned to the frontend. `ok` is the single source of truth
/// the Add Account button gates on; everything else is for the UI to
/// display.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    /// True iff the probe call succeeded and returned credentials that
    /// resolve to a real principal. False on any error (network,
    /// permission denied, expired token, malformed JSON, etc.).
    pub ok: bool,
    /// Human-readable string identifying the principal the credential
    /// resolved to. AWS: STS ARN. Azure: subscription display name +
    /// tenant. GCP: service account email + project. K8s: API server
    /// URL + server version. Empty when ok=false.
    pub identity: String,
    /// Optional secondary line the UI can show under the identity (e.g.
    /// account number, project ID).
    pub details: String,
    /// Error message when ok=false. Trimmed CLI stderr (or our own
    /// summary if stderr was empty). Empty when ok=true.
    pub error: String,
    /// True when the failure is "SSO session expired, silent refresh
    /// impossible" — the frontend pops the in-app sign-in instead of just
    /// showing the error.
    #[serde(default)]
    pub needs_reauth: bool,
}

impl ValidationResult {
    fn ok(identity: impl Into<String>, details: impl Into<String>) -> Self {
        Self {
            ok: true,
            identity: identity.into(),
            details: details.into(),
            error: String::new(),
            needs_reauth: false,
        }
    }

    fn err(message: impl Into<String>) -> Self {
        // The resolve layer marks re-auth-required failures with a
        // REAUTH_REQUIRED prefix; lift that into the structured flag and
        // strip the marker from the user-facing text.
        let raw = message.into();
        let needs_reauth = raw.contains("REAUTH_REQUIRED");
        let error = raw.replace("REAUTH_REQUIRED: ", "");
        Self {
            ok: false,
            identity: String::new(),
            details: String::new(),
            error,
            needs_reauth,
        }
    }
}

/// Output of a container exec — both streams + exit code so probe code
/// can branch on success/failure properly.
struct ExecOutput {
    stdout: String,
    stderr: String,
    exit_code: i64,
}

/// Execute a command in the Kali container with optional env vars.
/// Separates stdout/stderr (bollard's default attached stream interleaves
/// them) and waits for the exec to terminate to capture the exit code.
async fn exec_in_container(
    docker: &Docker,
    cmd: Vec<String>,
    env: Vec<String>,
) -> Result<ExecOutput> {
    // Borrow the &str views bollard wants. Owning the Strings outside
    // the call sites keeps lifetimes happy without a lot of leak/clone
    // gymnastics in each probe.
    let cmd_refs: Vec<&str> = cmd.iter().map(String::as_str).collect();
    let env_refs: Vec<&str> = env.iter().map(String::as_str).collect();

    let exec = docker
        .create_exec(
            CONTAINER_NAME,
            CreateExecOptions {
                attach_stdout: Some(true),
                attach_stderr: Some(true),
                cmd: Some(cmd_refs),
                env: if env_refs.is_empty() {
                    None
                } else {
                    Some(env_refs)
                },
                ..Default::default()
            },
        )
        .await
        .map_err(AppError::Docker)?;

    let stream = docker
        .start_exec(&exec.id, None)
        .await
        .map_err(AppError::Docker)?;

    let mut stdout = String::new();
    let mut stderr = String::new();
    if let StartExecResults::Attached { mut output, .. } = stream {
        while let Some(msg) = output.next().await {
            match msg {
                Ok(bollard::container::LogOutput::StdOut { message }) => {
                    stdout.push_str(&String::from_utf8_lossy(&message));
                }
                Ok(bollard::container::LogOutput::StdErr { message }) => {
                    stderr.push_str(&String::from_utf8_lossy(&message));
                }
                Ok(_) => {}
                Err(e) => {
                    warn!("exec stream read error: {e}");
                }
            }
        }
    }

    // Inspect the exec after the stream is drained to pick up the exit
    // code. Polling once is enough — `start_exec` only returns when the
    // process has finished.
    let inspect = docker
        .inspect_exec(&exec.id)
        .await
        .map_err(AppError::Docker)?;
    let exit_code = inspect.exit_code.unwrap_or(-1);

    Ok(ExecOutput {
        stdout,
        stderr,
        exit_code,
    })
}

/// Resolve the `aws` binary. A macOS GUI app inherits a minimal PATH
/// (usually `/usr/bin:/bin:...`) that omits Homebrew, so `which` may miss
/// it — fall back to the common install locations before giving up.
fn find_aws_binary() -> String {
    if let Ok(p) = which::which("aws") {
        return p.to_string_lossy().to_string();
    }
    #[cfg(windows)]
    for cand in [
        "C:\\Program Files\\Amazon\\AWSCLIV2\\aws.exe",
        "C:\\Program Files (x86)\\Amazon\\AWSCLIV2\\aws.exe",
    ] {
        if std::path::Path::new(cand).exists() {
            return cand.to_string();
        }
    }
    for cand in ["/opt/homebrew/bin/aws", "/usr/local/bin/aws", "/usr/bin/aws"] {
        if std::path::Path::new(cand).exists() {
            return cand.to_string();
        }
    }
    "aws".to_string()
}

/// Run a command on the HOST (not in the container). Used for AWS
/// `profile` source mode: named profiles live in the host `~/.aws`, which
/// the container can't see, so the assume-role must run where the profile
/// is. Static creds in the desktop process env are stripped so the
/// profile's own credentials are used.
async fn exec_on_host(cmd: Vec<String>, env: Vec<String>) -> Result<ExecOutput> {
    use tokio::process::Command;
    if cmd.is_empty() {
        return Err(AppError::Other("empty host command".into()));
    }
    let program = if cmd[0] == "aws" {
        find_aws_binary()
    } else {
        cmd[0].clone()
    };
    let mut c = Command::new(&program);
    c.args(&cmd[1..]);
    c.env_remove("AWS_ACCESS_KEY_ID");
    c.env_remove("AWS_SECRET_ACCESS_KEY");
    c.env_remove("AWS_SESSION_TOKEN");
    c.env_remove("AWS_PROFILE");
    for kv in &env {
        if let Some((k, v)) = kv.split_once('=') {
            c.env(k, v);
        }
    }
    let output = c
        .output()
        .await
        .map_err(|e| AppError::Other(format!("host aws exec failed ({program}): {e}")))?;
    Ok(ExecOutput {
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        exit_code: output.status.code().unwrap_or(-1) as i64,
    })
}

/// Truncate a long CLI error message so the UI doesn't overflow.
/// CLIs are sometimes verbose; the first 4 lines / 500 chars usually
/// contain the actionable bit.
fn trim_err(s: &str) -> String {
    let trimmed = s.trim();
    let line_limited: String = trimmed.lines().take(4).collect::<Vec<_>>().join("\n");
    if line_limited.len() > 500 {
        format!("{}…", &line_limited[..500])
    } else {
        line_limited
    }
}

// =============================================================================
// AWS probes
// =============================================================================

/// `aws sts get-caller-identity` — universal AWS "does this credential
/// resolve" call. Used by every AWS probe variant; what differs is how
/// we set up the credential context (profile name, env vars, AssumeRole
/// session credentials) before calling it.
async fn aws_sts_get_caller_identity(
    docker: &Docker,
    extra_args: Vec<String>,
    env: Vec<String>,
) -> Result<ValidationResult> {
    let mut cmd = vec![
        "aws".to_string(),
        "sts".to_string(),
        "get-caller-identity".to_string(),
        "--output".to_string(),
        "json".to_string(),
    ];
    cmd.extend(extra_args);
    let out = exec_in_container(docker, cmd, env).await?;

    if out.exit_code != 0 {
        return Ok(ValidationResult::err(trim_err(&out.stderr)));
    }

    // STS returns `{"UserId": "...", "Account": "...", "Arn": "..."}`
    let parsed: serde_json::Value = serde_json::from_str(&out.stdout)
        .map_err(|e| AppError::Config(format!("invalid AWS STS JSON: {e}")))?;
    let arn = parsed
        .get("Arn")
        .and_then(|v| v.as_str())
        .unwrap_or("<unknown>");
    let account = parsed
        .get("Account")
        .and_then(|v| v.as_str())
        .unwrap_or("<unknown>");
    Ok(ValidationResult::ok(arn, format!("Account {account}")))
}

async fn probe_aws_profile(docker: &Docker, account: &CloudAccountScope) -> Result<ValidationResult> {
    let profile = account
        .aws_profile
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| AppError::Config("AWS profile name is required".into()))?;
    aws_sts_get_caller_identity(
        docker,
        vec!["--profile".to_string(), profile.to_string()],
        vec![],
    )
    .await
}

async fn probe_aws_access_key(
    docker: &Docker,
    account: &CloudAccountScope,
) -> Result<ValidationResult> {
    let key_id = account
        .access_key_id
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| AppError::Config("Access Key ID is required".into()))?;
    let secret = account
        .secret_access_key
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| AppError::Config("Secret Access Key is required".into()))?;
    // Override any host-side AWS_PROFILE so this probe can't accidentally
    // resolve a different credential than the user typed.
    let env = vec![
        format!("AWS_ACCESS_KEY_ID={key_id}"),
        format!("AWS_SECRET_ACCESS_KEY={secret}"),
        "AWS_PROFILE=".to_string(),
        "AWS_DEFAULT_REGION=us-east-1".to_string(),
    ];
    aws_sts_get_caller_identity(docker, vec![], env).await
}

/// Cached AWS source credentials. Persisted in the macOS keyring under
/// the `aws_source` blob (see `secrets.rs`). One of {sso, access_keys,
/// profile} is populated based on which option the user picked in the
/// setup wizard.
#[derive(Debug, Clone, Deserialize)]
struct AwsSourceCredentials {
    /// `"sso"` | `"access_keys"` | `"profile"`. We don't enforce via
    /// enum because the keyring blob is opaque JSON the frontend
    /// authors — keeping it a string here means a future kind can be
    /// added without a coordinated backend/frontend deploy.
    kind: String,
    sso: Option<CachedSsoSession>,
    access_keys: Option<CachedAccessKeys>,
    profile: Option<CachedProfile>,
}

/// One entry in the `aws_sources` library blob. Same credential payload
/// as the legacy single `AwsSourceCredentials`, plus an `id`/`name` so a
/// deployment can hold several assume-from identities and pick one per
/// assessment.
#[derive(Debug, Clone, Deserialize)]
struct AwsSourceEntry {
    id: String,
    #[serde(default)]
    #[allow(dead_code)]
    name: String,
    kind: String,
    sso: Option<CachedSsoSession>,
    access_keys: Option<CachedAccessKeys>,
    profile: Option<CachedProfile>,
}

impl From<AwsSourceEntry> for AwsSourceCredentials {
    fn from(e: AwsSourceEntry) -> Self {
        AwsSourceCredentials {
            kind: e.kind,
            sso: e.sso,
            access_keys: e.access_keys,
            profile: e.profile,
        }
    }
}

/// The `aws_sources` keyring blob — a named library of source identities
/// plus which one is the default (used when an assessment doesn't pick
/// one explicitly).
#[derive(Debug, Clone, Deserialize, Default)]
struct AwsSourcesLibrary {
    #[serde(default)]
    default_id: Option<String>,
    #[serde(default)]
    sources: Vec<AwsSourceEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CachedSsoSession {
    region: String,
    access_token: String,
    /// Unix seconds.
    expires_at: i64,
    /// Account whose SSO permission-set role we'll use as the source
    /// identity for sts:AssumeRole. The wizard picks this when there
    /// are multiple options; usually it's the same account as the
    /// target Role ARN.
    source_account_id: String,
    source_role_name: String,
    /// SSO portal start URL — preserved across silent refreshes so a
    /// later interactive re-auth can prefill it. Not needed for minting
    /// creds, so optional for back-compat with pre-refresh blobs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    start_url: Option<String>,
    /// Refresh-token grant material. Present once a source is created by
    /// the refresh-aware wizard; absent on legacy blobs (those can't be
    /// silently refreshed and fall back to interactive re-auth).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    refresh_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    client_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    client_secret: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct CachedAccessKeys {
    access_key_id: String,
    secret_access_key: String,
}

#[derive(Debug, Clone, Deserialize)]
struct CachedProfile {
    name: String,
}

/// Read the `aws_source` blob from the keyring. Returns Ok(None) if the
/// blob doesn't exist yet (fresh install, never ran the wizard) or has
/// an unrecognized shape — both of those collapse to "no cached source
/// creds, fall back to the default chain."
async fn load_aws_source_credentials() -> Result<Option<AwsSourceCredentials>> {
    let blob = crate::commands::secrets::get_secret_blob("aws_source".to_string()).await?;
    // Empty object means "never written" — short-circuit so we don't try
    // to deserialize a missing `kind` field as a hard error.
    if blob.value.is_null() || matches!(blob.value, serde_json::Value::Object(ref m) if m.is_empty())
    {
        return Ok(None);
    }
    match serde_json::from_value::<AwsSourceCredentials>(blob.value) {
        Ok(c) => Ok(Some(c)),
        Err(e) => {
            warn!("aws_source blob present but unparseable: {e}");
            Ok(None)
        }
    }
}

/// Pick a source credential from the `aws_sources` library.
///
/// Selection order:
///   1. If `source_id` is given, the entry with that id.
///   2. Otherwise the library's `default_id` entry.
///   3. Otherwise the first entry in the library.
///
/// If the library is empty/missing (fresh install, or a user who only
/// ever used the legacy single-source wizard), fall back to the legacy
/// `aws_source` blob. This is the migration path — old installs keep
/// working until they re-save through the new library UI.
/// Returns `(entry_id, creds)` — `entry_id` is the library entry's id
/// (used to write a refreshed SSO token back to the right entry), or None
/// when the creds came from the legacy single `aws_source` blob.
async fn load_source_by_id(
    source_id: Option<&str>,
) -> Result<Option<(Option<String>, AwsSourceCredentials)>> {
    let blob = crate::commands::secrets::get_secret_blob("aws_sources".to_string()).await?;
    let is_empty = blob.value.is_null()
        || matches!(blob.value, serde_json::Value::Object(ref m) if m.is_empty());

    if !is_empty {
        match serde_json::from_value::<AwsSourcesLibrary>(blob.value) {
            Ok(lib) => {
                let chosen = match source_id {
                    Some(id) => lib.sources.into_iter().find(|s| s.id == id),
                    None => {
                        // default_id wins, else first entry.
                        let default_id = lib.default_id.clone();
                        let mut sources = lib.sources.into_iter();
                        match default_id {
                            Some(did) => {
                                // Re-scan for the default; if it's gone,
                                // fall back to whatever is first.
                                let all: Vec<AwsSourceEntry> = sources.collect();
                                all.iter()
                                    .find(|s| s.id == did)
                                    .cloned()
                                    .or_else(|| all.into_iter().next())
                            }
                            None => sources.next(),
                        }
                    }
                };
                if let Some(entry) = chosen {
                    let id = entry.id.clone();
                    return Ok(Some((Some(id), entry.into())));
                }
                // A specific id was requested but not found — don't
                // silently assume a different identity; surface "none".
                if source_id.is_some() {
                    warn!("aws_sources: requested source id not found");
                    return Ok(None);
                }
            }
            Err(e) => {
                warn!("aws_sources blob present but unparseable: {e}");
            }
        }
    }

    // Legacy fallback (no entry id).
    Ok(load_aws_source_credentials().await?.map(|c| (None, c)))
}

/// Persist a silently-refreshed SSO session back to wherever it came from
/// — the library entry by id, or the legacy single blob — so the next
/// resolve reuses the new access token instead of refreshing again.
async fn persist_refreshed_sso(entry_id: &Option<String>, sso: &CachedSsoSession) -> Result<()> {
    let sso_json = serde_json::to_value(sso)
        .map_err(|e| AppError::Other(format!("serialize refreshed sso: {e}")))?;
    match entry_id {
        Some(id) => {
            let blob = crate::commands::secrets::get_secret_blob("aws_sources".to_string()).await?;
            let mut lib = blob.value;
            if let Some(sources) = lib.get_mut("sources").and_then(|s| s.as_array_mut()) {
                for src in sources.iter_mut() {
                    if src.get("id").and_then(|v| v.as_str()) == Some(id.as_str()) {
                        src["sso"] = sso_json.clone();
                    }
                }
            }
            crate::commands::secrets::set_secret_blob("aws_sources".to_string(), lib).await
        }
        None => {
            let blob = serde_json::json!({ "kind": "sso", "sso": sso_json });
            crate::commands::secrets::set_secret_blob("aws_source".to_string(), blob).await
        }
    }
}

/// Resolve cached source credentials into the env vars + extra-args
/// pair that the AssumeRole exec needs. Returns
/// `(env, extra_args, hint, run_on_host)` where `hint` identifies which
/// source we used and `run_on_host` is true for the `profile` source —
/// named profiles live in the host `~/.aws`, which the container can't
/// see, so the assume-role must run on the host. SSO/access-key sources
/// inject env creds and run in the container (`run_on_host` = false).
///
/// Returns Ok(None) when no cached creds exist, signalling the caller
/// should fall through to the default credential chain.
async fn resolve_source_credentials_for_assume_role(
    source_id: Option<&str>,
) -> Result<Option<(Vec<String>, Vec<String>, String, bool)>> {
    let Some((entry_id, creds)) = load_source_by_id(source_id).await? else {
        return Ok(None);
    };

    match creds.kind.as_str() {
        "sso" => {
            let Some(mut sso) = creds.sso else {
                warn!("aws_source kind=sso but missing sso block");
                return Ok(None);
            };
            // Refresh-on-use, mirroring auth-handler.ts's cache-and-refresh:
            // if the token is expired (or within a 60s margin), try to renew
            // it silently with the stored refresh token, then persist the
            // new token so later resolves — and the background refresh task —
            // reuse it. Only when the refresh token itself is dead do we
            // surface a re-auth-required error (the SSO equivalent of the
            // OTP "needs a human" case). REAUTH_REQUIRED is the marker the
            // frontend keys on to pop the in-app sign-in.
            let now = chrono::Utc::now().timestamp();
            if sso.expires_at <= now + 60 {
                match (
                    sso.client_id.clone(),
                    sso.client_secret.clone(),
                    sso.refresh_token.clone(),
                ) {
                    (Some(cid), Some(csec), Some(rt)) => {
                        match crate::commands::aws_sso::aws_sso_refresh_token(
                            cid,
                            csec,
                            rt,
                            sso.region.clone(),
                        )
                        .await
                        {
                            Ok(refreshed) => {
                                sso.access_token = refreshed.access_token;
                                sso.expires_at = refreshed.expires_at;
                                if refreshed.refresh_token.is_some() {
                                    sso.refresh_token = refreshed.refresh_token;
                                }
                                if let Err(e) = persist_refreshed_sso(&entry_id, &sso).await {
                                    warn!("failed to persist refreshed SSO token: {e}");
                                }
                            }
                            Err(e) => {
                                return Err(AppError::Other(format!(
                                    "REAUTH_REQUIRED: AWS SSO session expired and refresh failed ({e}). Sign in again."
                                )));
                            }
                        }
                    }
                    _ => {
                        return Err(AppError::Other(
                            "REAUTH_REQUIRED: AWS SSO session expired. Sign in again.".to_string(),
                        ));
                    }
                }
            }
            // Mint short-lived IAM creds via the SSO portal. These are
            // what authenticate the sts:AssumeRole call.
            let role_creds = crate::commands::aws_sso::aws_sso_get_role_credentials(
                sso.access_token.clone(),
                sso.region.clone(),
                sso.source_account_id.clone(),
                sso.source_role_name.clone(),
            )
            .await?;
            let env = vec![
                format!("AWS_ACCESS_KEY_ID={}", role_creds.access_key_id),
                format!("AWS_SECRET_ACCESS_KEY={}", role_creds.secret_access_key),
                format!("AWS_SESSION_TOKEN={}", role_creds.session_token),
                "AWS_PROFILE=".to_string(),
                "AWS_DEFAULT_REGION=us-east-1".to_string(),
            ];
            let hint = format!(
                "via SSO ({}/{})",
                sso.source_account_id, sso.source_role_name
            );
            Ok(Some((env, vec![], hint, false)))
        }
        "access_keys" => {
            let Some(keys) = creds.access_keys else {
                warn!("aws_source kind=access_keys but missing access_keys block");
                return Ok(None);
            };
            let env = vec![
                format!("AWS_ACCESS_KEY_ID={}", keys.access_key_id),
                format!("AWS_SECRET_ACCESS_KEY={}", keys.secret_access_key),
                "AWS_PROFILE=".to_string(),
                "AWS_SESSION_TOKEN=".to_string(),
                "AWS_DEFAULT_REGION=us-east-1".to_string(),
            ];
            Ok(Some((
                env,
                vec![],
                "via long-term access keys".to_string(),
                false,
            )))
        }
        "profile" => {
            let Some(profile) = creds.profile else {
                warn!("aws_source kind=profile but missing profile block");
                return Ok(None);
            };
            // Profile sources resolve on the HOST (run_on_host = true):
            // we pass --profile and let the host AWS CLI handle whatever
            // chained AssumeRole / SSO resolution the profile prescribes,
            // reading the host ~/.aws the container can't see.
            Ok(Some((
                vec![],
                vec!["--profile".to_string(), profile.name.clone()],
                format!("via profile `{}`", profile.name),
                true,
            )))
        }
        other => {
            warn!("aws_source has unrecognized kind: {other}");
            Ok(None)
        }
    }
}

/// AWS Assume Role probe. Calls `sts:AssumeRole` directly so we can
/// surface a distinct "trust policy is wrong" error vs. "no source
/// credentials available."
///
/// Source credential resolution order:
///   1. Cached source creds in keyring (`aws_source` blob) — set by the
///      Add Cloud Account setup wizard via the SSO sign-in / paste-keys
///      / pick-profile flow.
///   2. The container's default credential chain — env vars set by the
///      Tauri runtime, mounted `~/.aws/credentials`, instance metadata.
///      This is the fallback for users who configured AWS outside of
///      Maestro and have working creds in the container.
///
/// If both miss, AssumeRole fails with "Unable to locate credentials"
/// and the frontend renders the setup wizard.
async fn probe_aws_assume_role(
    docker: &Docker,
    account: &CloudAccountScope,
    source_id: Option<&str>,
) -> Result<ValidationResult> {
    let role_arn = account
        .role_arn
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| AppError::Config("Role ARN is required".into()))?;

    // Step 1: try cached source creds. Any error here is surfaced as a
    // probe failure (e.g. expired SSO session) so the wizard can react.
    // `source_id` selects which library entry to assume from; None uses
    // the library default (or the legacy single source).
    let source = match resolve_source_credentials_for_assume_role(source_id).await {
        Ok(s) => s,
        Err(e) => return Ok(ValidationResult::err(e.to_string())),
    };
    let (env, source_extra_args, source_hint, run_on_host) = source
        .map(|(e, a, h, host)| (e, a, Some(h), host))
        .unwrap_or((vec![], vec![], None, false));

    let mut cmd = vec![
        "aws".to_string(),
        "sts".to_string(),
        "assume-role".to_string(),
        "--role-arn".to_string(),
        role_arn.to_string(),
        "--role-session-name".to_string(),
        "maestro-probe".to_string(),
        "--duration-seconds".to_string(),
        "900".to_string(),
        "--output".to_string(),
        "json".to_string(),
    ];
    cmd.extend(source_extra_args);
    if let Some(external_id) = account.external_id.as_deref().filter(|s| !s.is_empty()) {
        cmd.push("--external-id".to_string());
        cmd.push(external_id.to_string());
    }

    // Profile sources resolve on the host (host ~/.aws); everything else
    // runs in the container with injected env creds.
    let out = if run_on_host {
        exec_on_host(cmd, env).await?
    } else {
        exec_in_container(docker, cmd, env).await?
    };
    if out.exit_code != 0 {
        return Ok(ValidationResult::err(trim_err(&out.stderr)));
    }

    let parsed: serde_json::Value = serde_json::from_str(&out.stdout)
        .map_err(|e| AppError::Config(format!("invalid AWS STS JSON: {e}")))?;
    let assumed_arn = parsed
        .get("AssumedRoleUser")
        .and_then(|v| v.get("Arn"))
        .and_then(|v| v.as_str())
        .unwrap_or("<unknown>");
    let session_account = role_arn
        .split(':')
        .nth(4)
        .unwrap_or("<unknown>");
    let details = match source_hint {
        Some(hint) => format!("Account {session_account} · {hint}"),
        None => format!("Account {session_account}"),
    };
    Ok(ValidationResult::ok(assumed_arn, details))
}

// =============================================================================
// Azure probes
// =============================================================================

async fn probe_azure_cli(docker: &Docker, account: &CloudAccountScope) -> Result<ValidationResult> {
    let mut cmd = vec![
        "az".to_string(),
        "account".to_string(),
        "show".to_string(),
        "--output".to_string(),
        "json".to_string(),
    ];
    if let Some(sub_id) = account.subscription_id.as_deref().filter(|s| !s.is_empty()) {
        cmd.push("--subscription".to_string());
        cmd.push(sub_id.to_string());
    }
    let out = exec_in_container(docker, cmd, vec![]).await?;

    if out.exit_code != 0 {
        let stderr = trim_err(&out.stderr);
        let hint = if stderr.to_lowercase().contains("please run 'az login'") {
            "Run `az login` inside the Kali container terminal, then retry."
        } else {
            ""
        };
        return Ok(ValidationResult::err(if hint.is_empty() {
            stderr
        } else {
            format!("{stderr}\n\n{hint}")
        }));
    }

    let parsed: serde_json::Value = serde_json::from_str(&out.stdout)
        .map_err(|e| AppError::Config(format!("invalid Azure JSON: {e}")))?;
    let name = parsed
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("<subscription>");
    let id = parsed
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or("<unknown>");
    let tenant = parsed
        .get("tenantId")
        .and_then(|v| v.as_str())
        .unwrap_or("<unknown>");
    Ok(ValidationResult::ok(
        name,
        format!("Subscription {id} · tenant {tenant}"),
    ))
}

/// Azure service principal probe. Hit Azure AD's OAuth token endpoint
/// directly with `curl` — proves the SP exists and the secret is valid
/// without mutating the container's `az` session (which `az login
/// --service-principal` would do).
async fn probe_azure_service_principal(
    docker: &Docker,
    account: &CloudAccountScope,
) -> Result<ValidationResult> {
    let tenant = account
        .tenant_id
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| AppError::Config("Tenant ID is required".into()))?;
    let client_id = account
        .client_id
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| AppError::Config("Client ID is required".into()))?;
    let client_secret = account
        .client_secret
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| AppError::Config("Client Secret is required".into()))?;

    // curl returns 0 on HTTP errors too — use --fail-with-body to flip
    // non-2xx into a non-zero exit while still emitting the body so we
    // can surface Azure's `error_description` to the user.
    let url = format!("https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token");
    let body = format!(
        "grant_type=client_credentials&client_id={client_id}&client_secret={secret}&scope=https%3A%2F%2Fmanagement.azure.com%2F.default",
        secret = urlencoding::encode(client_secret),
    );
    let cmd = vec![
        "curl".to_string(),
        "-sS".to_string(),
        "--fail-with-body".to_string(),
        "-X".to_string(),
        "POST".to_string(),
        "-H".to_string(),
        "Content-Type: application/x-www-form-urlencoded".to_string(),
        "--data".to_string(),
        body,
        url,
    ];

    let out = exec_in_container(docker, cmd, vec![]).await?;
    if out.exit_code != 0 {
        // Body comes back on stdout because of --fail-with-body. Try to
        // pull `error_description` from it for a more useful message.
        let summary = serde_json::from_str::<serde_json::Value>(&out.stdout)
            .ok()
            .and_then(|v| {
                v.get("error_description")
                    .and_then(|d| d.as_str())
                    .map(|s| s.to_string())
            })
            .unwrap_or_else(|| trim_err(&out.stderr));
        return Ok(ValidationResult::err(summary));
    }

    // Successful response carries `{"access_token": "...", ...}`. We
    // don't decode the JWT — issuance alone proves the SP works.
    let _ok: serde_json::Value = serde_json::from_str(&out.stdout)
        .map_err(|e| AppError::Config(format!("invalid Azure token JSON: {e}")))?;
    let sub_id = account
        .subscription_id
        .as_deref()
        .unwrap_or("<no subscription>");
    Ok(ValidationResult::ok(
        format!("Service principal {client_id}"),
        format!("Tenant {tenant} · subscription {sub_id}"),
    ))
}

/// Azure Managed Identity can only be validated from inside Azure
/// (IMDS at 169.254.169.254 isn't reachable from a developer's laptop).
/// Probe it gracefully: if the metadata endpoint isn't responsive, tell
/// the user the credential will be tested at assessment runtime instead.
async fn probe_azure_managed_identity(
    docker: &Docker,
    account: &CloudAccountScope,
) -> Result<ValidationResult> {
    let cmd = vec![
        "curl".to_string(),
        "-sS".to_string(),
        "--max-time".to_string(),
        "3".to_string(),
        "-H".to_string(),
        "Metadata: true".to_string(),
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01".to_string(),
    ];
    let out = exec_in_container(docker, cmd, vec![]).await?;
    if out.exit_code == 0 && !out.stdout.is_empty() {
        let sub = account
            .subscription_id
            .as_deref()
            .unwrap_or("<no subscription>");
        return Ok(ValidationResult::ok(
            "Managed Identity reachable",
            format!("IMDS responded · subscription {sub}"),
        ));
    }
    Ok(ValidationResult::err(
        "Managed Identity cannot be validated from outside Azure. Credentials will be \
         tested when an assessment runs inside the Azure environment Maestro is deployed to."
            .to_string(),
    ))
}

// =============================================================================
// GCP probes
// =============================================================================

async fn probe_gcp_adc(docker: &Docker, account: &CloudAccountScope) -> Result<ValidationResult> {
    let cmd = vec![
        "gcloud".to_string(),
        "auth".to_string(),
        "application-default".to_string(),
        "print-access-token".to_string(),
    ];
    let out = exec_in_container(docker, cmd, vec![]).await?;
    if out.exit_code != 0 {
        let stderr = trim_err(&out.stderr);
        let hint = if stderr.to_lowercase().contains("application default credentials") {
            "Run `gcloud auth application-default login` inside the Kali container terminal, then retry."
        } else {
            ""
        };
        return Ok(ValidationResult::err(if hint.is_empty() {
            stderr
        } else {
            format!("{stderr}\n\n{hint}")
        }));
    }
    let project = account
        .project_id
        .as_deref()
        .unwrap_or("<no project set>");
    Ok(ValidationResult::ok(
        "ADC token issued",
        format!("Project {project}"),
    ))
}

async fn probe_gcp_service_account(
    docker: &Docker,
    account: &CloudAccountScope,
) -> Result<ValidationResult> {
    let key_json = account
        .service_account_key
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| AppError::Config("Service Account JSON is required".into()))?;

    // Validate the JSON shape locally first so we can give a cleaner
    // error than gcloud's "Could not load the default credentials" if
    // the paste is malformed.
    let parsed: serde_json::Value = serde_json::from_str(key_json).map_err(|_| {
        AppError::Config(
            "Service Account JSON is not valid JSON. Make sure you pasted the entire file."
                .into(),
        )
    })?;
    let email = parsed
        .get("client_email")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            AppError::Config("Service Account JSON missing `client_email` field".into())
        })?;
    let project = parsed
        .get("project_id")
        .and_then(|v| v.as_str())
        .unwrap_or("<unknown>");

    // Write the key to a temp file in the container, run gcloud, clean
    // up. We don't keep the file around even briefly — the auth shell
    // uses `&&` so cleanup runs only on success; trap-on-exit covers
    // failures.
    let escaped = serde_json::to_string(key_json)
        .map_err(|e| AppError::Config(format!("could not encode key for shell: {e}")))?;
    let script = format!(
        r#"set -eu; \
TMPFILE="$(mktemp -t maestro-gcp-sa-XXXXXX.json)"; \
trap 'rm -f "$TMPFILE"' EXIT; \
printf '%s' {escaped} > "$TMPFILE"; \
GOOGLE_APPLICATION_CREDENTIALS="$TMPFILE" gcloud auth application-default print-access-token"#,
    );
    let cmd = vec!["bash".to_string(), "-c".to_string(), script];
    let out = exec_in_container(docker, cmd, vec![]).await?;
    if out.exit_code != 0 {
        return Ok(ValidationResult::err(trim_err(&out.stderr)));
    }
    Ok(ValidationResult::ok(
        email.to_string(),
        format!("Project {project}"),
    ))
}

// =============================================================================
// K8s probes
// =============================================================================

async fn probe_k8s_kubeconfig(
    _docker: &Docker,
    account: &CloudAccountScope,
) -> Result<ValidationResult> {
    // K8s cluster config doesn't live on `CloudAccountScope` — clusters
    // are a separate scope type with their own auth fields. Routing
    // kubeconfig probes through this command keeps the API surface
    // simple but means we need to surface a clear error if the caller
    // wired this incorrectly.
    let _ = account;
    Ok(ValidationResult::err(
        "Kubernetes credentials live in the K8s Clusters section, not Cloud Accounts. \
         Use the Verify connection button there once K8s validation lands."
            .to_string(),
    ))
}

async fn probe_k8s_in_cluster(
    _docker: &Docker,
    account: &CloudAccountScope,
) -> Result<ValidationResult> {
    let _ = account;
    Ok(ValidationResult::err(
        "In-cluster credentials can't be probed from the desktop — Maestro must run as a \
         pod in the target cluster for that auth method to work."
            .to_string(),
    ))
}

// =============================================================================
// Dispatch
// =============================================================================

#[tauri::command]
pub async fn validate_cloud_account(
    account: CloudAccountScope,
    source_credential_id: Option<String>,
) -> Result<ValidationResult> {
    info!(
        "Validating cloud account: provider={} auth_method={} source={:?}",
        account.provider, account.auth_method, source_credential_id
    );
    let manager = DockerManager::new().await?;
    let status = manager.get_container_status().await?;
    if !status.running {
        return Ok(ValidationResult::err(
            "The Kali container isn't running. Start it from the system tray, then retry."
                .to_string(),
        ));
    }
    let docker = manager.docker();

    let result = match (account.provider.as_str(), account.auth_method.as_str()) {
        ("aws", "profile") => probe_aws_profile(docker, &account).await,
        ("aws", "access_key") => probe_aws_access_key(docker, &account).await,
        ("aws", "role") => {
            probe_aws_assume_role(docker, &account, source_credential_id.as_deref()).await
        }
        ("azure", "cli") => probe_azure_cli(docker, &account).await,
        ("azure", "service_principal") => probe_azure_service_principal(docker, &account).await,
        ("azure", "managed_identity") => probe_azure_managed_identity(docker, &account).await,
        ("gcp", "adc") => probe_gcp_adc(docker, &account).await,
        ("gcp", "service_account") => probe_gcp_service_account(docker, &account).await,
        ("kubernetes", "kubeconfig") => probe_k8s_kubeconfig(docker, &account).await,
        ("kubernetes", "in_cluster") => probe_k8s_in_cluster(docker, &account).await,
        (provider, method) => Ok(ValidationResult::err(format!(
            "No probe implemented for provider={provider} auth_method={method}"
        ))),
    };

    match &result {
        Ok(r) if r.ok => info!("Validation OK: {}", r.identity),
        Ok(r) => warn!("Validation failed: {}", r.error),
        Err(e) => warn!("Validation errored: {e}"),
    }
    result
}

// =============================================================================
// Assessment-time credential injection (Layer 3)
// =============================================================================
//
// The probe above proves a source can assume a target role. This section
// is what makes an actual assessment *run as* that role: at launch we
// assume the chosen source's role and install the resulting short-lived
// session into the Kali container, then refresh it before STS expires.
//
// Mechanism: the assumed session is written to the host file
// `~/.kali-mcp-pentest/aws-credentials`, which is already bind-mounted at
// `/mnt/host-home/.kali-mcp-pentest/aws-credentials` inside the container
// (docker.rs). A one-time symlink points the container's default AWS
// paths (`/root/.aws/credentials` + `/root/.aws/config`) at the mounted
// files, so every `aws` invocation any tool makes picks them up with no
// per-exec env threading. Refresh just rewrites the host file; the
// symlink is unchanged, and the AWS CLI re-reads the file each call.

/// Short-lived STS session returned by `sts:assume-role`.
#[derive(Debug, Clone)]
struct AssumedSession {
    access_key_id: String,
    secret_access_key: String,
    session_token: String,
    /// RFC3339 timestamp from STS — surfaced to the UI; refresh is driven
    /// off a fixed interval rather than parsing this.
    expiration: String,
}

/// Result of installing assessment credentials, returned to the frontend.
#[derive(Debug, Clone, Serialize)]
pub struct CloudSessionResult {
    pub ok: bool,
    pub identity: String,
    pub expiration: String,
    pub error: String,
    /// True when the install failed because the SSO session expired and
    /// couldn't be silently refreshed — the modal pops the in-app sign-in.
    #[serde(default)]
    pub needs_reauth: bool,
}

/// Assume the account's target role from the chosen source and parse the
/// resulting session credentials.
async fn assume_role_session(
    docker: &Docker,
    account: &CloudAccountScope,
    source_id: Option<&str>,
) -> Result<AssumedSession> {
    let role_arn = account
        .role_arn
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| AppError::Config("Role ARN is required".into()))?;

    let (env, source_extra_args, _hint, run_on_host) =
        resolve_source_credentials_for_assume_role(source_id)
            .await?
            .ok_or_else(|| {
                AppError::Other(
                    "No source credentials configured to assume from. Set up Source Credentials first."
                        .into(),
                )
            })?;

    let mut cmd = vec![
        "aws".to_string(),
        "sts".to_string(),
        "assume-role".to_string(),
        "--role-arn".to_string(),
        role_arn.to_string(),
        "--role-session-name".to_string(),
        "maestro-assessment".to_string(),
        "--duration-seconds".to_string(),
        "3600".to_string(),
        "--output".to_string(),
        "json".to_string(),
    ];
    cmd.extend(source_extra_args);
    if let Some(external_id) = account.external_id.as_deref().filter(|s| !s.is_empty()) {
        cmd.push("--external-id".to_string());
        cmd.push(external_id.to_string());
    }

    // Profile sources resolve on the host; env-cred sources in the container.
    let out = if run_on_host {
        exec_on_host(cmd, env).await?
    } else {
        exec_in_container(docker, cmd, env).await?
    };
    if out.exit_code != 0 {
        return Err(AppError::Other(format!(
            "assume-role failed: {}",
            trim_err(&out.stderr)
        )));
    }
    let parsed: serde_json::Value = serde_json::from_str(&out.stdout)
        .map_err(|e| AppError::Config(format!("invalid AWS STS JSON: {e}")))?;
    let c = parsed
        .get("Credentials")
        .ok_or_else(|| AppError::Other("STS response missing Credentials".into()))?;
    let field = |k: &str| {
        c.get(k)
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string()
    };
    Ok(AssumedSession {
        access_key_id: field("AccessKeyId"),
        secret_access_key: field("SecretAccessKey"),
        session_token: field("SessionToken"),
        expiration: field("Expiration"),
    })
}

/// Write the assumed session to the host-mounted creds file and ensure
/// the container's default AWS paths symlink to it. Idempotent — safe to
/// call on every refresh.
async fn install_container_aws_credentials(
    docker: &Docker,
    account: &CloudAccountScope,
    session: &AssumedSession,
) -> Result<()> {
    let config_dir = dirs::home_dir()
        .ok_or_else(|| AppError::Other("Could not resolve home directory".into()))?
        .join(".kali-mcp-pentest");
    std::fs::create_dir_all(&config_dir)
        .map_err(|e| AppError::Other(format!("create config dir: {e}")))?;

    // Credentials (secrets) — 0600 on the host.
    let creds_path = config_dir.join("aws-credentials");
    let creds_body = format!(
        "[default]\naws_access_key_id={}\naws_secret_access_key={}\naws_session_token={}\n",
        session.access_key_id, session.secret_access_key, session.session_token,
    );
    std::fs::write(&creds_path, creds_body)
        .map_err(|e| AppError::Other(format!("write aws-credentials: {e}")))?;
    // Lock the secrets file down to the owner on Unix. No-op on Windows
    // (the desktop's primary targets are macOS/Linux; this keeps the
    // Windows cross-compile happy).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&creds_path, std::fs::Permissions::from_mode(0o600));
    }

    // Config — region (first in-scope region) + json output, so tools
    // that don't pass --region still resolve one.
    let region = account
        .regions
        .first()
        .cloned()
        .unwrap_or_else(|| "us-east-1".to_string());
    let config_path = config_dir.join("aws-config");
    std::fs::write(
        &config_path,
        format!("[default]\nregion = {region}\noutput = json\n"),
    )
    .map_err(|e| AppError::Other(format!("write aws-config: {e}")))?;

    // Point the container's default AWS paths at the mounted files. Only
    // paths in argv — never the secret material.
    let link_cmd = vec![
        "bash".to_string(),
        "-c".to_string(),
        "mkdir -p /root/.aws && \
         ln -sf /mnt/host-home/.kali-mcp-pentest/aws-credentials /root/.aws/credentials && \
         ln -sf /mnt/host-home/.kali-mcp-pentest/aws-config /root/.aws/config"
            .to_string(),
    ];
    let out = exec_in_container(docker, link_cmd, vec![]).await?;
    if out.exit_code != 0 {
        return Err(AppError::Other(format!(
            "linking AWS creds in container failed: {}",
            trim_err(&out.stderr)
        )));
    }

    // Verify the creds actually authenticate. A written file + symlink is NOT
    // proof the credentials work: empty/expired keys, a 200-with-blank-fields
    // broker response, or clock skew all produce a "successfully installed"
    // file that fails at tool time with "Unable to locate credentials". Probing
    // STS here is what makes the caller's blocking error meaningful — without
    // it, broken creds look installed and every cloud tool fails mid-run.
    let verify_cmd = vec![
        "bash".to_string(),
        "-c".to_string(),
        // 2>&1 so the (often informative) STS error lands on stdout.
        "aws sts get-caller-identity --output json 2>&1".to_string(),
    ];
    let verify = exec_in_container(docker, verify_cmd, vec![]).await?;
    if verify.exit_code != 0 {
        let detail = {
            let on_stdout = trim_err(&verify.stdout);
            if on_stdout.is_empty() {
                trim_err(&verify.stderr)
            } else {
                on_stdout
            }
        };
        return Err(AppError::Other(format!(
            "AWS credentials installed but failed verification \
             (aws sts get-caller-identity): {detail}"
        )));
    }

    Ok(())
}

/// Read the desktop's current Cognito ID token from the cloud-session
/// store (the same token the login gate maintains and refreshes). This is
/// the web-identity token federation exchanges for STS creds — the
/// operator's machine never holds an AWS credential, only this short-lived
/// login token.
fn read_cognito_id_token() -> Result<String> {
    let path = dirs::home_dir()
        .ok_or_else(|| AppError::Other("Could not resolve home directory".into()))?
        .join(".kali-mcp-pentest")
        .join("cloud-session.json");
    let data = std::fs::read_to_string(&path).map_err(|_| {
        AppError::Other(
            "Not signed in to Maestro cloud (no cloud-session.json). Sign in, then retry."
                .to_string(),
        )
    })?;
    let v: serde_json::Value = serde_json::from_str(&data)
        .map_err(|e| AppError::Other(format!("cloud-session.json is invalid: {e}")))?;
    v.get("idToken")
        .and_then(|t| t.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .ok_or_else(|| {
            AppError::Other(
                "REAUTH_REQUIRED: No Maestro login token found — sign in to Maestro first."
                    .to_string(),
            )
        })
}

/// Mint an assessment session by federating the Maestro Cognito login
/// (sts:AssumeRoleWithWebIdentity). No laptop AWS credential involved —
/// the customer's role trust gates on the token's aud + org_id. The
/// session name carries the operator + account for CloudTrail.
async fn assume_role_via_federation(
    account: &CloudAccountScope,
    operator_label: Option<&str>,
) -> Result<AssumedSession> {
    let role_arn = account
        .role_arn
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| AppError::Config("Role ARN is required".into()))?;
    let id_token = read_cognito_id_token()?;
    let region = account
        .regions
        .first()
        .cloned()
        .unwrap_or_else(|| "us-east-1".to_string());
    let who = operator_label.unwrap_or("user");
    let session_name = format!("maestro-{who}-{}", account.id);

    let creds = crate::commands::aws_sso::aws_sts_assume_role_web_identity(
        role_arn.to_string(),
        id_token,
        session_name,
        Some(3600),
        Some(region),
    )
    .await?;
    Ok(AssumedSession {
        access_key_id: creds.access_key_id,
        secret_access_key: creds.secret_access_key,
        session_token: creds.session_token,
        expiration: creds.expiration,
    })
}

/// Mint an assessment session by asking the Maestro backend to broker it
/// (`POST /cloud/assume`). The backend (running in the customer's account)
/// validates the caller's org_id and assumes the assessment role with its
/// own task role — so no laptop AWS credential is involved AND tenant
/// isolation is enforced where org_id can actually be checked. This is the
/// north-star path (RFC Option A). Reads the backend URL + login token
/// from the cloud-session store.
async fn assume_role_via_backend(account: &CloudAccountScope) -> Result<AssumedSession> {
    let role_arn = account
        .role_arn
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| AppError::Config("Role ARN is required".into()))?;

    let path = dirs::home_dir()
        .ok_or_else(|| AppError::Other("Could not resolve home directory".into()))?
        .join(".kali-mcp-pentest")
        .join("cloud-session.json");
    let data = std::fs::read_to_string(&path).map_err(|_| {
        AppError::Other("Not signed in to Maestro cloud. Sign in, then retry.".to_string())
    })?;
    let v: serde_json::Value = serde_json::from_str(&data)
        .map_err(|e| AppError::Other(format!("cloud-session.json is invalid: {e}")))?;
    let backend_url = v
        .get("backendUrl")
        .and_then(|x| x.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| AppError::Other("No Maestro backend URL in the cloud session.".into()))?;
    let id_token = v
        .get("idToken")
        .and_then(|x| x.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            AppError::Other("REAUTH_REQUIRED: No Maestro login token — sign in first.".into())
        })?;

    let url = format!("{}/api/v1/cloud/assume", backend_url.trim_end_matches('/'));
    let http = reqwest::Client::new();
    let resp = http
        .post(&url)
        .bearer_auth(id_token)
        .json(&serde_json::json!({ "role_arn": role_arn }))
        .send()
        .await
        .map_err(|e| AppError::Other(format!("Maestro backend /cloud/assume request failed: {e}")))?;
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();

    if !status.is_success() {
        // backend errors render as {"detail": "..."}.
        let detail = serde_json::from_str::<serde_json::Value>(&text)
            .ok()
            .and_then(|j| j.get("detail").and_then(|d| d.as_str()).map(str::to_string))
            .unwrap_or_else(|| text.chars().take(300).collect());
        if status.as_u16() == 401 || status.as_u16() == 403 {
            return Err(AppError::Other(format!(
                "REAUTH_REQUIRED: Maestro cloud rejected the session ({detail})."
            )));
        }
        return Err(AppError::Other(format!(
            "Maestro backend broker failed ({status}): {detail}"
        )));
    }

    let parsed: serde_json::Value = serde_json::from_str(&text)
        .map_err(|e| AppError::Other(format!("backend /cloud/assume returned invalid JSON: {e}")))?;
    let field = |k: &str| {
        parsed
            .get(k)
            .and_then(|x| x.as_str())
            .unwrap_or_default()
            .to_string()
    };
    let session = AssumedSession {
        access_key_id: field("access_key_id"),
        secret_access_key: field("secret_access_key"),
        session_token: field("session_token"),
        expiration: parsed
            .get("expiration")
            .map(|e| e.to_string())
            .unwrap_or_default(),
    };
    // Reject empty creds rather than writing a blank `[default]` profile that
    // later fails with "Unable to locate credentials" at tool time. The broker
    // can return 200 with a missing field; the `unwrap_or_default()` above would
    // otherwise silently produce blank keys that look installed but don't auth.
    if session.access_key_id.is_empty()
        || session.secret_access_key.is_empty()
        || session.session_token.is_empty()
    {
        return Err(AppError::Other(
            "backend /cloud/assume returned 200 but with empty credential field(s) \
             (access_key_id / secret_access_key / session_token); refusing to install a \
             blank AWS profile"
                .to_string(),
        ));
    }
    Ok(session)
}

/// Mint a session by whichever path the assessment chose: backend-brokered
/// (Option A — recommended), web-identity federation (single-tenant), or a
/// configured source credential (legacy SSO/access-key/profile).
async fn mint_assessment_session(
    docker: &Docker,
    account: &CloudAccountScope,
    source_id: Option<&str>,
    use_backend: bool,
    use_federation: bool,
    operator_label: Option<&str>,
) -> Result<AssumedSession> {
    if use_backend {
        assume_role_via_backend(account).await
    } else if use_federation {
        assume_role_via_federation(account, operator_label).await
    } else {
        assume_role_session(docker, account, source_id).await
    }
}

/// Active refresh tasks, keyed by cloud account id. Starting a session
/// for an account aborts any prior refresher for it; stopping aborts and
/// removes it. A spawned-but-never-stopped task is bounded only by the
/// app lifetime — acceptable for a desktop session, and `stop` is wired
/// to assessment teardown on the frontend.
fn refresh_tasks() -> &'static Mutex<HashMap<String, tokio::task::JoinHandle<()>>> {
    static REFRESH_TASKS: OnceLock<Mutex<HashMap<String, tokio::task::JoinHandle<()>>>> =
        OnceLock::new();
    REFRESH_TASKS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Spawn (or replace) the background refresher for an account. Re-assumes
/// and reinstalls credentials ~10 minutes before the 1h STS session would
/// expire.
fn spawn_refresh(
    account: CloudAccountScope,
    source_id: Option<String>,
    use_backend: bool,
    use_federation: bool,
    operator_label: Option<String>,
) {
    let key = account.id.clone();
    if let Ok(mut map) = refresh_tasks().lock() {
        if let Some(handle) = map.remove(&key) {
            handle.abort();
        }
    }
    let handle = tokio::spawn(async move {
        loop {
            // 1h session, refreshed with a 10-minute safety margin.
            tokio::time::sleep(Duration::from_secs(3000)).await;
            let docker = match DockerManager::new().await {
                Ok(m) => m.docker().clone(),
                Err(e) => {
                    warn!("cred refresh: docker unavailable: {e}");
                    continue;
                }
            };
            // Federation re-reads a fresh Cognito token + re-federates;
            // the source path re-assumes from the cached source.
            match mint_assessment_session(
                &docker,
                &account,
                source_id.as_deref(),
                use_backend,
                use_federation,
                operator_label.as_deref(),
            )
            .await
            {
                Ok(session) => {
                    if let Err(e) =
                        install_container_aws_credentials(&docker, &account, &session).await
                    {
                        warn!("cred refresh: install failed for {}: {e}", account.id);
                    } else {
                        info!("refreshed assessment credentials for account {}", account.id);
                    }
                }
                Err(e) => warn!("cred refresh: assume-role failed for {}: {e}", account.id),
            }
        }
    });
    if let Ok(mut map) = refresh_tasks().lock() {
        map.insert(key, handle);
    }
}

/// Assume the chosen source's role for a cloud account and install the
/// session into the running Kali container, so the assessment authenticates
/// as that identity. Spawns a background refresher. Called by the
/// new-assessment flow when a cloud assessment is launched.
#[tauri::command]
pub async fn start_cloud_assessment_credentials(
    account: CloudAccountScope,
    source_credential_id: Option<String>,
    use_backend: Option<bool>,
    use_federation: Option<bool>,
    operator_label: Option<String>,
) -> Result<CloudSessionResult> {
    let use_backend = use_backend.unwrap_or(false);
    let use_federation = use_federation.unwrap_or(false);

    // Only AWS assume-role needs injection. Profile/access-key AWS auth and
    // the other providers carry their own credentials at probe time.
    if account.provider != "aws" || account.auth_method != "role" {
        return Ok(CloudSessionResult {
            ok: true,
            identity: String::new(),
            expiration: String::new(),
            error: String::new(),
            needs_reauth: false,
        });
    }

    let manager = DockerManager::new().await?;
    let status = manager.get_container_status().await?;
    if !status.running {
        return Ok(CloudSessionResult {
            ok: false,
            identity: String::new(),
            expiration: String::new(),
            error: "The Kali container isn't running. Start it, then launch the assessment."
                .to_string(),
            needs_reauth: false,
        });
    }
    let docker = manager.docker().clone();

    let session = match mint_assessment_session(
        &docker,
        &account,
        source_credential_id.as_deref(),
        use_backend,
        use_federation,
        operator_label.as_deref(),
    )
    .await
    {
        Ok(s) => s,
        Err(e) => {
            let raw = e.to_string();
            let needs_reauth = raw.contains("REAUTH_REQUIRED");
            return Ok(CloudSessionResult {
                ok: false,
                identity: String::new(),
                expiration: String::new(),
                error: raw.replace("REAUTH_REQUIRED: ", ""),
                needs_reauth,
            });
        }
    };
    if let Err(e) = install_container_aws_credentials(&docker, &account, &session).await {
        return Ok(CloudSessionResult {
            ok: false,
            identity: String::new(),
            expiration: String::new(),
            error: e.to_string(),
            needs_reauth: false,
        });
    }
    spawn_refresh(
        account.clone(),
        source_credential_id,
        use_backend,
        use_federation,
        operator_label,
    );

    let identity = format!(
        "Assumed {}{}",
        account.role_arn.clone().unwrap_or_default(),
        account
            .account_id
            .clone()
            .map(|a| format!(" (account {a})"))
            .unwrap_or_default(),
    );
    info!("cloud assessment creds installed: {identity}");
    Ok(CloudSessionResult {
        ok: true,
        identity,
        expiration: session.expiration,
        error: String::new(),
        needs_reauth: false,
    })
}

/// Stop the background refresher for an account (assessment teardown).
#[tauri::command]
pub async fn stop_cloud_assessment_credentials(account_id: String) -> Result<()> {
    if let Ok(mut map) = refresh_tasks().lock() {
        if let Some(handle) = map.remove(&account_id) {
            handle.abort();
        }
    }
    Ok(())
}
