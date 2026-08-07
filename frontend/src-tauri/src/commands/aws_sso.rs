//! AWS SSO OIDC device-code client.
//!
//! Implements the same OIDC device-authorization flow that `aws sso login`
//! uses, but driven from Rust + reqwest so the desktop UI can render the
//! verification code + URL natively instead of dumping CLI output. Wire-
//! compatible with AWS SSO (and IAM Identity Center, which is the same
//! API).
//!
//! Reference: <https://docs.aws.amazon.com/sso-oidc/latest/APIReference/welcome.html>
//!
//! The flow has four stages:
//!
//! 1. **Register client.** A one-time call (we don't cache because the
//!    response is cheap and the client_id can be reused across orgs;
//!    caching adds invalidation surface for no measurable win).
//! 2. **Start device authorization.** Returns the user_code +
//!    verification_uri the user pastes into a browser, plus a
//!    device_code we poll on.
//! 3. **Poll create_token.** Every `interval` seconds (default 5) until
//!    the user has approved in the browser. Returns the SSO access token.
//! 4. **(Caller's responsibility)** Use the access token against the SSO
//!    portal API to list accounts and mint short-lived IAM creds via
//!    `sso:GetRoleCredentials`. Those calls live in this same module
//!    because they share the same client lifecycle.
//!
//! Token storage isn't this module's concern — the wizard saves the
//! resulting `SsoSession` into the `aws_source` keyring blob via the
//! existing `secrets.rs` API.

use crate::error::{AppError, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

const CLIENT_NAME: &str = "maestro-cloud-assessment";
const CLIENT_TYPE: &str = "public";
const GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:device_code";
// Scope requested for our access token. `sso:account:access` gets us
// account listing + role credentials, which is exactly what the AssumeRole
// source-credential flow needs and nothing more.
const SSO_SCOPES: &[&str] = &["sso:account:access"];

fn oidc_endpoint(region: &str, path: &str) -> String {
    format!("https://oidc.{region}.amazonaws.com{path}")
}

fn portal_endpoint(region: &str, path: &str) -> String {
    format!("https://portal.sso.{region}.amazonaws.com{path}")
}

// =============================================================================
// Step 1 — Register client
// =============================================================================

#[derive(Serialize)]
struct RegisterClientRequest<'a> {
    #[serde(rename = "clientName")]
    client_name: &'a str,
    #[serde(rename = "clientType")]
    client_type: &'a str,
    scopes: &'a [&'a str],
}

#[derive(Deserialize, Debug)]
struct RegisterClientResponse {
    #[serde(rename = "clientId")]
    client_id: String,
    #[serde(rename = "clientSecret")]
    client_secret: String,
}

async fn register_client(http: &Client, region: &str) -> Result<RegisterClientResponse> {
    let body = RegisterClientRequest {
        client_name: CLIENT_NAME,
        client_type: CLIENT_TYPE,
        scopes: SSO_SCOPES,
    };
    let resp = http
        .post(oidc_endpoint(region, "/client/register"))
        .json(&body)
        .send()
        .await
        .map_err(|e| AppError::Other(format!("SSO register_client request failed: {e}")))?;
    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        return Err(AppError::Other(format!(
            "SSO register_client returned {status}: {text}"
        )));
    }
    resp.json::<RegisterClientResponse>()
        .await
        .map_err(|e| AppError::Other(format!("SSO register_client invalid JSON: {e}")))
}

// =============================================================================
// Step 2 — Start device authorization
// =============================================================================

#[derive(Serialize)]
struct StartDeviceAuthRequest<'a> {
    #[serde(rename = "clientId")]
    client_id: &'a str,
    #[serde(rename = "clientSecret")]
    client_secret: &'a str,
    #[serde(rename = "startUrl")]
    start_url: &'a str,
}

#[derive(Deserialize, Debug, Serialize, Clone)]
pub struct DeviceAuthSession {
    /// What the user types into the verification page.
    #[serde(rename = "userCode", alias = "user_code")]
    pub user_code: String,
    /// The page the user opens.
    #[serde(rename = "verificationUri", alias = "verification_uri")]
    pub verification_uri: String,
    /// Same URL but with the code already embedded — what we hand to the
    /// frontend as a "click here to skip code entry" link.
    #[serde(
        rename = "verificationUriComplete",
        alias = "verification_uri_complete"
    )]
    pub verification_uri_complete: String,
    /// Opaque token we poll create_token with. NEVER displayed to the
    /// user — they only see `user_code`.
    #[serde(rename = "deviceCode", alias = "device_code")]
    pub device_code: String,
    /// How long the entire device flow has before it expires (seconds).
    /// Typically 600 (10 minutes).
    #[serde(rename = "expiresIn", alias = "expires_in")]
    pub expires_in: u32,
    /// Minimum seconds between create_token poll attempts. Respect this
    /// — AWS will return SlowDown errors if we poll faster.
    pub interval: u32,
    /// The OIDC client_id we registered for this session. The poll endpoint
    /// needs it back.
    #[serde(rename = "clientId")]
    pub client_id: String,
    /// The OIDC client_secret we registered for this session.
    #[serde(rename = "clientSecret")]
    pub client_secret: String,
    /// The SSO region — needed for both poll and portal calls later.
    pub region: String,
}

/// First-touch Tauri command for the wizard. Registers an OIDC client,
/// starts a device authorization, and returns everything the frontend
/// needs to (a) show the user a code + link, (b) poll for completion.
#[tauri::command]
pub async fn aws_sso_start_device_auth(
    start_url: String,
    region: String,
) -> Result<DeviceAuthSession> {
    info!("Starting AWS SSO device auth: start_url={start_url} region={region}");
    let http = Client::new();
    let client = register_client(&http, &region).await?;
    let body = StartDeviceAuthRequest {
        client_id: &client.client_id,
        client_secret: &client.client_secret,
        start_url: &start_url,
    };
    let resp = http
        .post(oidc_endpoint(&region, "/device_authorization"))
        .json(&body)
        .send()
        .await
        .map_err(|e| AppError::Other(format!("SSO device_authorization failed: {e}")))?;
    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        return Err(AppError::Other(format!(
            "SSO device_authorization returned {status}: {text}"
        )));
    }
    // The API returns a partial DeviceAuthSession; we fill in client_id /
    // client_secret / region before handing it back.
    #[derive(Deserialize)]
    struct PartialDeviceAuth {
        #[serde(rename = "userCode")]
        user_code: String,
        #[serde(rename = "verificationUri")]
        verification_uri: String,
        #[serde(rename = "verificationUriComplete")]
        verification_uri_complete: String,
        #[serde(rename = "deviceCode")]
        device_code: String,
        #[serde(rename = "expiresIn")]
        expires_in: u32,
        interval: Option<u32>,
    }
    let p = resp
        .json::<PartialDeviceAuth>()
        .await
        .map_err(|e| AppError::Other(format!("SSO device_authorization invalid JSON: {e}")))?;
    Ok(DeviceAuthSession {
        user_code: p.user_code,
        verification_uri: p.verification_uri,
        verification_uri_complete: p.verification_uri_complete,
        device_code: p.device_code,
        expires_in: p.expires_in,
        // 5s is the documented minimum if the server doesn't return one.
        interval: p.interval.unwrap_or(5),
        client_id: client.client_id,
        client_secret: client.client_secret,
        region,
    })
}

// =============================================================================
// Step 3 — Poll for token
// =============================================================================

#[derive(Serialize)]
struct CreateTokenRequest<'a> {
    #[serde(rename = "clientId")]
    client_id: &'a str,
    #[serde(rename = "clientSecret")]
    client_secret: &'a str,
    #[serde(rename = "grantType")]
    grant_type: &'a str,
    #[serde(rename = "deviceCode")]
    device_code: &'a str,
}

#[derive(Deserialize, Debug)]
struct CreateTokenResponse {
    #[serde(rename = "accessToken")]
    access_token: String,
    #[serde(rename = "expiresIn")]
    expires_in: i64,
    #[serde(rename = "refreshToken")]
    refresh_token: Option<String>,
    #[serde(rename = "tokenType")]
    _token_type: Option<String>,
}

/// One poll attempt against the SSO create_token endpoint. The frontend
/// is responsible for calling this on a timer respecting `session.interval`;
/// driving the loop from Rust would either tie up the runtime thread or
/// require an event channel for status updates.
///
/// Return values:
/// - `Pending` — user hasn't approved yet, frontend should keep polling
/// - `Authorized(session)` — token issued, save it and stop polling
/// - `Err` — terminal failure (expired, denied, server error)
#[derive(Serialize, Debug)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum PollResult {
    Pending,
    Authorized {
        access_token: String,
        /// Unix-seconds expiry — frontend stores this with the session
        /// so the probe can detect/refresh expired tokens.
        expires_at: i64,
        refresh_token: Option<String>,
    },
}

/// Refresh-token grant body. Same endpoint as the device-code flow, but
/// `grantType=refresh_token` + the stored refresh token instead of a
/// device code.
#[derive(Serialize)]
struct RefreshTokenRequest<'a> {
    #[serde(rename = "clientId")]
    client_id: &'a str,
    #[serde(rename = "clientSecret")]
    client_secret: &'a str,
    #[serde(rename = "grantType")]
    grant_type: &'a str,
    #[serde(rename = "refreshToken")]
    refresh_token: &'a str,
}

/// Result of a silent SSO refresh. AWS may rotate the refresh token, so
/// callers persist the new one when present (else keep the old).
#[derive(Serialize, Debug)]
pub struct RefreshedToken {
    pub access_token: String,
    pub expires_at: i64,
    pub refresh_token: Option<String>,
}

/// Exchange a refresh token for a fresh access token. This is the cloud
/// analog of the OAuth refresh-on-expiry path in `auth-handler.ts` — it
/// keeps an SSO source alive for the whole SSO session window without
/// re-prompting the user. Errors (refresh token expired/revoked) are the
/// signal that interactive re-auth is required.
#[tauri::command]
pub async fn aws_sso_refresh_token(
    client_id: String,
    client_secret: String,
    refresh_token: String,
    region: String,
) -> Result<RefreshedToken> {
    let http = Client::new();
    let body = RefreshTokenRequest {
        client_id: &client_id,
        client_secret: &client_secret,
        grant_type: "refresh_token",
        refresh_token: &refresh_token,
    };
    let resp = http
        .post(oidc_endpoint(&region, "/token"))
        .json(&body)
        .send()
        .await
        .map_err(|e| AppError::Other(format!("SSO refresh request failed: {e}")))?;
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        let parsed: serde_json::Value =
            serde_json::from_str(&text).unwrap_or_else(|_| serde_json::json!({}));
        let desc = parsed
            .get("error_description")
            .and_then(|v| v.as_str())
            .or_else(|| parsed.get("error").and_then(|v| v.as_str()))
            .unwrap_or("token refresh failed");
        return Err(AppError::Other(format!("SSO refresh failed: {desc}")));
    }
    let parsed = serde_json::from_str::<CreateTokenResponse>(&text)
        .map_err(|e| AppError::Other(format!("SSO refresh invalid JSON: {e}")))?;
    Ok(RefreshedToken {
        access_token: parsed.access_token,
        expires_at: chrono::Utc::now().timestamp() + parsed.expires_in,
        refresh_token: parsed.refresh_token,
    })
}

#[tauri::command]
pub async fn aws_sso_poll_device_auth(session: DeviceAuthSession) -> Result<PollResult> {
    let http = Client::new();
    let body = CreateTokenRequest {
        client_id: &session.client_id,
        client_secret: &session.client_secret,
        grant_type: GRANT_TYPE,
        device_code: &session.device_code,
    };
    let resp = http
        .post(oidc_endpoint(&session.region, "/token"))
        .json(&body)
        .send()
        .await
        .map_err(|e| AppError::Other(format!("SSO create_token request failed: {e}")))?;
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();

    if status.is_success() {
        let parsed = serde_json::from_str::<CreateTokenResponse>(&text)
            .map_err(|e| AppError::Other(format!("SSO create_token invalid JSON: {e}")))?;
        let expires_at = chrono::Utc::now().timestamp() + parsed.expires_in;
        info!("SSO authorization completed, token valid for {}s", parsed.expires_in);
        return Ok(PollResult::Authorized {
            access_token: parsed.access_token,
            expires_at,
            refresh_token: parsed.refresh_token,
        });
    }

    // AWS encodes the "still pending" / "slow down" hints in the body
    // even though the HTTP status is 400. Anything we don't recognize
    // bubbles up as a hard error so the wizard can show it.
    let parsed: serde_json::Value =
        serde_json::from_str(&text).unwrap_or_else(|_| serde_json::json!({}));
    let error_code = parsed
        .get("error")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    match error_code {
        "authorization_pending" | "slow_down" => Ok(PollResult::Pending),
        "" => Err(AppError::Other(format!(
            "SSO create_token returned {status} with body: {text}"
        ))),
        other => {
            let desc = parsed
                .get("error_description")
                .and_then(|v| v.as_str())
                .unwrap_or("(no description)");
            warn!("SSO create_token terminal error: {other} — {desc}");
            Err(AppError::Other(format!("SSO auth failed: {other} — {desc}")))
        }
    }
}

// =============================================================================
// Portal calls — list accounts / list account roles / get role credentials
// =============================================================================
//
// Once we have an access_token, we can hit the SSO Portal API to discover
// which accounts the user can reach and mint short-lived IAM credentials
// for a specific (account, permission-set-role) pair. Those IAM creds are
// what we inject into the container as AWS_* env vars when running
// sts:AssumeRole against the customer's MaestroSecurityAudit role.

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct SsoAccount {
    #[serde(rename = "accountId")]
    pub account_id: String,
    #[serde(rename = "accountName")]
    pub account_name: Option<String>,
    #[serde(rename = "emailAddress")]
    pub email_address: Option<String>,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct SsoAccountRole {
    #[serde(rename = "accountId")]
    pub account_id: String,
    #[serde(rename = "roleName")]
    pub role_name: String,
}

#[derive(Deserialize, Debug)]
struct ListAccountsResponse {
    #[serde(rename = "accountList")]
    account_list: Vec<SsoAccount>,
}

#[derive(Deserialize, Debug)]
struct ListAccountRolesResponse {
    #[serde(rename = "roleList")]
    role_list: Vec<SsoAccountRole>,
}

/// List accounts the user can reach with their SSO session.
#[tauri::command]
pub async fn aws_sso_list_accounts(
    access_token: String,
    region: String,
) -> Result<Vec<SsoAccount>> {
    let http = Client::new();
    let resp = http
        .get(portal_endpoint(&region, "/federation/accounts"))
        .header("x-amz-sso_bearer_token", access_token)
        .send()
        .await
        .map_err(|e| AppError::Other(format!("SSO list_accounts request failed: {e}")))?;
    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        return Err(AppError::Other(format!(
            "SSO list_accounts returned {status}: {text}"
        )));
    }
    let parsed = resp
        .json::<ListAccountsResponse>()
        .await
        .map_err(|e| AppError::Other(format!("SSO list_accounts invalid JSON: {e}")))?;
    Ok(parsed.account_list)
}

/// List the permission-set roles the user has in a given account. The
/// probe picks one of these as the source identity for AssumeRole.
#[tauri::command]
pub async fn aws_sso_list_account_roles(
    access_token: String,
    region: String,
    account_id: String,
) -> Result<Vec<SsoAccountRole>> {
    let http = Client::new();
    let resp = http
        .get(portal_endpoint(&region, "/federation/roles"))
        .header("x-amz-sso_bearer_token", access_token)
        .query(&[("account_id", account_id.as_str())])
        .send()
        .await
        .map_err(|e| AppError::Other(format!("SSO list_account_roles request failed: {e}")))?;
    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        return Err(AppError::Other(format!(
            "SSO list_account_roles returned {status}: {text}"
        )));
    }
    let parsed = resp
        .json::<ListAccountRolesResponse>()
        .await
        .map_err(|e| AppError::Other(format!("SSO list_account_roles invalid JSON: {e}")))?;
    Ok(parsed.role_list)
}

/// Short-lived IAM credentials minted by SSO for a (account, role) pair.
/// These are the env vars we'll inject when running `sts:AssumeRole`
/// inside the Kali container.
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct SsoRoleCredentials {
    #[serde(rename = "accessKeyId")]
    pub access_key_id: String,
    #[serde(rename = "secretAccessKey")]
    pub secret_access_key: String,
    #[serde(rename = "sessionToken")]
    pub session_token: String,
    /// Unix-millis (NOT seconds — the portal API returns ms here).
    pub expiration: i64,
}

#[derive(Deserialize, Debug)]
struct GetRoleCredentialsResponse {
    #[serde(rename = "roleCredentials")]
    role_credentials: SsoRoleCredentials,
}

#[tauri::command]
pub async fn aws_sso_get_role_credentials(
    access_token: String,
    region: String,
    account_id: String,
    role_name: String,
) -> Result<SsoRoleCredentials> {
    let http = Client::new();
    let resp = http
        .get(portal_endpoint(&region, "/federation/credentials"))
        .header("x-amz-sso_bearer_token", access_token)
        .query(&[
            ("account_id", account_id.as_str()),
            ("role_name", role_name.as_str()),
        ])
        .send()
        .await
        .map_err(|e| AppError::Other(format!("SSO get_role_credentials request failed: {e}")))?;
    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        return Err(AppError::Other(format!(
            "SSO get_role_credentials returned {status}: {text}"
        )));
    }
    let parsed = resp
        .json::<GetRoleCredentialsResponse>()
        .await
        .map_err(|e| AppError::Other(format!("SSO get_role_credentials invalid JSON: {e}")))?;
    Ok(parsed.role_credentials)
}

// =============================================================================
// Web-identity federation (Phase 2 — RFC-CLOUD-CREDENTIAL-FEDERATION)
// =============================================================================
//
// The north-star path: exchange the user's Cognito ID token directly for
// short-lived STS creds via sts:AssumeRoleWithWebIdentity. This is an
// UNSIGNED STS action — no AWS credentials are needed to call it, only the
// web-identity token — so the operator's machine never holds an AWS
// credential. The customer's role trust policy gates on the token's
// `aud` (app client) + `custom:org_id` (tenant); see the federation
// trust_mode in infra/.../customer-cloud-assessment.

/// Short-lived STS session from web-identity federation. Mirrors the
/// shape the credential endpoint / container injection consume.
#[derive(Serialize, Debug, Clone)]
pub struct WebIdentityCredentials {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: String,
    /// ISO-8601 expiry from STS.
    pub expiration: String,
}

/// RoleSessionName must match `[\w+=,.@-]{2,64}`. Sanitize freely-formed
/// names (e.g. `maestro-alex@groovysec.com-<assessmentId>`) into that set
/// and clamp the length so CloudTrail still shows a useful identity.
fn sanitize_session_name(raw: &str) -> String {
    let cleaned: String = raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '+' | '=' | ',' | '.' | '@' | '-' | '_') {
                c
            } else {
                '-'
            }
        })
        .collect();
    let trimmed = cleaned.trim_matches('-');
    let bounded = if trimmed.len() > 64 { &trimmed[..64] } else { trimmed };
    if bounded.len() < 2 {
        "maestro-assessment".to_string()
    } else {
        bounded.to_string()
    }
}

/// Extract the text of the first `<tag>…</tag>` from an STS XML response.
/// STS's query API returns XML (no JSON), but the fields we need are flat,
/// well-defined elements, so a targeted slice avoids pulling an XML crate.
fn extract_xml(body: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = body.find(&open)? + open.len();
    let end = body[start..].find(&close)? + start;
    Some(body[start..end].trim().to_string())
}

/// Assume a role via web identity (the user's Cognito ID token). Unsigned
/// STS call. `role_session_name` should encode the operator + assessment
/// for CloudTrail attribution. Session tags are intentionally not passed —
/// AssumeRoleWithWebIdentity derives tags from the token's
/// `https://aws.amazon.com/tags` claim, which Cognito doesn't emit today
/// (future: add via a token customizer if per-tag IAM conditions are wanted).
#[tauri::command]
pub async fn aws_sts_assume_role_web_identity(
    role_arn: String,
    web_identity_token: String,
    role_session_name: String,
    duration_seconds: Option<i64>,
    region: Option<String>,
) -> Result<WebIdentityCredentials> {
    let http = Client::new();
    let region = region.unwrap_or_else(|| "us-east-1".to_string());
    let dur = duration_seconds.unwrap_or(3600).clamp(900, 43200);
    // Regional STS endpoint; the action requires no SigV4 signature.
    let url = format!("https://sts.{region}.amazonaws.com/");
    let params = [
        ("Action", "AssumeRoleWithWebIdentity".to_string()),
        ("Version", "2011-06-15".to_string()),
        ("RoleArn", role_arn),
        ("RoleSessionName", sanitize_session_name(&role_session_name)),
        ("WebIdentityToken", web_identity_token),
        ("DurationSeconds", dur.to_string()),
    ];

    let resp = http
        .post(&url)
        .form(&params)
        .send()
        .await
        .map_err(|e| AppError::Other(format!("STS AssumeRoleWithWebIdentity request failed: {e}")))?;
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();

    if !status.is_success() {
        // STS errors come back as <ErrorResponse><Error><Message>…</Message>.
        let msg = extract_xml(&text, "Message").unwrap_or_else(|| text.chars().take(300).collect());
        return Err(AppError::Other(format!(
            "AssumeRoleWithWebIdentity failed ({status}): {msg}"
        )));
    }

    let access_key_id = extract_xml(&text, "AccessKeyId")
        .ok_or_else(|| AppError::Other("STS response missing AccessKeyId".into()))?;
    let secret_access_key = extract_xml(&text, "SecretAccessKey")
        .ok_or_else(|| AppError::Other("STS response missing SecretAccessKey".into()))?;
    let session_token = extract_xml(&text, "SessionToken")
        .ok_or_else(|| AppError::Other("STS response missing SessionToken".into()))?;
    let expiration = extract_xml(&text, "Expiration").unwrap_or_default();

    info!("AssumeRoleWithWebIdentity ok; session expires {expiration}");
    Ok(WebIdentityCredentials {
        access_key_id,
        secret_access_key,
        session_token,
        expiration,
    })
}
