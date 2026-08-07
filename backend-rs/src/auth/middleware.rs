//! Authenticated request extractor — dispatches to the right JWT verifier
//! based on `auth_provider`, enforces the `ALLOWED_ORG_ID` tenancy guard,
//! and exposes the resulting `AuthUser` to handlers via axum's extractor
//! machinery.

use axum::{
    extract::{FromRequestParts, Request, State},
    http::{header::AUTHORIZATION, request::Parts, Method},
    middleware::Next,
    response::Response,
};

use crate::auth::jwt::{verify_cognito_token, verify_local_token, verify_oidc_token, TokenData};
use crate::error::{AppError, AppResult};
use crate::state::AppState;

/// Cognito groups that mark a view-only user. Both the canonical `read_only`
/// group and the legacy `viewer` group are honored so neither naming slips
/// through. Mirrors the desktop client's read-only group set.
pub const READ_ONLY_GROUPS: [&str; 2] = ["read_only", "viewer"];

fn is_mutating(method: &Method) -> bool {
    matches!(
        *method,
        Method::POST | Method::PUT | Method::PATCH | Method::DELETE
    )
}

/// The authenticated user populated into every protected handler.
/// Same shape as `backend/app/core/security.py:User`.
#[derive(Debug, Clone)]
pub struct AuthUser {
    pub id: String,
    pub email: String,
    pub org_id: Option<String>,
    pub roles: Vec<String>,
    /// Set when the token is an M2M service-account JWT (Phase 6
    /// caching plan). Identifies which service issued it (e.g.,
    /// "cache-stats-router"). User tokens are None.
    pub service_caller: Option<String>,
}

impl AuthUser {
    fn from_token(data: TokenData) -> Self {
        Self {
            id: data.sub,
            email: data.email.unwrap_or_default(),
            org_id: data.org_id,
            roles: data.roles,
            service_caller: data.service_caller,
        }
    }

    #[allow(dead_code)]
    pub fn has_any_role(&self, required: &[&str]) -> bool {
        required.iter().any(|r| self.roles.iter().any(|x| x == r))
    }

    /// True when this user is restricted to view-only access.
    pub fn is_read_only(&self) -> bool {
        self.has_any_role(&READ_ONLY_GROUPS)
    }

    /// True when this caller is the cache-stats router service token.
    /// Used by `/cache-stats` to allow cross-tenant writes via the
    /// `service_org_id` query param.
    pub fn is_cache_stats_router(&self) -> bool {
        self.service_caller.as_deref() == Some("cache-stats-router")
    }

    // ── DAST RBAC (WS2) ──────────────────────────────────────────────────
    // Recognized roles (Cognito groups): admin, app-owner, scan-operator,
    // viewer/read_only. Enforcement is OPT-IN per org: a user with NO roles
    // keeps full (non-readonly) access, so orgs that haven't provisioned the
    // groups are unaffected. Once a DAST role is assigned, it's required.
    pub fn is_admin(&self) -> bool {
        self.has_any_role(&["admin", "admins", "Admin"])
    }
    pub fn is_app_owner(&self) -> bool {
        self.has_any_role(&["app-owner", "app_owner"])
    }
    #[allow(dead_code)]
    pub fn is_scan_operator(&self) -> bool {
        self.has_any_role(&["scan-operator", "scan_operator"])
    }

    /// Can manage DAST config (policies, schedules, applications, configs).
    /// Read-only is always denied; otherwise allowed (the global read_only_guard
    /// is the live boundary today — this is the explicit per-route hook).
    #[allow(dead_code)]
    pub fn can_manage_dast(&self) -> bool {
        !self.is_read_only()
    }

    /// Can issue/revoke org-wide CI API keys — the most sensitive action.
    /// Restricted to admins / app-owners once roles are adopted; orgs with no
    /// roles assigned keep current behavior (any non-readonly user).
    pub fn can_manage_keys(&self) -> bool {
        if self.is_read_only() {
            return false;
        }
        if self.service_caller.is_some() {
            return true;
        }
        self.roles.is_empty() || self.is_admin() || self.is_app_owner()
    }
}

#[axum::async_trait]
impl FromRequestParts<AppState> for AuthUser {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let token = extract_bearer(parts)?;
        // CI API keys (WS5): `dast_<prefix>_<secret>`. Resolve the org from the
        // key hash and run as a service_caller="ci" principal (bypasses the
        // tenancy guard like other service tokens — the key IS the org binding).
        if token.starts_with("dast_") {
            return api_key_auth(&state.pool, &token).await;
        }
        let data = match state.settings.auth_provider.as_str() {
            "local" => verify_local_token(&state.settings, &token)?,
            "cognito" => verify_cognito_token(&state.settings, &token, &state.jwks).await?,
            "oidc" | "okta" => verify_oidc_token(&state.settings, &token, &state.jwks).await?,
            other => {
                return Err(AppError::Internal(format!(
                    "Invalid auth provider configured: {other}"
                )))
            }
        };
        // Service-account tokens bypass the per-tenant org_id check —
        // they're authorized to write to any org by definition (e.g.,
        // the cache-stats-router Lambda fanning proxy events out
        // across all tenants). The route handlers that accept these
        // tokens enforce per-call org targeting via query params
        // (see `/cache-stats?service_org_id=X`). User-facing routes
        // never opt in to service tokens, so the bypass is safe.
        if data.service_caller.is_none() {
            enforce_tenancy(&state.settings.allowed_org_id, &data.org_id)?;
        } else {
            tracing::info!(
                service = %data.service_caller.as_deref().unwrap_or(""),
                "auth: service-account token accepted, tenancy guard bypassed"
            );
        }
        let user = AuthUser::from_token(data);
        // Ensure the user row exists so FK-referencing inserts (repos,
        // findings, audit logs, etc.) succeed. Idempotent — inserts on
        // first authed request, no-op on every request after. Failure to
        // upsert is logged but doesn't block the request — auth itself
        // succeeded.
        if let Err(e) = ensure_user_row(&state.pool, &user).await {
            tracing::warn!(user_id = %user.id, error = %e, "ensure_user_row failed");
        }
        Ok(user)
    }
}

/// Global guard that makes the `read_only` role a real server-side boundary,
/// not just a UI affordance: any mutating request (POST/PUT/PATCH/DELETE) from
/// a read-only user is rejected with 403. Mirrors the desktop client's
/// `cloudRequest` method guard.
///
/// This middleware *only blocks* — it never *authenticates*. Public routes
/// (login / register / token refresh) carry no valid bearer token, so
/// `AuthUser` extraction fails and the request passes straight through;
/// authentication for protected routes stays in their `AuthUser` extractor.
/// Service-account tokens (e.g. the cache-stats router) are never read-only
/// and pass through. Non-mutating methods are never touched.
pub async fn read_only_guard(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Result<Response, AppError> {
    if !is_mutating(req.method()) {
        return Ok(next.run(req).await);
    }
    let (mut parts, body) = req.into_parts();
    if let Ok(user) = AuthUser::from_request_parts(&mut parts, &state).await {
        if user.is_read_only() {
            return Err(AppError::Forbidden(
                "Read-only access — this action is disabled for your role.".into(),
            ));
        }
    }
    Ok(next.run(Request::from_parts(parts, body)).await)
}

/// SHA-256 hex of an API token.
pub fn hash_api_key(token: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(token.as_bytes());
    hex::encode(h.finalize())
}

/// Authenticate a `dast_*` API key: validate the hash, stamp last_used_at, and
/// build a CI service principal scoped to the key's org. 401 if unknown/revoked.
async fn api_key_auth(pool: &sqlx::PgPool, token: &str) -> AppResult<AuthUser> {
    let key_hash = hash_api_key(token);
    let row: Option<(String, Option<String>)> = sqlx::query_as(
        r#"UPDATE api_keys SET last_used_at = NOW()
           WHERE key_hash = $1 AND revoked_at IS NULL
           RETURNING org_id, created_by"#,
    )
    .bind(&key_hash)
    .fetch_optional(pool)
    .await
    .map_err(|e| AppError::Internal(format!("api key lookup failed: {e}")))?;

    let Some((org_id, created_by)) = row else {
        return Err(AppError::Unauthorized("Invalid or revoked API key".into()));
    };
    Ok(AuthUser {
        id: created_by.unwrap_or_else(|| format!("ci:{org_id}")),
        email: "ci@apikey".to_string(),
        org_id: Some(org_id),
        // CI keys can run scans + trigger; service_caller bypasses the tenancy
        // guard (the key already binds to one org).
        roles: vec!["scan-operator".to_string()],
        service_caller: Some("ci".to_string()),
    })
}

async fn ensure_user_row(pool: &sqlx::PgPool, user: &AuthUser) -> sqlx::Result<()> {
    sqlx::query(
        r#"INSERT INTO users (id, email, name, is_active, org_id)
           VALUES ($1, $2, $3, TRUE, $4)
           ON CONFLICT (id) DO NOTHING"#,
    )
    .bind(&user.id)
    .bind(&user.email)
    .bind(user.email.split('@').next().unwrap_or(&user.email))
    .bind(&user.org_id)
    .execute(pool)
    .await
    .map(|_| ())
}

fn extract_bearer(parts: &Parts) -> AppResult<String> {
    let header = parts
        .headers
        .get(AUTHORIZATION)
        .ok_or_else(|| AppError::Unauthorized("Not authenticated".into()))?
        .to_str()
        .map_err(|_| AppError::Unauthorized("Invalid Authorization header".into()))?;
    let (scheme, token) = header
        .split_once(' ')
        .ok_or_else(|| AppError::Unauthorized("Invalid Authorization header".into()))?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return Err(AppError::Unauthorized(
            "Invalid authentication scheme".into(),
        ));
    }
    Ok(token.to_string())
}

fn enforce_tenancy(allowed: &Option<String>, token_org: &Option<String>) -> AppResult<()> {
    let Some(required) = allowed else {
        return Ok(());
    };
    match token_org.as_deref() {
        Some(t) if t == required.as_str() => Ok(()),
        None => {
            tracing::warn!(required = %required, "auth: token missing custom:org_id claim");
            Err(AppError::Forbidden(format!(
                "ACCOUNT_NOT_PROVISIONED: your user is missing the custom:org_id claim. \
                 Have an admin set custom:org_id = \"{required}\" on your Cognito user."
            )))
        }
        Some(t) => {
            tracing::warn!(required = %required, got = %t, "auth: cross-tenant token rejected");
            Err(AppError::Forbidden(format!(
                "WRONG_TENANT: your account is provisioned for org '{t}' but this backend serves '{required}'."
            )))
        }
    }
}
