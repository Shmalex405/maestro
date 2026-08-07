//! `/cloud/*` — AWS credential broker for cloud assessments (Option A).
//!
//! `POST /cloud/assume` — the authenticated caller gets short-lived AWS
//! credentials for a read-only cloud assessment. The backend assumes the
//! customer's assessment role using its **ECS task role** (which the role
//! trusts), so:
//!   - the operator's machine never holds an AWS credential, and
//!   - **tenant isolation is enforced here** — the `AuthUser` extractor
//!     applies the `ALLOWED_ORG_ID` guard, so only this org's users reach
//!     this handler. This is the correct home for isolation, because IAM
//!     trust policies cannot gate on the Cognito `custom:org_id` claim
//!     (see docs/RFC-CLOUD-CREDENTIAL-FEDERATION.md addendum).
//!
//! IAM on the task role is the backstop for *which* roles are assumable —
//! even if a caller passes an arbitrary `role_arn`, STS only succeeds for
//! roles the task role is granted `sts:AssumeRole` on.

use axum::{extract::State, routing::post, Json, Router};
use serde::{Deserialize, Serialize};

use crate::auth::AuthUser;
use crate::error::{AppError, AppResult};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route("/cloud/assume", post(assume))
}

#[derive(Debug, Deserialize)]
struct AssumeRequest {
    /// Target assessment role to assume. Falls back to the deployment's
    /// `ASSESSMENT_ROLE_ARN` when omitted.
    #[serde(default)]
    role_arn: Option<String>,
    /// Optional label (e.g. assessment id) folded into the RoleSessionName
    /// for CloudTrail attribution.
    #[serde(default)]
    session_label: Option<String>,
}

#[derive(Debug, Serialize)]
struct AssumeResponse {
    access_key_id: String,
    secret_access_key: String,
    session_token: String,
    /// Unix-seconds expiry of the session.
    expiration: i64,
    /// The ARN that was assumed (for display / audit on the desktop).
    assumed_role_arn: String,
}

/// RoleSessionName must match `[\w+=,.@-]{2,64}`. Build one from the parts
/// and sanitize so CloudTrail still shows a useful, per-user identity.
fn session_name(parts: &[&str]) -> String {
    let raw = parts.join("-");
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
    let bounded = if trimmed.len() > 64 {
        &trimmed[..64]
    } else {
        trimmed
    };
    if bounded.len() < 2 {
        "maestro-assessment".to_string()
    } else {
        bounded.to_string()
    }
}

async fn assume(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<AssumeRequest>,
) -> AppResult<Json<AssumeResponse>> {
    // Tenant isolation is already enforced by the AuthUser extractor
    // (ALLOWED_ORG_ID guard); org_id is required for the audit session name.
    let org_id = user
        .org_id
        .clone()
        .ok_or_else(|| AppError::Forbidden("Missing org_id on caller".to_string()))?;

    let role_arn = req
        .role_arn
        .clone()
        .or_else(|| state.settings.assessment_role_arn.clone())
        .ok_or_else(|| {
            AppError::BadRequest(
                "No role_arn provided and ASSESSMENT_ROLE_ARN not configured".to_string(),
            )
        })?;

    let label = req.session_label.as_deref().unwrap_or("assessment");
    let name = session_name(&["maestro", user.email.as_str(), org_id.as_str(), label]);

    let client = state.sts_client().await;
    let resp = client
        .assume_role()
        .role_arn(&role_arn)
        .role_session_name(&name)
        .duration_seconds(3600)
        .send()
        .await
        .map_err(|e| {
            // The SdkError `Display` alone is just "service error" — the real
            // STS reason (AccessDenied with the principal/resource detail,
            // ValidationError, etc.) lives in the source chain. Walk it so a
            // misconfigured trust policy or a missing task-role grant is
            // legible in the toast/logs instead of an opaque 500.
            use std::error::Error as _;
            let mut detail = e.to_string();
            let mut src = e.source();
            while let Some(s) = src {
                detail.push_str(" | ");
                detail.push_str(&s.to_string());
                src = s.source();
            }
            AppError::Internal(format!("AssumeRole failed for {role_arn}: {detail}"))
        })?;

    let creds = resp
        .credentials()
        .ok_or_else(|| AppError::Internal("AssumeRole returned no credentials".to_string()))?;

    Ok(Json(AssumeResponse {
        access_key_id: creds.access_key_id().to_string(),
        secret_access_key: creds.secret_access_key().to_string(),
        session_token: creds.session_token().to_string(),
        expiration: creds.expiration().secs(),
        assumed_role_arn: role_arn,
    }))
}
