//! `/configs/{kind}` — generic key-value store for org-shared settings.
//!
//! One endpoint pair (GET + PUT) handles every config kind so the desktop
//! doesn't need a per-config table when shapes change. Storage is one
//! row per `(org_id, kind)` in `org_configs` with a JSONB `value`. Schema
//! validation lives client-side at the Tauri command boundary; backend
//! treats the blob as opaque.
//!
//! Personal credentials (Jira API tokens, GitHub PATs, etc.) MUST NEVER
//! be sent here. Per-user secrets stay in the OS keychain on each user's
//! machine. The whitelist below enforces that the only allowed `kind`s
//! are org-shared shapes.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::get,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use crate::auth::AuthUser;
use crate::error::{AppError, AppResult};
use crate::state::AppState;

/// Kinds the API accepts. Anything outside this list returns 400 to
/// prevent the endpoint from becoming a generic dumping ground that
/// drifts out of frontend type safety. Keep in sync with the desktop
/// `tauri-api.ts` config.* methods.
const ALLOWED_KINDS: &[&str] = &["scope", "integrations", "llm", "tools", "agents", "credentials"];

pub fn router() -> Router<AppState> {
    Router::new().route("/configs/:kind", get(get_config).put(put_config))
}

#[derive(Debug, Deserialize)]
struct ConfigUpsert {
    value: JsonValue,
}

#[derive(Debug, Serialize)]
struct ConfigResponse {
    kind: String,
    value: JsonValue,
    updated_at: Option<chrono::DateTime<chrono::Utc>>,
    updated_by: Option<String>,
}

fn check_kind(kind: &str) -> AppResult<()> {
    if !ALLOWED_KINDS.iter().any(|k| *k == kind) {
        return Err(AppError::BadRequest(format!(
            "Unknown config kind '{kind}'. Allowed: {}",
            ALLOWED_KINDS.join(", ")
        )));
    }
    Ok(())
}

async fn get_config(
    State(state): State<AppState>,
    Path(kind): Path<String>,
    user: AuthUser,
) -> AppResult<Json<ConfigResponse>> {
    check_kind(&kind)?;
    let org_id = user
        .org_id
        .as_ref()
        .ok_or_else(|| AppError::BadRequest("JWT missing org_id claim".into()))?;

    let row: Option<(JsonValue, Option<chrono::DateTime<chrono::Utc>>, Option<String>)> =
        sqlx::query_as(
            "SELECT value, updated_at, updated_by FROM org_configs
              WHERE org_id = $1 AND kind = $2",
        )
        .bind(org_id)
        .bind(&kind)
        .fetch_optional(&state.pool)
        .await?;

    let (value, updated_at, updated_by) = row
        .unwrap_or_else(|| (JsonValue::Object(serde_json::Map::new()), None, None));

    Ok(Json(ConfigResponse {
        kind,
        value,
        updated_at,
        updated_by,
    }))
}

async fn put_config(
    State(state): State<AppState>,
    Path(kind): Path<String>,
    user: AuthUser,
    Json(req): Json<ConfigUpsert>,
) -> AppResult<(StatusCode, Json<ConfigResponse>)> {
    check_kind(&kind)?;
    let org_id = user
        .org_id
        .as_ref()
        .ok_or_else(|| AppError::BadRequest("JWT missing org_id claim".into()))?;

    sqlx::query(
        r#"INSERT INTO org_configs (org_id, kind, value, updated_by)
            VALUES ($1, $2, $3, $4)
           ON CONFLICT (org_id, kind) DO UPDATE
              SET value = EXCLUDED.value,
                  updated_at = NOW(),
                  updated_by = EXCLUDED.updated_by"#,
    )
    .bind(org_id)
    .bind(&kind)
    .bind(&req.value)
    .bind(&user.id)
    .execute(&state.pool)
    .await?;

    let (value, updated_at, updated_by): (
        JsonValue,
        Option<chrono::DateTime<chrono::Utc>>,
        Option<String>,
    ) = sqlx::query_as(
        "SELECT value, updated_at, updated_by FROM org_configs
          WHERE org_id = $1 AND kind = $2",
    )
    .bind(org_id)
    .bind(&kind)
    .fetch_one(&state.pool)
    .await?;

    Ok((
        StatusCode::OK,
        Json(ConfigResponse {
            kind,
            value,
            updated_at,
            updated_by,
        }),
    ))
}
