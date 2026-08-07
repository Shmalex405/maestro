//! `/scan-configs` — per-target authenticated-scan + scope config (DAST page).
//!
//!   GET  /scan-configs?target_id=X  → the config (or empty defaults)
//!   POST /scan-configs              → upsert by (org, target)
//!
//! The deterministic DAST run reads this to scan behind auth + stay in scope.
//! auth/scope are opaque JSONB (see migration 0028). Per-org scoped.

use axum::{
    extract::{Query, State},
    http::StatusCode,
    routing::post,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use uuid::Uuid;

use crate::auth::AuthUser;
use crate::error::{AppError, AppResult};
use crate::models::scan_config::ScanConfigRow;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route("/scan-configs", post(upsert_config).get(get_config))
}

fn empty_object() -> JsonValue {
    JsonValue::Object(serde_json::Map::new())
}

#[derive(Debug, Serialize)]
struct ConfigView {
    target_id: String,
    auth: JsonValue,
    scope: JsonValue,
}

#[derive(Debug, Deserialize)]
struct ConfigQuery {
    target_id: String,
}

async fn get_config(
    State(state): State<AppState>,
    Query(q): Query<ConfigQuery>,
    user: AuthUser,
) -> AppResult<Json<ConfigView>> {
    let org_id = user
        .org_id
        .clone()
        .ok_or_else(|| AppError::Forbidden("Missing org_id on caller".to_string()))?;

    let row: Option<ScanConfigRow> = sqlx::query_as(
        r#"SELECT id, org_id, target_id, auth, scope, created_at, updated_at
           FROM scan_configs WHERE org_id = $1 AND target_id = $2"#,
    )
    .bind(&org_id)
    .bind(&q.target_id)
    .fetch_optional(&state.pool)
    .await?;

    Ok(Json(match row {
        Some(c) => ConfigView {
            target_id: c.target_id,
            auth: c.auth,
            scope: c.scope,
        },
        None => ConfigView {
            target_id: q.target_id,
            auth: empty_object(),
            scope: empty_object(),
        },
    }))
}

#[derive(Debug, Deserialize)]
struct UpsertBody {
    target_id: String,
    #[serde(default = "empty_object")]
    auth: JsonValue,
    #[serde(default = "empty_object")]
    scope: JsonValue,
}

async fn upsert_config(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<UpsertBody>,
) -> AppResult<(StatusCode, Json<ConfigView>)> {
    let org_id = user
        .org_id
        .clone()
        .ok_or_else(|| AppError::Forbidden("Missing org_id on caller".to_string()))?;

    let id = Uuid::new_v4().to_string();
    let row: ScanConfigRow = sqlx::query_as(
        r#"INSERT INTO scan_configs (id, org_id, target_id, auth, scope, created_at, updated_at)
           VALUES ($1, $2, $3, $4, $5, NOW(), NOW())
           ON CONFLICT (org_id, target_id)
           DO UPDATE SET auth = EXCLUDED.auth, scope = EXCLUDED.scope, updated_at = NOW()
           RETURNING id, org_id, target_id, auth, scope, created_at, updated_at"#,
    )
    .bind(&id)
    .bind(&org_id)
    .bind(&req.target_id)
    .bind(&req.auth)
    .bind(&req.scope)
    .fetch_one(&state.pool)
    .await?;

    Ok((
        StatusCode::OK,
        Json(ConfigView {
            target_id: row.target_id,
            auth: row.auth,
            scope: row.scope,
        }),
    ))
}
