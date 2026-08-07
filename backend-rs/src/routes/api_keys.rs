//! `/api-keys` — CI/non-interactive API tokens (Scheduled DAST WS5).
//!
//! Mint a long-lived `dast_<prefix>_<secret>` token (shown ONCE), list keys
//! (metadata only — never the secret), and revoke. Auth resolves the org from
//! the key hash in the middleware (see `auth::middleware::api_key_auth`).

use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::get,
    Json, Router,
};
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::{json, Value as JsonValue};
use uuid::Uuid;

use crate::audit;
use crate::auth::middleware::hash_api_key;
use crate::auth::AuthUser;
use crate::error::{AppError, AppResult};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api-keys", get(list).post(mint))
        .route("/api-keys/:id", axum::routing::delete(revoke))
}

#[derive(Debug, sqlx::FromRow, Serialize)]
struct ApiKeyRow {
    id: String,
    name: String,
    prefix: String,
    created_at: DateTime<Utc>,
    last_used_at: Option<DateTime<Utc>>,
    revoked_at: Option<DateTime<Utc>>,
}

async fn list(State(state): State<AppState>, user: AuthUser) -> AppResult<Json<Vec<ApiKeyRow>>> {
    let org_id = user
        .org_id
        .clone()
        .ok_or_else(|| AppError::Forbidden("Missing org_id on caller".to_string()))?;
    let rows: Vec<ApiKeyRow> = sqlx::query_as(
        "SELECT id, name, prefix, created_at, last_used_at, revoked_at
           FROM api_keys WHERE org_id = $1 ORDER BY created_at DESC",
    )
    .bind(&org_id)
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(rows))
}

#[derive(Debug, serde::Deserialize)]
struct MintBody {
    name: String,
}

async fn mint(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<MintBody>,
) -> AppResult<(StatusCode, Json<JsonValue>)> {
    if !user.can_manage_keys() {
        return Err(AppError::Forbidden(
            "Issuing API keys requires the admin or app-owner role.".into(),
        ));
    }
    let org_id = user
        .org_id
        .clone()
        .ok_or_else(|| AppError::Forbidden("Missing org_id on caller".to_string()))?;
    if req.name.trim().is_empty() {
        return Err(AppError::BadRequest("name is required".into()));
    }
    // prefix (display) + secret. uuid gives randomness without a `rand` dep.
    let prefix = Uuid::new_v4().simple().to_string()[..8].to_string();
    let secret = format!(
        "{}{}",
        Uuid::new_v4().simple(),
        Uuid::new_v4().simple()
    );
    let token = format!("dast_{prefix}_{secret}");
    let key_hash = hash_api_key(&token);
    let id = Uuid::new_v4().to_string();

    sqlx::query(
        r#"INSERT INTO api_keys (id, org_id, name, prefix, key_hash, created_by)
           VALUES ($1,$2,$3,$4,$5,$6)"#,
    )
    .bind(&id)
    .bind(&org_id)
    .bind(&req.name)
    .bind(&prefix)
    .bind(&key_hash)
    .bind(&user.id)
    .execute(&state.pool)
    .await?;

    audit::record(&state.pool, &user, "api_key.mint", "api_key", Some(&id), None).await;

    // The plaintext token is returned ONCE — never stored, never re-shown.
    Ok((StatusCode::CREATED, Json(json!({ "id": id, "name": req.name, "prefix": prefix, "token": token }))))
}

async fn revoke(
    State(state): State<AppState>,
    Path(id): Path<String>,
    user: AuthUser,
) -> AppResult<StatusCode> {
    if !user.can_manage_keys() {
        return Err(AppError::Forbidden(
            "Revoking API keys requires the admin or app-owner role.".into(),
        ));
    }
    let org_id = user
        .org_id
        .clone()
        .ok_or_else(|| AppError::Forbidden("Missing org_id on caller".to_string()))?;
    let res = sqlx::query(
        "UPDATE api_keys SET revoked_at = NOW() WHERE id = $1 AND org_id = $2 AND revoked_at IS NULL",
    )
    .bind(&id)
    .bind(&org_id)
    .execute(&state.pool)
    .await?;
    if res.rows_affected() == 0 {
        return Err(AppError::NotFound("API key not found".into()));
    }
    audit::record(&state.pool, &user, "api_key.revoke", "api_key", Some(&id), None).await;
    Ok(StatusCode::NO_CONTENT)
}
