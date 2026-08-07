//! `/footholds` — the post-exploitation foothold / loot store (RFC §6.1).
//!
//! Assessment-scoped record of acquired access (a token / cred / assumed-role /
//! session / shell) that the post-exploit-operator deposits on acquire and operates
//! THROUGH on later steps. Internal-only — `material` is never redacted (same trust
//! model as findings). Revoked wholesale at end-of-run.
//!
//! Endpoints:
//!   POST /footholds                        — establish (deposit) a foothold
//!   GET  /footholds?assessment_id=&status= — list (operator enumerates held access)
//!   GET  /footholds/:id                    — consume one (returns material)
//!   POST /footholds/:id/revoke             — revoke one
//!   POST /footholds/revoke?assessment_id=  — revoke all live for an assessment (end-of-run)

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use serde_json::{json, Value as JsonValue};
use uuid::Uuid;

use crate::auth::AuthUser;
use crate::error::{AppError, AppResult};
use crate::models::foothold::{FootholdRow, FOOTHOLD_KINDS};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/footholds", post(establish).get(list))
        .route("/footholds/revoke", post(revoke_all))
        .route("/footholds/:id", get(consume))
        .route("/footholds/:id/revoke", post(revoke_one))
}

const SELECT_COLS: &str = "id, org_id, assessment_id, kind, target, material, grants, \
     how_acquired, node_key, status, established_at, expires_at, evidence_ref";

fn require_org(user: &AuthUser) -> AppResult<String> {
    user.org_id
        .clone()
        .ok_or_else(|| AppError::Forbidden("Missing org_id on caller".to_string()))
}

#[derive(Debug, Deserialize)]
struct EstablishBody {
    assessment_id: String,
    kind: String,
    target: String,
    #[serde(default)]
    material: Option<JsonValue>,
    #[serde(default)]
    grants: Option<Vec<String>>,
    #[serde(default)]
    how_acquired: Option<String>,
    #[serde(default)]
    node_key: Option<String>,
    #[serde(default)]
    expires_at: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default)]
    evidence_ref: Option<String>,
}

async fn establish(
    State(state): State<AppState>,
    user: AuthUser,
    Json(body): Json<EstablishBody>,
) -> AppResult<(StatusCode, Json<FootholdRow>)> {
    let org_id = require_org(&user)?;
    if !FOOTHOLD_KINDS.contains(&body.kind.as_str()) {
        return Err(AppError::BadRequest(format!(
            "Invalid foothold kind '{}'. Must be one of: {}",
            body.kind,
            FOOTHOLD_KINDS.join(", ")
        )));
    }
    let id = Uuid::new_v4().to_string();
    let row: FootholdRow = sqlx::query_as(
        r#"INSERT INTO footholds
              (id, org_id, assessment_id, kind, target, material, grants,
               how_acquired, node_key, status, established_at, expires_at, evidence_ref)
           VALUES ($1,$2,$3,$4,$5, COALESCE($6::jsonb,'{}'::jsonb),
                   COALESCE($7::text[], ARRAY[]::text[]),
                   $8,$9,'live', NOW(), $10, $11)
           RETURNING id, org_id, assessment_id, kind, target, material, grants,
                     how_acquired, node_key, status, established_at, expires_at, evidence_ref"#,
    )
    .bind(&id)
    .bind(&org_id)
    .bind(&body.assessment_id)
    .bind(&body.kind)
    .bind(&body.target)
    .bind(&body.material)
    .bind(body.grants.clone().unwrap_or_default())
    .bind(&body.how_acquired)
    .bind(&body.node_key)
    .bind(body.expires_at)
    .bind(&body.evidence_ref)
    .fetch_one(&state.pool)
    .await?;
    Ok((StatusCode::CREATED, Json(row)))
}

#[derive(Debug, Deserialize)]
struct ListQuery {
    #[serde(default)]
    assessment_id: Option<String>,
    /// Filter by raw status; with status=live, past-expiry footholds are excluded.
    #[serde(default)]
    status: Option<String>,
}

async fn list(
    State(state): State<AppState>,
    Query(q): Query<ListQuery>,
    user: AuthUser,
) -> AppResult<Json<Vec<FootholdRow>>> {
    let org_id = require_org(&user)?;
    // status=live also requires not-past-expiry, so the operator never plans
    // through dead access. ($3 IS DISTINCT FROM 'live' short-circuits the expiry
    // constraint for null / non-live filters.)
    let sql = format!(
        "SELECT {SELECT_COLS} FROM footholds
         WHERE org_id = $1
           AND ($2::text IS NULL OR assessment_id = $2)
           AND ($3::text IS NULL OR status = $3)
           AND ($3::text IS DISTINCT FROM 'live' OR expires_at IS NULL OR expires_at >= NOW())
         ORDER BY established_at DESC"
    );
    let rows: Vec<FootholdRow> = sqlx::query_as(&sql)
        .bind(&org_id)
        .bind(&q.assessment_id)
        .bind(&q.status)
        .fetch_all(&state.pool)
        .await?;
    Ok(Json(rows))
}

async fn consume(
    State(state): State<AppState>,
    Path(id): Path<String>,
    user: AuthUser,
) -> AppResult<Json<FootholdRow>> {
    let org_id = require_org(&user)?;
    let sql = format!("SELECT {SELECT_COLS} FROM footholds WHERE org_id = $1 AND id = $2");
    let row: Option<FootholdRow> = sqlx::query_as(&sql)
        .bind(&org_id)
        .bind(&id)
        .fetch_optional(&state.pool)
        .await?;
    row.map(Json)
        .ok_or_else(|| AppError::NotFound(format!("foothold '{id}' not found")))
}

async fn revoke_one(
    State(state): State<AppState>,
    Path(id): Path<String>,
    user: AuthUser,
) -> AppResult<Json<FootholdRow>> {
    let org_id = require_org(&user)?;
    let sql = format!(
        "UPDATE footholds SET status = 'revoked' WHERE org_id = $1 AND id = $2 RETURNING {SELECT_COLS}"
    );
    let row: Option<FootholdRow> = sqlx::query_as(&sql)
        .bind(&org_id)
        .bind(&id)
        .fetch_optional(&state.pool)
        .await?;
    row.map(Json)
        .ok_or_else(|| AppError::NotFound(format!("foothold '{id}' not found")))
}

#[derive(Debug, Deserialize)]
struct RevokeAllQuery {
    assessment_id: String,
}

async fn revoke_all(
    State(state): State<AppState>,
    Query(q): Query<RevokeAllQuery>,
    user: AuthUser,
) -> AppResult<Json<JsonValue>> {
    let org_id = require_org(&user)?;
    let res = sqlx::query(
        "UPDATE footholds SET status = 'revoked'
         WHERE org_id = $1 AND assessment_id = $2 AND status <> 'revoked'",
    )
    .bind(&org_id)
    .bind(&q.assessment_id)
    .execute(&state.pool)
    .await?;
    Ok(Json(json!({ "revoked": res.rows_affected() })))
}
