//! `/targets` — canonical target identity layer.
//!
//! Phase 2 of the caching plan (see `backend-rs/migrations/0018_targets.sql`).
//!
//! Endpoints:
//!   GET  /targets               — list targets for the org
//!   GET  /targets/:id           — single target with metadata
//!   POST /targets/resolve       — canonicalize a raw target string and
//!                                  upsert into the targets table; returns
//!                                  the stable target_id
//!
//! POST /targets/resolve is the workhorse — every other caching layer
//! (baseline-aware findings, SAST cache, recon cache) keys off
//! `target_id`, so before any cache lookup the caller resolves their
//! raw scope entry through this endpoint.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use uuid::Uuid;

use crate::auth::AuthUser;
use crate::error::{AppError, AppResult};
use crate::state::AppState;
use crate::util::target_canonical::{canonicalize, fingerprint, TargetType};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/targets", get(list_targets))
        .route("/targets/resolve", post(resolve_target))
        .route(
            "/targets/:id",
            get(get_target).patch(update_target).delete(archive_target),
        )
}

/// Archive a target (soft delete) — removes it from the active list. Used by the
/// Scheduled DAST Targets page to clean up targets. Idempotent.
async fn archive_target(
    State(state): State<AppState>,
    Path(id): Path<String>,
    user: AuthUser,
) -> AppResult<StatusCode> {
    let org_id = user
        .org_id
        .clone()
        .ok_or_else(|| AppError::Forbidden("Missing org_id on caller".to_string()))?;
    let res = sqlx::query(
        "UPDATE targets SET archived_at = NOW(), updated_at = NOW() \
         WHERE id = $1 AND org_id = $2 AND archived_at IS NULL",
    )
    .bind(&id)
    .bind(&org_id)
    .execute(&state.pool)
    .await?;
    if res.rows_affected() == 0 {
        return Err(AppError::NotFound("Target not found".into()));
    }
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize)]
struct UpdateTargetBody {
    /// Assign (or, with empty string, clear) the application. NULL = unchanged.
    #[serde(default)]
    application_id: Option<String>,
}

async fn update_target(
    State(state): State<AppState>,
    Path(id): Path<String>,
    user: AuthUser,
    Json(req): Json<UpdateTargetBody>,
) -> AppResult<Json<TargetResponse>> {
    let org_id = user
        .org_id
        .clone()
        .ok_or_else(|| AppError::Forbidden("Missing org_id on caller".to_string()))?;
    // '' clears the assignment, NULL leaves it unchanged.
    let row: Option<TargetRow> = sqlx::query_as(
        r#"UPDATE targets
              SET application_id = CASE WHEN $3 IS NULL THEN application_id
                                       WHEN $3 = '' THEN NULL ELSE $3 END,
                  last_seen_at = last_seen_at
            WHERE id = $1 AND org_id = $2
            RETURNING *"#,
    )
    .bind(&id)
    .bind(&org_id)
    .bind(&req.application_id)
    .fetch_optional(&state.pool)
    .await?;
    let row = row.ok_or_else(|| AppError::NotFound("Target not found".into()))?;
    Ok(Json(TargetResponse::from(&row)))
}

#[derive(Debug, sqlx::FromRow)]
struct TargetRow {
    id: String,
    org_id: String,
    target_type: String,
    canonical_value: String,
    raw_values: JsonValue,
    fingerprint: String,
    metadata: JsonValue,
    first_seen_at: DateTime<Utc>,
    last_seen_at: DateTime<Utc>,
    archived_at: Option<DateTime<Utc>>,
    /// Application this target belongs to (migration 0038). NULL = unassigned.
    application_id: Option<String>,
    /// How this target was created (migration 0043): 'dast' | 'assessment' |
    /// 'scope' | NULL. The DAST page lists source='dast'.
    source: Option<String>,
}

#[derive(Debug, Serialize)]
struct TargetResponse {
    id: String,
    org_id: String,
    target_type: String,
    canonical_value: String,
    raw_values: JsonValue,
    fingerprint: String,
    metadata: JsonValue,
    first_seen_at: DateTime<Utc>,
    last_seen_at: DateTime<Utc>,
    archived_at: Option<DateTime<Utc>>,
    application_id: Option<String>,
    source: Option<String>,
}

impl From<&TargetRow> for TargetResponse {
    fn from(t: &TargetRow) -> Self {
        Self {
            id: t.id.clone(),
            org_id: t.org_id.clone(),
            target_type: t.target_type.clone(),
            canonical_value: t.canonical_value.clone(),
            raw_values: t.raw_values.clone(),
            fingerprint: t.fingerprint.clone(),
            metadata: t.metadata.clone(),
            first_seen_at: t.first_seen_at,
            last_seen_at: t.last_seen_at,
            archived_at: t.archived_at,
            application_id: t.application_id.clone(),
            source: t.source.clone(),
        }
    }
}

#[derive(Debug, Deserialize)]
struct ListQuery {
    /// Filter by target_type. Accepts the same enum values as the table.
    #[serde(default)]
    target_type: Option<String>,
    /// Include archived targets in the response. Default: false (the
    /// dashboard's "active targets" view).
    #[serde(default)]
    include_archived: Option<bool>,
    /// Filter by source ('dast' | 'assessment' | 'scope'). The Scheduled DAST
    /// Targets page passes 'dast' so it shows only targets created there.
    #[serde(default)]
    source: Option<String>,
    /// Filter to a single application's targets (the runner/UI fan-out query).
    #[serde(default)]
    application_id: Option<String>,
}

async fn list_targets(
    State(state): State<AppState>,
    Query(q): Query<ListQuery>,
    user: AuthUser,
) -> AppResult<Json<Vec<TargetResponse>>> {
    let org_id = user
        .org_id
        .clone()
        .ok_or_else(|| AppError::Forbidden("Missing org_id on caller".to_string()))?;

    // QueryBuilder so target_type + source filters compose without juggling
    // positional bind indexes.
    let mut qb = sqlx::QueryBuilder::new("SELECT * FROM targets WHERE org_id = ");
    qb.push_bind(&org_id);
    if !q.include_archived.unwrap_or(false) {
        qb.push(" AND archived_at IS NULL");
    }
    if let Some(tt) = q.target_type.as_ref() {
        qb.push(" AND target_type = ").push_bind(tt);
    }
    if let Some(src) = q.source.as_ref() {
        qb.push(" AND source = ").push_bind(src);
    }
    if let Some(app) = q.application_id.as_ref() {
        qb.push(" AND application_id = ").push_bind(app);
    }
    qb.push(" ORDER BY last_seen_at DESC LIMIT 500");

    let rows: Vec<TargetRow> = qb.build_query_as().fetch_all(&state.pool).await?;

    Ok(Json(rows.iter().map(TargetResponse::from).collect()))
}

async fn get_target(
    State(state): State<AppState>,
    Path(id): Path<String>,
    user: AuthUser,
) -> AppResult<Json<TargetResponse>> {
    let org_id = user
        .org_id
        .clone()
        .ok_or_else(|| AppError::Forbidden("Missing org_id on caller".to_string()))?;

    let row: Option<TargetRow> = sqlx::query_as(
        "SELECT * FROM targets WHERE id = $1 AND org_id = $2",
    )
    .bind(&id)
    .bind(&org_id)
    .fetch_optional(&state.pool)
    .await?;

    let row = row.ok_or_else(|| AppError::NotFound("Target not found".into()))?;
    Ok(Json(TargetResponse::from(&row)))
}

#[derive(Debug, Deserialize)]
struct ResolveBody {
    /// The raw target string from scope.yml (URL, hostname, CIDR, repo
    /// URL, or cloud account identifier).
    raw_value: String,
    /// One of: 'web' | 'host' | 'cidr' | 'repo' | 'cloud_account'.
    /// When omitted, the server classifies via the heuristic
    /// `TargetType::classify` — but the caller SHOULD pass this
    /// explicitly because classification heuristics are best-effort.
    #[serde(default)]
    target_type: Option<String>,
    /// Optional metadata to merge into the targets row (e.g.,
    /// { "git_url": "...", "default_branch": "main" } for repos).
    #[serde(default)]
    metadata: Option<JsonValue>,
    /// How this target was created: 'dast' (Scheduled DAST Targets page),
    /// 'assessment', 'scope'. NULL leaves an existing row's source unchanged.
    #[serde(default)]
    source: Option<String>,
}

fn parse_target_type(s: &str) -> AppResult<TargetType> {
    match s {
        "web" => Ok(TargetType::Web),
        "host" => Ok(TargetType::Host),
        "cidr" => Ok(TargetType::Cidr),
        "repo" => Ok(TargetType::Repo),
        "cloud_account" => Ok(TargetType::CloudAccount),
        other => Err(AppError::BadRequest(format!(
            "Invalid target_type '{}'. Must be web | host | cidr | repo | cloud_account",
            other
        ))),
    }
}

async fn resolve_target(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<ResolveBody>,
) -> AppResult<(StatusCode, Json<TargetResponse>)> {
    let org_id = user
        .org_id
        .clone()
        .ok_or_else(|| AppError::Forbidden("Missing org_id on caller".to_string()))?;

    // Determine target_type — explicit when provided, else heuristic.
    let target_type = match req.target_type.as_deref() {
        Some(s) => parse_target_type(s)?,
        None => TargetType::classify(&req.raw_value),
    };

    let canonical = canonicalize(&req.raw_value, target_type);
    let fp = fingerprint(&org_id, target_type, &canonical);
    let id = Uuid::new_v4().to_string();
    let metadata = req.metadata.unwrap_or(JsonValue::Object(Default::default()));

    // Upsert: insert new on fresh fingerprint, append raw_value to the
    // existing JSONB array on conflict (so we keep a history of the
    // raw inputs that resolved here — useful for debugging
    // canonicalization drift).
    let row: TargetRow = sqlx::query_as(
        r#"INSERT INTO targets (
              id, org_id, target_type, canonical_value, raw_values,
              fingerprint, metadata, source, first_seen_at, last_seen_at,
              created_at, updated_at
           )
           VALUES (
              $1, $2, $3, $4, jsonb_build_array($5::text),
              $6, $7, $8, NOW(), NOW(),
              NOW(), NOW()
           )
           ON CONFLICT (org_id, fingerprint) WHERE archived_at IS NULL
           DO UPDATE SET
              raw_values = (
                  SELECT jsonb_agg(DISTINCT v)
                  FROM jsonb_array_elements_text(
                      targets.raw_values || jsonb_build_array($5::text)
                  ) AS v
              ),
              last_seen_at = NOW(),
              -- Merge metadata: incoming wins for overlapping keys, but
              -- preserve any fields the existing row had that the caller
              -- didn't pass.
              metadata = targets.metadata || $7,
              -- Adopt an explicit source (e.g. promote to 'dast'); keep the
              -- existing source when the caller doesn't pass one.
              source = COALESCE($8, targets.source),
              updated_at = NOW()
           RETURNING *"#,
    )
    .bind(&id)
    .bind(&org_id)
    .bind(target_type.as_str())
    .bind(&canonical)
    .bind(&req.raw_value)
    .bind(&fp)
    .bind(&metadata)
    .bind(&req.source)
    .fetch_one(&state.pool)
    .await?;

    Ok((StatusCode::OK, Json(TargetResponse::from(&row))))
}
