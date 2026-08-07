//! `/recon-cache` — Phase 5 of the caching plan.
//!
//! Endpoints:
//!   GET    /recon-cache/lookup?target_id=X&scan_type=Y
//!          → 200 { cached: true, entry: {...} } | { cached: false }
//!
//!   POST   /recon-cache         — upsert by (target_id, scan_type)
//!   DELETE /recon-cache/:id     — invalidate a specific entry
//!   DELETE /recon-cache?target_id=X        — flush all recon for a target
//!
//! All per-org scoped via JWT `custom:org_id`.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{delete, get, post},
    Json, Router,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use uuid::Uuid;

use crate::auth::AuthUser;
use crate::error::{AppError, AppResult};
use crate::models::recon_cache::{ReconCacheEntry, RECON_SCAN_TYPES};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/recon-cache", post(upsert_entry).delete(flush_for_target))
        .route("/recon-cache/lookup", get(lookup_entry))
        .route("/recon-cache/:id", delete(delete_entry))
}

fn validate_scan_type(s: &str) -> AppResult<()> {
    if RECON_SCAN_TYPES.contains(&s) {
        Ok(())
    } else {
        Err(AppError::BadRequest(format!(
            "Invalid scan_type '{}'. Must be one of: {}",
            s,
            RECON_SCAN_TYPES.join(", ")
        )))
    }
}

#[derive(Debug, Deserialize)]
struct LookupQuery {
    target_id: String,
    scan_type: String,
}

#[derive(Debug, Serialize)]
struct LookupResponse {
    cached: bool,
    entry: Option<EntryView>,
}

#[derive(Debug, Serialize)]
struct EntryView {
    id: String,
    target_id: String,
    scan_type: String,
    snapshot: JsonValue,
    scanner_version: Option<String>,
    scan_completed_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

impl From<&ReconCacheEntry> for EntryView {
    fn from(e: &ReconCacheEntry) -> Self {
        Self {
            id: e.id.clone(),
            target_id: e.target_id.clone(),
            scan_type: e.scan_type.clone(),
            snapshot: e.snapshot.clone(),
            scanner_version: e.scanner_version.clone(),
            scan_completed_at: e.scan_completed_at,
            expires_at: e.expires_at,
        }
    }
}

async fn lookup_entry(
    State(state): State<AppState>,
    Query(q): Query<LookupQuery>,
    user: AuthUser,
) -> AppResult<Json<LookupResponse>> {
    let org_id = user
        .org_id
        .clone()
        .ok_or_else(|| AppError::Forbidden("Missing org_id on caller".to_string()))?;

    validate_scan_type(&q.scan_type)?;

    let row: Option<ReconCacheEntry> = sqlx::query_as(
        r#"SELECT
              id, org_id, target_id, scan_type::text AS scan_type,
              snapshot, scanner_version,
              scan_completed_at, expires_at, created_at, updated_at
           FROM recon_cache_entries
           WHERE org_id = $1
             AND target_id = $2
             AND scan_type = $3::reconscantype
             AND expires_at > NOW()"#,
    )
    .bind(&org_id)
    .bind(&q.target_id)
    .bind(&q.scan_type)
    .fetch_optional(&state.pool)
    .await?;

    Ok(Json(LookupResponse {
        cached: row.is_some(),
        entry: row.as_ref().map(EntryView::from),
    }))
}

#[derive(Debug, Deserialize)]
struct UpsertBody {
    target_id: String,
    scan_type: String,
    snapshot: JsonValue,
    #[serde(default)]
    scanner_version: Option<String>,
    scan_completed_at: DateTime<Utc>,
    /// Optional override of the per-org default TTL.
    #[serde(default)]
    ttl_days: Option<i32>,
}

async fn upsert_entry(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<UpsertBody>,
) -> AppResult<(StatusCode, Json<EntryView>)> {
    let org_id = user
        .org_id
        .clone()
        .ok_or_else(|| AppError::Forbidden("Missing org_id on caller".to_string()))?;

    validate_scan_type(&req.scan_type)?;

    let ttl_days = if let Some(d) = req.ttl_days {
        d
    } else {
        sqlx::query_scalar::<_, i32>(
            "SELECT recon_cache_ttl_days FROM org_settings WHERE org_id = $1",
        )
        .bind(&org_id)
        .fetch_optional(&state.pool)
        .await?
        .unwrap_or(7)
    };

    let expires_at = req.scan_completed_at + chrono::Duration::days(ttl_days as i64);
    let id = Uuid::new_v4().to_string();

    let row: ReconCacheEntry = sqlx::query_as(
        r#"INSERT INTO recon_cache_entries (
              id, org_id, target_id, scan_type,
              snapshot, scanner_version,
              scan_completed_at, expires_at,
              created_at, updated_at
           )
           VALUES ($1, $2, $3, $4::reconscantype, $5, $6, $7, $8, NOW(), NOW())
           ON CONFLICT (org_id, target_id, scan_type)
           DO UPDATE SET
               snapshot          = EXCLUDED.snapshot,
               scanner_version   = EXCLUDED.scanner_version,
               scan_completed_at = EXCLUDED.scan_completed_at,
               expires_at        = EXCLUDED.expires_at,
               updated_at        = NOW()
           RETURNING
               id, org_id, target_id, scan_type::text AS scan_type,
               snapshot, scanner_version,
               scan_completed_at, expires_at, created_at, updated_at"#,
    )
    .bind(&id)
    .bind(&org_id)
    .bind(&req.target_id)
    .bind(&req.scan_type)
    .bind(&req.snapshot)
    .bind(&req.scanner_version)
    .bind(req.scan_completed_at)
    .bind(expires_at)
    .fetch_one(&state.pool)
    .await?;

    Ok((StatusCode::OK, Json(EntryView::from(&row))))
}

async fn delete_entry(
    State(state): State<AppState>,
    Path(id): Path<String>,
    user: AuthUser,
) -> AppResult<StatusCode> {
    let org_id = user
        .org_id
        .clone()
        .ok_or_else(|| AppError::Forbidden("Missing org_id on caller".to_string()))?;

    let rows: u64 = sqlx::query("DELETE FROM recon_cache_entries WHERE id = $1 AND org_id = $2")
        .bind(&id)
        .bind(&org_id)
        .execute(&state.pool)
        .await?
        .rows_affected();

    if rows == 0 {
        return Err(AppError::NotFound("Recon cache entry not found".into()));
    }
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize)]
struct FlushQuery {
    target_id: String,
    /// Optional: when set, only flush this scan_type. Lets the MCP
    /// server invalidate just "ports for example.com" without dropping
    /// cached subdomains.
    #[serde(default)]
    scan_type: Option<String>,
}

async fn flush_for_target(
    State(state): State<AppState>,
    Query(q): Query<FlushQuery>,
    user: AuthUser,
) -> AppResult<Json<JsonValue>> {
    let org_id = user
        .org_id
        .clone()
        .ok_or_else(|| AppError::Forbidden("Missing org_id on caller".to_string()))?;

    if let Some(st) = q.scan_type.as_ref() {
        validate_scan_type(st)?;
    }

    let rows = match q.scan_type.as_ref() {
        Some(scan_type) => {
            sqlx::query(
                "DELETE FROM recon_cache_entries
                 WHERE org_id = $1 AND target_id = $2 AND scan_type = $3::reconscantype",
            )
            .bind(&org_id)
            .bind(&q.target_id)
            .bind(scan_type)
            .execute(&state.pool)
            .await?
            .rows_affected()
        }
        None => {
            sqlx::query("DELETE FROM recon_cache_entries WHERE org_id = $1 AND target_id = $2")
                .bind(&org_id)
                .bind(&q.target_id)
                .execute(&state.pool)
                .await?
                .rows_affected()
        }
    };

    Ok(Json(serde_json::json!({ "deleted": rows })))
}
