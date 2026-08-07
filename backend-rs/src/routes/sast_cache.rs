//! `/sast-cache` — Phase 4 of the caching plan.
//!
//! Endpoints:
//!   GET    /sast-cache/lookup?target_id=X&commit_sha=Y&scanner=Z
//!                              &scanner_version=V&rule_pack_hash=H
//!                              [&dependency_lock_hash=L]
//!          → 200 { cached: true, entry: {...} } | { cached: false }
//!
//!   POST   /sast-cache         — upsert by full cache key
//!   DELETE /sast-cache/:id     — invalidate a specific entry
//!   DELETE /sast-cache?target_id=X        — flush all entries for a repo
//!
//! All endpoints are per-org scoped via JWT `custom:org_id`.

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
use crate::models::sast_cache::SastCacheEntry;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/sast-cache", post(upsert_entry).delete(flush_for_target))
        .route("/sast-cache/lookup", get(lookup_entry))
        .route("/sast-cache/:id", delete(delete_entry))
}

#[derive(Debug, Deserialize)]
struct LookupQuery {
    target_id: String,
    commit_sha: String,
    scanner: String,
    scanner_version: String,
    rule_pack_hash: String,
    #[serde(default)]
    dependency_lock_hash: Option<String>,
}

#[derive(Debug, Serialize)]
struct LookupResponse {
    cached: bool,
    /// Present only when `cached: true` AND `expires_at > NOW()`.
    entry: Option<EntryView>,
}

#[derive(Debug, Serialize)]
struct EntryView {
    id: String,
    target_id: String,
    commit_sha: String,
    scanner: String,
    scanner_version: String,
    rule_pack_hash: String,
    dependency_lock_hash: Option<String>,
    finding_fingerprints: JsonValue,
    raw_output_s3_key: Option<String>,
    scan_started_at: DateTime<Utc>,
    scan_completed_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

impl From<&SastCacheEntry> for EntryView {
    fn from(e: &SastCacheEntry) -> Self {
        Self {
            id: e.id.clone(),
            target_id: e.target_id.clone(),
            commit_sha: e.commit_sha.clone(),
            scanner: e.scanner.clone(),
            scanner_version: e.scanner_version.clone(),
            rule_pack_hash: e.rule_pack_hash.clone(),
            dependency_lock_hash: e.dependency_lock_hash.clone(),
            finding_fingerprints: e.finding_fingerprints.clone(),
            raw_output_s3_key: e.raw_output_s3_key.clone(),
            scan_started_at: e.scan_started_at,
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

    // The lookup includes the dependency_lock_hash when provided. Two
    // scanners can share a (commit, scanner_version, rule_pack) key
    // and differ only by lockfile — we treat NULL = "any lockfile" so
    // source-only scanners (semgrep, bandit) hit cleanly regardless.
    let row: Option<SastCacheEntry> = sqlx::query_as(
        r#"SELECT * FROM sast_cache_entries
           WHERE org_id = $1
             AND target_id = $2
             AND commit_sha = $3
             AND scanner = $4
             AND scanner_version = $5
             AND rule_pack_hash = $6
             AND (
                 $7::text IS NULL
                 OR dependency_lock_hash IS NULL
                 OR dependency_lock_hash = $7
             )
             AND expires_at > NOW()
           ORDER BY scan_completed_at DESC
           LIMIT 1"#,
    )
    .bind(&org_id)
    .bind(&q.target_id)
    .bind(&q.commit_sha)
    .bind(&q.scanner)
    .bind(&q.scanner_version)
    .bind(&q.rule_pack_hash)
    .bind(&q.dependency_lock_hash)
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
    commit_sha: String,
    scanner: String,
    scanner_version: String,
    rule_pack_hash: String,
    #[serde(default)]
    dependency_lock_hash: Option<String>,
    finding_fingerprints: JsonValue,
    #[serde(default)]
    raw_output_s3_key: Option<String>,
    scan_started_at: DateTime<Utc>,
    scan_completed_at: DateTime<Utc>,
    /// Optional override of the per-org default TTL. Mostly useful for
    /// integration tests; production code should let the server apply
    /// the org_settings.sast_cache_ttl_days default.
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

    // Pull the per-org TTL default if the caller didn't override.
    let ttl_days = if let Some(d) = req.ttl_days {
        d
    } else {
        sqlx::query_scalar::<_, i32>(
            "SELECT sast_cache_ttl_days FROM org_settings WHERE org_id = $1",
        )
        .bind(&org_id)
        .fetch_optional(&state.pool)
        .await?
        .unwrap_or(30)
    };

    let expires_at = req.scan_completed_at + chrono::Duration::days(ttl_days as i64);
    let id = Uuid::new_v4().to_string();

    let row: SastCacheEntry = sqlx::query_as(
        r#"INSERT INTO sast_cache_entries (
              id, org_id, target_id,
              commit_sha, scanner, scanner_version, rule_pack_hash, dependency_lock_hash,
              finding_fingerprints, raw_output_s3_key,
              scan_started_at, scan_completed_at, expires_at,
              created_at, updated_at
           )
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, NOW(), NOW())
           ON CONFLICT (org_id, target_id, commit_sha, scanner, scanner_version, rule_pack_hash)
           DO UPDATE SET
               dependency_lock_hash = EXCLUDED.dependency_lock_hash,
               finding_fingerprints = EXCLUDED.finding_fingerprints,
               raw_output_s3_key    = COALESCE(EXCLUDED.raw_output_s3_key, sast_cache_entries.raw_output_s3_key),
               scan_started_at      = EXCLUDED.scan_started_at,
               scan_completed_at    = EXCLUDED.scan_completed_at,
               expires_at           = EXCLUDED.expires_at,
               updated_at           = NOW()
           RETURNING *"#,
    )
    .bind(&id)
    .bind(&org_id)
    .bind(&req.target_id)
    .bind(&req.commit_sha)
    .bind(&req.scanner)
    .bind(&req.scanner_version)
    .bind(&req.rule_pack_hash)
    .bind(&req.dependency_lock_hash)
    .bind(&req.finding_fingerprints)
    .bind(&req.raw_output_s3_key)
    .bind(req.scan_started_at)
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

    let rows: u64 = sqlx::query("DELETE FROM sast_cache_entries WHERE id = $1 AND org_id = $2")
        .bind(&id)
        .bind(&org_id)
        .execute(&state.pool)
        .await?
        .rows_affected();

    if rows == 0 {
        return Err(AppError::NotFound("SAST cache entry not found".into()));
    }
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize)]
struct FlushQuery {
    target_id: String,
    /// Optional: when set, only flush entries for this scanner. Lets the
    /// MCP server invalidate just "semgrep results for repo X" without
    /// blowing away cached bandit / grype output.
    #[serde(default)]
    scanner: Option<String>,
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

    let rows = match q.scanner.as_ref() {
        Some(scanner) => {
            sqlx::query(
                "DELETE FROM sast_cache_entries
                 WHERE org_id = $1 AND target_id = $2 AND scanner = $3",
            )
            .bind(&org_id)
            .bind(&q.target_id)
            .bind(scanner)
            .execute(&state.pool)
            .await?
            .rows_affected()
        }
        None => {
            sqlx::query(
                "DELETE FROM sast_cache_entries WHERE org_id = $1 AND target_id = $2",
            )
            .bind(&org_id)
            .bind(&q.target_id)
            .execute(&state.pool)
            .await?
            .rows_affected()
        }
    };

    Ok(Json(serde_json::json!({ "deleted": rows })))
}
