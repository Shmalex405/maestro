//! `/scan-snapshots` — frozen point-in-time finding counts per assessment.
//!
//! Used for diff views and trend reports. Captured at completion of an
//! assessment OR by manual "freeze this baseline" action. Read-only from
//! the UI; the desktop calls POST after a scan run completes.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    routing::get,
    Json, Router,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use crate::auth::AuthUser;
use crate::error::{AppError, AppResult};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/scan-snapshots",
            get(list_snapshots).post(create_snapshot),
        )
        .route("/scan-snapshots/:id", get(get_snapshot))
}

#[derive(Debug, FromRow, Serialize)]
struct ScanSnapshotRow {
    id: String,
    assessment_id: Option<String>,
    target: Option<String>,
    critical_count: Option<i32>,
    high_count: Option<i32>,
    medium_count: Option<i32>,
    low_count: Option<i32>,
    info_count: Option<i32>,
    total_count: Option<i32>,
    notes: Option<String>,
    org_id: Option<String>,
    created_by: Option<String>,
    created_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize)]
struct ListQuery {
    #[serde(default)]
    target: Option<String>,
    #[serde(default)]
    assessment_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CreateReq {
    assessment_id: String,
    #[serde(default)]
    notes: Option<String>,
}

async fn list_snapshots(
    State(state): State<AppState>,
    Query(q): Query<ListQuery>,
    user: AuthUser,
) -> AppResult<Json<Vec<ScanSnapshotRow>>> {
    let mut sql = String::from("SELECT * FROM scan_snapshots WHERE 1=1");
    let mut binds: Vec<String> = Vec::new();
    if let Some(org) = user.org_id.as_ref() {
        binds.push(org.clone());
        sql.push_str(&format!(" AND org_id = ${}", binds.len()));
    }
    if let Some(t) = q.target.as_ref() {
        binds.push(t.clone());
        sql.push_str(&format!(" AND target = ${}", binds.len()));
    }
    if let Some(a) = q.assessment_id.as_ref() {
        binds.push(a.clone());
        sql.push_str(&format!(" AND assessment_id = ${}", binds.len()));
    }
    sql.push_str(" ORDER BY created_at DESC LIMIT 500");

    let mut qx = sqlx::query_as::<_, ScanSnapshotRow>(&sql);
    for b in &binds {
        qx = qx.bind(b);
    }
    Ok(Json(qx.fetch_all(&state.pool).await?))
}

async fn get_snapshot(
    State(state): State<AppState>,
    Path(id): Path<String>,
    user: AuthUser,
) -> AppResult<Json<ScanSnapshotRow>> {
    let row: Option<ScanSnapshotRow> = sqlx::query_as(
        "SELECT * FROM scan_snapshots
          WHERE id = $1 AND ($2::varchar IS NULL OR org_id = $2)",
    )
    .bind(&id)
    .bind(&user.org_id)
    .fetch_optional(&state.pool)
    .await?;
    row.map(Json).ok_or_else(|| AppError::NotFound("Snapshot not found".into()))
}

/// Capture current finding counts for an assessment. The desktop calls
/// this on assessment completion (or via a manual "freeze baseline"
/// button); the backend reads the live finding counts and persists them
/// so future diffs have a stable comparison point.
async fn create_snapshot(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<CreateReq>,
) -> AppResult<(StatusCode, Json<ScanSnapshotRow>)> {
    // Confirm assessment is visible to the caller's org and grab the
    // first target as the snapshot's `target` field. `targets` is JSONB
    // (a JSON array of strings, NOT a Postgres TEXT[]), so we decode it
    // as JsonValue and pull the first element.
    use serde_json::Value as JsonValue;
    let target_row: Option<(Option<JsonValue>,)> = sqlx::query_as(
        "SELECT targets FROM assessments
          WHERE id = $1 AND ($2::varchar IS NULL OR org_id = $2)",
    )
    .bind(&req.assessment_id)
    .bind(&user.org_id)
    .fetch_optional(&state.pool)
    .await?;
    let target = target_row
        .and_then(|(t,)| t)
        .and_then(|v| v.as_array().and_then(|arr| arr.first().cloned()))
        .and_then(|v| v.as_str().map(String::from))
        .unwrap_or_else(|| "(none)".to_string());

    // Aggregate current findings counts for this assessment. `findings.
    // assessment_id` is the direct FK in this schema — no join table.
    #[derive(FromRow)]
    struct Counts {
        critical: Option<i64>,
        high: Option<i64>,
        medium: Option<i64>,
        low: Option<i64>,
        info: Option<i64>,
        total: Option<i64>,
    }
    let counts: Counts = sqlx::query_as(
        r#"SELECT
              COUNT(*) FILTER (WHERE COALESCE(calibrated_severity, severity) = 'critical') AS critical,
              COUNT(*) FILTER (WHERE COALESCE(calibrated_severity, severity) = 'high')     AS high,
              COUNT(*) FILTER (WHERE COALESCE(calibrated_severity, severity) = 'medium')   AS medium,
              COUNT(*) FILTER (WHERE COALESCE(calibrated_severity, severity) = 'low')      AS low,
              COUNT(*) FILTER (WHERE COALESCE(calibrated_severity, severity) = 'info')     AS info,
              COUNT(*)                                                                       AS total
            FROM findings
           WHERE assessment_id = $1"#,
    )
    .bind(&req.assessment_id)
    .fetch_one(&state.pool)
    .await?;

    let id = Uuid::new_v4().to_string();
    sqlx::query(
        r#"INSERT INTO scan_snapshots
              (id, assessment_id, target, critical_count, high_count,
               medium_count, low_count, info_count, total_count, notes,
               org_id, created_by)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)"#,
    )
    .bind(&id)
    .bind(&req.assessment_id)
    .bind(&target)
    .bind(counts.critical.unwrap_or(0) as i32)
    .bind(counts.high.unwrap_or(0) as i32)
    .bind(counts.medium.unwrap_or(0) as i32)
    .bind(counts.low.unwrap_or(0) as i32)
    .bind(counts.info.unwrap_or(0) as i32)
    .bind(counts.total.unwrap_or(0) as i32)
    .bind(&req.notes)
    .bind(&user.org_id)
    .bind(&user.id)
    .execute(&state.pool)
    .await?;

    let row: ScanSnapshotRow =
        sqlx::query_as("SELECT * FROM scan_snapshots WHERE id = $1")
            .bind(&id)
            .fetch_one(&state.pool)
            .await?;

    Ok((StatusCode::CREATED, Json(row)))
}
