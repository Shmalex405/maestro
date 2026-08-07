//! `/cache-drift-alerts` — operator-facing surface for cache drift events.
//!
//! Phase 6.4 of the caching plan.
//!
//! Endpoints:
//!   GET   /cache-drift-alerts                 — paginated list (filters: acknowledged, target_id)
//!   POST  /cache-drift-alerts                 — write (called by crossval-qa on drift detection)
//!   PATCH /cache-drift-alerts/:id/acknowledge — operator triage
//!   GET   /cache-drift-alerts/summary         — rolling-30-day aggregate (drives the auto-disable check)
//!
//! All per-org scoped.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{get, patch},
    Json, Router,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use uuid::Uuid;

use crate::auth::AuthUser;
use crate::error::{AppError, AppResult};
use crate::models::cache_drift_alert::CacheDriftAlert;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/cache-drift-alerts", get(list).post(create))
        .route("/cache-drift-alerts/summary", get(summary))
        .route("/cache-drift-alerts/:id/acknowledge", patch(acknowledge))
}

#[derive(Debug, Serialize)]
struct AlertResponse {
    id: String,
    org_id: String,
    target_id: Option<String>,
    finding_fingerprint: String,
    prior_assessment_id: Option<String>,
    prior_status: Option<String>,
    prior_severity: Option<String>,
    current_assessment_id: Option<String>,
    current_status: Option<String>,
    current_severity: Option<String>,
    drift_summary: Option<String>,
    triggered_auto_disable: bool,
    acknowledged_at: Option<DateTime<Utc>>,
    acknowledged_by: Option<String>,
    acknowledgement_notes: Option<String>,
    detected_at: DateTime<Utc>,
}

impl From<&CacheDriftAlert> for AlertResponse {
    fn from(a: &CacheDriftAlert) -> Self {
        Self {
            id: a.id.clone(),
            org_id: a.org_id.clone(),
            target_id: a.target_id.clone(),
            finding_fingerprint: a.finding_fingerprint.clone(),
            prior_assessment_id: a.prior_assessment_id.clone(),
            prior_status: a.prior_status.clone(),
            prior_severity: a.prior_severity.clone(),
            current_assessment_id: a.current_assessment_id.clone(),
            current_status: a.current_status.clone(),
            current_severity: a.current_severity.clone(),
            drift_summary: a.drift_summary.clone(),
            triggered_auto_disable: a.triggered_auto_disable,
            acknowledged_at: a.acknowledged_at,
            acknowledged_by: a.acknowledged_by.clone(),
            acknowledgement_notes: a.acknowledgement_notes.clone(),
            detected_at: a.detected_at,
        }
    }
}

#[derive(Debug, Deserialize)]
struct ListQuery {
    /// 'true' = only unacknowledged, 'false' = only acknowledged,
    /// absent = both.
    #[serde(default)]
    acknowledged: Option<String>,
    #[serde(default)]
    target_id: Option<String>,
    #[serde(default = "default_limit")]
    limit: i64,
}

fn default_limit() -> i64 {
    100
}

async fn list(
    State(state): State<AppState>,
    Query(q): Query<ListQuery>,
    user: AuthUser,
) -> AppResult<Json<Vec<AlertResponse>>> {
    let org_id = user
        .org_id
        .clone()
        .ok_or_else(|| AppError::Forbidden("Missing org_id on caller".to_string()))?;

    let mut sql =
        String::from("SELECT * FROM cache_drift_alerts WHERE org_id = $1");
    let mut bind_idx = 1;
    let mut target_bind: Option<String> = None;
    if let Some(ack) = q.acknowledged.as_deref() {
        match ack {
            "true" => sql.push_str(" AND acknowledged_at IS NOT NULL"),
            "false" => sql.push_str(" AND acknowledged_at IS NULL"),
            _ => {} // ignore unknown
        }
    }
    if let Some(t) = q.target_id.as_ref() {
        bind_idx += 1;
        sql.push_str(&format!(" AND target_id = ${}", bind_idx));
        target_bind = Some(t.clone());
    }
    sql.push_str(" ORDER BY detected_at DESC LIMIT $");
    sql.push_str(&(bind_idx + 1).to_string());

    let limit = q.limit.clamp(1, 500);
    let mut query = sqlx::query_as::<_, CacheDriftAlert>(&sql).bind(&org_id);
    if let Some(t) = target_bind {
        query = query.bind(t);
    }
    query = query.bind(limit);
    let rows: Vec<CacheDriftAlert> = query.fetch_all(&state.pool).await?;

    Ok(Json(rows.iter().map(AlertResponse::from).collect()))
}

#[derive(Debug, Deserialize)]
struct CreateBody {
    #[serde(default)]
    target_id: Option<String>,
    finding_fingerprint: String,
    #[serde(default)]
    prior_assessment_id: Option<String>,
    #[serde(default)]
    prior_status: Option<String>,
    #[serde(default)]
    prior_severity: Option<String>,
    #[serde(default)]
    current_assessment_id: Option<String>,
    #[serde(default)]
    current_status: Option<String>,
    #[serde(default)]
    current_severity: Option<String>,
    #[serde(default)]
    drift_summary: Option<String>,
}

async fn create(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<CreateBody>,
) -> AppResult<(StatusCode, Json<AlertResponse>)> {
    let org_id = user
        .org_id
        .clone()
        .ok_or_else(|| AppError::Forbidden("Missing org_id on caller".to_string()))?;

    let id = Uuid::new_v4().to_string();
    let row: CacheDriftAlert = sqlx::query_as(
        r#"INSERT INTO cache_drift_alerts (
              id, org_id, target_id, finding_fingerprint,
              prior_assessment_id, prior_status, prior_severity,
              current_assessment_id, current_status, current_severity,
              drift_summary
           )
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
           RETURNING *"#,
    )
    .bind(&id)
    .bind(&org_id)
    .bind(&req.target_id)
    .bind(&req.finding_fingerprint)
    .bind(&req.prior_assessment_id)
    .bind(&req.prior_status)
    .bind(&req.prior_severity)
    .bind(&req.current_assessment_id)
    .bind(&req.current_status)
    .bind(&req.current_severity)
    .bind(&req.drift_summary)
    .fetch_one(&state.pool)
    .await?;

    Ok((StatusCode::OK, Json(AlertResponse::from(&row))))
}

#[derive(Debug, Deserialize)]
struct AckBody {
    notes: Option<String>,
}

async fn acknowledge(
    State(state): State<AppState>,
    Path(id): Path<String>,
    user: AuthUser,
    Json(req): Json<AckBody>,
) -> AppResult<Json<AlertResponse>> {
    let org_id = user
        .org_id
        .clone()
        .ok_or_else(|| AppError::Forbidden("Missing org_id on caller".to_string()))?;

    let row: Option<CacheDriftAlert> = sqlx::query_as(
        r#"UPDATE cache_drift_alerts
           SET acknowledged_at = NOW(),
               acknowledged_by = $2,
               acknowledgement_notes = $3
           WHERE id = $1 AND org_id = $4
           RETURNING *"#,
    )
    .bind(&id)
    .bind(&user.id)
    .bind(&req.notes)
    .bind(&org_id)
    .fetch_optional(&state.pool)
    .await?;

    let row = row.ok_or_else(|| AppError::NotFound("Drift alert not found".into()))?;
    Ok(Json(AlertResponse::from(&row)))
}

/// Rolling-30-day count + auto-disable threshold breach detection.
/// Drives the desktop's "needs review" badge AND will drive the
/// future auto-disable cron when it lands.
async fn summary(
    State(state): State<AppState>,
    user: AuthUser,
) -> AppResult<Json<JsonValue>> {
    let org_id = user
        .org_id
        .clone()
        .ok_or_else(|| AppError::Forbidden("Missing org_id on caller".to_string()))?;

    // The threshold subquery returns NULL when the org has no org_settings
    // row yet — COALESCE to the schema default (migration 0019:
    // drift_alert_threshold INT NOT NULL DEFAULT 3) so decoding into a
    // non-Option i32 never hits "unexpected null".
    let (count_30d, unacked, threshold): (i64, i64, i32) = sqlx::query_as(
        r#"SELECT
              (SELECT COUNT(*) FROM cache_drift_alerts
                 WHERE org_id = $1 AND detected_at > NOW() - INTERVAL '30 days')::bigint,
              (SELECT COUNT(*) FROM cache_drift_alerts
                 WHERE org_id = $1 AND acknowledged_at IS NULL)::bigint,
              COALESCE((SELECT drift_alert_threshold FROM org_settings WHERE org_id = $1), 3)"#,
    )
    .bind(&org_id)
    .fetch_one(&state.pool)
    .await?;

    let breached = count_30d >= threshold as i64;

    Ok(Json(serde_json::json!({
        "alerts_30d": count_30d,
        "unacknowledged": unacked,
        "threshold": threshold,
        "threshold_breached": breached,
    })))
}
