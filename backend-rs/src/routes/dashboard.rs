//! `/dashboard/stats` — aggregate counters for the home page.
//!
//! Returns total/critical/high/medium/low/info finding counts across the
//! org, plus a few rollups (active assessments, completed-this-month).
//! The desktop's home page primarily uses `/findings/stats` and
//! `/assessments` directly; this exists for compact one-shot rendering
//! when rendering simpler dashboard widgets.

use axum::{extract::State, routing::get, Json, Router};
use serde::Serialize;
use sqlx::FromRow;

use crate::auth::AuthUser;
use crate::error::AppResult;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route("/dashboard/stats", get(get_stats))
}

#[derive(Debug, Serialize)]
struct DashboardStats {
    total_findings: i64,
    by_severity: SeverityCounts,
    total_assessments: i64,
    active_assessments: i64,
    completed_assessments: i64,
    total_repositories: i64,
}

#[derive(Debug, Serialize, Default)]
struct SeverityCounts {
    critical: i64,
    high: i64,
    medium: i64,
    low: i64,
    info: i64,
}

#[derive(FromRow)]
struct SeverityRow {
    critical: Option<i64>,
    high: Option<i64>,
    medium: Option<i64>,
    low: Option<i64>,
    info: Option<i64>,
    total: Option<i64>,
}

#[derive(FromRow)]
struct AssessmentRollup {
    total: Option<i64>,
    active: Option<i64>,
    completed: Option<i64>,
}

async fn get_stats(
    State(state): State<AppState>,
    user: AuthUser,
) -> AppResult<Json<DashboardStats>> {
    // Findings counts. `findings.org_id` is set directly on each row, so
    // we filter on that — no JOIN needed (the v0.1.22 dashboard handler
    // joined a non-existent `assessment_findings` table inherited from
    // the legacy Python schema and returned 500 in prod).
    let sev: SeverityRow = sqlx::query_as(
        r#"SELECT
              COUNT(*) FILTER (WHERE COALESCE(calibrated_severity, severity) = 'critical') AS critical,
              COUNT(*) FILTER (WHERE COALESCE(calibrated_severity, severity) = 'high')     AS high,
              COUNT(*) FILTER (WHERE COALESCE(calibrated_severity, severity) = 'medium')   AS medium,
              COUNT(*) FILTER (WHERE COALESCE(calibrated_severity, severity) = 'low')      AS low,
              COUNT(*) FILTER (WHERE COALESCE(calibrated_severity, severity) = 'info')     AS info,
              COUNT(*)                                                                       AS total
            FROM findings
           WHERE $1::varchar IS NULL OR org_id = $1"#,
    )
    .bind(&user.org_id)
    .fetch_one(&state.pool)
    .await?;

    let asmt: AssessmentRollup = sqlx::query_as(
        r#"SELECT
              COUNT(*)                                              AS total,
              COUNT(*) FILTER (WHERE status = 'running')            AS active,
              COUNT(*) FILTER (WHERE status = 'completed')          AS completed
            FROM assessments
           WHERE $1::varchar IS NULL OR org_id = $1"#,
    )
    .bind(&user.org_id)
    .fetch_one(&state.pool)
    .await?;

    let total_repos: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM repositories WHERE $1::varchar IS NULL OR org_id = $1",
    )
    .bind(&user.org_id)
    .fetch_one(&state.pool)
    .await?;

    Ok(Json(DashboardStats {
        total_findings: sev.total.unwrap_or(0),
        by_severity: SeverityCounts {
            critical: sev.critical.unwrap_or(0),
            high: sev.high.unwrap_or(0),
            medium: sev.medium.unwrap_or(0),
            low: sev.low.unwrap_or(0),
            info: sev.info.unwrap_or(0),
        },
        total_assessments: asmt.total.unwrap_or(0),
        active_assessments: asmt.active.unwrap_or(0),
        completed_assessments: asmt.completed.unwrap_or(0),
        total_repositories: total_repos,
    }))
}
