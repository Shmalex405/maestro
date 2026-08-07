//! `POST /sync` + `GET /sync/status`.
//! Mirror of `backend/app/routers/sync.py`.
//!
//! Quirks replicated for parity:
//!   - `Assessment.started_at` (not `updated_at`) is the freshness column,
//!     matching the Python query. `Assessment` has no `updated_at` column.
//!   - `client_id` is the desktop-provided key used for upserts.
//!   - Without `client_id`, incoming rows are silently skipped (same as
//!     `sync.py:45,73,119` which check `if ...client_id:` first).

use axum::{extract::State, routing::{get, post}, Json, Router};
use chrono::{DateTime, TimeZone, Utc};
use serde_json::json;

use crate::auth::AuthUser;
use crate::error::AppResult;
use crate::models::assessment::Assessment;
use crate::models::finding::Finding;
use crate::models::report::Report;
use crate::routes::{assessments, findings, reports};
use crate::schemas::assessment::AssessmentResponse;
use crate::schemas::finding::FindingResponse;
use crate::schemas::report::ReportResponse;
use crate::schemas::sync::{SyncRequest, SyncResponse};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/sync", post(sync_data))
        .route("/sync/status", get(sync_status))
}

async fn sync_data(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<SyncRequest>,
) -> AppResult<Json<SyncResponse<AssessmentResponse, FindingResponse, ReportResponse>>> {
    for a in &req.assessments {
        if a.client_id.is_some() {
            let _ = assessments::upsert_from_sync(&state, &user, a).await?;
        }
    }
    for f in &req.findings {
        if f.client_id.is_some() {
            let _ = findings::upsert_from_sync(&state, &user, f).await?;
        }
    }
    for r in &req.reports {
        if r.client_id.is_some() {
            let _ = reports::upsert_from_sync(&state, &user, r).await?;
        }
    }

    let last_sync: DateTime<Utc> = req
        .last_sync_at
        .unwrap_or_else(|| Utc.timestamp_opt(0, 0).unwrap());

    let (asses, finds, reps) = fetch_changed(&state, &user, last_sync).await?;

    Ok(Json(SyncResponse {
        assessments: asses.iter().map(AssessmentResponse::from).collect(),
        findings: finds.iter().map(FindingResponse::from).collect(),
        reports: reps.iter().map(ReportResponse::from).collect(),
        sync_at: Utc::now(),
    }))
}

async fn fetch_changed(
    state: &AppState,
    user: &AuthUser,
    last_sync: DateTime<Utc>,
) -> AppResult<(Vec<Assessment>, Vec<Finding>, Vec<Report>)> {
    let org_filter = |col: &str| -> String {
        if user.org_id.is_some() {
            format!(" AND {col} = $2")
        } else {
            String::new()
        }
    };

    let a_sql = format!(
        "SELECT * FROM assessments WHERE started_at >= $1{}",
        org_filter("org_id")
    );
    let mut a_q = sqlx::query_as::<_, Assessment>(&a_sql).bind(last_sync);
    if let Some(org) = user.org_id.as_ref() {
        a_q = a_q.bind(org);
    }
    let a: Vec<Assessment> = a_q.fetch_all(&state.pool).await?;

    let f_sql = format!(
        "SELECT * FROM findings WHERE updated_at >= $1{}",
        org_filter("org_id")
    );
    let mut f_q = sqlx::query_as::<_, Finding>(&f_sql).bind(last_sync);
    if let Some(org) = user.org_id.as_ref() {
        f_q = f_q.bind(org);
    }
    let f: Vec<Finding> = f_q.fetch_all(&state.pool).await?;

    let r_sql = format!(
        "SELECT * FROM reports WHERE updated_at >= $1{}",
        org_filter("org_id")
    );
    let mut r_q = sqlx::query_as::<_, Report>(&r_sql).bind(last_sync);
    if let Some(org) = user.org_id.as_ref() {
        r_q = r_q.bind(org);
    }
    let r: Vec<Report> = r_q.fetch_all(&state.pool).await?;

    Ok((a, f, r))
}

async fn sync_status(
    State(state): State<AppState>,
    user: AuthUser,
) -> AppResult<Json<serde_json::Value>> {
    let (a, f, r): (i64, i64, i64) = if let Some(org) = user.org_id.as_ref() {
        let a: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM assessments WHERE org_id = $1")
            .bind(org)
            .fetch_one(&state.pool)
            .await?;
        let f: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM findings WHERE org_id = $1")
            .bind(org)
            .fetch_one(&state.pool)
            .await?;
        let r: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM reports WHERE org_id = $1")
            .bind(org)
            .fetch_one(&state.pool)
            .await?;
        (a, f, r)
    } else {
        let a: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM assessments")
            .fetch_one(&state.pool)
            .await?;
        let f: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM findings")
            .fetch_one(&state.pool)
            .await?;
        let r: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM reports")
            .fetch_one(&state.pool)
            .await?;
        (a, f, r)
    };

    Ok(Json(json!({
        "assessments": a,
        "findings": f,
        "reports": r,
        "org_id": user.org_id,
    })))
}
