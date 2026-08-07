//! `/assessments/:id/scope-decisions` — scope-decision overview (Option B).
//!
//! Endpoints:
//!   POST /assessments/:id/scope-decisions  — ingest the per-target verdict summary
//!                                             (replaces the prior set for the run)
//!   GET  /assessments/:id/scope-decisions  — list the run's scope decisions
//!
//! Promoted at end-of-run by the MCP `promote_execution_meta` tool (Shape A).
//! The desktop "Assessment Execution Overview" reads the GET to show which
//! targets were in/out of scope (with the violation reason) and how many times
//! each verdict was hit. Per-org scoped via JWT `custom:org_id`.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::post,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::AuthUser;
use crate::error::{AppError, AppResult};
use crate::models::scope_decision::ScopeDecisionRow;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route(
        "/assessments/:id/scope-decisions",
        post(ingest).get(list),
    )
}

#[derive(Debug, Deserialize)]
struct IngestBody {
    #[serde(default)]
    decisions: Vec<DecisionEntry>,
}

#[derive(Debug, Deserialize)]
struct DecisionEntry {
    target: String,
    #[serde(default)]
    dimension: Option<String>,
    in_scope: bool,
    #[serde(default)]
    reason: Option<String>,
    #[serde(default = "default_attempts")]
    attempts: i32,
}

fn default_attempts() -> i32 {
    1
}

#[derive(Debug, Serialize)]
struct ScopeDecisionView {
    target: String,
    dimension: Option<String>,
    in_scope: bool,
    reason: Option<String>,
    attempts: i32,
}

impl From<&ScopeDecisionRow> for ScopeDecisionView {
    fn from(r: &ScopeDecisionRow) -> Self {
        Self {
            target: r.target.clone(),
            dimension: r.dimension.clone(),
            in_scope: r.in_scope,
            reason: r.reason.clone(),
            attempts: r.attempts,
        }
    }
}

#[derive(Debug, Serialize)]
struct IngestResponse {
    upserted: usize,
}

async fn ingest(
    State(state): State<AppState>,
    user: AuthUser,
    Path(assessment_id): Path<String>,
    Json(body): Json<IngestBody>,
) -> AppResult<(StatusCode, Json<IngestResponse>)> {
    let org_id = user
        .org_id
        .clone()
        .ok_or_else(|| AppError::Forbidden("Missing org_id on caller".to_string()))?;

    let mut tx = state.pool.begin().await?;

    // Replace the prior decisions for this assessment — re-promotion refreshes.
    sqlx::query("DELETE FROM assessment_scope_decisions WHERE org_id = $1 AND assessment_id = $2")
        .bind(&org_id)
        .bind(&assessment_id)
        .execute(&mut *tx)
        .await?;

    let mut upserted = 0usize;
    for d in &body.decisions {
        let id = Uuid::new_v4().to_string();
        sqlx::query(
            r#"INSERT INTO assessment_scope_decisions
                  (id, org_id, assessment_id, target, dimension, in_scope, reason,
                   attempts, last_seen)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8,NOW())
               ON CONFLICT (org_id, assessment_id, target, in_scope) DO UPDATE SET
                   dimension = EXCLUDED.dimension,
                   reason = EXCLUDED.reason,
                   attempts = EXCLUDED.attempts,
                   last_seen = NOW()"#,
        )
        .bind(&id)
        .bind(&org_id)
        .bind(&assessment_id)
        .bind(&d.target)
        .bind(&d.dimension)
        .bind(d.in_scope)
        .bind(&d.reason)
        .bind(d.attempts)
        .execute(&mut *tx)
        .await?;
        upserted += 1;
    }

    tx.commit().await?;

    Ok((StatusCode::OK, Json(IngestResponse { upserted })))
}

async fn list(
    State(state): State<AppState>,
    user: AuthUser,
    Path(assessment_id): Path<String>,
) -> AppResult<Json<Vec<ScopeDecisionView>>> {
    let org_id = user
        .org_id
        .clone()
        .ok_or_else(|| AppError::Forbidden("Missing org_id on caller".to_string()))?;

    let rows: Vec<ScopeDecisionRow> = sqlx::query_as(
        r#"SELECT id, org_id, assessment_id, target, dimension, in_scope, reason,
                  attempts, last_seen
           FROM assessment_scope_decisions
           WHERE org_id = $1 AND assessment_id = $2
           ORDER BY target ASC, in_scope ASC"#,
    )
    .bind(&org_id)
    .bind(&assessment_id)
    .fetch_all(&state.pool)
    .await?;

    Ok(Json(rows.iter().map(ScopeDecisionView::from).collect()))
}
