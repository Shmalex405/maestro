//! `/assessments/:id/test-results` — per-test execution overview (Option B).
//!
//! Endpoints:
//!   POST /assessments/:id/test-results  — ingest the per-test verdict summary
//!                                          (replaces the prior set for the run)
//!   GET  /assessments/:id/test-results  — list the run's per-test results
//!
//! Promoted at end-of-run by the MCP `promote_execution_meta` tool (Shape A).
//! The desktop "Assessment Execution Overview" reads the GET to show every test's
//! PASS/FAIL/N_A/BLOCKED verdict + the provenance gate's enforced flag.
//! Per-org scoped via JWT `custom:org_id`.

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
use crate::models::test_result::TestResultRow;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route(
        "/assessments/:id/test-results",
        post(ingest).get(list),
    )
}

#[derive(Debug, Deserialize)]
struct IngestBody {
    #[serde(default)]
    tests: Vec<TestEntry>,
}

#[derive(Debug, Deserialize)]
struct TestEntry {
    #[serde(default)]
    agent: Option<String>,
    test_id: String,
    status: String,
    #[serde(default)]
    enforced: bool,
    #[serde(default)]
    enforced_reason: Option<String>,
    #[serde(default)]
    finding_count: i32,
    #[serde(default)]
    notes: Option<String>,
}

#[derive(Debug, Serialize)]
struct TestResultView {
    agent: Option<String>,
    test_id: String,
    status: String,
    enforced: bool,
    enforced_reason: Option<String>,
    finding_count: i32,
    notes: Option<String>,
}

impl From<&TestResultRow> for TestResultView {
    fn from(r: &TestResultRow) -> Self {
        Self {
            agent: r.agent.clone(),
            test_id: r.test_id.clone(),
            status: r.status.clone(),
            enforced: r.enforced,
            enforced_reason: r.enforced_reason.clone(),
            finding_count: r.finding_count,
            notes: r.notes.clone(),
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

    // Replace the prior results for this assessment — re-promotion refreshes.
    sqlx::query("DELETE FROM assessment_test_results WHERE org_id = $1 AND assessment_id = $2")
        .bind(&org_id)
        .bind(&assessment_id)
        .execute(&mut *tx)
        .await?;

    let mut upserted = 0usize;
    for t in &body.tests {
        let id = Uuid::new_v4().to_string();
        sqlx::query(
            r#"INSERT INTO assessment_test_results
                  (id, org_id, assessment_id, agent, test_id, status, enforced,
                   enforced_reason, finding_count, notes, created_at)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,NOW())
               ON CONFLICT (org_id, assessment_id, agent, test_id) DO UPDATE SET
                   status = EXCLUDED.status,
                   enforced = EXCLUDED.enforced,
                   enforced_reason = EXCLUDED.enforced_reason,
                   finding_count = EXCLUDED.finding_count,
                   notes = EXCLUDED.notes"#,
        )
        .bind(&id)
        .bind(&org_id)
        .bind(&assessment_id)
        .bind(&t.agent)
        .bind(&t.test_id)
        .bind(&t.status)
        .bind(t.enforced)
        .bind(&t.enforced_reason)
        .bind(t.finding_count)
        .bind(&t.notes)
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
) -> AppResult<Json<Vec<TestResultView>>> {
    let org_id = user
        .org_id
        .clone()
        .ok_or_else(|| AppError::Forbidden("Missing org_id on caller".to_string()))?;

    let rows: Vec<TestResultRow> = sqlx::query_as(
        r#"SELECT id, org_id, assessment_id, agent, test_id, status, enforced,
                  enforced_reason, finding_count, notes, created_at
           FROM assessment_test_results
           WHERE org_id = $1 AND assessment_id = $2
           ORDER BY agent ASC, test_id ASC"#,
    )
    .bind(&org_id)
    .bind(&assessment_id)
    .fetch_all(&state.pool)
    .await?;

    Ok(Json(rows.iter().map(TestResultView::from).collect()))
}
