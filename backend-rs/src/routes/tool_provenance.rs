//! `/assessments/:id/tool-executions` — tool-execution provenance (P1).
//!
//! Endpoints:
//!   POST /assessments/:id/tool-executions  — ingest the per-tool summary
//!                                            (replaces the prior set for the run)
//!   GET  /assessments/:id/tool-executions  — list the run's tool provenance
//!
//! Promoted at end-of-run by the MCP `promote_tool_provenance` tool (Shape A).
//! The desktop "Tools" view reads the GET to show which tools actually ran.
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
use crate::models::tool_provenance::ToolExecutionRow;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route(
        "/assessments/:id/tool-executions",
        post(ingest).get(list),
    )
}

#[derive(Debug, Deserialize)]
struct IngestBody {
    #[serde(default)]
    tools: Vec<ToolEntry>,
}

#[derive(Debug, Deserialize)]
struct ToolEntry {
    tool_name: String,
    #[serde(default)]
    binary: Option<String>,
    #[serde(default)]
    installed: Option<bool>,
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    run_count: i32,
    #[serde(default)]
    ok_count: i32,
    #[serde(default)]
    fail_count: i32,
    #[serde(default)]
    last_exit_code: Option<i32>,
}

#[derive(Debug, Serialize)]
struct ToolExecView {
    tool_name: String,
    binary: Option<String>,
    installed: Option<bool>,
    version: Option<String>,
    run_count: i32,
    ok_count: i32,
    fail_count: i32,
    last_exit_code: Option<i32>,
}

impl From<&ToolExecutionRow> for ToolExecView {
    fn from(r: &ToolExecutionRow) -> Self {
        Self {
            tool_name: r.tool_name.clone(),
            binary: r.binary.clone(),
            installed: r.installed,
            version: r.version.clone(),
            run_count: r.run_count,
            ok_count: r.ok_count,
            fail_count: r.fail_count,
            last_exit_code: r.last_exit_code,
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

    // Replace the prior provenance for this assessment — re-promotion refreshes.
    sqlx::query("DELETE FROM tool_executions WHERE org_id = $1 AND assessment_id = $2")
        .bind(&org_id)
        .bind(&assessment_id)
        .execute(&mut *tx)
        .await?;

    let mut upserted = 0usize;
    for t in &body.tools {
        let id = Uuid::new_v4().to_string();
        sqlx::query(
            r#"INSERT INTO tool_executions
                  (id, org_id, assessment_id, tool_name, "binary", installed, version,
                   run_count, ok_count, fail_count, last_exit_code, created_at, updated_at)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,NOW(),NOW())
               ON CONFLICT (org_id, assessment_id, tool_name) DO UPDATE SET
                   "binary" = EXCLUDED."binary",
                   installed = EXCLUDED.installed,
                   version = EXCLUDED.version,
                   run_count = EXCLUDED.run_count,
                   ok_count = EXCLUDED.ok_count,
                   fail_count = EXCLUDED.fail_count,
                   last_exit_code = EXCLUDED.last_exit_code,
                   updated_at = NOW()"#,
        )
        .bind(&id)
        .bind(&org_id)
        .bind(&assessment_id)
        .bind(&t.tool_name)
        .bind(&t.binary)
        .bind(t.installed)
        .bind(&t.version)
        .bind(t.run_count)
        .bind(t.ok_count)
        .bind(t.fail_count)
        .bind(t.last_exit_code)
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
) -> AppResult<Json<Vec<ToolExecView>>> {
    let org_id = user
        .org_id
        .clone()
        .ok_or_else(|| AppError::Forbidden("Missing org_id on caller".to_string()))?;

    let rows: Vec<ToolExecutionRow> = sqlx::query_as(
        r#"SELECT id, org_id, assessment_id, tool_name, "binary", installed, version,
                  run_count, ok_count, fail_count, last_exit_code, created_at, updated_at
           FROM tool_executions
           WHERE org_id = $1 AND assessment_id = $2
           ORDER BY tool_name ASC"#,
    )
    .bind(&org_id)
    .bind(&assessment_id)
    .fetch_all(&state.pool)
    .await?;

    Ok(Json(rows.iter().map(ToolExecView::from).collect()))
}
