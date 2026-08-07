//! `/assessments/:id/events` — persistent activity feed for an assessment.
//!
//! Real-time stream lives in the desktop's `activity-feed.tsx` (parses
//! tool_call blocks from the chat). This persists what that component
//! captures so the timeline survives the app being closed and is
//! visible to teammates / post-run viewers via the cloud DB.
//!
//! Org-scoping is enforced via the parent assessment's org_id — we
//! resolve the assessment first, fail with 404 if it isn't visible,
//! then operate on events.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    routing::get,
    Json, Router,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use sqlx::FromRow;
use uuid::Uuid;

use crate::auth::AuthUser;
use crate::error::{AppError, AppResult};
use crate::state::AppState;

/// Whitelist of event types the API accepts. Lets the desktop send
/// structured types without us silently allowing typos that future
/// queries would never match.
const ALLOWED_EVENT_TYPES: &[&str] = &[
    "tool_call",
    "tool_result",
    "finding_detected",
    "phase_change",
    "guidance_request",
    "orchestrator_message",
    "error",
];

pub fn router() -> Router<AppState> {
    Router::new().route(
        "/assessments/:id/events",
        get(list_events).post(create_event),
    )
}

#[derive(Debug, FromRow, Serialize)]
struct EventRow {
    id: String,
    assessment_id: String,
    event_type: String,
    tool: Option<String>,
    target: Option<String>,
    details: Option<JsonValue>,
    ref_finding_id: Option<String>,
    created_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize)]
struct ListQuery {
    /// Optional `event_type` filter: e.g. "tool_call" to show only the
    /// scanner-execution view, "finding_detected" for a finding-only timeline.
    #[serde(default)]
    event_type: Option<String>,
    /// Default 500 events; UI paginates older ones via `before` cursor
    /// (created_at) once we hit that.
    #[serde(default = "default_limit")]
    limit: i64,
}

fn default_limit() -> i64 {
    500
}

#[derive(Debug, Deserialize)]
struct CreateEventReq {
    event_type: String,
    #[serde(default)]
    tool: Option<String>,
    #[serde(default)]
    target: Option<String>,
    #[serde(default)]
    details: Option<JsonValue>,
    #[serde(default)]
    ref_finding_id: Option<String>,
}

/// Confirm the assessment is visible to the caller before touching its
/// events. Mirrors the pattern the other entity routes use.
async fn assessment_in_scope(
    state: &AppState,
    assessment_id: &str,
    user: &AuthUser,
) -> AppResult<()> {
    let row: Option<(String,)> = sqlx::query_as(
        "SELECT id FROM assessments
          WHERE id = $1 AND ($2::varchar IS NULL OR org_id = $2)",
    )
    .bind(assessment_id)
    .bind(&user.org_id)
    .fetch_optional(&state.pool)
    .await?;
    row.map(|_| ())
        .ok_or_else(|| AppError::NotFound("Assessment not found".into()))
}

async fn list_events(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(q): Query<ListQuery>,
    user: AuthUser,
) -> AppResult<Json<Vec<EventRow>>> {
    assessment_in_scope(&state, &id, &user).await?;

    let limit = q.limit.max(1).min(2000);
    let rows: Vec<EventRow> = if let Some(et) = q.event_type.as_ref() {
        sqlx::query_as(
            "SELECT * FROM assessment_events
              WHERE assessment_id = $1 AND event_type = $2
              ORDER BY created_at ASC
              LIMIT $3",
        )
        .bind(&id)
        .bind(et)
        .bind(limit)
        .fetch_all(&state.pool)
        .await?
    } else {
        sqlx::query_as(
            "SELECT * FROM assessment_events
              WHERE assessment_id = $1
              ORDER BY created_at ASC
              LIMIT $2",
        )
        .bind(&id)
        .bind(limit)
        .fetch_all(&state.pool)
        .await?
    };
    Ok(Json(rows))
}

async fn create_event(
    State(state): State<AppState>,
    Path(assessment_id): Path<String>,
    user: AuthUser,
    Json(req): Json<CreateEventReq>,
) -> AppResult<(StatusCode, Json<EventRow>)> {
    assessment_in_scope(&state, &assessment_id, &user).await?;

    if !ALLOWED_EVENT_TYPES.iter().any(|t| *t == req.event_type) {
        return Err(AppError::BadRequest(format!(
            "Unknown event_type '{}'. Allowed: {}",
            req.event_type,
            ALLOWED_EVENT_TYPES.join(", ")
        )));
    }

    let id = Uuid::new_v4().to_string();
    sqlx::query(
        r#"INSERT INTO assessment_events
              (id, assessment_id, event_type, tool, target, details, ref_finding_id)
           VALUES ($1, $2, $3, $4, $5, $6, $7)"#,
    )
    .bind(&id)
    .bind(&assessment_id)
    .bind(&req.event_type)
    .bind(&req.tool)
    .bind(&req.target)
    .bind(&req.details)
    .bind(&req.ref_finding_id)
    .execute(&state.pool)
    .await?;

    let row: EventRow =
        sqlx::query_as("SELECT * FROM assessment_events WHERE id = $1")
            .bind(&id)
            .fetch_one(&state.pool)
            .await?;
    Ok((StatusCode::CREATED, Json(row)))
}
