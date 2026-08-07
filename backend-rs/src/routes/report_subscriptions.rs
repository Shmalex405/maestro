//! `/report-subscriptions` — scheduled DAST report delivery (WS6).
//!
//! CRUD over delivery subscriptions. NOTE: the actual email send needs an
//! external provider (SES/SendGrid) not wired in this repo — these rows are
//! stored + manageable but not yet delivered (the UI flags this clearly).

use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::get,
    Json, Router,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::AuthUser;
use crate::error::{AppError, AppResult};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/report-subscriptions", get(list).post(create))
        .route("/report-subscriptions/:id", axum::routing::patch(update).delete(remove))
}

const CADENCES: [&str; 3] = ["daily", "weekly", "monthly"];

#[derive(Debug, sqlx::FromRow, Serialize)]
struct ReportSubscription {
    id: String,
    org_id: String,
    application_id: Option<String>,
    target_id: Option<String>,
    recipients: Vec<String>,
    cadence: String,
    enabled: bool,
    last_sent_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

async fn list(State(state): State<AppState>, user: AuthUser) -> AppResult<Json<Vec<ReportSubscription>>> {
    let org_id = user
        .org_id
        .clone()
        .ok_or_else(|| AppError::Forbidden("Missing org_id on caller".to_string()))?;
    let rows: Vec<ReportSubscription> = sqlx::query_as(
        "SELECT * FROM report_subscriptions WHERE org_id = $1 ORDER BY created_at DESC",
    )
    .bind(&org_id)
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(rows))
}

#[derive(Debug, Deserialize)]
struct CreateBody {
    #[serde(default)]
    application_id: Option<String>,
    #[serde(default)]
    target_id: Option<String>,
    recipients: Vec<String>,
    #[serde(default)]
    cadence: Option<String>,
}

async fn create(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<CreateBody>,
) -> AppResult<(StatusCode, Json<ReportSubscription>)> {
    let org_id = user
        .org_id
        .clone()
        .ok_or_else(|| AppError::Forbidden("Missing org_id on caller".to_string()))?;
    if req.recipients.is_empty() {
        return Err(AppError::BadRequest("at least one recipient is required".into()));
    }
    let cadence = req.cadence.unwrap_or_else(|| "weekly".to_string());
    if !CADENCES.contains(&cadence.as_str()) {
        return Err(AppError::BadRequest(format!("cadence must be one of: {}", CADENCES.join(", "))));
    }
    let id = Uuid::new_v4().to_string();
    let row: ReportSubscription = sqlx::query_as(
        r#"INSERT INTO report_subscriptions
              (id, org_id, application_id, target_id, recipients, cadence, created_by)
           VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *"#,
    )
    .bind(&id)
    .bind(&org_id)
    .bind(&req.application_id)
    .bind(&req.target_id)
    .bind(&req.recipients)
    .bind(&cadence)
    .bind(&user.id)
    .fetch_one(&state.pool)
    .await?;
    Ok((StatusCode::CREATED, Json(row)))
}

#[derive(Debug, Deserialize)]
struct UpdateBody {
    #[serde(default)]
    recipients: Option<Vec<String>>,
    #[serde(default)]
    cadence: Option<String>,
    #[serde(default)]
    enabled: Option<bool>,
}

async fn update(
    State(state): State<AppState>,
    Path(id): Path<String>,
    user: AuthUser,
    Json(req): Json<UpdateBody>,
) -> AppResult<Json<ReportSubscription>> {
    let org_id = user
        .org_id
        .clone()
        .ok_or_else(|| AppError::Forbidden("Missing org_id on caller".to_string()))?;
    let row: Option<ReportSubscription> = sqlx::query_as(
        r#"UPDATE report_subscriptions SET
               recipients = COALESCE($3, recipients),
               cadence    = COALESCE($4, cadence),
               enabled    = COALESCE($5, enabled),
               updated_at = NOW()
           WHERE id = $1 AND org_id = $2 RETURNING *"#,
    )
    .bind(&id)
    .bind(&org_id)
    .bind(&req.recipients)
    .bind(&req.cadence)
    .bind(req.enabled)
    .fetch_optional(&state.pool)
    .await?;
    row.map(Json).ok_or_else(|| AppError::NotFound("Subscription not found".into()))
}

async fn remove(
    State(state): State<AppState>,
    Path(id): Path<String>,
    user: AuthUser,
) -> AppResult<StatusCode> {
    let org_id = user
        .org_id
        .clone()
        .ok_or_else(|| AppError::Forbidden("Missing org_id on caller".to_string()))?;
    let res = sqlx::query("DELETE FROM report_subscriptions WHERE id = $1 AND org_id = $2")
        .bind(&id)
        .bind(&org_id)
        .execute(&state.pool)
        .await?;
    if res.rows_affected() == 0 {
        return Err(AppError::NotFound("Subscription not found".into()));
    }
    Ok(StatusCode::NO_CONTENT)
}
