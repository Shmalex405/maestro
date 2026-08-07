//! `/applications` — the grouping layer above targets (Scheduled DAST Phase 4).
//!
//! An application carries ownership + business context (team, criticality,
//! environment) for the targets assigned to it. Org-scoped via JWT `custom:org_id`.
//!
//! Endpoints:
//!   GET    /applications        — list the org's applications
//!   POST   /applications        — create
//!   PATCH  /applications/:id     — partial update (COALESCE)
//!   DELETE /applications/:id     — delete (targets' application_id → NULL via FK)

use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::get,
    Json, Router,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::audit;
use crate::auth::AuthUser;
use crate::error::{AppError, AppResult};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/applications", get(list).post(create))
        .route("/applications/:id", axum::routing::patch(update).delete(remove))
}

const CRITICALITIES: [&str; 4] = ["low", "medium", "high", "critical"];

#[derive(Debug, sqlx::FromRow, Serialize)]
struct Application {
    id: String,
    org_id: String,
    name: String,
    description: Option<String>,
    team: Option<String>,
    criticality: String,
    environment: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
struct ApplicationView {
    #[serde(flatten)]
    app: Application,
    /// Number of targets assigned to this application.
    target_count: i64,
}

async fn list(State(state): State<AppState>, user: AuthUser) -> AppResult<Json<Vec<ApplicationView>>> {
    let org_id = user
        .org_id
        .clone()
        .ok_or_else(|| AppError::Forbidden("Missing org_id on caller".to_string()))?;

    let apps: Vec<Application> = sqlx::query_as(
        "SELECT * FROM applications WHERE org_id = $1 ORDER BY name ASC",
    )
    .bind(&org_id)
    .fetch_all(&state.pool)
    .await?;

    // Per-app target counts in one query, then zip.
    let counts: Vec<(Option<String>, i64)> = sqlx::query_as(
        "SELECT application_id, COUNT(*) FROM targets
          WHERE org_id = $1 AND application_id IS NOT NULL
          GROUP BY application_id",
    )
    .bind(&org_id)
    .fetch_all(&state.pool)
    .await?;
    let count_for = |id: &str| counts.iter().find(|(a, _)| a.as_deref() == Some(id)).map(|(_, c)| *c).unwrap_or(0);

    Ok(Json(
        apps.into_iter()
            .map(|a| ApplicationView { target_count: count_for(&a.id), app: a })
            .collect(),
    ))
}

#[derive(Debug, Deserialize)]
struct CreateBody {
    name: String,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    team: Option<String>,
    #[serde(default)]
    criticality: Option<String>,
    #[serde(default)]
    environment: Option<String>,
}

async fn create(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<CreateBody>,
) -> AppResult<(StatusCode, Json<Application>)> {
    let org_id = user
        .org_id
        .clone()
        .ok_or_else(|| AppError::Forbidden("Missing org_id on caller".to_string()))?;
    if req.name.trim().is_empty() {
        return Err(AppError::BadRequest("name is required".into()));
    }
    let crit = req.criticality.unwrap_or_else(|| "medium".to_string());
    if !CRITICALITIES.contains(&crit.as_str()) {
        return Err(AppError::BadRequest(format!(
            "criticality must be one of: {}",
            CRITICALITIES.join(", ")
        )));
    }
    let id = Uuid::new_v4().to_string();
    let row: Application = sqlx::query_as(
        r#"INSERT INTO applications (id, org_id, name, description, team, criticality, environment)
           VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *"#,
    )
    .bind(&id)
    .bind(&org_id)
    .bind(&req.name)
    .bind(&req.description)
    .bind(&req.team)
    .bind(&crit)
    .bind(&req.environment)
    .fetch_one(&state.pool)
    .await?;

    audit::record(&state.pool, &user, "application.create", "application", Some(&row.id), None).await;
    Ok((StatusCode::CREATED, Json(row)))
}

#[derive(Debug, Deserialize)]
struct UpdateBody {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    team: Option<String>,
    #[serde(default)]
    criticality: Option<String>,
    #[serde(default)]
    environment: Option<String>,
}

async fn update(
    State(state): State<AppState>,
    Path(id): Path<String>,
    user: AuthUser,
    Json(req): Json<UpdateBody>,
) -> AppResult<Json<Application>> {
    let org_id = user
        .org_id
        .clone()
        .ok_or_else(|| AppError::Forbidden("Missing org_id on caller".to_string()))?;
    if let Some(c) = req.criticality.as_ref() {
        if !CRITICALITIES.contains(&c.as_str()) {
            return Err(AppError::BadRequest(format!(
                "criticality must be one of: {}",
                CRITICALITIES.join(", ")
            )));
        }
    }
    let row: Option<Application> = sqlx::query_as(
        r#"UPDATE applications SET
               name        = COALESCE($3, name),
               description = COALESCE($4, description),
               team        = COALESCE($5, team),
               criticality = COALESCE($6, criticality),
               environment = COALESCE($7, environment),
               updated_at  = NOW()
           WHERE id = $1 AND org_id = $2
           RETURNING *"#,
    )
    .bind(&id)
    .bind(&org_id)
    .bind(&req.name)
    .bind(&req.description)
    .bind(&req.team)
    .bind(&req.criticality)
    .bind(&req.environment)
    .fetch_optional(&state.pool)
    .await?;
    row.map(Json).ok_or_else(|| AppError::NotFound("Application not found".into()))
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
    let res = sqlx::query("DELETE FROM applications WHERE id = $1 AND org_id = $2")
        .bind(&id)
        .bind(&org_id)
        .execute(&state.pool)
        .await?;
    if res.rows_affected() == 0 {
        return Err(AppError::NotFound("Application not found".into()));
    }
    audit::record(&state.pool, &user, "application.delete", "application", Some(&id), None).await;
    Ok(StatusCode::NO_CONTENT)
}
