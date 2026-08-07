//! `/projects` CRUD + `/{id}/archive`.
//! Mirror of `backend/app/routers/projects.py`.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{get, put},
    Json, Router,
};
use serde::Deserialize;
use uuid::Uuid;

use crate::auth::AuthUser;
use crate::error::{AppError, AppResult};
use crate::models::project::Project;
use crate::schemas::project::{ProjectCreate, ProjectResponse, ProjectUpdate};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/projects", get(list_projects).post(create_project))
        .route(
            "/projects/:id",
            get(get_project).patch(update_project).delete(delete_project),
        )
        .route("/projects/:id/archive", put(archive_project))
}

#[derive(Debug, Deserialize)]
struct ListFilters {
    #[serde(default)]
    status: Option<String>,
}

async fn list_projects(
    State(state): State<AppState>,
    Query(q): Query<ListFilters>,
    user: AuthUser,
) -> AppResult<Json<Vec<ProjectResponse>>> {
    let mut sql = String::from("SELECT * FROM projects WHERE 1=1");
    let mut args: Vec<String> = Vec::new();

    if let Some(org) = user.org_id.as_ref() {
        args.push(org.clone());
        sql.push_str(&format!(" AND org_id = ${}", args.len()));
    }
    if let Some(s) = q.status.as_ref() {
        args.push(s.clone());
        sql.push_str(&format!(" AND status = ${}::projectstatus", args.len()));
    }
    sql.push_str(" ORDER BY updated_at DESC");

    let mut qx = sqlx::query_as::<_, Project>(&sql);
    for a in &args {
        qx = qx.bind(a);
    }
    let rows = qx.fetch_all(&state.pool).await?;

    let mut out = Vec::with_capacity(rows.len());
    for p in &rows {
        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM assessments WHERE project_id = $1")
                .bind(&p.id)
                .fetch_one(&state.pool)
                .await?;
        out.push(ProjectResponse::from_row(p, count));
    }
    Ok(Json(out))
}

async fn get_project(
    State(state): State<AppState>,
    Path(id): Path<String>,
    user: AuthUser,
) -> AppResult<Json<ProjectResponse>> {
    let p = fetch_scoped(&state, &id, &user).await?;
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM assessments WHERE project_id = $1")
        .bind(&p.id)
        .fetch_one(&state.pool)
        .await?;
    Ok(Json(ProjectResponse::from_row(&p, count)))
}

async fn create_project(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<ProjectCreate>,
) -> AppResult<(StatusCode, Json<ProjectResponse>)> {
    let id = Uuid::new_v4().to_string();
    // Bind status explicitly even though the column has DEFAULT 'active'.
    // Defense-in-depth — every legacy project row in prod had status=NULL
    // somehow (see migration 0010_projects_status_backfill.sql), and the
    // result was that the `?status=active` filter never matched any of
    // them, making newly-created projects invisible in the Maestro sidebar.
    sqlx::query(
        r#"INSERT INTO projects (id, name, description, status, org_id, created_by, scope)
           VALUES ($1, $2, $3, 'active'::projectstatus, $4, $5, COALESCE($6, '{}'::jsonb))"#,
    )
    .bind(&id)
    .bind(&req.name)
    .bind(&req.description)
    .bind(&user.org_id)
    .bind(&user.id)
    .bind(&req.scope)
    .execute(&state.pool)
    .await?;

    let p: Project = sqlx::query_as("SELECT * FROM projects WHERE id = $1")
        .bind(&id)
        .fetch_one(&state.pool)
        .await?;
    Ok((StatusCode::CREATED, Json(ProjectResponse::from_row(&p, 0))))
}

async fn update_project(
    State(state): State<AppState>,
    Path(id): Path<String>,
    user: AuthUser,
    Json(req): Json<ProjectUpdate>,
) -> AppResult<Json<ProjectResponse>> {
    let _ = fetch_scoped(&state, &id, &user).await?;
    let p: Project = sqlx::query_as(
        r#"UPDATE projects
              SET name = COALESCE($2, name),
                  description = COALESCE($3, description),
                  status = COALESCE($4::projectstatus, status),
                  scope = COALESCE($5, scope),
                  updated_at = NOW()
            WHERE id = $1
            RETURNING *"#,
    )
    .bind(&id)
    .bind(&req.name)
    .bind(&req.description)
    .bind(&req.status)
    .bind(&req.scope)
    .fetch_one(&state.pool)
    .await?;

    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM assessments WHERE project_id = $1")
        .bind(&id)
        .fetch_one(&state.pool)
        .await?;
    Ok(Json(ProjectResponse::from_row(&p, count)))
}

async fn delete_project(
    State(state): State<AppState>,
    Path(id): Path<String>,
    user: AuthUser,
) -> AppResult<StatusCode> {
    let _ = fetch_scoped(&state, &id, &user).await?;
    sqlx::query("DELETE FROM projects WHERE id = $1")
        .bind(&id)
        .execute(&state.pool)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn archive_project(
    State(state): State<AppState>,
    Path(id): Path<String>,
    user: AuthUser,
) -> AppResult<Json<ProjectResponse>> {
    let _ = fetch_scoped(&state, &id, &user).await?;
    let p: Project = sqlx::query_as(
        r#"UPDATE projects SET status = 'archived', updated_at = NOW()
            WHERE id = $1 RETURNING *"#,
    )
    .bind(&id)
    .fetch_one(&state.pool)
    .await?;
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM assessments WHERE project_id = $1")
        .bind(&id)
        .fetch_one(&state.pool)
        .await?;
    Ok(Json(ProjectResponse::from_row(&p, count)))
}

async fn fetch_scoped(state: &AppState, id: &str, user: &AuthUser) -> AppResult<Project> {
    let mut sql = String::from("SELECT * FROM projects WHERE id = $1");
    let mut binds: Vec<String> = vec![id.to_string()];
    if let Some(org) = user.org_id.as_ref() {
        sql.push_str(" AND org_id = $2");
        binds.push(org.clone());
    }
    let mut q = sqlx::query_as::<_, Project>(&sql);
    for b in &binds {
        q = q.bind(b);
    }
    let row: Option<Project> = q.fetch_optional(&state.pool).await?;
    row.ok_or_else(|| AppError::NotFound("Project not found".into()))
}
