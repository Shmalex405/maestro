//! `/repositories` CRUD — org-shared code repo metadata.
//!
//! See `models/repository.rs` for the path-vs-metadata split rationale.
//! Each row is scoped to `org_id` (matched against the JWT's tenancy claim).

use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::get,
    Json, Router,
};
use uuid::Uuid;

use crate::auth::AuthUser;
use crate::error::{AppError, AppResult};
use crate::models::repository::Repository;
use crate::schemas::repository::{RepositoryCreate, RepositoryResponse, RepositoryUpdate};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/repositories", get(list_repositories).post(create_repository))
        .route(
            "/repositories/:id",
            get(get_repository)
                .patch(update_repository)
                .delete(delete_repository),
        )
}

async fn list_repositories(
    State(state): State<AppState>,
    user: AuthUser,
) -> AppResult<Json<Vec<RepositoryResponse>>> {
    let mut sql = String::from("SELECT * FROM repositories WHERE 1=1");
    let mut binds: Vec<String> = Vec::new();
    if let Some(org) = user.org_id.as_ref() {
        binds.push(org.clone());
        sql.push_str(&format!(" AND org_id = ${}", binds.len()));
    }
    sql.push_str(" ORDER BY updated_at DESC");

    let mut q = sqlx::query_as::<_, Repository>(&sql);
    for b in &binds {
        q = q.bind(b);
    }
    let rows = q.fetch_all(&state.pool).await?;
    Ok(Json(rows.iter().map(RepositoryResponse::from_row).collect()))
}

async fn get_repository(
    State(state): State<AppState>,
    Path(id): Path<String>,
    user: AuthUser,
) -> AppResult<Json<RepositoryResponse>> {
    let r = fetch_scoped(&state, &id, &user).await?;
    Ok(Json(RepositoryResponse::from_row(&r)))
}

async fn create_repository(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<RepositoryCreate>,
) -> AppResult<(StatusCode, Json<RepositoryResponse>)> {
    let id = Uuid::new_v4().to_string();
    let source_type = req.source_type.as_deref().unwrap_or("local");
    let languages = req
        .languages
        .clone()
        .unwrap_or_else(|| serde_json::Value::Array(vec![]));
    let scan_config = req
        .default_scan_config
        .clone()
        .unwrap_or_else(|| serde_json::Value::Object(serde_json::Map::new()));

    sqlx::query(
        r#"INSERT INTO repositories
            (id, name, description, default_path, source_type, github_owner,
             github_repo, github_url, languages, default_scan_config,
             org_id, created_by)
           VALUES ($1, $2, $3, $4, $5::reposourcetype, $6, $7, $8, $9, $10, $11, $12)"#,
    )
    .bind(&id)
    .bind(&req.name)
    .bind(&req.description)
    .bind(&req.path)
    .bind(source_type)
    .bind(&req.github_owner)
    .bind(&req.github_repo)
    .bind(&req.github_url)
    .bind(&languages)
    .bind(&scan_config)
    .bind(&user.org_id)
    .bind(&user.id)
    .execute(&state.pool)
    .await?;

    let r: Repository = sqlx::query_as("SELECT * FROM repositories WHERE id = $1")
        .bind(&id)
        .fetch_one(&state.pool)
        .await?;
    Ok((StatusCode::CREATED, Json(RepositoryResponse::from_row(&r))))
}

async fn update_repository(
    State(state): State<AppState>,
    Path(id): Path<String>,
    user: AuthUser,
    Json(req): Json<RepositoryUpdate>,
) -> AppResult<Json<RepositoryResponse>> {
    let _ = fetch_scoped(&state, &id, &user).await?;
    let r: Repository = sqlx::query_as(
        r#"UPDATE repositories SET
              name = COALESCE($2, name),
              description = COALESCE($3, description),
              source_type = COALESCE($4::reposourcetype, source_type),
              github_owner = COALESCE($5, github_owner),
              github_repo = COALESCE($6, github_repo),
              github_url = COALESCE($7, github_url),
              languages = COALESCE($8, languages),
              default_scan_config = COALESCE($9, default_scan_config),
              last_scan_at = COALESCE($10, last_scan_at),
              last_scan_findings = COALESCE($11, last_scan_findings),
              updated_at = NOW()
           WHERE id = $1
           RETURNING *"#,
    )
    .bind(&id)
    .bind(&req.name)
    .bind(&req.description)
    .bind(&req.source_type)
    .bind(&req.github_owner)
    .bind(&req.github_repo)
    .bind(&req.github_url)
    .bind(&req.languages)
    .bind(&req.default_scan_config)
    .bind(&req.last_scan_at)
    .bind(&req.last_scan_findings)
    .fetch_one(&state.pool)
    .await?;
    Ok(Json(RepositoryResponse::from_row(&r)))
}

async fn delete_repository(
    State(state): State<AppState>,
    Path(id): Path<String>,
    user: AuthUser,
) -> AppResult<StatusCode> {
    let _ = fetch_scoped(&state, &id, &user).await?;
    sqlx::query("DELETE FROM repositories WHERE id = $1")
        .bind(&id)
        .execute(&state.pool)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn fetch_scoped(state: &AppState, id: &str, user: &AuthUser) -> AppResult<Repository> {
    let mut sql = String::from("SELECT * FROM repositories WHERE id = $1");
    let mut binds: Vec<String> = vec![id.to_string()];
    if let Some(org) = user.org_id.as_ref() {
        sql.push_str(" AND org_id = $2");
        binds.push(org.clone());
    }
    let mut q = sqlx::query_as::<_, Repository>(&sql);
    for b in &binds {
        q = q.bind(b);
    }
    let row: Option<Repository> = q.fetch_optional(&state.pool).await?;
    row.ok_or_else(|| AppError::NotFound("Repository not found".into()))
}
