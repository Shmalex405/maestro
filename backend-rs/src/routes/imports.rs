//! `/imports` + `/imported-findings` — bulk vuln-list ingestion.
//!
//! `imports` = a record of one CSV/Cycode upload (metadata + raw payload).
//! `imported_findings` = parsed rows from those uploads, kept distinct
//! from native findings until validated. The desktop's Import page hits
//! both; the actual CSV parsing happens client-side at the Tauri layer
//! and we just persist the structured rows here.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{get, post},
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

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/imports", get(list_imports).post(create_import))
        .route("/imports/:id", get(get_import).delete(delete_import))
        .route("/imports/stats", get(import_stats))
        .route(
            "/imported-findings",
            get(list_imported_findings).post(create_imported_finding),
        )
        .route(
            "/imported-findings/:id",
            get(get_imported_finding),
        )
        .route(
            "/imported-findings/:id/status",
            axum::routing::patch(update_imported_finding_status),
        )
        .route(
            "/imported-findings/link-repository",
            post(link_findings_to_repository),
        )
        .route(
            "/imported-findings/validate",
            post(create_validation_assessment),
        )
}

// ── imports ─────────────────────────────────────────────────────────

#[derive(Debug, FromRow, Serialize)]
struct ImportRow {
    id: String,
    name: Option<String>,
    source: Option<String>,
    filename: Option<String>,
    row_count: Option<i32>,
    org_id: Option<String>,
    created_by: Option<String>,
    created_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize)]
struct ImportCreate {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    source: Option<String>,
    #[serde(default)]
    filename: Option<String>,
    csv_content: String,
    /// Pre-parsed rows from the desktop's CSV preview step. We accept and
    /// persist them in a single transaction so a successful response
    /// means the rows landed too.
    #[serde(default)]
    rows: Vec<ImportedFindingPayload>,
}

#[derive(Debug, Deserialize)]
struct ImportedFindingPayload {
    #[serde(default)]
    external_ref: Option<String>,
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    severity: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    cve: Option<String>,
    #[serde(default)]
    cwe: Option<String>,
    #[serde(default)]
    file_path: Option<String>,
    #[serde(default)]
    line_start: Option<i32>,
    #[serde(default)]
    line_end: Option<i32>,
    #[serde(default)]
    code_snippet: Option<String>,
    #[serde(default)]
    raw_row: Option<JsonValue>,
}

#[derive(Debug, Serialize)]
struct ImportStats {
    total_imports: i64,
    total_imported_findings: i64,
    pending_validation: i64,
}

async fn list_imports(
    State(state): State<AppState>,
    user: AuthUser,
) -> AppResult<Json<Vec<ImportRow>>> {
    let mut sql = String::from("SELECT id, name, source, filename, row_count, org_id, created_by, created_at FROM imports WHERE 1=1");
    let mut binds: Vec<String> = Vec::new();
    if let Some(org) = user.org_id.as_ref() {
        binds.push(org.clone());
        sql.push_str(&format!(" AND org_id = ${}", binds.len()));
    }
    sql.push_str(" ORDER BY created_at DESC");
    let mut q = sqlx::query_as::<_, ImportRow>(&sql);
    for b in &binds {
        q = q.bind(b);
    }
    Ok(Json(q.fetch_all(&state.pool).await?))
}

async fn get_import(
    State(state): State<AppState>,
    Path(id): Path<String>,
    user: AuthUser,
) -> AppResult<Json<ImportRow>> {
    let row: Option<ImportRow> = sqlx::query_as(
        "SELECT id, name, source, filename, row_count, org_id, created_by, created_at
           FROM imports WHERE id = $1 AND ($2::varchar IS NULL OR org_id = $2)",
    )
    .bind(&id)
    .bind(&user.org_id)
    .fetch_optional(&state.pool)
    .await?;
    row.map(Json).ok_or_else(|| AppError::NotFound("Import not found".into()))
}

async fn create_import(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<ImportCreate>,
) -> AppResult<(StatusCode, Json<JsonValue>)> {
    if req.csv_content.len() > 1_048_576 {
        return Err(AppError::BadRequest(
            "CSV payload over 1MB — split into smaller imports".into(),
        ));
    }

    let import_id = Uuid::new_v4().to_string();
    let mut tx = state.pool.begin().await?;

    sqlx::query(
        "INSERT INTO imports (id, name, source, filename, row_count, raw_csv, org_id, created_by)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(&import_id)
    .bind(&req.name)
    .bind(&req.source)
    .bind(&req.filename)
    .bind(req.rows.len() as i32)
    .bind(&req.csv_content)
    .bind(&user.org_id)
    .bind(&user.id)
    .execute(&mut *tx)
    .await?;

    for row in &req.rows {
        let row_id = Uuid::new_v4().to_string();
        sqlx::query(
            r#"INSERT INTO imported_findings
                 (id, import_id, external_ref, title, severity, description,
                  cve, cwe, file_path, line_start, line_end, code_snippet,
                  raw_row, org_id)
               VALUES ($1, $2, $3, $4, $5::severity, $6, $7, $8, $9, $10, $11, $12, $13, $14)"#,
        )
        .bind(&row_id)
        .bind(&import_id)
        .bind(&row.external_ref)
        .bind(&row.title)
        .bind(&row.severity)
        .bind(&row.description)
        .bind(&row.cve)
        .bind(&row.cwe)
        .bind(&row.file_path)
        .bind(row.line_start)
        .bind(row.line_end)
        .bind(&row.code_snippet)
        .bind(&row.raw_row)
        .bind(&user.org_id)
        .execute(&mut *tx)
        .await?;
    }

    tx.commit().await?;

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "id": import_id,
            "imported_count": req.rows.len(),
        })),
    ))
}

async fn delete_import(
    State(state): State<AppState>,
    Path(id): Path<String>,
    user: AuthUser,
) -> AppResult<StatusCode> {
    let res = sqlx::query(
        "DELETE FROM imports WHERE id = $1 AND ($2::varchar IS NULL OR org_id = $2)",
    )
    .bind(&id)
    .bind(&user.org_id)
    .execute(&state.pool)
    .await?;
    if res.rows_affected() == 0 {
        return Err(AppError::NotFound("Import not found".into()));
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn import_stats(
    State(state): State<AppState>,
    user: AuthUser,
) -> AppResult<Json<ImportStats>> {
    let total_imports: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM imports WHERE $1::varchar IS NULL OR org_id = $1",
    )
    .bind(&user.org_id)
    .fetch_one(&state.pool)
    .await?;

    let total_imported: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM imported_findings WHERE $1::varchar IS NULL OR org_id = $1",
    )
    .bind(&user.org_id)
    .fetch_one(&state.pool)
    .await?;

    let pending: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM imported_findings
          WHERE status = 'imported' AND ($1::varchar IS NULL OR org_id = $1)",
    )
    .bind(&user.org_id)
    .fetch_one(&state.pool)
    .await?;

    Ok(Json(ImportStats {
        total_imports,
        total_imported_findings: total_imported,
        pending_validation: pending,
    }))
}

// ── imported_findings ──────────────────────────────────────────────

#[derive(Debug, FromRow, Serialize)]
struct ImportedFindingRow {
    id: String,
    import_id: Option<String>,
    external_ref: Option<String>,
    title: Option<String>,
    severity: Option<String>,
    description: Option<String>,
    cve: Option<String>,
    cwe: Option<String>,
    file_path: Option<String>,
    line_start: Option<i32>,
    line_end: Option<i32>,
    code_snippet: Option<String>,
    status: Option<String>,
    repository_id: Option<String>,
    linked_finding_id: Option<String>,
    linked_assessment_id: Option<String>,
    org_id: Option<String>,
    created_at: Option<DateTime<Utc>>,
    updated_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize)]
struct ListImportedFindingsQuery {
    #[serde(default)]
    import_id: Option<String>,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    repository_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ImportedFindingCreate {
    #[serde(flatten)]
    base: ImportedFindingPayload,
    import_id: String,
}

async fn list_imported_findings(
    State(state): State<AppState>,
    Query(q): Query<ListImportedFindingsQuery>,
    user: AuthUser,
) -> AppResult<Json<Vec<ImportedFindingRow>>> {
    let mut sql = String::from(
        "SELECT id, import_id, external_ref, title, severity::text AS severity,
                description, cve, cwe, file_path, line_start, line_end,
                code_snippet, status::text AS status, repository_id,
                linked_finding_id, linked_assessment_id, org_id,
                created_at, updated_at
           FROM imported_findings WHERE 1=1",
    );
    let mut binds: Vec<String> = Vec::new();
    if let Some(org) = user.org_id.as_ref() {
        binds.push(org.clone());
        sql.push_str(&format!(" AND org_id = ${}", binds.len()));
    }
    if let Some(v) = q.import_id.as_ref() {
        binds.push(v.clone());
        sql.push_str(&format!(" AND import_id = ${}", binds.len()));
    }
    if let Some(v) = q.status.as_ref() {
        binds.push(v.clone());
        sql.push_str(&format!(" AND status = ${}::importedfindingstatus", binds.len()));
    }
    if let Some(v) = q.repository_id.as_ref() {
        binds.push(v.clone());
        sql.push_str(&format!(" AND repository_id = ${}", binds.len()));
    }
    sql.push_str(" ORDER BY created_at DESC LIMIT 500");

    let mut qx = sqlx::query_as::<_, ImportedFindingRow>(&sql);
    for b in &binds {
        qx = qx.bind(b);
    }
    Ok(Json(qx.fetch_all(&state.pool).await?))
}

async fn get_imported_finding(
    State(state): State<AppState>,
    Path(id): Path<String>,
    user: AuthUser,
) -> AppResult<Json<ImportedFindingRow>> {
    let row: Option<ImportedFindingRow> = sqlx::query_as(
        "SELECT id, import_id, external_ref, title, severity::text AS severity,
                description, cve, cwe, file_path, line_start, line_end,
                code_snippet, status::text AS status, repository_id,
                linked_finding_id, linked_assessment_id, org_id,
                created_at, updated_at
           FROM imported_findings
          WHERE id = $1 AND ($2::varchar IS NULL OR org_id = $2)",
    )
    .bind(&id)
    .bind(&user.org_id)
    .fetch_optional(&state.pool)
    .await?;
    row.map(Json).ok_or_else(|| AppError::NotFound("Imported finding not found".into()))
}

async fn create_imported_finding(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<ImportedFindingCreate>,
) -> AppResult<(StatusCode, Json<JsonValue>)> {
    let id = Uuid::new_v4().to_string();
    sqlx::query(
        r#"INSERT INTO imported_findings
              (id, import_id, external_ref, title, severity, description,
               cve, cwe, file_path, line_start, line_end, code_snippet,
               raw_row, org_id)
           VALUES ($1, $2, $3, $4, $5::severity, $6, $7, $8, $9, $10, $11, $12, $13, $14)"#,
    )
    .bind(&id)
    .bind(&req.import_id)
    .bind(&req.base.external_ref)
    .bind(&req.base.title)
    .bind(&req.base.severity)
    .bind(&req.base.description)
    .bind(&req.base.cve)
    .bind(&req.base.cwe)
    .bind(&req.base.file_path)
    .bind(req.base.line_start)
    .bind(req.base.line_end)
    .bind(&req.base.code_snippet)
    .bind(&req.base.raw_row)
    .bind(&user.org_id)
    .execute(&state.pool)
    .await?;
    Ok((StatusCode::CREATED, Json(serde_json::json!({"id": id}))))
}

#[derive(Debug, Deserialize)]
struct UpdateStatusReq {
    status: String,
    #[serde(default)]
    linked_finding_id: Option<String>,
    #[serde(default)]
    linked_assessment_id: Option<String>,
}

async fn update_imported_finding_status(
    State(state): State<AppState>,
    Path(id): Path<String>,
    user: AuthUser,
    Json(req): Json<UpdateStatusReq>,
) -> AppResult<StatusCode> {
    let res = sqlx::query(
        r#"UPDATE imported_findings SET
              status = $2::importedfindingstatus,
              linked_finding_id = COALESCE($3, linked_finding_id),
              linked_assessment_id = COALESCE($4, linked_assessment_id),
              updated_at = NOW()
            WHERE id = $1 AND ($5::varchar IS NULL OR org_id = $5)"#,
    )
    .bind(&id)
    .bind(&req.status)
    .bind(&req.linked_finding_id)
    .bind(&req.linked_assessment_id)
    .bind(&user.org_id)
    .execute(&state.pool)
    .await?;
    if res.rows_affected() == 0 {
        return Err(AppError::NotFound("Imported finding not found".into()));
    }
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize)]
struct LinkRepoReq {
    finding_ids: Vec<String>,
    repository_id: String,
}

async fn link_findings_to_repository(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<LinkRepoReq>,
) -> AppResult<Json<JsonValue>> {
    let updated: Vec<(String,)> = sqlx::query_as(
        r#"UPDATE imported_findings
              SET repository_id = $1, updated_at = NOW()
            WHERE id = ANY($2)
              AND ($3::varchar IS NULL OR org_id = $3)
            RETURNING id"#,
    )
    .bind(&req.repository_id)
    .bind(&req.finding_ids)
    .bind(&user.org_id)
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(serde_json::json!({
        "linked": updated.len(),
        "ids": updated.iter().map(|(id,)| id.clone()).collect::<Vec<_>>(),
    })))
}

#[derive(Debug, Deserialize)]
struct CreateValidationReq {
    finding_ids: Vec<String>,
    target: String,
    #[serde(default)]
    name: Option<String>,
}

/// Spawn a `cycode_validation` assessment that re-tests imported findings
/// against a live target. Marks the imported rows as `validating` so the
/// UI can group + show progress. The actual scan runs locally on the
/// desktop driving the assessment record we create here.
async fn create_validation_assessment(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<CreateValidationReq>,
) -> AppResult<(StatusCode, Json<JsonValue>)> {
    if req.finding_ids.is_empty() {
        return Err(AppError::BadRequest("finding_ids cannot be empty".into()));
    }
    let assessment_id = Uuid::new_v4().to_string();
    let mut tx = state.pool.begin().await?;

    sqlx::query(
        r#"INSERT INTO assessments
              (id, name, type, status, targets, org_id, created_by)
           VALUES ($1, $2, $3::assessmenttype, 'pending'::assessmentstatus, $4, $5, $6)"#,
    )
    .bind(&assessment_id)
    .bind(req.name.as_deref().unwrap_or("Cycode validation"))
    .bind("cycode_validation")
    .bind(&[req.target.clone()])
    .bind(&user.org_id)
    .bind(&user.id)
    .execute(&mut *tx)
    .await?;

    sqlx::query(
        r#"UPDATE imported_findings
              SET status = 'validating'::importedfindingstatus,
                  linked_assessment_id = $1,
                  updated_at = NOW()
            WHERE id = ANY($2)
              AND ($3::varchar IS NULL OR org_id = $3)"#,
    )
    .bind(&assessment_id)
    .bind(&req.finding_ids)
    .bind(&user.org_id)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "id": assessment_id,
            "name": req.name,
            "type": "cycode_validation",
            "status": "pending",
            "targets": [req.target],
            "imported_finding_count": req.finding_ids.len(),
        })),
    ))
}
