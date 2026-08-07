//! `/reports` CRUD + `/{id}/download`.
//! Mirror of `backend/app/routers/reports.py`.

use axum::{
    body::Body,
    extract::{Multipart, Path, Query, State},
    http::{header, StatusCode},
    response::Response,
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use serde_json::Value as JsonValue;
use uuid::Uuid;

use crate::auth::AuthUser;
use crate::error::{AppError, AppResult};
use crate::models::report::Report;
use crate::pdf;
use crate::schemas::common::{pages_for, PaginatedResponse, PaginationQuery};
use crate::schemas::report::{ReportCreate, ReportResponse};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/reports", get(list_reports).post(create_report))
        .route("/reports/:id", get(get_report).delete(delete_report))
        .route("/reports/:id/download", get(download_report))
        .route("/reports/:id/artifact-url", get(get_artifact_url))
        .route("/reports/:id/upload", post(upload_report_artifact))
        // 50 MB cap — well above any sane PDF size but stops accidental
        // huge uploads from filling the request memory.
        .layer(axum::extract::DefaultBodyLimit::max(50 * 1024 * 1024))
}

#[derive(Debug, Deserialize)]
struct ListFilters {
    #[serde(flatten)]
    page: PaginationQuery,
    #[serde(default)]
    assessment_id: Option<String>,
}

async fn list_reports(
    State(state): State<AppState>,
    Query(q): Query<ListFilters>,
    user: AuthUser,
) -> AppResult<Json<PaginatedResponse>> {
    let mut sql = String::from("SELECT * FROM reports WHERE 1=1");
    let mut count_sql = String::from("SELECT COUNT(*) FROM reports WHERE 1=1");
    let mut args: Vec<String> = Vec::new();

    if let Some(org) = user.org_id.as_ref() {
        args.push(org.clone());
        sql.push_str(&format!(" AND org_id = ${}", args.len()));
        count_sql.push_str(&format!(" AND org_id = ${}", args.len()));
    }
    if let Some(a) = q.assessment_id.as_ref() {
        args.push(a.clone());
        sql.push_str(&format!(" AND assessment_id = ${}", args.len()));
        count_sql.push_str(&format!(" AND assessment_id = ${}", args.len()));
    }
    sql.push_str(" ORDER BY created_at DESC OFFSET $");
    let offset_pos = args.len() + 1;
    sql.push_str(&offset_pos.to_string());
    sql.push_str(" LIMIT $");
    sql.push_str(&(offset_pos + 1).to_string());

    let page = q.page.page.max(1);
    let limit = q.page.limit.clamp(1, 100);
    let offset = (page - 1) * limit;

    let mut cq = sqlx::query_scalar::<_, i64>(&count_sql);
    for a in &args {
        cq = cq.bind(a);
    }
    let total: i64 = cq.fetch_one(&state.pool).await?;

    let mut lq = sqlx::query_as::<_, Report>(&sql);
    for a in &args {
        lq = lq.bind(a);
    }
    lq = lq.bind(offset).bind(limit);
    let rows = lq.fetch_all(&state.pool).await?;

    let data: Vec<JsonValue> = rows
        .iter()
        .map(|r| serde_json::to_value(ReportResponse::from(r)).unwrap())
        .collect();

    let pages = pages_for(total, limit);
    Ok(Json(PaginatedResponse {
        data,
        total,
        page,
        limit,
        pages,
        has_more: page < pages,
    }))
}

async fn get_report(
    State(state): State<AppState>,
    Path(id): Path<String>,
    user: AuthUser,
) -> AppResult<Json<ReportResponse>> {
    let r = fetch_scoped(&state, &id, &user).await?;
    Ok(Json(ReportResponse::from(&r)))
}

async fn create_report(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<ReportCreate>,
) -> AppResult<(StatusCode, Json<ReportResponse>)> {
    let id = Uuid::new_v4().to_string();
    // If the caller provides an assessment_id, verify it exists in the
    // user's org before insert. Otherwise the FK insert would 500 with
    // a Postgres FK violation — better to give a precise 404. A NULL
    // assessment_id is fine: the report stands on its own (migration
    // 0011 made the column nullable for exactly this case).
    if let Some(aid) = req.assessment_id.as_ref() {
        let exists: Option<String> = {
            let mut sql = String::from("SELECT id FROM assessments WHERE id = $1");
            let mut binds: Vec<String> = vec![aid.clone()];
            if let Some(org) = user.org_id.as_ref() {
                sql.push_str(" AND org_id = $2");
                binds.push(org.clone());
            }
            let mut q = sqlx::query_scalar::<_, String>(&sql);
            for b in &binds {
                q = q.bind(b);
            }
            q.fetch_optional(&state.pool).await?
        };
        if exists.is_none() {
            return Err(AppError::NotFound(format!(
                "assessment_id {aid} not found in this org — omit assessment_id to upload an orphan report"
            )));
        }
    }
    sqlx::query(
        r#"INSERT INTO reports
              (id, title, format, content, executive_summary,
               assessment_id, org_id, created_by, client_id,
               file_path, findings_count, critical_count, high_count,
               medium_count, low_count, exploitable_count)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,
                   COALESCE($11,0), COALESCE($12,0), COALESCE($13,0),
                   COALESCE($14,0), COALESCE($15,0), COALESCE($16,0))"#,
    )
    .bind(&id)
    .bind(&req.title)
    .bind(&req.format)
    .bind(&req.content)
    .bind(&req.executive_summary)
    .bind(&req.assessment_id)
    .bind(&user.org_id)
    .bind(&user.id)
    .bind(&req.client_id)
    .bind(&req.file_path)
    .bind(req.findings_count)
    .bind(req.critical_count)
    .bind(req.high_count)
    .bind(req.medium_count)
    .bind(req.low_count)
    .bind(req.exploitable_count)
    .execute(&state.pool)
    .await?;

    let r: Report = sqlx::query_as("SELECT * FROM reports WHERE id = $1")
        .bind(&id)
        .fetch_one(&state.pool)
        .await?;
    Ok((StatusCode::CREATED, Json(ReportResponse::from(&r))))
}

async fn delete_report(
    State(state): State<AppState>,
    Path(id): Path<String>,
    user: AuthUser,
) -> AppResult<StatusCode> {
    let _ = fetch_scoped(&state, &id, &user).await?;
    sqlx::query("DELETE FROM reports WHERE id = $1")
        .bind(&id)
        .execute(&state.pool)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize)]
struct DownloadQuery {
    #[serde(default = "default_download_format")]
    format: String,
}

fn default_download_format() -> String {
    "markdown".to_string()
}

async fn download_report(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(q): Query<DownloadQuery>,
    user: AuthUser,
) -> AppResult<Response> {
    let report = fetch_scoped(&state, &id, &user).await?;
    let title = report.title.clone();

    // PDF format with S3-backed bytes: return a JSON envelope with a
    // short-lived presigned URL. We can't 302 here because the auth
    // header on this endpoint (Bearer JWT) can't ride along with an
    // iframe src or a browser-initiated redirect — the frontend
    // fetches this authed and follows the URL itself. Bucket stays
    // private; only presigned URLs work.
    if q.format == "pdf" {
        if let Some(key) = report.s3_key.as_deref() {
            let bucket = state
                .settings
                .s3_bucket
                .as_deref()
                .ok_or_else(|| {
                    AppError::Internal(
                        "S3_BUCKET not configured — cannot serve S3-backed reports".into(),
                    )
                })?;
            let url = presign_get(&state, bucket, key, &title, "attachment").await?;
            return Ok(Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({ "url": url }).to_string(),
                ))
                .unwrap());
        }
    }

    // Legacy path: re-render from the markdown stored in the DB.
    // Used for markdown/html downloads and for old PDFs that never
    // had bytes uploaded.
    let content = report
        .content
        .as_ref()
        .ok_or_else(|| AppError::NotFound("Report has no content".into()))?;

    match q.format.as_str() {
        "markdown" => Ok(Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "text/markdown")
            .header(
                header::CONTENT_DISPOSITION,
                format!(r#"attachment; filename="{title}.md""#),
            )
            .body(Body::from(content.clone()))
            .unwrap()),
        "html" => {
            let html = pdf::render_html(&title, content);
            Ok(Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "text/html")
                .header(
                    header::CONTENT_DISPOSITION,
                    format!(r#"attachment; filename="{title}.html""#),
                )
                .body(Body::from(html))
                .unwrap())
        }
        "pdf" => {
            // No s3_key, no content — caught above. If we get here we
            // have markdown but no bytes; render on the fly.
            let bytes = pdf::render_pdf(title.clone(), content.clone()).await?;
            Ok(Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/pdf")
                .header(
                    header::CONTENT_DISPOSITION,
                    format!(r#"attachment; filename="{title}.pdf""#),
                )
                .body(Body::from(bytes))
                .unwrap())
        }
        _ => Err(AppError::BadRequest("Invalid format".into())),
    }
}

/// Accept a multipart upload of report artifact bytes, store them in
/// the per-customer S3 bucket, and stamp `s3_key` on the row.
///
/// Expected payload: a single multipart part named `file` (any
/// filename, any content-type — server forces application/pdf on
/// object metadata). Caller must be authenticated and the report must
/// be in the user's org.
///
/// The key format is `reports/{report_id}.pdf` — flat, predictable,
/// per-customer bucket already provides tenant isolation so we don't
/// need an org_id prefix inside the bucket.
async fn upload_report_artifact(
    State(state): State<AppState>,
    Path(id): Path<String>,
    user: AuthUser,
    mut multipart: Multipart,
) -> AppResult<Json<ReportResponse>> {
    let _ = fetch_scoped(&state, &id, &user).await?;

    let bucket = state
        .settings
        .s3_bucket
        .as_deref()
        .ok_or_else(|| {
            AppError::Internal(
                "S3_BUCKET not configured — cannot accept artifact uploads".into(),
            )
        })?;

    // Read the first file part. Multipart upload protocol gives one
    // request = one part for our use case.
    let field = multipart
        .next_field()
        .await
        .map_err(|e| AppError::BadRequest(format!("Multipart parse failed: {e}")))?
        .ok_or_else(|| AppError::BadRequest("No file part in upload".into()))?;

    let bytes = field
        .bytes()
        .await
        .map_err(|e| AppError::BadRequest(format!("Failed to read upload bytes: {e}")))?;

    if bytes.is_empty() {
        return Err(AppError::BadRequest("Upload body is empty".into()));
    }

    let key = format!("reports/{id}.pdf");
    let client = state.s3_client().await;
    client
        .put_object()
        .bucket(bucket)
        .key(&key)
        .body(bytes.to_vec().into())
        .content_type("application/pdf")
        .send()
        .await
        .map_err(|e| AppError::Internal(format!("S3 put_object failed: {e}")))?;

    // Mark the row so future downloads know to serve from S3.
    sqlx::query("UPDATE reports SET s3_key = $1, updated_at = NOW() WHERE id = $2")
        .bind(&key)
        .bind(&id)
        .execute(&state.pool)
        .await?;

    let row: Report = sqlx::query_as("SELECT * FROM reports WHERE id = $1")
        .bind(&id)
        .fetch_one(&state.pool)
        .await?;
    Ok(Json(ReportResponse::from(&row)))
}

/// JSON endpoint that returns just the presigned URL for the
/// frontend's iframe preview. Uses `inline` content-disposition so
/// the webview renders the PDF instead of triggering a download
/// dialog. `/download` uses `attachment` for the same key — the
/// presigned URL controls which behavior S3 advertises.
async fn get_artifact_url(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(q): Query<ArtifactUrlQuery>,
    user: AuthUser,
) -> AppResult<Response> {
    let report = fetch_scoped(&state, &id, &user).await?;
    let key = report
        .s3_key
        .as_deref()
        .ok_or_else(|| AppError::NotFound("Report has no artifact in cloud storage".into()))?;
    let bucket = state
        .settings
        .s3_bucket
        .as_deref()
        .ok_or_else(|| {
            AppError::Internal(
                "S3_BUCKET not configured — cannot serve S3-backed reports".into(),
            )
        })?;
    let disposition = if q.disposition == "attachment" {
        "attachment"
    } else {
        "inline"
    };
    let url = presign_get(&state, bucket, key, &report.title, disposition).await?;
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::json!({ "url": url }).to_string(),
        ))
        .unwrap())
}

#[derive(Debug, Deserialize)]
struct ArtifactUrlQuery {
    #[serde(default = "default_disposition")]
    disposition: String,
}

fn default_disposition() -> String {
    "inline".to_string()
}

/// Generate a short-lived presigned GET URL for a report object.
/// 15-minute TTL matches the desktop's Cognito refresh cadence — a
/// user re-opening the report inside a session always gets a fresh
/// URL via a backend round-trip rather than caching the URL itself.
///
/// `disposition` is either "inline" (for iframe preview — webview
/// renders the PDF) or "attachment" (for explicit download — webview
/// saves the file with the friendly name).
async fn presign_get(
    state: &AppState,
    bucket: &str,
    key: &str,
    title: &str,
    disposition: &str,
) -> AppResult<String> {
    use aws_sdk_s3::presigning::PresigningConfig;
    use std::time::Duration;

    let cfg = PresigningConfig::expires_in(Duration::from_secs(15 * 60))
        .map_err(|e| AppError::Internal(format!("Presign config failed: {e}")))?;

    // S3 only accepts ISO-8859-1 in `response-content-disposition`, so
    // titles with em-dashes / unicode quotes etc. cause `InvalidArgument`
    // on presign GET ("Header value cannot be represented using
    // ISO-8859-1"). Build the header with an ASCII fallback (`filename=`)
    // for legacy clients plus an RFC 5987 UTF-8 variant (`filename*=`)
    // for everything modern.
    let ascii_filename = ascii_fold_filename(title);
    let utf8_filename = percent_encode_filename(&format!("{title}.pdf"));
    let disposition_header = format!(
        r#"{disposition}; filename="{ascii_filename}.pdf"; filename*=UTF-8''{utf8_filename}"#,
    );

    let presigned = state
        .s3_client()
        .await
        .get_object()
        .bucket(bucket)
        .key(key)
        .response_content_disposition(disposition_header)
        .response_content_type("application/pdf")
        .presigned(cfg)
        .await
        .map_err(|e| AppError::Internal(format!("Presign failed: {e}")))?;

    Ok(presigned.uri().to_string())
}

/// Strip a title down to ASCII-safe characters for the legacy
/// `filename=` parameter. Em-dashes, smart quotes, etc. collapse to
/// hyphens / drop entirely so the resulting string is fully
/// ISO-8859-1 representable.
fn ascii_fold_filename(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '\u{2010}'..='\u{2015}' => '-', // hyphens, en/em dashes, horizontal bar
            '\u{2018}' | '\u{2019}' => '\'',
            '\u{201C}' | '\u{201D}' => '"',
            '\u{00A0}' => ' ',              // nbsp
            c if c.is_ascii() => c,
            _ => '_',
        })
        .collect()
}

/// Percent-encode for the `filename*=UTF-8''` parameter (RFC 5987).
/// We URL-encode everything that's not in the unreserved-ish set so
/// the value is safe inside the header even when the title contains
/// spaces or punctuation.
fn percent_encode_filename(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for byte in s.bytes() {
        match byte {
            // Conservative allowlist — alnum + a handful of safe punct
            // that doesn't need escaping in HTTP header context.
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'.' | b'-' | b'_' | b'~' => {
                out.push(byte as char);
            }
            _ => {
                out.push_str(&format!("%{:02X}", byte));
            }
        }
    }
    out
}

async fn fetch_scoped(state: &AppState, id: &str, user: &AuthUser) -> AppResult<Report> {
    let mut sql = String::from("SELECT * FROM reports WHERE id = $1");
    let mut binds: Vec<String> = vec![id.to_string()];
    if let Some(org) = user.org_id.as_ref() {
        sql.push_str(" AND org_id = $2");
        binds.push(org.clone());
    }
    let mut q = sqlx::query_as::<_, Report>(&sql);
    for b in &binds {
        q = q.bind(b);
    }
    let row: Option<Report> = q.fetch_optional(&state.pool).await?;
    row.ok_or_else(|| AppError::NotFound("Report not found".into()))
}

pub(crate) async fn upsert_from_sync(
    state: &AppState,
    user: &AuthUser,
    incoming: &crate::schemas::sync::SyncReportIn,
) -> AppResult<Report> {
    let client_id = incoming.client_id.as_deref();
    let existing: Option<Report> = match (client_id, user.org_id.as_ref()) {
        (Some(cid), Some(org)) => {
            sqlx::query_as("SELECT * FROM reports WHERE client_id = $1 AND org_id = $2")
                .bind(cid)
                .bind(org)
                .fetch_optional(&state.pool)
                .await?
        }
        (Some(cid), None) => sqlx::query_as("SELECT * FROM reports WHERE client_id = $1")
            .bind(cid)
            .fetch_optional(&state.pool)
            .await?,
        _ => None,
    };

    // Resolve assessment id (server-side id or client_id map).
    let resolved_assessment_id: Option<String> = {
        let mut sql = String::from(
            "SELECT id FROM assessments WHERE (id = $1 OR client_id = $1)",
        );
        let mut binds: Vec<String> = vec![incoming.assessment_id.clone()];
        if let Some(org) = user.org_id.as_ref() {
            sql.push_str(" AND org_id = $2");
            binds.push(org.clone());
        }
        let mut q = sqlx::query_scalar::<_, String>(&sql);
        for b in &binds {
            q = q.bind(b);
        }
        q.fetch_optional(&state.pool).await?
    };
    let assessment_id =
        resolved_assessment_id.unwrap_or_else(|| incoming.assessment_id.clone());

    if let Some(r) = existing {
        let row: Report = sqlx::query_as(
            r#"UPDATE reports
                  SET title = $2,
                      format = $3,
                      content = COALESCE($4, content),
                      executive_summary = COALESCE($5, executive_summary),
                      assessment_id = $6,
                      updated_at = NOW()
                WHERE id = $1
                RETURNING *"#,
        )
        .bind(&r.id)
        .bind(&incoming.title)
        .bind(&incoming.format)
        .bind(&incoming.content)
        .bind(&incoming.executive_summary)
        .bind(&assessment_id)
        .fetch_one(&state.pool)
        .await?;
        return Ok(row);
    }

    let id = Uuid::new_v4().to_string();
    sqlx::query(
        r#"INSERT INTO reports
              (id, title, format, content, executive_summary,
               assessment_id, org_id, created_by, client_id)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)"#,
    )
    .bind(&id)
    .bind(&incoming.title)
    .bind(&incoming.format)
    .bind(&incoming.content)
    .bind(&incoming.executive_summary)
    .bind(&assessment_id)
    .bind(&user.org_id)
    .bind(&user.id)
    .bind(client_id)
    .execute(&state.pool)
    .await?;
    let row: Report = sqlx::query_as("SELECT * FROM reports WHERE id = $1")
        .bind(&id)
        .fetch_one(&state.pool)
        .await?;
    Ok(row)
}
