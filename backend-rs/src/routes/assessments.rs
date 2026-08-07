//! `/assessments` CRUD + `/{id}/project` assignment.
//! Mirror of `backend/app/routers/assessments.py`.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{get, post, put},
    Json, Router,
};
use serde::Deserialize;
use serde_json::Value as JsonValue;
use uuid::Uuid;

use crate::audit;
use crate::auth::AuthUser;
use crate::error::{AppError, AppResult};
use crate::models::assessment::Assessment;
use crate::models::project::Project;
use crate::schemas::assessment::{
    AssessmentCreate, AssessmentResponse, AssessmentUpdate, AssignProjectRequest,
};
use crate::schemas::common::{pages_for, PaginatedResponse, PaginationQuery};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/assessments",
            get(list_assessments).post(create_assessment),
        )
        .route(
            "/assessments/:id",
            get(get_assessment)
                .patch(update_assessment)
                .delete(delete_assessment),
        )
        .route("/assessments/:id/project", put(assign_project))
        .route("/assessments/:id/heartbeat", post(heartbeat_assessment))
}

#[derive(Debug, Deserialize)]
struct ListFilters {
    #[serde(flatten)]
    page: PaginationQuery,
    #[serde(default)]
    status: Option<String>,
    #[serde(default, rename = "type")]
    type_: Option<String>,
    #[serde(default)]
    project_id: Option<String>,
    /// Default is to hide soft-archived rows so the Active list stays
    /// clean. Dashboard's Recent Assessments rail sets this to true so
    /// closed-out runs still appear in the historical record.
    #[serde(default)]
    include_archived: bool,
}

/// Close out assessments stuck in `running` so they stop showing as live.
/// Two cases get reaped:
///   1. No liveness heartbeat for over 3h. The in-flight agent pings
///      `POST /assessments/:id/heartbeat` (throttled, on tool activity) and the
///      0005 trigger bumps updated_at, so a genuinely-live run — however long —
///      stays fresh and is never reaped. Only a run that has gone fully silent
///      for 3h ages past the cutoff.
///   2. Already archived (soft-deleted) but still `running` — an archived run is
///      closed by definition, so a lingering `running` status is always stale.
///
/// Completion guard: a reaped run that is NOT archived and actually produced
/// findings is graded `completed` (it did the work but never called
/// `complete_assessment`), not `failed`. A run with no findings — or any
/// archived/deleted run — becomes `failed`. This stops a real run that emitted
/// findings from being mislabeled failed just because the final completion call
/// didn't land.
///
/// Scoped to the caller's org when present. Best-effort: logs and swallows
/// errors so a read path is never blocked by reconciliation.
async fn reconcile_stale_running(state: &AppState, org_id: Option<&str>) {
    let res = sqlx::query(
        r#"UPDATE assessments a
              -- "Did real work" = produced findings OR a bound report. A clean
              -- / recon-only run legitimately has zero findings but still
              -- writes a report, so a findings-only test buried such runs as
              -- not-completed.
              --
              -- A stale/archived run that produced nothing is `incomplete`, NOT
              -- `failed`: the agent simply stopped heartbeating before it
              -- called complete_assessment — that's an un-finished run, not an
              -- error. `failed` is reserved for runs that report a real error
              -- (explicit PATCH). See migration 0042.
              SET status = CASE
                      WHEN a.archived_at IS NULL
                           AND (
                               EXISTS (SELECT 1 FROM findings f WHERE f.assessment_id = a.id)
                               OR EXISTS (SELECT 1 FROM reports r WHERE r.assessment_id = a.id)
                           )
                        THEN 'completed'::assessmentstatus
                      ELSE 'incomplete'::assessmentstatus
                    END,
                  error_message = CASE
                      WHEN a.archived_at IS NULL
                           AND (
                               EXISTS (SELECT 1 FROM findings f WHERE f.assessment_id = a.id)
                               OR EXISTS (SELECT 1 FROM reports r WHERE r.assessment_id = a.id)
                           )
                        THEN NULL
                      ELSE COALESCE(
                          a.error_message,
                          'Auto-closed: ran but never completed (no heartbeat for over 3 hours, or archived while running)'
                      )
                    END,
                  completed_at = COALESCE(a.completed_at, NOW())
            WHERE a.status = 'running'::assessmentstatus
              AND (a.updated_at < NOW() - INTERVAL '3 hours' OR a.archived_at IS NOT NULL)
              AND ($1::text IS NULL OR a.org_id = $1)
              -- Exempt a deliberately-paused run (desktop sets a `pause_state`
              -- marker in config when the user pauses; pause syncs as a
              -- `running` row, not a `paused` status — the enum has no such
              -- variant). It would otherwise be auto-failed the moment the
              -- laptop sleeps past 3h. Still reap an *abandoned* pause after 7
              -- days, and never exempt an archived row (archive overrides pause).
              AND NOT (
                  a.archived_at IS NULL
                  AND COALESCE(a.config->>'pause_state', '') = 'paused'
                  AND a.updated_at > NOW() - INTERVAL '7 days'
              )"#,
    )
    .bind(org_id)
    .execute(&state.pool)
    .await;
    match res {
        Ok(r) if r.rows_affected() > 0 => {
            tracing::info!("reconciled {} stale running assessment(s)", r.rows_affected());
        }
        Ok(_) => {}
        Err(e) => tracing::warn!("reconcile_stale_running failed: {e}"),
    }
}

/// Lightweight liveness ping for an in-flight assessment. The in-container agent
/// calls this (throttled, on tool activity) so a long but live run keeps a fresh
/// `updated_at` and is never caught by [`reconcile_stale_running`]. It is a
/// deliberate no-op unless the row is a currently-live (running, non-archived)
/// run owned by the caller's org — it never resurrects a closed or deleted run.
async fn heartbeat_assessment(
    State(state): State<AppState>,
    Path(id): Path<String>,
    user: AuthUser,
) -> AppResult<StatusCode> {
    sqlx::query(
        r#"UPDATE assessments
              SET updated_at = NOW()
            WHERE id = $1
              AND status = 'running'::assessmentstatus
              AND archived_at IS NULL
              AND ($2::text IS NULL OR org_id = $2)"#,
    )
    .bind(&id)
    .bind(user.org_id.as_deref())
    .execute(&state.pool)
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn list_assessments(
    State(state): State<AppState>,
    Query(q): Query<ListFilters>,
    user: AuthUser,
) -> AppResult<Json<PaginatedResponse>> {
    // Reconcile dead runs before reading. Nothing marks a crashed/abandoned run
    // terminal, so it lingers as `running` forever — the "Active Assessments"
    // rail then shows weeks-old 0% runs as running. The 0005 trigger bumps
    // updated_at on every progress PATCH, so updated_at is a reliable liveness
    // heartbeat: a live run stays fresh, a dead one ages past the cutoff. Best
    // effort — a failure here must not block the list.
    reconcile_stale_running(&state, user.org_id.as_deref()).await;

    let mut sql = String::from("SELECT * FROM assessments WHERE 1=1");
    let mut count_sql = String::from("SELECT COUNT(*) FROM assessments WHERE 1=1");
    let mut args: Vec<String> = Vec::new();

    if let Some(org) = user.org_id.as_ref() {
        args.push(org.clone());
        sql.push_str(&format!(" AND org_id = ${}", args.len()));
        count_sql.push_str(&format!(" AND org_id = ${}", args.len()));
    }
    if let Some(s) = q.status.as_ref() {
        args.push(s.clone());
        sql.push_str(&format!(" AND status = ${}::assessmentstatus", args.len()));
        count_sql.push_str(&format!(" AND status = ${}::assessmentstatus", args.len()));
    }
    if let Some(t) = q.type_.as_ref() {
        args.push(t.clone());
        sql.push_str(&format!(" AND type = ${}::assessmenttype", args.len()));
        count_sql.push_str(&format!(" AND type = ${}::assessmenttype", args.len()));
    }
    if let Some(pid) = q.project_id.as_ref() {
        args.push(pid.clone());
        sql.push_str(&format!(" AND project_id = ${}", args.len()));
        count_sql.push_str(&format!(" AND project_id = ${}", args.len()));
    }
    if !q.include_archived {
        sql.push_str(" AND archived_at IS NULL");
        count_sql.push_str(" AND archived_at IS NULL");
    }
    sql.push_str(" ORDER BY started_at DESC OFFSET $");
    let offset_pos = args.len() + 1;
    sql.push_str(&offset_pos.to_string());
    sql.push_str(" LIMIT $");
    sql.push_str(&(offset_pos + 1).to_string());

    let page = q.page.page.max(1);
    let limit = q.page.limit.clamp(1, 100);
    let offset = (page - 1) * limit;

    let mut count_q = sqlx::query_scalar::<_, i64>(&count_sql);
    for a in &args {
        count_q = count_q.bind(a);
    }
    let total: i64 = count_q.fetch_one(&state.pool).await?;

    let mut list_q = sqlx::query_as::<_, Assessment>(&sql);
    for a in &args {
        list_q = list_q.bind(a);
    }
    list_q = list_q.bind(offset).bind(limit);
    let rows = list_q.fetch_all(&state.pool).await?;

    let data: Vec<JsonValue> = rows
        .iter()
        .map(|a| serde_json::to_value(AssessmentResponse::from(a)).unwrap())
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

async fn get_assessment(
    State(state): State<AppState>,
    Path(id): Path<String>,
    user: AuthUser,
) -> AppResult<Json<AssessmentResponse>> {
    let a = fetch_scoped(&state, &id, &user).await?;
    Ok(Json(AssessmentResponse::from(&a)))
}

/// Allowed values for the `assessmenttype` postgres enum. Keep in sync with
/// `migrations/0001_initial.sql` + `migrations/0008_assessment_type_expanded.sql`
/// and `models/sql_enums.rs::AssessmentTypeDb`. The wizard's
/// `frontend/lib/types.ts::AssessmentType` is the upstream source of truth.
///
/// We validate the incoming string against this list *before* the SQL bind
/// so an unknown value produces a precise 400 ("unknown assessment type:
/// foo. Allowed: ...") instead of an opaque 500 (sqlx::Error from a failed
/// `::assessmenttype` cast, which `AppError::Database` deliberately masks
/// behind a generic "Internal server error" detail).
const ALLOWED_ASSESSMENT_TYPES: &[&str] = &[
    "full",
    "recon",
    "vuln_scan",
    "web_app",
    "api_security",
    "cloud_assessment",
    "combined",
    "code_scan",
    "cycode_validation",
    "exploit_validation",
    "custom",
];

async fn create_assessment(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<AssessmentCreate>,
) -> AppResult<(StatusCode, Json<AssessmentResponse>)> {
    if !ALLOWED_ASSESSMENT_TYPES.contains(&req.assessment_type.as_str()) {
        return Err(AppError::BadRequest(format!(
            "unknown assessment type '{}'. Allowed values: {}",
            req.assessment_type,
            ALLOWED_ASSESSMENT_TYPES.join(", "),
        )));
    }

    let id = Uuid::new_v4().to_string();
    let targets = serde_json::to_value(&req.targets).unwrap();
    let repo_paths = serde_json::to_value(&req.repo_paths).unwrap();
    let phases = serde_json::to_value(&req.phases).unwrap();
    // Pydantic defaults `config: dict = {}` — never null.
    let config = if req.config.is_null() {
        JsonValue::Object(Default::default())
    } else {
        req.config.clone()
    };

    sqlx::query(
        r#"INSERT INTO assessments
              (id, type, name, targets, repo_paths, config, phases,
               project_id, org_id, created_by, client_id)
           VALUES ($1,$2::assessmenttype,$3,$4,$5,$6,$7,$8,$9,$10,$11)"#,
    )
    .bind(&id)
    .bind(&req.assessment_type)
    .bind(&req.name)
    .bind(&targets)
    .bind(&repo_paths)
    .bind(&config)
    .bind(&phases)
    .bind(&req.project_id)
    .bind(&user.org_id)
    .bind(&user.id)
    .bind(&req.client_id)
    .execute(&state.pool)
    .await?;

    let a: Assessment = sqlx::query_as("SELECT * FROM assessments WHERE id = $1")
        .bind(&id)
        .fetch_one(&state.pool)
        .await?;

    audit::record(
        &state.pool,
        &user,
        "assessment.create",
        "assessment",
        Some(&a.id),
        Some(serde_json::json!({
            "type": req.assessment_type,
            "name": req.name,
            "targets": req.targets,
        })),
    )
    .await;

    Ok((StatusCode::CREATED, Json(AssessmentResponse::from(&a))))
}

async fn update_assessment(
    State(state): State<AppState>,
    Path(id): Path<String>,
    user: AuthUser,
    Json(req): Json<AssessmentUpdate>,
) -> AppResult<Json<AssessmentResponse>> {
    let existing = fetch_scoped(&state, &id, &user).await?;

    // Build a sparse UPDATE — only fields the client actually sent.
    // For the `targets` column (JSONB), avoid COALESCE entirely: resolve
    // the new-or-existing value here in Rust, then bind one definitive
    // jsonb. Three earlier attempts (raw JsonValue, sqlx::types::Json
    // wrapper, text+::jsonb cast) all hit "COALESCE could not convert
    // type json to jsonb" because Postgres unifies COALESCE arg types at
    // PARSE time and the cast never applies in time. Bypassing COALESCE
    // sidesteps the whole issue.
    let targets_value: serde_json::Value = match req.targets.as_ref() {
        Some(v) => serde_json::to_value(v).unwrap(),
        None => existing
            .targets
            .clone()
            .unwrap_or_else(|| serde_json::Value::Array(vec![])),
    };

    let a: Assessment = sqlx::query_as(
        r#"UPDATE assessments
              SET type = COALESCE($2::assessmenttype, type),
                  name = COALESCE($3, name),
                  status = COALESCE($4::assessmentstatus, status),
                  targets = $5,
                  progress = COALESCE($6, progress),
                  current_step = COALESCE($7, current_step),
                  error_message = COALESCE($8, error_message),
                  findings_count = COALESCE($9, findings_count),
                  critical_count = COALESCE($10, critical_count),
                  high_count = COALESCE($11, high_count),
                  medium_count = COALESCE($12, medium_count),
                  low_count = COALESCE($13, low_count),
                  completed_at = COALESCE($14, completed_at),
                  project_id = COALESCE($15, project_id)
            WHERE id = $1
            RETURNING *"#,
    )
    .bind(&existing.id)
    .bind(&req.assessment_type)
    .bind(&req.name)
    .bind(&req.status)
    .bind(sqlx::types::Json(&targets_value))
    .bind(req.progress)
    .bind(&req.current_step)
    .bind(&req.error_message)
    .bind(req.findings_count)
    .bind(req.critical_count)
    .bind(req.high_count)
    .bind(req.medium_count)
    .bind(req.low_count)
    .bind(req.completed_at)
    .bind(&req.project_id)
    .fetch_one(&state.pool)
    .await?;

    audit::record(
        &state.pool,
        &user,
        "assessment.update",
        "assessment",
        Some(&a.id),
        Some(serde_json::json!({
            "status": req.status,
            "progress": req.progress,
            "name": req.name,
        })),
    )
    .await;

    Ok(Json(AssessmentResponse::from(&a)))
}

/// "Delete" an assessment. Implementation is a soft-archive (sets
/// `archived_at = NOW()`) rather than a row drop, so the user keeps
/// a tracking record of past engagements. The default list view
/// filters archived rows out; the dashboard's Recent Assessments rail
/// passes `include_archived=true` so closed runs stay visible there.
///
/// Archiving a *running* assessment also closes it out (status → failed):
/// the run is no longer live once deleted, so it must not keep showing a
/// `running` badge on the Recent rail. We deliberately do NOT bump
/// `updated_at` here — that field is the liveness heartbeat the stale-run
/// reaper keys on, and refreshing it on archive would mask a stale run.
///
/// If a hard delete is ever needed (compliance purge, etc.), add a
/// separate endpoint — don't repurpose this one.
async fn delete_assessment(
    State(state): State<AppState>,
    Path(id): Path<String>,
    user: AuthUser,
) -> AppResult<StatusCode> {
    let a = fetch_scoped(&state, &id, &user).await?;
    sqlx::query(
        r#"UPDATE assessments
              SET archived_at = NOW(),
                  -- Archiving a still-running run closes it as `incomplete`
                  -- (it never finished), not `failed` (no error occurred).
                  status = CASE WHEN status = 'running'::assessmentstatus
                                THEN 'incomplete'::assessmentstatus ELSE status END,
                  error_message = CASE WHEN status = 'running'::assessmentstatus
                                       THEN COALESCE(error_message, 'Archived while running')
                                       ELSE error_message END,
                  completed_at = CASE WHEN status = 'running'::assessmentstatus
                                      THEN COALESCE(completed_at, NOW()) ELSE completed_at END
            WHERE id = $1"#,
    )
    .bind(&a.id)
    .execute(&state.pool)
    .await?;

    audit::record(
        &state.pool,
        &user,
        "assessment.archive",
        "assessment",
        Some(&a.id),
        Some(serde_json::json!({ "name": a.name })),
    )
    .await;

    Ok(StatusCode::NO_CONTENT)
}

async fn assign_project(
    State(state): State<AppState>,
    Path(id): Path<String>,
    user: AuthUser,
    Json(req): Json<AssignProjectRequest>,
) -> AppResult<Json<AssessmentResponse>> {
    let a = fetch_scoped(&state, &id, &user).await?;

    if let Some(pid) = req.project_id.as_ref() {
        let mut q = String::from("SELECT * FROM projects WHERE id = $1");
        let mut binds: Vec<String> = vec![pid.clone()];
        if let Some(org) = user.org_id.as_ref() {
            q.push_str(" AND org_id = $2");
            binds.push(org.clone());
        }
        let mut qx = sqlx::query_as::<_, Project>(&q);
        for b in &binds {
            qx = qx.bind(b);
        }
        let proj: Option<Project> = qx.fetch_optional(&state.pool).await?;
        if proj.is_none() {
            return Err(AppError::NotFound("Project not found".into()));
        }
    }

    sqlx::query("UPDATE assessments SET project_id = $1 WHERE id = $2")
        .bind(&req.project_id)
        .bind(&a.id)
        .execute(&state.pool)
        .await?;

    let updated: Assessment = sqlx::query_as("SELECT * FROM assessments WHERE id = $1")
        .bind(&a.id)
        .fetch_one(&state.pool)
        .await?;
    Ok(Json(AssessmentResponse::from(&updated)))
}

async fn fetch_scoped(
    state: &AppState,
    id: &str,
    user: &AuthUser,
) -> AppResult<Assessment> {
    let mut sql = String::from("SELECT * FROM assessments WHERE id = $1");
    let mut binds: Vec<String> = vec![id.to_string()];
    if let Some(org) = user.org_id.as_ref() {
        sql.push_str(" AND org_id = $2");
        binds.push(org.clone());
    }
    let mut q = sqlx::query_as::<_, Assessment>(&sql);
    for b in &binds {
        q = q.bind(b);
    }
    let found: Option<Assessment> = q.fetch_optional(&state.pool).await?;
    found.ok_or_else(|| AppError::NotFound("Assessment not found".into()))
}

/// Normalize enum-like strings from the desktop's local SQLite.
///
/// The desktop historically stored enum values with hyphens
/// (`code-scan`, `cycode-validation`, etc.) while both Python SQLAlchemy
/// and our Rust schema use underscores (`code_scan`, `cycode_validation`).
/// The Python backend has the same latent mismatch — it would have 500'd
/// on these rows too — but cloud sync is new enough that no customer has
/// actually tripped it. We normalize on ingestion so existing local
/// assessments sync cleanly.
fn normalize_enum(value: &str) -> String {
    value.replace('-', "_")
}

// Sync needs to push incoming assessments via the same insert/update logic.
pub(crate) async fn upsert_from_sync(
    state: &AppState,
    user: &AuthUser,
    incoming: &crate::schemas::sync::SyncAssessmentIn,
) -> AppResult<Assessment> {
    let norm_type = normalize_enum(&incoming.assessment_type);
    let norm_status = incoming.status.as_deref().map(normalize_enum);
    let client_id = incoming.client_id.as_deref();
    let existing: Option<Assessment> = if let (Some(cid), Some(org)) = (client_id, user.org_id.as_ref()) {
        sqlx::query_as("SELECT * FROM assessments WHERE client_id = $1 AND org_id = $2")
            .bind(cid)
            .bind(org)
            .fetch_optional(&state.pool)
            .await?
    } else if let Some(cid) = client_id {
        sqlx::query_as("SELECT * FROM assessments WHERE client_id = $1")
            .bind(cid)
            .fetch_optional(&state.pool)
            .await?
    } else {
        None
    };

    let targets = serde_json::to_value(&incoming.targets).unwrap();
    let repo_paths = serde_json::to_value(&incoming.repo_paths).unwrap();
    let phases = serde_json::to_value(&incoming.phases).unwrap();
    let config = if incoming.config.is_null() {
        JsonValue::Object(Default::default())
    } else {
        incoming.config.clone()
    };

    if let Some(a) = existing {
        let row: Assessment = sqlx::query_as(
            r#"UPDATE assessments
                  SET type = $2::assessmenttype, name = COALESCE($3, name),
                      status = COALESCE($4::assessmentstatus, status),
                      targets = $5, repo_paths = $6, config = $7, phases = $8,
                      project_id = COALESCE($9, project_id),
                      progress = COALESCE($10, progress),
                      current_step = COALESCE($11, current_step),
                      error_message = COALESCE($12, error_message),
                      findings_count = COALESCE($13, findings_count),
                      critical_count = COALESCE($14, critical_count),
                      high_count = COALESCE($15, high_count),
                      medium_count = COALESCE($16, medium_count),
                      low_count = COALESCE($17, low_count),
                      completed_at = COALESCE($18, completed_at)
                WHERE id = $1
                RETURNING *"#,
        )
        .bind(&a.id)
        .bind(&norm_type)
        .bind(&incoming.name)
        .bind(&norm_status)
        .bind(&targets)
        .bind(&repo_paths)
        .bind(&config)
        .bind(&phases)
        .bind(&incoming.project_id)
        .bind(incoming.progress)
        .bind(&incoming.current_step)
        .bind(&incoming.error_message)
        .bind(incoming.findings_count)
        .bind(incoming.critical_count)
        .bind(incoming.high_count)
        .bind(incoming.medium_count)
        .bind(incoming.low_count)
        .bind(incoming.completed_at)
        .fetch_one(&state.pool)
        .await?;
        return Ok(row);
    }

    let id = Uuid::new_v4().to_string();
    sqlx::query(
        r#"INSERT INTO assessments
              (id, type, name, status, targets, repo_paths, config, phases,
               project_id, progress, current_step, error_message,
               findings_count, critical_count, high_count, medium_count, low_count,
               completed_at, org_id, created_by, client_id)
           VALUES ($1,$2::assessmenttype,$3,COALESCE($4::assessmentstatus,'pending'),$5,$6,$7,$8,$9,
                   COALESCE($10,0), $11, $12,
                   COALESCE($13,0), COALESCE($14,0), COALESCE($15,0), COALESCE($16,0), COALESCE($17,0),
                   $18, $19, $20, $21)"#,
    )
    .bind(&id)
    .bind(&norm_type)
    .bind(&incoming.name)
    .bind(&norm_status)
    .bind(&targets)
    .bind(&repo_paths)
    .bind(&config)
    .bind(&phases)
    .bind(&incoming.project_id)
    .bind(incoming.progress)
    .bind(&incoming.current_step)
    .bind(&incoming.error_message)
    .bind(incoming.findings_count)
    .bind(incoming.critical_count)
    .bind(incoming.high_count)
    .bind(incoming.medium_count)
    .bind(incoming.low_count)
    .bind(incoming.completed_at)
    .bind(&user.org_id)
    .bind(&user.id)
    .bind(client_id)
    .execute(&state.pool)
    .await?;
    let row: Assessment = sqlx::query_as("SELECT * FROM assessments WHERE id = $1")
        .bind(&id)
        .fetch_one(&state.pool)
        .await?;
    Ok(row)
}

