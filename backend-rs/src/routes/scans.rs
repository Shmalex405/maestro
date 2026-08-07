//! `/scans` — continuous-DAST run history (consolidation-roadmap Phase 0).
//!
//! Endpoints:
//!   POST /scans                      — record a scan run (per target)
//!   GET  /scans?target_id=X&limit=N  — recent scan history for a target
//!   GET  /scans/diff?target_id=X     — new vs still-present vs fixed since the
//!                                      previous scan (added in the trend step)
//!
//! A "scan" here is a cheap DETERMINISTIC pipeline run (runDeterministic — no
//! inner LLM, ~$0 Anthropic) recorded so the dashboard can show trends. All
//! per-org scoped via JWT `custom:org_id`.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use uuid::Uuid;

use crate::auth::AuthUser;
use crate::error::{AppError, AppResult};
use crate::models::scan::{ScanRow, SCAN_TRIGGERS, SCAN_TYPES};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/scans", post(record_scan).get(list_scans))
        .route("/scans/diff", get(scan_diff))
        .route("/scans/trigger", post(trigger_scan))
        .route("/scans/:id/findings", get(scan_findings))
        .route("/scans/:id", axum::routing::patch(update_scan))
}

// ── CI scan-now trigger (WS5) ───────────────────────────────────────────────
// Makes a target's deterministic schedule due NOW so the external runner fires
// it on its next poll (reuses the existing due/fired mechanism). Creates the
// schedule if absent. Callable with a `dast_*` API key.

#[derive(Debug, Deserialize)]
struct TriggerBody {
    target_id: String,
    #[serde(default)]
    policy_id: Option<String>,
    /// 'authed' (default) | 'unauthed'. Lets CI run-now choose the auth mode.
    #[serde(default = "default_trigger_auth_mode")]
    auth_mode: String,
}

fn default_trigger_auth_mode() -> String {
    "authed".to_string()
}

async fn trigger_scan(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<TriggerBody>,
) -> AppResult<(StatusCode, Json<JsonValue>)> {
    let org_id = user
        .org_id
        .clone()
        .ok_or_else(|| AppError::Forbidden("Missing org_id on caller".to_string()))?;

    let id = Uuid::new_v4().to_string();
    sqlx::query(
        r#"INSERT INTO scan_schedules
              (id, org_id, target_id, auth_mode, cadence, scan_type, enabled, next_run_at,
               policy_id, created_by, created_at, updated_at)
           VALUES ($1,$2,$3,$4,'daily','deterministic',TRUE,NOW(),$5,$6,NOW(),NOW())
           ON CONFLICT (org_id, COALESCE(application_id, target_id), scan_type, auth_mode) DO UPDATE SET
               enabled     = TRUE,
               next_run_at = NOW(),
               policy_id   = COALESCE(EXCLUDED.policy_id, scan_schedules.policy_id),
               updated_at  = NOW()"#,
    )
    .bind(&id)
    .bind(&org_id)
    .bind(&req.target_id)
    .bind(&req.auth_mode)
    .bind(&req.policy_id)
    .bind(&user.id)
    .execute(&state.pool)
    .await?;

    Ok((
        StatusCode::ACCEPTED,
        Json(serde_json::json!({
            "status": "queued",
            "message": "Scan made due now — the runner will execute it on its next poll.",
            "target_id": req.target_id,
        })),
    ))
}

fn empty_array() -> JsonValue {
    JsonValue::Array(vec![])
}

#[derive(Debug, Deserialize)]
struct RecordBody {
    target_id: String,
    #[serde(default)]
    assessment_id: Option<String>,
    scan_type: String,
    #[serde(default = "default_trigger")]
    trigger_kind: String,
    #[serde(default = "default_status")]
    status: String,
    #[serde(default = "empty_array")]
    scanner_set: JsonValue,
    #[serde(default)]
    critical_count: i32,
    #[serde(default)]
    high_count: i32,
    #[serde(default)]
    medium_count: i32,
    #[serde(default)]
    low_count: i32,
    #[serde(default)]
    info_count: i32,
    #[serde(default)]
    total_count: i32,
    started_at: chrono::DateTime<chrono::Utc>,
    #[serde(default)]
    finished_at: Option<chrono::DateTime<chrono::Utc>>,
}

fn default_trigger() -> String {
    "manual".to_string()
}
fn default_status() -> String {
    "completed".to_string()
}

#[derive(Debug, Serialize)]
struct ScanView {
    id: String,
    target_id: String,
    assessment_id: Option<String>,
    scan_type: String,
    trigger_kind: String,
    status: String,
    scanner_set: JsonValue,
    critical_count: i32,
    high_count: i32,
    medium_count: i32,
    low_count: i32,
    info_count: i32,
    total_count: i32,
    started_at: chrono::DateTime<chrono::Utc>,
    finished_at: Option<chrono::DateTime<chrono::Utc>>,
    // Live progress (migration 0037).
    progress_pct: i32,
    phase: Option<String>,
    current_activity: Option<String>,
    tests_total: i32,
    tests_done: i32,
    // Runtime attack volume (migration 0045).
    attacks_executed: i32,
    attacks_estimated: bool,
    attacks_by_tool: JsonValue,
}

impl From<&ScanRow> for ScanView {
    fn from(s: &ScanRow) -> Self {
        Self {
            id: s.id.clone(),
            target_id: s.target_id.clone(),
            assessment_id: s.assessment_id.clone(),
            scan_type: s.scan_type.clone(),
            trigger_kind: s.trigger_kind.clone(),
            status: s.status.clone(),
            scanner_set: s.scanner_set.clone(),
            critical_count: s.critical_count,
            high_count: s.high_count,
            medium_count: s.medium_count,
            low_count: s.low_count,
            info_count: s.info_count,
            total_count: s.total_count,
            started_at: s.started_at,
            finished_at: s.finished_at,
            progress_pct: s.progress_pct,
            phase: s.phase.clone(),
            current_activity: s.current_activity.clone(),
            tests_total: s.tests_total,
            tests_done: s.tests_done,
            attacks_executed: s.attacks_executed,
            attacks_estimated: s.attacks_estimated,
            attacks_by_tool: s.attacks_by_tool.clone(),
        }
    }
}

/// Shared column list for ScanRow `SELECT`/`RETURNING` (explicit — no SELECT *).
const SCAN_COLS: &str = "id, org_id, target_id, assessment_id, scan_type, trigger_kind, status, \
     scanner_set, critical_count, high_count, medium_count, low_count, \
     info_count, total_count, started_at, finished_at, created_at, \
     progress_pct, phase, current_activity, tests_total, tests_done, \
     attacks_executed, attacks_estimated, attacks_by_tool";

async fn record_scan(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<RecordBody>,
) -> AppResult<(StatusCode, Json<ScanView>)> {
    let org_id = user
        .org_id
        .clone()
        .ok_or_else(|| AppError::Forbidden("Missing org_id on caller".to_string()))?;

    if !SCAN_TYPES.contains(&req.scan_type.as_str()) {
        return Err(AppError::BadRequest(format!(
            "Invalid scan_type '{}'. Must be one of: {}",
            req.scan_type,
            SCAN_TYPES.join(", ")
        )));
    }
    if !SCAN_TRIGGERS.contains(&req.trigger_kind.as_str()) {
        return Err(AppError::BadRequest(format!(
            "Invalid trigger_kind '{}'. Must be one of: {}",
            req.trigger_kind,
            SCAN_TRIGGERS.join(", ")
        )));
    }

    let id = Uuid::new_v4().to_string();
    let row: ScanRow = sqlx::query_as(&format!(
        r#"INSERT INTO scans (
              id, org_id, target_id, assessment_id, scan_type, trigger_kind, status,
              scanner_set, critical_count, high_count, medium_count, low_count,
              info_count, total_count, started_at, finished_at, created_at
           )
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,NOW())
           RETURNING {SCAN_COLS}"#
    ))
    .bind(&id)
    .bind(&org_id)
    .bind(&req.target_id)
    .bind(&req.assessment_id)
    .bind(&req.scan_type)
    .bind(&req.trigger_kind)
    .bind(&req.status)
    .bind(&req.scanner_set)
    .bind(req.critical_count)
    .bind(req.high_count)
    .bind(req.medium_count)
    .bind(req.low_count)
    .bind(req.info_count)
    .bind(req.total_count)
    .bind(req.started_at)
    .bind(req.finished_at)
    .fetch_one(&state.pool)
    .await?;

    Ok((StatusCode::CREATED, Json(ScanView::from(&row))))
}

// ── Live progress update (Phase 3) ─────────────────────────────────────────
// The deterministic pipeline creates the scan row at START (status 'running')
// then PATCHes throttled progress heartbeats + a final completion. All fields
// optional (COALESCE) so a heartbeat can send just progress/phase.

#[derive(Debug, Deserialize)]
struct UpdateScanBody {
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    progress_pct: Option<i32>,
    #[serde(default)]
    phase: Option<String>,
    #[serde(default)]
    current_activity: Option<String>,
    #[serde(default)]
    tests_total: Option<i32>,
    #[serde(default)]
    tests_done: Option<i32>,
    #[serde(default)]
    critical_count: Option<i32>,
    #[serde(default)]
    high_count: Option<i32>,
    #[serde(default)]
    medium_count: Option<i32>,
    #[serde(default)]
    low_count: Option<i32>,
    #[serde(default)]
    info_count: Option<i32>,
    #[serde(default)]
    total_count: Option<i32>,
    /// Runtime attack volume (migration 0045) — sent on completion.
    #[serde(default)]
    attacks_executed: Option<i32>,
    #[serde(default)]
    attacks_estimated: Option<bool>,
    #[serde(default)]
    attacks_by_tool: Option<JsonValue>,
    /// Set the finish timestamp to NOW() (used on completion).
    #[serde(default)]
    finished: Option<bool>,
}

async fn update_scan(
    State(state): State<AppState>,
    Path(id): Path<String>,
    user: AuthUser,
    Json(req): Json<UpdateScanBody>,
) -> AppResult<Json<ScanView>> {
    let org_id = user
        .org_id
        .clone()
        .ok_or_else(|| AppError::Forbidden("Missing org_id on caller".to_string()))?;

    let row: Option<ScanRow> = sqlx::query_as(&format!(
        r#"UPDATE scans SET
               status           = COALESCE($3, status),
               progress_pct     = COALESCE($4, progress_pct),
               phase            = COALESCE($5, phase),
               current_activity = COALESCE($6, current_activity),
               tests_total      = COALESCE($7, tests_total),
               tests_done       = COALESCE($8, tests_done),
               critical_count   = COALESCE($9, critical_count),
               high_count       = COALESCE($10, high_count),
               medium_count     = COALESCE($11, medium_count),
               low_count        = COALESCE($12, low_count),
               info_count       = COALESCE($13, info_count),
               total_count      = COALESCE($14, total_count),
               attacks_executed  = COALESCE($16, attacks_executed),
               attacks_estimated = COALESCE($17, attacks_estimated),
               attacks_by_tool   = COALESCE($18, attacks_by_tool),
               finished_at      = CASE WHEN $15 THEN NOW() ELSE finished_at END
           WHERE id = $1 AND org_id = $2
           RETURNING {SCAN_COLS}"#
    ))
    .bind(&id)
    .bind(&org_id)
    .bind(&req.status)
    .bind(req.progress_pct)
    .bind(&req.phase)
    .bind(&req.current_activity)
    .bind(req.tests_total)
    .bind(req.tests_done)
    .bind(req.critical_count)
    .bind(req.high_count)
    .bind(req.medium_count)
    .bind(req.low_count)
    .bind(req.info_count)
    .bind(req.total_count)
    .bind(req.finished.unwrap_or(false))
    .bind(req.attacks_executed)
    .bind(req.attacks_estimated)
    .bind(&req.attacks_by_tool)
    .fetch_optional(&state.pool)
    .await?;

    row.map(|r| Json(ScanView::from(&r)))
        .ok_or_else(|| AppError::NotFound("Scan not found".into()))
}

#[derive(Debug, Deserialize)]
struct ListQuery {
    /// Omit for an org-wide scan history (the Scans view); set for one target.
    #[serde(default)]
    target_id: Option<String>,
    #[serde(default = "default_limit")]
    limit: i64,
}

fn default_limit() -> i64 {
    50
}

async fn list_scans(
    State(state): State<AppState>,
    Query(q): Query<ListQuery>,
    user: AuthUser,
) -> AppResult<Json<Vec<ScanView>>> {
    let org_id = user
        .org_id
        .clone()
        .ok_or_else(|| AppError::Forbidden("Missing org_id on caller".to_string()))?;

    let limit = q.limit.clamp(1, 500);
    // `($2::text IS NULL OR target_id = $2)` → org-wide when target_id omitted.
    let rows: Vec<ScanRow> = sqlx::query_as(&format!(
        r#"SELECT {SCAN_COLS}
           FROM scans
           WHERE org_id = $1 AND ($2::text IS NULL OR target_id = $2)
           ORDER BY started_at DESC
           LIMIT $3"#
    ))
    .bind(&org_id)
    .bind(&q.target_id)
    .bind(limit)
    .fetch_all(&state.pool)
    .await?;

    Ok(Json(rows.iter().map(ScanView::from).collect()))
}

// -----------------------------------------------------------------------------
// new vs still-present vs fixed since the latest scan.
//
// Computed from the findings dedup substrate (0007): a finding seen during the
// latest scan has its `last_seen_at` bumped to >= that scan's `started_at` (the
// create_finding upsert does this on re-confirmation). So, relative to the
// latest scan's start:
//   new      = first_seen_at >= start            (first observed this scan)
//   fixed    = open + last_seen_at < start        (was open, not re-confirmed)
//   present  = first_seen_at < start AND last_seen_at >= start
// Requires findings to carry target_id (set via target resolution).
// -----------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct DiffQuery {
    target_id: String,
}

#[derive(Debug, sqlx::FromRow)]
struct FindingSummary {
    id: String,
    title: String,
    severity: String,
    cve: Option<String>,
}

#[derive(Debug, Serialize)]
struct FindingSummaryView {
    id: String,
    title: String,
    severity: String,
    cve: Option<String>,
}

impl From<&FindingSummary> for FindingSummaryView {
    fn from(f: &FindingSummary) -> Self {
        Self {
            id: f.id.clone(),
            title: f.title.clone(),
            severity: f.severity.clone(),
            cve: f.cve.clone(),
        }
    }
}

#[derive(Debug, Serialize)]
struct DiffResponse {
    latest_scan_id: Option<String>,
    since: Option<chrono::DateTime<chrono::Utc>>,
    new: Vec<FindingSummaryView>,
    fixed: Vec<FindingSummaryView>,
    still_present_count: i64,
}

async fn scan_diff(
    State(state): State<AppState>,
    Query(q): Query<DiffQuery>,
    user: AuthUser,
) -> AppResult<Json<DiffResponse>> {
    let org_id = user
        .org_id
        .clone()
        .ok_or_else(|| AppError::Forbidden("Missing org_id on caller".to_string()))?;

    // The latest scan's start is the threshold for "this scan".
    let latest: Option<(String, chrono::DateTime<chrono::Utc>)> = sqlx::query_as(
        r#"SELECT id, started_at FROM scans
           WHERE org_id = $1 AND target_id = $2
           ORDER BY started_at DESC
           LIMIT 1"#,
    )
    .bind(&org_id)
    .bind(&q.target_id)
    .fetch_optional(&state.pool)
    .await?;

    let Some((latest_id, since)) = latest else {
        // No scans recorded yet for this target — empty diff (not an error).
        return Ok(Json(DiffResponse {
            latest_scan_id: None,
            since: None,
            new: vec![],
            fixed: vec![],
            still_present_count: 0,
        }));
    };

    let new: Vec<FindingSummary> = sqlx::query_as(
        r#"SELECT id, title, severity::text AS severity, cve
           FROM findings
           WHERE org_id = $1 AND target_id = $2 AND first_seen_at >= $3
           ORDER BY severity"#,
    )
    .bind(&org_id)
    .bind(&q.target_id)
    .bind(since)
    .fetch_all(&state.pool)
    .await?;

    let fixed: Vec<FindingSummary> = sqlx::query_as(
        r#"SELECT id, title, severity::text AS severity, cve
           FROM findings
           WHERE org_id = $1 AND target_id = $2
             AND status = 'open' AND last_seen_at < $3
           ORDER BY severity"#,
    )
    .bind(&org_id)
    .bind(&q.target_id)
    .bind(since)
    .fetch_all(&state.pool)
    .await?;

    let still_present_count: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*) FROM findings
           WHERE org_id = $1 AND target_id = $2
             AND first_seen_at < $3 AND last_seen_at >= $3"#,
    )
    .bind(&org_id)
    .bind(&q.target_id)
    .bind(since)
    .fetch_one(&state.pool)
    .await?;

    Ok(Json(DiffResponse {
        latest_scan_id: Some(latest_id),
        since: Some(since),
        new: new.iter().map(FindingSummaryView::from).collect(),
        fixed: fixed.iter().map(FindingSummaryView::from).collect(),
        still_present_count,
    }))
}

// ---------------------------------------------------------------------------
// Per-scan findings (DAST page — "view a run"). Findings aren't linked to a
// scan_id, so we approximate by the scan's target + time window: a finding
// re-confirmed during the scan has last_seen_at in [started_at, finished_at].
// Returns full detail (description + evidence) for the run drill-down.
// ---------------------------------------------------------------------------

#[derive(Debug, sqlx::FromRow)]
struct ScanFinding {
    id: String,
    title: String,
    severity: String,
    cve: Option<String>,
    status: String,
    description: String,
    evidence: Option<String>,
    target: String,
}

#[derive(Debug, Serialize)]
struct ScanFindingView {
    id: String,
    title: String,
    severity: String,
    cve: Option<String>,
    status: String,
    description: String,
    evidence: Option<String>,
    target: String,
}

impl From<&ScanFinding> for ScanFindingView {
    fn from(f: &ScanFinding) -> Self {
        Self {
            id: f.id.clone(),
            title: f.title.clone(),
            severity: f.severity.clone(),
            cve: f.cve.clone(),
            status: f.status.clone(),
            description: f.description.clone(),
            evidence: f.evidence.clone(),
            target: f.target.clone(),
        }
    }
}

async fn scan_findings(
    State(state): State<AppState>,
    Path(id): Path<String>,
    user: AuthUser,
) -> AppResult<Json<Vec<ScanFindingView>>> {
    let org_id = user
        .org_id
        .clone()
        .ok_or_else(|| AppError::Forbidden("Missing org_id on caller".to_string()))?;

    let scan: Option<ScanRow> = sqlx::query_as(&format!(
        r#"SELECT {SCAN_COLS} FROM scans WHERE id = $1 AND org_id = $2"#
    ))
    .bind(&id)
    .bind(&org_id)
    .fetch_optional(&state.pool)
    .await?;

    let Some(scan) = scan else {
        return Err(AppError::NotFound("Scan not found".into()));
    };

    // Preferred path (migration 0035): exact attribution via scan_id. The
    // deterministic pipeline now stamps each persisted finding with the scan
    // that produced it, so this is precise — no cross-contamination from LLM
    // findings or prior scans of the same target.
    let order = r#"ORDER BY
             CASE severity
               WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2
               WHEN 'low' THEN 3 ELSE 4 END"#;

    let mut rows: Vec<ScanFinding> = sqlx::query_as(&format!(
        r#"SELECT id, title, severity::text AS severity, cve, status::text AS status,
                  description, evidence, target
           FROM findings
           WHERE org_id = $1 AND scan_id = $2
           {order}"#
    ))
    .bind(&org_id)
    .bind(&scan.id)
    .fetch_all(&state.pool)
    .await?;

    // Backward-compat: pre-0035 scans have no stamped findings. Fall back to
    // the legacy time-window correlation (lossy but best-effort) so historical
    // scans still render their drill-down.
    if rows.is_empty() {
        rows = sqlx::query_as(&format!(
            r#"SELECT id, title, severity::text AS severity, cve, status::text AS status,
                      description, evidence, target
               FROM findings
               WHERE org_id = $1 AND target_id = $2
                 AND last_seen_at >= $3
                 AND last_seen_at <= COALESCE($4, NOW())
               {order}"#
        ))
        .bind(&org_id)
        .bind(&scan.target_id)
        .bind(scan.started_at)
        .bind(scan.finished_at)
        .fetch_all(&state.pool)
        .await?;
    }

    Ok(Json(rows.iter().map(ScanFindingView::from).collect()))
}
