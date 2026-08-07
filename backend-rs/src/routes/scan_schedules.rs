//! `/scan-schedules` — continuous-DAST cadence (consolidation-roadmap Phase 4).
//!
//! Endpoints:
//!   POST   /scan-schedules         — upsert a schedule by (target, scan_type)
//!   GET    /scan-schedules         — list this org's schedules
//!   DELETE /scan-schedules/:id     — remove a schedule
//!
//! The cadence data model the Scheduled DAST page edits. The firing component
//! (runs runDeterministic when next_run_at passes) is separate. Per-org scoped.

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
use crate::models::scan::SCAN_TYPES;
use crate::models::scan_schedule::{ScanScheduleRow, SCAN_CADENCES};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/scan-schedules", post(upsert_schedule).get(list_schedules))
        .route("/scan-schedules/due", axum::routing::get(due_schedules))
        .route("/scan-schedules/:id", axum::routing::delete(delete_schedule))
        .route("/scan-schedules/:id/fired", post(mark_fired))
}

/// Cadence → interval. Drives next_run_at computation (the scheduler reads it).
fn cadence_interval(cadence: &str) -> chrono::Duration {
    match cadence {
        "hourly" => chrono::Duration::hours(1),
        "daily" => chrono::Duration::days(1),
        "weekly" => chrono::Duration::days(7),
        "monthly" => chrono::Duration::days(30),
        _ => chrono::Duration::days(1),
    }
}

/// Shared column list for ScanScheduleRow SELECT/RETURNING (explicit — no *).
const SCHED_COLS: &str = "id, org_id, target_id, application_id, auth_mode, cadence, scan_type, enabled, \
     last_run_at, next_run_at, created_by, created_at, updated_at, \
     policy_id, window_start, window_end, timezone";

#[derive(Debug, Deserialize)]
struct UpsertBody {
    /// Exactly one of target_id / application_id (XOR). target_id = solo target;
    /// application_id = fan out to all the app's current targets at run time.
    #[serde(default)]
    target_id: Option<String>,
    #[serde(default)]
    application_id: Option<String>,
    /// 'authed' (default) applies the target's configured auth; 'unauthed' scans anonymously.
    #[serde(default = "default_auth_mode")]
    auth_mode: String,
    cadence: String,
    #[serde(default = "default_scan_type")]
    scan_type: String,
    #[serde(default = "default_enabled")]
    enabled: bool,
    #[serde(default)]
    next_run_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Scan policy to pin (migration 0039). '' clears.
    #[serde(default)]
    policy_id: Option<String>,
    /// Blackout window as "HH:MM" strings + IANA timezone (migration 0039).
    #[serde(default)]
    window_start: Option<String>,
    #[serde(default)]
    window_end: Option<String>,
    #[serde(default)]
    timezone: Option<String>,
}

fn default_scan_type() -> String {
    "deterministic".to_string()
}
fn default_auth_mode() -> String {
    "authed".to_string()
}
fn default_enabled() -> bool {
    true
}

#[derive(Debug, Serialize)]
struct ScheduleView {
    id: String,
    target_id: Option<String>,
    application_id: Option<String>,
    auth_mode: String,
    cadence: String,
    scan_type: String,
    enabled: bool,
    last_run_at: Option<chrono::DateTime<chrono::Utc>>,
    next_run_at: Option<chrono::DateTime<chrono::Utc>>,
    policy_id: Option<String>,
    window_start: Option<chrono::NaiveTime>,
    window_end: Option<chrono::NaiveTime>,
    timezone: Option<String>,
}

impl From<&ScanScheduleRow> for ScheduleView {
    fn from(s: &ScanScheduleRow) -> Self {
        Self {
            id: s.id.clone(),
            target_id: s.target_id.clone(),
            application_id: s.application_id.clone(),
            auth_mode: s.auth_mode.clone(),
            cadence: s.cadence.clone(),
            scan_type: s.scan_type.clone(),
            enabled: s.enabled,
            last_run_at: s.last_run_at,
            next_run_at: s.next_run_at,
            policy_id: s.policy_id.clone(),
            window_start: s.window_start,
            window_end: s.window_end,
            timezone: s.timezone.clone(),
        }
    }
}

async fn upsert_schedule(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<UpsertBody>,
) -> AppResult<(StatusCode, Json<ScheduleView>)> {
    let org_id = user
        .org_id
        .clone()
        .ok_or_else(|| AppError::Forbidden("Missing org_id on caller".to_string()))?;

    if !SCAN_CADENCES.contains(&req.cadence.as_str()) {
        return Err(AppError::BadRequest(format!(
            "Invalid cadence '{}'. Must be one of: {}",
            req.cadence,
            SCAN_CADENCES.join(", ")
        )));
    }
    if !SCAN_TYPES.contains(&req.scan_type.as_str()) {
        return Err(AppError::BadRequest(format!(
            "Invalid scan_type '{}'. Must be one of: {}",
            req.scan_type,
            SCAN_TYPES.join(", ")
        )));
    }

    // Exactly one of target_id / application_id (matches the XOR CHECK).
    let target_id = req.target_id.as_deref().filter(|s| !s.is_empty()).map(str::to_string);
    let application_id = req
        .application_id
        .as_deref()
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    if target_id.is_some() == application_id.is_some() {
        return Err(AppError::BadRequest(
            "Provide exactly one of target_id or application_id".into(),
        ));
    }
    if req.auth_mode != "authed" && req.auth_mode != "unauthed" {
        return Err(AppError::BadRequest(
            "auth_mode must be 'authed' or 'unauthed'".into(),
        ));
    }

    // Compute next_run_at from the cadence when the caller didn't pin one, so
    // the UI shows a real next-run time and the scheduler has something to poll.
    let next_run_at = req
        .next_run_at
        .unwrap_or_else(|| chrono::Utc::now() + cadence_interval(&req.cadence));

    // '' on policy_id clears it; NULL/absent → unchanged on conflict, NULL on insert.
    let policy_id = match req.policy_id.as_deref() {
        Some("") => None,
        other => other.map(|s| s.to_string()),
    };
    let id = Uuid::new_v4().to_string();
    let row: ScanScheduleRow = sqlx::query_as(&format!(
        r#"INSERT INTO scan_schedules (
              id, org_id, target_id, application_id, auth_mode, cadence, scan_type, enabled,
              next_run_at, created_by, policy_id, window_start, window_end, timezone,
              created_at, updated_at
           )
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::time,$13::time,$14,NOW(),NOW())
           ON CONFLICT (org_id, COALESCE(application_id, target_id), scan_type, auth_mode)
           DO UPDATE SET
               cadence      = EXCLUDED.cadence,
               enabled      = EXCLUDED.enabled,
               next_run_at  = EXCLUDED.next_run_at,
               -- Preserve policy/window when the caller omitted them (e.g. a
               -- cadence-only edit) so they aren't wiped. COALESCE → set when sent.
               policy_id    = COALESCE(EXCLUDED.policy_id, scan_schedules.policy_id),
               window_start = COALESCE(EXCLUDED.window_start, scan_schedules.window_start),
               window_end   = COALESCE(EXCLUDED.window_end, scan_schedules.window_end),
               timezone     = COALESCE(EXCLUDED.timezone, scan_schedules.timezone),
               updated_at   = NOW()
           RETURNING {SCHED_COLS}"#
    ))
    .bind(&id)
    .bind(&org_id)
    .bind(&target_id)
    .bind(&application_id)
    .bind(&req.auth_mode)
    .bind(&req.cadence)
    .bind(&req.scan_type)
    .bind(req.enabled)
    .bind(next_run_at)
    .bind(&user.id)
    .bind(&policy_id)
    .bind(&req.window_start)
    .bind(&req.window_end)
    .bind(&req.timezone)
    .fetch_one(&state.pool)
    .await?;

    Ok((StatusCode::OK, Json(ScheduleView::from(&row))))
}

async fn list_schedules(
    State(state): State<AppState>,
    user: AuthUser,
) -> AppResult<Json<Vec<ScheduleView>>> {
    let org_id = user
        .org_id
        .clone()
        .ok_or_else(|| AppError::Forbidden("Missing org_id on caller".to_string()))?;

    let rows: Vec<ScanScheduleRow> = sqlx::query_as(&format!(
        r#"SELECT {SCHED_COLS} FROM scan_schedules
           WHERE org_id = $1 ORDER BY updated_at DESC"#
    ))
    .bind(&org_id)
    .fetch_all(&state.pool)
    .await?;

    Ok(Json(rows.iter().map(ScheduleView::from).collect()))
}

async fn delete_schedule(
    State(state): State<AppState>,
    Path(id): Path<String>,
    user: AuthUser,
) -> AppResult<StatusCode> {
    let org_id = user
        .org_id
        .clone()
        .ok_or_else(|| AppError::Forbidden("Missing org_id on caller".to_string()))?;

    let rows = sqlx::query("DELETE FROM scan_schedules WHERE id = $1 AND org_id = $2")
        .bind(&id)
        .bind(&org_id)
        .execute(&state.pool)
        .await?
        .rows_affected();

    if rows == 0 {
        return Err(AppError::NotFound("Scan schedule not found".into()));
    }
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// Scheduler interface (consumed by the hosted Kali runner — see
// docs/dast-scheduler-infra-spec.md). The runner polls /due, executes the
// deterministic scan for each, then POSTs /:id/fired to advance the schedule.
// ---------------------------------------------------------------------------

/// Schedules that are due to run: enabled + next_run_at has passed. Org-scoped
/// (the runner iterates orgs with a service token, or the UI shows "due now").
async fn due_schedules(
    State(state): State<AppState>,
    user: AuthUser,
) -> AppResult<Json<Vec<ScheduleView>>> {
    let org_id = user
        .org_id
        .clone()
        .ok_or_else(|| AppError::Forbidden("Missing org_id on caller".to_string()))?;

    // Blackout windows (migration 0039): a schedule is only "due" if the current
    // local time (in its timezone, default UTC) is inside [window_start,window_end].
    // Handles windows that span midnight (start > end). The external runner honors
    // the same rule; this keeps the UI's "due now" view consistent.
    let rows: Vec<ScanScheduleRow> = sqlx::query_as(&format!(
        r#"SELECT {SCHED_COLS} FROM scan_schedules
           WHERE org_id = $1 AND enabled = TRUE
             AND next_run_at IS NOT NULL AND next_run_at <= NOW()
             AND (
               window_start IS NULL OR window_end IS NULL
               OR (
                 window_start <= window_end
                 AND (NOW() AT TIME ZONE COALESCE(timezone, 'UTC'))::time BETWEEN window_start AND window_end
               )
               OR (
                 window_start > window_end
                 AND ((NOW() AT TIME ZONE COALESCE(timezone, 'UTC'))::time >= window_start
                      OR (NOW() AT TIME ZONE COALESCE(timezone, 'UTC'))::time <= window_end)
               )
             )
           ORDER BY next_run_at"#
    ))
    .bind(&org_id)
    .fetch_all(&state.pool)
    .await?;

    Ok(Json(rows.iter().map(ScheduleView::from).collect()))
}

/// Mark a schedule fired: stamp last_run_at = NOW() and advance next_run_at by
/// the cadence. Called by the runner after it dispatches/executes the scan, so
/// the schedule doesn't re-fire.
async fn mark_fired(
    State(state): State<AppState>,
    Path(id): Path<String>,
    user: AuthUser,
) -> AppResult<(StatusCode, Json<ScheduleView>)> {
    let org_id = user
        .org_id
        .clone()
        .ok_or_else(|| AppError::Forbidden("Missing org_id on caller".to_string()))?;

    // Read the cadence to compute the next run.
    let existing: Option<ScanScheduleRow> = sqlx::query_as(&format!(
        r#"SELECT {SCHED_COLS} FROM scan_schedules WHERE id = $1 AND org_id = $2"#
    ))
    .bind(&id)
    .bind(&org_id)
    .fetch_optional(&state.pool)
    .await?;

    let Some(sched) = existing else {
        return Err(AppError::NotFound("Scan schedule not found".into()));
    };
    let next = chrono::Utc::now() + cadence_interval(&sched.cadence);

    let row: ScanScheduleRow = sqlx::query_as(&format!(
        r#"UPDATE scan_schedules
           SET last_run_at = NOW(), next_run_at = $3, updated_at = NOW()
           WHERE id = $1 AND org_id = $2
           RETURNING {SCHED_COLS}"#
    ))
    .bind(&id)
    .bind(&org_id)
    .bind(next)
    .fetch_one(&state.pool)
    .await?;

    Ok((StatusCode::OK, Json(ScheduleView::from(&row))))
}
