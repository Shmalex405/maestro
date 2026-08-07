//! `scan_schedules` row — continuous-DAST cadence (migration 0026).
//!
//! The cadence data model the Scheduled DAST page reads/writes. The firing
//! mechanism (a cron that runs runDeterministic when `next_run_at` passes) is a
//! separate component whose home is TBD.

use chrono::{DateTime, NaiveTime, Utc};
use sqlx::FromRow;

/// Valid `cadence` values (mirrors the CHECK constraint in 0026).
pub const SCAN_CADENCES: &[&str] = &["hourly", "daily", "weekly", "monthly"];

#[derive(Debug, Clone, FromRow)]
pub struct ScanScheduleRow {
    pub id: String,
    pub org_id: String,
    /// The scanned target — NULL when the schedule is application-scoped
    /// (application_id set, fan out to all the app's targets at run time).
    pub target_id: Option<String>,
    /// Application this schedule fans out across (migration 0044). Mutually
    /// exclusive with target_id (XOR CHECK).
    pub application_id: Option<String>,
    /// 'authed' (apply the target's scan-config auth) | 'unauthed' (anonymous).
    pub auth_mode: String,
    pub cadence: String,
    pub scan_type: String,
    pub enabled: bool,
    pub last_run_at: Option<DateTime<Utc>>,
    pub next_run_at: Option<DateTime<Utc>>,
    pub created_by: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    /// Scan policy pinned to this schedule (migration 0039). NULL = full assessment.
    pub policy_id: Option<String>,
    /// Blackout window (migration 0039): only run between these local times in
    /// `timezone`. NULL window_start = no restriction.
    pub window_start: Option<NaiveTime>,
    pub window_end: Option<NaiveTime>,
    pub timezone: Option<String>,
}
