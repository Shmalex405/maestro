//! `scans` row — continuous-DAST run history (migration 0025).
//!
//! One row per deterministic/scheduled scan run, per (org, target). Anchors the
//! "new vs fixed since last scan" trend computation (the deltas come from the
//! findings dedup substrate; this table supplies the run timestamps + counts).

use chrono::{DateTime, Utc};
use serde_json::Value as JsonValue;
use sqlx::FromRow;

/// Valid `scan_type` values (mirrors the CHECK constraint in 0025).
pub const SCAN_TYPES: &[&str] = &["dast", "sast", "full", "deterministic"];
/// Valid `trigger_kind` values.
pub const SCAN_TRIGGERS: &[&str] = &["manual", "scheduled", "ci"];

#[derive(Debug, Clone, FromRow)]
pub struct ScanRow {
    pub id: String,
    pub org_id: String,
    pub target_id: String,
    pub assessment_id: Option<String>,
    pub scan_type: String,
    pub trigger_kind: String,
    pub status: String,
    pub scanner_set: JsonValue,
    pub critical_count: i32,
    pub high_count: i32,
    pub medium_count: i32,
    pub low_count: i32,
    pub info_count: i32,
    pub total_count: i32,
    pub started_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    /// Live progress telemetry (migration 0037).
    pub progress_pct: i32,
    pub phase: Option<String>,
    pub current_activity: Option<String>,
    pub tests_total: i32,
    pub tests_done: i32,
    /// Runtime attack volume (migration 0045): real HTTP requests fired, whether
    /// any contributing count was estimated, and the per-tool breakdown.
    pub attacks_executed: i32,
    pub attacks_estimated: bool,
    pub attacks_by_tool: JsonValue,
}
