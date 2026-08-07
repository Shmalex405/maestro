//! `assessment_test_results` row (migration 0031) — per-assessment, per-test verdict.
//! Records every test's PASS/FAIL/N_A/BLOCKED status plus the deterministic
//! provenance gate's enforced flag + reason. Read by the desktop "Assessment
//! Execution Overview".

use chrono::{DateTime, Utc};
use sqlx::FromRow;

#[derive(Debug, Clone, FromRow)]
pub struct TestResultRow {
    pub id: String,
    pub org_id: String,
    pub assessment_id: String,
    pub agent: Option<String>,
    pub test_id: String,
    pub status: String,
    pub enforced: bool,
    pub enforced_reason: Option<String>,
    pub finding_count: i32,
    pub notes: Option<String>,
    pub created_at: DateTime<Utc>,
}
