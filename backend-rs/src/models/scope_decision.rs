//! `assessment_scope_decisions` row (migration 0032) — per-assessment scope verdict.
//! Records every target a tool resolved to during the run and whether it was in
//! scope (and why not, when out). Read by the desktop "Assessment Execution
//! Overview".

use chrono::{DateTime, Utc};
use sqlx::FromRow;

#[derive(Debug, Clone, FromRow)]
pub struct ScopeDecisionRow {
    pub id: String,
    pub org_id: String,
    pub assessment_id: String,
    pub target: String,
    pub dimension: Option<String>,
    pub in_scope: bool,
    pub reason: Option<String>,
    pub attempts: i32,
    pub last_seen: DateTime<Utc>,
}
