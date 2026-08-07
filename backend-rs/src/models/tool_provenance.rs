//! `tool_executions` row (migration 0029) — per-assessment, per-tool provenance.
//! Proves which security tool ran for each test, whether its binary was present,
//! and the recorded exit-code rollup. Read by the desktop "Tools" view.

use chrono::{DateTime, Utc};
use sqlx::FromRow;

#[derive(Debug, Clone, FromRow)]
pub struct ToolExecutionRow {
    pub id: String,
    pub org_id: String,
    pub assessment_id: String,
    pub tool_name: String,
    pub binary: Option<String>,
    pub installed: Option<bool>,
    pub version: Option<String>,
    pub run_count: i32,
    pub ok_count: i32,
    pub fail_count: i32,
    pub last_exit_code: Option<i32>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
