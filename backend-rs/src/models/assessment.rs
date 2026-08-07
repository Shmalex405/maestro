//! `assessments` table row. Mirrors
//! `backend/app/models/assessment.py:Assessment`.

use chrono::{DateTime, Utc};
use serde_json::Value as JsonValue;
use sqlx::FromRow;

use crate::models::sql_enums::{AssessmentStatusDb, AssessmentTypeDb};

#[derive(Debug, Clone, FromRow)]
pub struct Assessment {
    pub id: String,
    pub name: Option<String>,
    pub r#type: AssessmentTypeDb,
    pub status: Option<AssessmentStatusDb>,
    pub project_id: Option<String>,
    pub targets: Option<JsonValue>,
    /// JSONB array of resolved target_id strings (FK → targets.id).
    /// Added in migration 0018 for cross-assessment caching. Mirrors
    /// `targets` 1:1 once the Rust-app backfill repair runs at startup.
    pub target_ids: JsonValue,
    pub repo_paths: Option<JsonValue>,
    pub progress: Option<i32>,
    pub current_step: Option<String>,
    pub error_message: Option<String>,
    pub config: Option<JsonValue>,
    pub phases: Option<JsonValue>,
    pub findings_count: Option<i32>,
    pub critical_count: Option<i32>,
    pub high_count: Option<i32>,
    pub medium_count: Option<i32>,
    pub low_count: Option<i32>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub org_id: Option<String>,
    pub created_by: Option<String>,
    pub client_id: Option<String>,
    /// Soft-delete marker — when set, the assessment is hidden from
    /// the default list view but kept around so users keep a record
    /// of past engagements. See migration 0015.
    pub archived_at: Option<DateTime<Utc>>,
}
