//! `projects` table row. Mirrors `backend/app/models/project.py:Project`.

use chrono::{DateTime, Utc};
use sqlx::FromRow;

use crate::models::sql_enums::ProjectStatusDb;

#[derive(Debug, Clone, FromRow)]
pub struct Project {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub status: Option<ProjectStatusDb>,
    pub created_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
    pub org_id: Option<String>,
    pub created_by: Option<String>,
    /// Opaque scope JSON owned by the frontend (networks/domains/repos/
    /// cloud_account_ids/identity_target_ids/exclusions). NULL on legacy rows
    /// is normalized to `{}` in `ProjectResponse::from_row`.
    pub scope: Option<serde_json::Value>,
}
