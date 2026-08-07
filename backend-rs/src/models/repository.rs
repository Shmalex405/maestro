//! `repositories` table row — org-shared code repo metadata.
//!
//! See `0002_repositories_and_configs.sql`. The `default_path` field is the
//! creator's clone path on their machine, kept as a hint for teammates;
//! each user's actual path is per-machine and resolved client-side.

use chrono::{DateTime, Utc};
use serde_json::Value as JsonValue;
use sqlx::FromRow;

use crate::models::sql_enums::RepoSourceTypeDb;

#[derive(Debug, Clone, FromRow)]
pub struct Repository {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub default_path: Option<String>,
    pub source_type: Option<RepoSourceTypeDb>,
    pub github_owner: Option<String>,
    pub github_repo: Option<String>,
    pub github_url: Option<String>,
    pub languages: Option<JsonValue>,
    pub default_scan_config: Option<JsonValue>,
    pub last_scan_at: Option<DateTime<Utc>>,
    pub last_scan_findings: Option<JsonValue>,
    pub org_id: Option<String>,
    pub created_by: Option<String>,
    pub created_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
}
