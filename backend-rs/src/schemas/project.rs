//! Request/response schemas for `/projects`.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::models::project::Project;
use crate::models::sql_enums::WireName;

#[derive(Debug, Deserialize)]
pub struct ProjectCreate {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    /// Opaque scope JSON — see the shared scope contract. Defaults to `{}`
    /// in the INSERT when omitted.
    #[serde(default)]
    pub scope: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
pub struct ProjectUpdate {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    /// Opaque scope JSON. When omitted the existing scope is left unchanged
    /// (`COALESCE($n, scope)` in the UPDATE).
    #[serde(default)]
    pub scope: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
pub struct ProjectResponse {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub status: String,
    pub created_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
    pub org_id: Option<String>,
    pub created_by: Option<String>,
    pub assessment_count: i64,
    /// Opaque scope JSON. NULL columns are normalized to `{}` here so the
    /// frontend always receives an object.
    pub scope: serde_json::Value,
}

impl ProjectResponse {
    pub fn from_row(p: &Project, assessment_count: i64) -> Self {
        ProjectResponse {
            id: p.id.clone(),
            name: p.name.clone(),
            description: p.description.clone(),
            status: p
                .status
                .as_ref()
                .map(|s| s.wire_name().to_string())
                .unwrap_or_else(|| "active".to_string()),
            created_at: p.created_at,
            updated_at: p.updated_at,
            org_id: p.org_id.clone(),
            created_by: p.created_by.clone(),
            assessment_count,
            scope: p
                .scope
                .clone()
                .unwrap_or_else(|| serde_json::json!({})),
        }
    }
}
