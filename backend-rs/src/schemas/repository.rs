//! Request/response schemas for `/repositories`.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use crate::models::repository::Repository;
use crate::models::sql_enums::WireName;

#[derive(Debug, Deserialize)]
pub struct RepositoryCreate {
    pub name: String,
    /// The creating user's local clone path. Stored as a hint for teammates;
    /// each user has their own per-machine override (handled client-side).
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub source_type: Option<String>,
    #[serde(default)]
    pub github_owner: Option<String>,
    #[serde(default)]
    pub github_repo: Option<String>,
    #[serde(default)]
    pub github_url: Option<String>,
    #[serde(default)]
    pub languages: Option<JsonValue>,
    #[serde(default)]
    pub default_scan_config: Option<JsonValue>,
}

#[derive(Debug, Deserialize)]
pub struct RepositoryUpdate {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub source_type: Option<String>,
    #[serde(default)]
    pub github_owner: Option<String>,
    #[serde(default)]
    pub github_repo: Option<String>,
    #[serde(default)]
    pub github_url: Option<String>,
    #[serde(default)]
    pub languages: Option<JsonValue>,
    #[serde(default)]
    pub default_scan_config: Option<JsonValue>,
    #[serde(default)]
    pub last_scan_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub last_scan_findings: Option<JsonValue>,
}

#[derive(Debug, Serialize)]
pub struct RepositoryResponse {
    pub id: String,
    pub name: String,
    /// The creator's clone path — clients should treat as a hint and apply
    /// their own per-machine override before using.
    pub path: Option<String>,
    pub description: Option<String>,
    pub source_type: String,
    pub github_owner: Option<String>,
    pub github_repo: Option<String>,
    pub github_url: Option<String>,
    pub languages: JsonValue,
    pub default_scan_config: JsonValue,
    pub last_scan_at: Option<DateTime<Utc>>,
    pub last_scan_findings: Option<JsonValue>,
    pub org_id: Option<String>,
    pub created_by: Option<String>,
    pub created_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
}

impl RepositoryResponse {
    pub fn from_row(r: &Repository) -> Self {
        RepositoryResponse {
            id: r.id.clone(),
            name: r.name.clone(),
            path: r.default_path.clone(),
            description: r.description.clone(),
            source_type: r
                .source_type
                .as_ref()
                .map(|s| s.wire_name().to_string())
                .unwrap_or_else(|| "local".to_string()),
            github_owner: r.github_owner.clone(),
            github_repo: r.github_repo.clone(),
            github_url: r.github_url.clone(),
            languages: r.languages.clone().unwrap_or_else(|| JsonValue::Array(vec![])),
            default_scan_config: r
                .default_scan_config
                .clone()
                .unwrap_or_else(|| JsonValue::Object(serde_json::Map::new())),
            last_scan_at: r.last_scan_at,
            last_scan_findings: r.last_scan_findings.clone(),
            org_id: r.org_id.clone(),
            created_by: r.created_by.clone(),
            created_at: r.created_at,
            updated_at: r.updated_at,
        }
    }
}
