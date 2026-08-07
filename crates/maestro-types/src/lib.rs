//! Wire types shared between the Maestro desktop shell (Tauri) and the Rust
//! backend (`backend-rs`). These mirror the JSON shapes that the Python
//! FastAPI backend emits in `backend/app/models/schemas.py`, so either
//! backend implementation can be driven by the same desktop binary.
//!
//! Only types that cross the HTTP boundary belong here. Internal DB row
//! structs and server-side helpers stay in their respective crates.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ---------- Auth ----------

#[derive(Debug, Deserialize, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthProvidersResponse {
    pub providers: Vec<ProviderInfo>,
    pub default: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProviderInfo {
    #[serde(rename = "type")]
    pub provider_type: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_pool_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub login_url: Option<String>,
}

// ---------- Sync ----------

#[derive(Debug, Serialize, Deserialize)]
pub struct SyncRequest {
    pub assessments: Vec<AssessmentSync>,
    pub findings: Vec<FindingSync>,
    pub reports: Vec<ReportSync>,
    pub last_sync_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SyncResponse {
    pub assessments: Vec<AssessmentSync>,
    pub findings: Vec<FindingSync>,
    pub reports: Vec<ReportSync>,
    pub sync_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssessmentSync {
    pub id: Option<String>,
    pub client_id: String,
    #[serde(rename = "type")]
    pub assessment_type: String,
    pub status: String,
    pub targets: Vec<String>,
    pub repo_paths: Vec<String>,
    pub progress: i32,
    pub current_step: Option<String>,
    pub error_message: Option<String>,
    pub config: serde_json::Value,
    pub phases: Vec<String>,
    pub findings_count: i32,
    pub critical_count: i32,
    pub high_count: i32,
    pub medium_count: i32,
    pub low_count: i32,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingSync {
    pub id: Option<String>,
    pub client_id: String,
    pub title: String,
    pub description: Option<String>,
    pub severity: String,
    pub status: String,
    pub target: String,
    pub target_type: Option<String>,
    pub evidence: Option<String>,
    pub remediation: Option<String>,
    pub references: Option<String>,
    pub cve: Option<String>,
    pub cwe: Option<String>,
    pub cvss_score: Option<String>,
    pub jira_ticket: Option<String>,
    pub jira_url: Option<String>,
    pub source: Option<String>,
    pub source_id: Option<String>,
    pub assessment_id: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportSync {
    pub id: Option<String>,
    pub client_id: String,
    pub title: String,
    pub format: String,
    pub content: Option<String>,
    pub executive_summary: Option<String>,
    pub findings_count: i32,
    pub critical_count: i32,
    pub high_count: i32,
    pub exploitable_count: i32,
    pub assessment_id: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// ---------- Version ----------

#[derive(Debug, Serialize, Deserialize)]
pub struct VersionResponse {
    pub version: String,
    #[serde(rename = "minDesktopVersion")]
    pub min_desktop_version: String,
    pub name: String,
}
