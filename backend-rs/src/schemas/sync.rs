//! Request/response schemas for `POST /sync`.
//! These are the fields the desktop sends when pushing local changes up and
//! pulling server changes down. On the response side we reuse the `*Response`
//! shapes from the individual resource modules because that is what the
//! Python backend emits.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

#[derive(Debug, Deserialize)]
pub struct SyncRequest {
    #[serde(default)]
    pub assessments: Vec<SyncAssessmentIn>,
    #[serde(default)]
    pub findings: Vec<SyncFindingIn>,
    #[serde(default)]
    pub reports: Vec<SyncReportIn>,
    #[serde(default)]
    pub last_sync_at: Option<DateTime<Utc>>,
}

/// Incoming assessment row from the desktop. Shape matches `AssessmentCreate`
/// in the Python backend (sync uses the same Pydantic class).
#[derive(Debug, Deserialize)]
pub struct SyncAssessmentIn {
    #[serde(rename = "type")]
    pub assessment_type: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub targets: Vec<String>,
    #[serde(default)]
    pub repo_paths: Vec<String>,
    #[serde(default)]
    pub config: JsonValue,
    #[serde(default)]
    pub phases: Vec<String>,
    #[serde(default)]
    pub project_id: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub progress: Option<i32>,
    #[serde(default)]
    pub current_step: Option<String>,
    #[serde(default)]
    pub error_message: Option<String>,
    #[serde(default)]
    pub findings_count: Option<i32>,
    #[serde(default)]
    pub critical_count: Option<i32>,
    #[serde(default)]
    pub high_count: Option<i32>,
    #[serde(default)]
    pub medium_count: Option<i32>,
    #[serde(default)]
    pub low_count: Option<i32>,
    #[serde(default)]
    pub completed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize)]
pub struct SyncFindingIn {
    pub title: String,
    #[serde(default)]
    pub description: Option<String>,
    pub severity: String,
    pub target: String,
    #[serde(default)]
    pub target_type: Option<String>,
    #[serde(default)]
    pub evidence: Option<String>,
    #[serde(default)]
    pub remediation: Option<String>,
    #[serde(default)]
    pub references: Option<String>,
    #[serde(default)]
    pub cve: Option<String>,
    #[serde(default)]
    pub cwe: Option<String>,
    #[serde(default)]
    pub cvss_score: Option<String>,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub source_id: Option<String>,
    #[serde(default)]
    pub assessment_id: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct SyncReportIn {
    pub title: String,
    #[serde(default = "default_format")]
    pub format: String,
    #[serde(default)]
    pub content: Option<String>,
    #[serde(default)]
    pub executive_summary: Option<String>,
    pub assessment_id: String,
    #[serde(default)]
    pub client_id: Option<String>,
}

fn default_format() -> String {
    "markdown".to_string()
}

#[derive(Debug, Serialize)]
pub struct SyncResponse<A, F, R> {
    pub assessments: Vec<A>,
    pub findings: Vec<F>,
    pub reports: Vec<R>,
    pub sync_at: DateTime<Utc>,
}
