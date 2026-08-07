//! Request/response schemas for `/assessments` and the sync payload.
//! Mirror of the `Assessment*` Pydantic classes in
//! `backend/app/models/schemas.py`.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use crate::models::assessment::Assessment;
use crate::models::sql_enums::WireName;

#[derive(Debug, Deserialize)]
pub struct AssessmentCreate {
    #[serde(rename = "type")]
    pub assessment_type: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub targets: Vec<String>,
    #[serde(default)]
    pub repo_paths: Vec<String>,
    // Accept either `config` (legacy / Pydantic shape) or `options` (the
    // shape the desktop wizard's TypeScript `AssessmentCreate` sends). They
    // mean the same JSONB blob on the assessments table; the alias keeps
    // both client styles working without forcing a frontend rename.
    #[serde(default, alias = "options")]
    pub config: JsonValue,
    #[serde(default)]
    pub phases: Vec<String>,
    #[serde(default)]
    pub project_id: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AssessmentUpdate {
    #[serde(default, rename = "type")]
    pub assessment_type: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub targets: Option<Vec<String>>,
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
    #[serde(default)]
    pub project_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AssessmentResponse {
    pub id: String,
    pub name: Option<String>,
    #[serde(rename = "type")]
    pub assessment_type: String,
    pub status: String,
    pub targets: Vec<String>,
    /// Resolved canonical target_id values (FK → targets.id). Mirrors
    /// `targets` 1:1; populated by migration 0018's backfill + the
    /// Rust-app's startup repair pass. Used by the desktop's
    /// "Baseline reuse" panel and by the team lead's Phase 1.5 baseline
    /// fetch step. May be empty on pre-Phase 2 assessments.
    pub target_ids: Vec<String>,
    pub repo_paths: Vec<String>,
    pub progress: i32,
    pub current_step: Option<String>,
    pub error_message: Option<String>,
    pub config: JsonValue,
    // Mirror of `config` under the name the desktop's `Assessment.options`
    // type expects. Same JSON value, two keys — the desktop reads
    // `assessment.options.{brain,capabilities,cloud_scope,pending_prompt,
    // claude_session_id,…}`; keeping `config` too means any older client
    // that still reads `config` keeps working. See AssessmentResponse::from.
    pub options: JsonValue,
    pub phases: Vec<String>,
    pub findings_count: i32,
    pub critical_count: i32,
    pub high_count: i32,
    pub medium_count: i32,
    pub low_count: i32,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub org_id: Option<String>,
    pub created_by: Option<String>,
    pub project_id: Option<String>,
    pub client_id: Option<String>,
    /// Set when the row has been soft-archived (the "close out" path).
    /// Frontend uses this to render an Archived badge so users can still
    /// track historical engagements without those rows dominating the
    /// default Active view.
    pub archived_at: Option<DateTime<Utc>>,
}

impl From<&Assessment> for AssessmentResponse {
    fn from(a: &Assessment) -> Self {
        // Normalize the JSONB blob once and mirror it under both keys —
        // `config` (legacy) and `options` (what the desktop reads). Python's
        // AssessmentResponse requires `config: dict`, so a null read-back
        // (SQL NULL or JSONB 'null') becomes {}.
        let normalized_config = a
            .config
            .clone()
            .filter(|v| !v.is_null())
            .unwrap_or(JsonValue::Object(Default::default()));

        AssessmentResponse {
            id: a.id.clone(),
            name: a.name.clone(),
            assessment_type: a.r#type.wire_name().to_string(),
            status: a
                .status
                .as_ref()
                .map(|s| s.wire_name().to_string())
                .unwrap_or_else(|| "pending".to_string()),
            targets: json_to_string_vec(&a.targets),
            // target_ids is NOT NULL on the column (default '[]') but
            // json_to_string_vec accepts &Option<JsonValue> uniformly —
            // wrap in Some for the call.
            target_ids: json_to_string_vec(&Some(a.target_ids.clone())),
            repo_paths: json_to_string_vec(&a.repo_paths),
            progress: a.progress.unwrap_or(0),
            current_step: a.current_step.clone(),
            error_message: a.error_message.clone(),
            config: normalized_config.clone(),
            options: normalized_config,
            phases: json_to_string_vec(&a.phases),
            findings_count: a.findings_count.unwrap_or(0),
            critical_count: a.critical_count.unwrap_or(0),
            high_count: a.high_count.unwrap_or(0),
            medium_count: a.medium_count.unwrap_or(0),
            low_count: a.low_count.unwrap_or(0),
            started_at: a.started_at,
            completed_at: a.completed_at,
            created_at: a.created_at,
            updated_at: a.updated_at,
            org_id: a.org_id.clone(),
            created_by: a.created_by.clone(),
            project_id: a.project_id.clone(),
            client_id: a.client_id.clone(),
            archived_at: a.archived_at,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct AssignProjectRequest {
    #[serde(default)]
    pub project_id: Option<String>,
}

fn json_to_string_vec(v: &Option<JsonValue>) -> Vec<String> {
    v.as_ref()
        .and_then(|x| x.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|e| e.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}
