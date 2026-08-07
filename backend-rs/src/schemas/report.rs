//! Request/response schemas for `/reports`.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::models::report::Report;

#[derive(Debug, Deserialize)]
pub struct ReportCreate {
    pub title: String,
    #[serde(default = "default_format")]
    pub format: String,
    #[serde(default)]
    pub content: Option<String>,
    #[serde(default)]
    pub executive_summary: Option<String>,
    // Optional since migration 0011 — clients can upload a report that
    // never had an assessment (e.g. the recovery script after the user
    // already deleted the original assessment).
    #[serde(default)]
    pub assessment_id: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
    // Path on the host where the bytes live. MCP-generated PDFs are
    // rendered inside the container, copied to ~/.kali-mcp-pentest/reports/
    // on the host, then registered here with the container-side path
    // (`/mnt/host-home/...`). The desktop translates back to a host
    // path and opens with the system PDF viewer. None for cloud-only
    // reports whose bytes live in `content`.
    #[serde(default)]
    pub file_path: Option<String>,
    // Severity counts and total. The MCP report-creation path passes
    // these through alongside the row so the Reports page can show
    // accurate stat chips without needing a separate findings fetch.
    // Previously dropped silently (schema mismatch with MCP payload),
    // which is why existing rows show "0 Critical / 0 High" in the UI.
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
    pub exploitable_count: Option<i32>,
}

fn default_format() -> String {
    "markdown".to_string()
}

#[derive(Debug, Serialize)]
pub struct ReportResponse {
    pub id: String,
    pub title: String,
    pub format: String,
    pub content: Option<String>,
    pub executive_summary: Option<String>,
    pub findings_count: i32,
    pub critical_count: i32,
    pub high_count: i32,
    pub medium_count: i32,
    pub low_count: i32,
    pub exploitable_count: i32,
    pub file_path: Option<String>,
    pub file_url: Option<String>,
    /// True if the row has bytes in S3. Frontend uses this to decide
    /// whether the inline preview can fetch the presigned URL or
    /// needs to fall back to the legacy local-file path.
    pub has_artifact: bool,
    // None means the parent assessment was deleted; the report row
    // survives as a standalone artifact (see migration 0011).
    pub assessment_id: Option<String>,
    pub org_id: Option<String>,
    pub created_by: Option<String>,
    pub client_id: Option<String>,
    pub created_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
}

impl From<&Report> for ReportResponse {
    fn from(r: &Report) -> Self {
        ReportResponse {
            id: r.id.clone(),
            title: r.title.clone(),
            format: r.format.clone().unwrap_or_else(|| "markdown".to_string()),
            content: r.content.clone(),
            executive_summary: r.executive_summary.clone(),
            findings_count: r.findings_count.unwrap_or(0),
            critical_count: r.critical_count.unwrap_or(0),
            high_count: r.high_count.unwrap_or(0),
            medium_count: r.medium_count.unwrap_or(0),
            low_count: r.low_count.unwrap_or(0),
            exploitable_count: r.exploitable_count.unwrap_or(0),
            file_path: r.file_path.clone(),
            file_url: r.file_url.clone(),
            has_artifact: r.s3_key.is_some(),
            assessment_id: r.assessment_id.clone(),  // already Option<String>, see model
            org_id: r.org_id.clone(),
            created_by: r.created_by.clone(),
            client_id: r.client_id.clone(),
            created_at: r.created_at,
            updated_at: r.updated_at,
        }
    }
}
