//! `reports` table row. Mirrors `backend/app/models/report.py:Report`.

use chrono::{DateTime, Utc};
use sqlx::FromRow;

#[derive(Debug, Clone, FromRow)]
pub struct Report {
    pub id: String,
    pub title: String,
    pub format: Option<String>,
    pub content: Option<String>,
    pub executive_summary: Option<String>,
    pub findings_count: Option<i32>,
    pub critical_count: Option<i32>,
    pub high_count: Option<i32>,
    // Added in migration 0013 to match the columns the MCP create_report
    // payload was already trying to write.
    pub medium_count: Option<i32>,
    pub low_count: Option<i32>,
    pub exploitable_count: Option<i32>,
    pub file_path: Option<String>,
    pub file_url: Option<String>,
    /// S3 object key (e.g. `reports/{id}.pdf`). Populated by the
    /// upload endpoint; NULL for legacy rows whose bytes only live
    /// on the originating machine's disk.
    pub s3_key: Option<String>,
    pub created_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
    // Nullable because reports outlive their parent assessment: migration
    // 0011 changed the FK from ON DELETE CASCADE to ON DELETE SET NULL so
    // a user cleaning up an assessment doesn't destroy the report PDFs/MDs
    // that document it. A NULL value means "orphaned — the source
    // assessment was deleted but the report remains as an artifact."
    pub assessment_id: Option<String>,
    pub org_id: Option<String>,
    pub created_by: Option<String>,
    pub client_id: Option<String>,
}
