//! `scan_configs` row (migration 0028) — per-target authenticated-scan +
//! scope/exclusion config the DAST run reads. auth/scope are opaque JSONB.

use chrono::{DateTime, Utc};
use serde_json::Value as JsonValue;
use sqlx::FromRow;

#[derive(Debug, Clone, FromRow)]
pub struct ScanConfigRow {
    pub id: String,
    pub org_id: String,
    pub target_id: String,
    pub auth: JsonValue,
    pub scope: JsonValue,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
