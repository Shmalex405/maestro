//! `cache_drift_alerts` row. Phase 6.4 of the caching plan — records
//! every event where a baseline-trusted finding fails to reproduce in
//! a forced revalidation pass.
//!
//! Migration: `migrations/0023_cache_drift_alerts.sql`.

use chrono::{DateTime, Utc};
use sqlx::FromRow;

#[derive(Debug, Clone, FromRow)]
pub struct CacheDriftAlert {
    pub id: String,
    pub org_id: String,
    pub target_id: Option<String>,
    pub finding_fingerprint: String,
    pub prior_assessment_id: Option<String>,
    pub prior_status: Option<String>,
    pub prior_severity: Option<String>,
    pub current_assessment_id: Option<String>,
    pub current_status: Option<String>,
    pub current_severity: Option<String>,
    /// Free-form crossval-qa summary of what changed.
    pub drift_summary: Option<String>,
    /// Sticky flag — true if this row contributed to a threshold breach
    /// that flipped `org_settings.caching_enabled` to false.
    pub triggered_auto_disable: bool,
    pub acknowledged_at: Option<DateTime<Utc>>,
    pub acknowledged_by: Option<String>,
    pub acknowledgement_notes: Option<String>,
    pub detected_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}
