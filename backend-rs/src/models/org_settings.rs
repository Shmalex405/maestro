//! `org_settings` row. One per org, governs every cache layer's
//! behavior — the master kill switch + cadence + TTL knobs.
//!
//! Migration: `migrations/0019_org_settings.sql`.

use chrono::{DateTime, Utc};
use sqlx::FromRow;

#[derive(Debug, Clone, FromRow)]
pub struct OrgSettings {
    pub org_id: String,
    /// Master kill switch. False disables all cache lookups for this org.
    pub caching_enabled: bool,
    /// Every Nth assessment of a target forces a full revalidation pass.
    /// 0 disables forced revalidation entirely.
    pub full_revalidation_interval: i32,
    /// TTL (days) for sast_cache_entries.
    pub sast_cache_ttl_days: i32,
    /// TTL (days) for recon_cache_entries.
    pub recon_cache_ttl_days: i32,
    /// Maximum age (days) of a finding before crossval-qa considers it
    /// ineligible for VALIDATED_FROM_BASELINE.
    pub baseline_max_age_days: i32,
    /// Number of drift alerts in 30 days that trips auto-disable.
    pub drift_alert_threshold: i32,
    /// Per-severity days-to-remediate SLA. Migration 0036.
    pub sla_critical_days: i32,
    pub sla_high_days: i32,
    pub sla_medium_days: i32,
    pub sla_low_days: i32,
    /// When true, a scheduled scan that surfaces a NEW finding in
    /// `dast_auto_escalate_severities` auto-creates a not-started "Prove it"
    /// assessment (cost-safe — user starts it). Migration 0036.
    pub dast_auto_escalate_enabled: bool,
    /// CSV of severities that trigger auto-escalation (e.g. "critical,high").
    pub dast_auto_escalate_severities: String,
    /// Outbound notification webhook (Slack-compatible). NULL = disabled. Migration 0038.
    pub dast_webhook_url: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
