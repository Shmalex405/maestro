//! `recon_cache_entries` row. Phase 5 of the caching plan — per-target
//! reconnaissance snapshot cache so repeat assessments can do quick
//! delta probes instead of full enumeration.
//!
//! Migration: `migrations/0022_recon_cache.sql`.
//!
//! Cache key: `(org_id, target_id, scan_type)`. One snapshot per scan
//! type per target per org. TTL default 7 days (per
//! `org_settings.recon_cache_ttl_days`).

use chrono::{DateTime, Utc};
use serde_json::Value as JsonValue;
use sqlx::FromRow;

/// Mirror of the PostgreSQL `reconscantype` enum (migration 0022).
/// Stored as TEXT in Rust to avoid the sqlx derive ceremony — the
/// route layer enforces the valid set on inbound requests.
pub const RECON_SCAN_TYPES: &[&str] = &["ports", "subdomains", "services", "tls", "dns"];

#[derive(Debug, Clone, FromRow)]
pub struct ReconCacheEntry {
    pub id: String,
    pub org_id: String,
    pub target_id: String,
    /// One of `RECON_SCAN_TYPES`. SQL column is the `reconscantype` enum;
    /// sqlx maps it to String via the default TEXT casting at query time
    /// (we cast on bind with `::reconscantype` in the route).
    pub scan_type: String,
    /// Parsed structured snapshot. Shape varies per scan_type — see
    /// the migration comment block for examples.
    pub snapshot: JsonValue,
    pub scanner_version: Option<String>,
    pub scan_completed_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
