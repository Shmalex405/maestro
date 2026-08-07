//! `sast_cache_entries` row. Phase 4 of the caching plan — repo-aware
//! SAST scan cache so unchanged-commit re-runs skip scanner execution.
//!
//! Migration: `migrations/0021_sast_cache.sql`.
//!
//! The cache key is `(org_id, target_id, commit_sha, scanner, scanner_version,
//! rule_pack_hash)`. Any one of these changes → cache miss → full scan.
//! The `finding_fingerprints` column lets the MCP server resolve the
//! cached findings against the current `findings` table on hit.

use chrono::{DateTime, Utc};
use serde_json::Value as JsonValue;
use sqlx::FromRow;

#[derive(Debug, Clone, FromRow)]
pub struct SastCacheEntry {
    pub id: String,
    pub org_id: String,
    pub target_id: String,
    pub commit_sha: String,
    pub scanner: String,
    pub scanner_version: String,
    pub rule_pack_hash: String,
    /// NULL for source-only scanners (semgrep, bandit). Populated for
    /// dependency scanners (grype, trivy) where the lockfile is part of
    /// what was scanned.
    pub dependency_lock_hash: Option<String>,
    /// JSONB array of finding fingerprints — same shape as
    /// `findings.fingerprint`. On cache hit, the MCP server resolves
    /// each against the current finding row.
    pub finding_fingerprints: JsonValue,
    /// Optional pointer to S3 blob containing the full raw scanner
    /// output (for the SAST companion report rendering on cache hit).
    pub raw_output_s3_key: Option<String>,
    /// When the scanner actually ran (not when this row was last
    /// touched). Surfaced in the report as "Last scanned …".
    pub scan_started_at: DateTime<Utc>,
    pub scan_completed_at: DateTime<Utc>,
    /// TTL boundary. After this, the application treats the cache as
    /// missing even if the key matches — safety net against silent
    /// scanner regressions.
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
