//! `cache_stats` table row. Tracks per-assessment LLM token usage with
//! prompt-cache fields broken out so the desktop can show how much each
//! assessment cost and how much caching saved.
//!
//! Migration: `migrations/0017_cache_stats.sql`
//!
//! Two intended write paths (one will land first):
//!   - MCP server pushes aggregated counts at `complete_assessment` time
//!   - Proxy → CloudWatch → Firehose → backend-rs ingester (cross-account)
//!
//! Read path: desktop cost panel queries `GET /cache-stats?assessment_id=X`.
//!
//! Cost fields use `f64` (mapped to Postgres `DOUBLE PRECISION`) because
//! the project's existing convention (see `Finding.cvss_score`) avoids
//! the `bigdecimal` / `rust_decimal` sqlx feature flag. Sub-cent precision
//! is unnecessary for display-only cost fields; for billing accuracy the
//! source of truth remains the proxy's DDB token counts.

use chrono::{DateTime, Utc};
use sqlx::FromRow;

#[derive(Debug, Clone, FromRow)]
pub struct CacheStats {
    pub id: String,
    pub org_id: String,
    pub assessment_id: Option<String>,
    /// 'anthropic' | 'openai' — the upstream LLM provider this row covers.
    pub provider: String,
    /// Predominant model used in this assessment (e.g. "claude-opus-4-7").
    pub model: Option<String>,

    // Token counts (cumulative for the assessment).
    pub input_tokens: i64,
    pub output_tokens: i64,
    pub cache_read_input_tokens: i64,
    pub cache_creation_input_tokens: i64,
    /// `input_tokens + 0.1 * cache_read + 1.25 * cache_create`. Frozen at
    /// write time so cost computations are stable against shifting price
    /// tables (and so downstream queries don't re-derive).
    pub effective_input_tokens: i64,

    // Cost computation. Stored explicitly so we don't recompute against
    // shifting price tables — these are frozen at write time.
    pub cost_usd: f64,
    pub cost_usd_without_cache: f64,
    pub savings_usd: f64,
    /// 0-100. Computed as cache_read / (cache_read + cache_create + fresh_input) * 100.
    pub cache_hit_pct: f64,

    pub request_count: i32,
    /// Number of requests in this assessment that included the
    /// `anthropic-beta: extended-cache-ttl-2025-04-11` header (1h TTL).
    /// Used to diagnose whether the Claude Code harness is leveraging 1h
    /// TTL vs the default 5min — critical for multi-phase assessments.
    pub requests_with_extended_ttl: i32,
    /// Number of requests without any prompt-caching beta header. If this
    /// is most of an assessment, caching savings are leaving money on the
    /// table.
    pub requests_without_cache_beta: i32,

    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
