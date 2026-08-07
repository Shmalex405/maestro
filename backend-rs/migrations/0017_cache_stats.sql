-- =============================================================================
-- Cache statistics (Phase 0 of caching plan) — 2026-05-22
-- =============================================================================
--
-- Per-assessment aggregation of LLM API token usage with prompt-cache fields
-- broken out. The proxy at proxy.maestro.groovysec.com captures these per
-- request; the cache_stats table is the per-org, per-assessment summary so
-- the desktop cost panel can show "this assessment cost $X with caching
-- saving you $Y" without paging through individual proxy log lines.
--
-- Architecture note:
--   The proxy runs in Groovy-managed AWS and writes to DynamoDB
--   (maestro_bundled_meter) for billing. The per-customer backend-rs runs
--   in the customer's AWS and can't directly read the Groovy DDB row.
--   This table is fed by one of two paths (both planned, neither shipped
--   in this migration alone):
--     (a) MCP server pushes aggregated counts at `complete_assessment`
--         time using the harness's own usage tally
--     (b) Proxy emits CloudWatch logs → Firehose → backend-rs ingester
--   The schema is identical regardless of which path lands first.
--
-- Semantics:
--   input_tokens                  — fresh input tokens (not from cache, not written to cache)
--   output_tokens                 — model output tokens
--   cache_read_input_tokens       — input tokens served from cache (charged ~10% of fresh rate)
--   cache_creation_input_tokens   — input tokens written to cache (charged ~125-200% of fresh rate)
--   effective_input_tokens        — input_tokens + 0.1*cache_read + 1.25*cache_create
--                                    (best-effort dollar-equivalent — see upstream.ts for ratios)
--   cost_usd                      — $ value of this assessment's LLM spend (post-cache discount)
--   cost_usd_without_cache        — $ value if no caching was used (all input billed at fresh rate)
--   savings_usd                   — cost_usd_without_cache - cost_usd
--   cache_hit_pct                 — cache_read / (cache_read + cache_create + fresh_input) * 100
--   request_count                 — number of distinct API calls in this assessment
--   model                         — predominant model used (e.g. "claude-opus-4-7")
-- =============================================================================

CREATE TABLE IF NOT EXISTS cache_stats (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL,
    assessment_id TEXT,
    -- Provider attribution: 'anthropic' | 'openai' (codex bundled mode also feeds here)
    provider TEXT NOT NULL DEFAULT 'anthropic',
    model TEXT,

    -- Token counts (cumulative for the assessment)
    input_tokens BIGINT NOT NULL DEFAULT 0,
    output_tokens BIGINT NOT NULL DEFAULT 0,
    cache_read_input_tokens BIGINT NOT NULL DEFAULT 0,
    cache_creation_input_tokens BIGINT NOT NULL DEFAULT 0,
    effective_input_tokens BIGINT NOT NULL DEFAULT 0,

    -- Cost computation (stored explicitly so we don't recompute against
    -- shifting price tables — these are frozen at write time). Stored as
    -- DOUBLE PRECISION to match the project's existing convention (see
    -- findings.cvss_score) — avoids the bigdecimal sqlx feature flag.
    -- Sub-cent precision is irrelevant for display; source-of-truth
    -- billing lives in the proxy's DDB token counts.
    cost_usd DOUBLE PRECISION NOT NULL DEFAULT 0,
    cost_usd_without_cache DOUBLE PRECISION NOT NULL DEFAULT 0,
    savings_usd DOUBLE PRECISION NOT NULL DEFAULT 0,
    cache_hit_pct DOUBLE PRECISION NOT NULL DEFAULT 0,

    request_count INTEGER NOT NULL DEFAULT 0,

    -- Header telemetry — how many requests in this assessment included the
    -- extended-cache-ttl-2025-04-11 beta? Helps diagnose whether the harness
    -- is using 1h TTL (good for multi-phase assessments) vs default 5min
    -- (will lose cache between phases).
    requests_with_extended_ttl INTEGER NOT NULL DEFAULT 0,
    requests_without_cache_beta INTEGER NOT NULL DEFAULT 0,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- One row per (org_id, assessment_id). Upsert path increments tokens.
-- assessment_id is nullable in the schema (so unscoped proxy traffic can
-- still be metered into the org's daily bucket) but uniqueness is on the
-- composite — duplicate inserts for the same assessment update in place.
CREATE UNIQUE INDEX IF NOT EXISTS cache_stats_org_assessment_idx
    ON cache_stats (org_id, COALESCE(assessment_id, ''))
    WHERE assessment_id IS NOT NULL;

-- Fast lookup for "show me cache stats for this assessment"
CREATE INDEX IF NOT EXISTS cache_stats_assessment_idx
    ON cache_stats (assessment_id)
    WHERE assessment_id IS NOT NULL;

-- Fast lookup for org-wide rollups (cost dashboard across all assessments)
CREATE INDEX IF NOT EXISTS cache_stats_org_created_idx
    ON cache_stats (org_id, created_at DESC);
