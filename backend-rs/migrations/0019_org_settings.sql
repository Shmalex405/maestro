-- =============================================================================
-- Per-org cache configuration (Phase 6 of caching plan) — 2026-05-22
-- =============================================================================
--
-- Single row per org governing every cache layer's behavior. The
-- application code reads this on every assessment start and uses it
-- to decide:
--   - Whether to use any caching at all (caching_enabled)
--   - When to force a full revalidation pass (full_revalidation_interval)
--   - How long cache entries are valid (sast/recon TTL days)
--   - How aggressive the baseline-reuse decision tree is (baseline_max_age_days)
--   - When drift alerts auto-disable caching (drift_alert_threshold)
--
-- These knobs are per-org so customers with stricter compliance
-- requirements can dial caching down (or off) without affecting other
-- tenants. Default values reflect the conservative recommendation in
-- docs/caching-plan-2026-05-22.md: caching on, full revalidation every
-- 4 assessments, 30 days for SAST cache, 7 days for recon, 14 days for
-- baseline reuse (overridden per severity by the crossval-qa decision
-- tree).
--
-- Per-org isolation: org_id is the primary key. Every read filters by
-- the JWT's custom:org_id claim (same pattern as the rest of the routes).
-- =============================================================================

CREATE TABLE IF NOT EXISTS org_settings (
    org_id TEXT PRIMARY KEY,

    -- Master kill switch. When false:
    --   - All cache lookups return "miss"
    --   - All force_full_revalidation flags are implicitly true
    --   - The cost panel still computes savings counterfactually
    caching_enabled BOOLEAN NOT NULL DEFAULT true,

    -- Every Nth assessment of a target forces a full re-validation
    -- (ignores all caches, runs full crossval-qa). Default 4 means roughly
    -- 1-in-4 assessments is a "clean" run. Set to 0 to disable forced
    -- revalidation entirely (relies on TTLs + drift detection only).
    full_revalidation_interval INT NOT NULL DEFAULT 4
        CHECK (full_revalidation_interval >= 0),

    -- TTL for sast_cache_entries (Phase 4). Cache hits beyond this age
    -- trigger a full rescan. 30 days is conservative — most repos see
    -- their dependency_lock_hash change more often than that anyway.
    sast_cache_ttl_days INT NOT NULL DEFAULT 30
        CHECK (sast_cache_ttl_days > 0),

    -- TTL for recon_cache_entries (Phase 5). Recon is fast to invalidate
    -- because DNS/services/ports change frequently in active environments.
    recon_cache_ttl_days INT NOT NULL DEFAULT 7
        CHECK (recon_cache_ttl_days > 0),

    -- Maximum age (in days) of a finding's last_seen_at before crossval-qa
    -- considers it ineligible for VALIDATED_FROM_BASELINE. Severity-specific
    -- override sliders live in the agent prompt, not here.
    baseline_max_age_days INT NOT NULL DEFAULT 30
        CHECK (baseline_max_age_days > 0),

    -- Number of cache_drift_alerts (Phase 6.4, future table) within a
    -- 30-day window that triggers automatic caching_enabled=false. The
    -- safety circuit-breaker for "the cache is producing wrong results."
    drift_alert_threshold INT NOT NULL DEFAULT 3
        CHECK (drift_alert_threshold > 0),

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Lookup is always by primary key, no extra indexes needed.

-- ─── Default rows for known orgs (best-effort) ───────────────────────
--
-- Insert a default row for each org that has at least one finding.
-- ON CONFLICT DO NOTHING so re-running the migration is safe and
-- existing per-org tuning isn't clobbered. New orgs get a row inserted
-- by the application on first /cache-stats access (see Phase 3 endpoint
-- implementation).
INSERT INTO org_settings (org_id)
SELECT DISTINCT org_id
FROM findings
WHERE org_id IS NOT NULL AND org_id != ''
ON CONFLICT (org_id) DO NOTHING;
