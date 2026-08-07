-- =============================================================================
-- SAST cache entries (Phase 4 of caching plan) — 2026-05-22
-- =============================================================================
--
-- Stores per-(target, commit, scanner) cached scan results so repeat
-- assessments can skip scanner execution when nothing relevant has
-- changed. SAST scans are the most expensive single phase of an
-- assessment (43-80K tokens of raw output, ~10 min wall time); a hit
-- here is the highest single dollar-per-bit win in the cross-assessment
-- caching plan.
--
-- WHAT THE CACHE KEY DEPENDS ON:
--
--   - org_id              — tenancy boundary, always
--   - target_id           — the repo being scanned (FK → targets, type='repo')
--   - commit_sha          — the exact tree the scanner saw
--   - scanner             — 'semgrep' | 'bandit' | 'gitleaks' | etc.
--   - scanner_version     — bumping the scanner busts the cache
--   - rule_pack_hash      — SHA256 of the rule files used; rule pack
--                           updates bust the cache transparently
--   - dependency_lock_hash — only for dep scanners (grype, trivy, snyk);
--                           NULL for source-only scanners
--
-- Any one of these changes → cache miss → full scan. Operators can
-- trust that an unchanged commit + scanner_version + rule_pack with
-- a fresh cache entry will not silently miss a new rule that landed
-- in the meantime.
--
-- CONTENT:
--
--   - finding_fingerprints: JSONB array of finding fingerprints
--     (SHA256 hex strings — same shape as `findings.fingerprint`). On
--     cache hit, the MCP server resolves these against the current
--     `findings` table; the underlying finding records may have evolved
--     (occurrence_count incremented, etc.) but the *set* of findings
--     this scan produced is replayable.
--
--   - raw_output_s3_key: optional pointer to a per-org S3 bucket where
--     the scanner's full output blob lives. Lets the SAST companion
--     report render verbatim scanner output on cache hit without
--     re-running. NULL when S3 wasn't configured at write time.
--
-- TTL: 30 days by default (per `org_settings.sast_cache_ttl_days`).
-- Past that, we force a full rescan even if the cache key matches —
-- a safety net against silent scanner regressions and rule-pack drift
-- the hash didn't catch.
-- =============================================================================

CREATE TABLE IF NOT EXISTS sast_cache_entries (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL,
    target_id TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,

    /* Cache-key components — all NOT NULL, all part of the unique index. */
    commit_sha TEXT NOT NULL,
    scanner TEXT NOT NULL,
    scanner_version TEXT NOT NULL,
    rule_pack_hash TEXT NOT NULL,

    /* Optional refinement: dependency lockfile hash for dep scanners.
       NULL for source-only scanners (semgrep, bandit, etc.). */
    dependency_lock_hash TEXT,

    /* The cached payload itself. */
    finding_fingerprints JSONB NOT NULL DEFAULT '[]',
    raw_output_s3_key TEXT,

    /* When the scanner actually ran (not when this row was last touched).
       Lets the report render "Last scanned <date>" honestly even on cache hit. */
    scan_started_at TIMESTAMPTZ NOT NULL,
    scan_completed_at TIMESTAMPTZ NOT NULL,

    /* TTL — set to scan_completed_at + org_settings.sast_cache_ttl_days
       at insert time. The application checks this on lookup. */
    expires_at TIMESTAMPTZ NOT NULL,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Unique constraint = the cache key. ON CONFLICT path in the application
-- updates the cached payload (newer scan superseding an earlier one with
-- the same key — happens when expires_at is refreshed on a re-run of the
-- exact same scan).
CREATE UNIQUE INDEX IF NOT EXISTS sast_cache_key_idx
    ON sast_cache_entries (
        org_id, target_id, commit_sha, scanner, scanner_version, rule_pack_hash
    );

-- Lookup index for the common "any non-expired entry for this target +
-- scanner" query (used by the MCP server before deciding to run).
CREATE INDEX IF NOT EXISTS sast_cache_lookup_idx
    ON sast_cache_entries (org_id, target_id, scanner, expires_at);

-- Cleanup index for the future TTL sweep cron (Phase 6 housekeeping).
CREATE INDEX IF NOT EXISTS sast_cache_expires_idx
    ON sast_cache_entries (expires_at);
