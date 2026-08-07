-- =============================================================================
-- Recon cache entries (Phase 5 of caching plan) — 2026-05-22
-- =============================================================================
--
-- Stores per-(target, scan_type) cached reconnaissance snapshots so
-- repeat assessments can do a quick delta scan instead of full
-- enumeration. Recon runs ~10 min per target for a thorough sweep;
-- on a target that doesn't change between weekly assessments, that's
-- pure waste.
--
-- HOW THE CACHE IS USED:
--
--   1. MCP server tools (scan_ports, enumerate_subdomains, etc.) check
--      the cache before running. If a snapshot < 7 days old exists:
--        - Run a quick delta probe (e.g. nmap -F on cached ports instead
--          of full -p-)
--        - Diff against cached snapshot
--        - If no delta: return cached snapshot, mark `cached: true`
--        - If delta: full re-scan, update cache, annotate snapshot with
--          delta info
--   2. On true miss or expired entry: full scan, populate cache.
--
-- SCAN_TYPE values: 'ports' | 'subdomains' | 'services' | 'tls' | 'dns'
--
-- TTL: 7 days by default (per `org_settings.recon_cache_ttl_days`).
-- Recon data ages faster than SAST — DNS/services/ports churn weekly
-- in active environments, so we set a tighter window.
--
-- CONTENT:
--
--   - snapshot JSONB: parsed structured output (NOT raw scanner blob).
--     The recon agent already parses scanner output; the parsed form is
--     ~100x smaller than raw nmap XML and is what the agent context
--     would have seen anyway. Easier to diff than raw.
-- =============================================================================

-- ENUM for scan_type — keeps the cache table compact and the
-- application-layer dispatch table cleaner than free-text.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'reconscantype') THEN
        CREATE TYPE reconscantype AS ENUM (
            'ports',
            'subdomains',
            'services',
            'tls',
            'dns'
        );
    END IF;
END$$;

CREATE TABLE IF NOT EXISTS recon_cache_entries (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL,
    target_id TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    scan_type reconscantype NOT NULL,

    /* Parsed structured snapshot — what the recon agent saw last time.
       Example for scan_type='ports':
         { "open": [22, 80, 443, 8080],
           "services": { "22": "openssh-9.0", "80": "nginx-1.24", … },
           "scan_command": "nmap -sV -p- example.com" }
       The diff logic in the MCP server reads this JSONB to know what
       to delta-probe against. */
    snapshot JSONB NOT NULL DEFAULT '{}',

    /* Track the scanner version that produced this snapshot. A bump
       (e.g., nmap 7.93 → 7.95) is enough to invalidate the cache:
       new fingerprints could detect services the old version missed. */
    scanner_version TEXT,

    /* When the scanner actually ran, distinct from when this row was
       last touched. Surfaced in the report. */
    scan_completed_at TIMESTAMPTZ NOT NULL,

    expires_at TIMESTAMPTZ NOT NULL,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Unique constraint = cache key. One snapshot per (org, target, scan_type).
CREATE UNIQUE INDEX IF NOT EXISTS recon_cache_key_idx
    ON recon_cache_entries (org_id, target_id, scan_type);

-- Index for the housekeeping cleanup sweep.
CREATE INDEX IF NOT EXISTS recon_cache_expires_idx
    ON recon_cache_entries (expires_at);
