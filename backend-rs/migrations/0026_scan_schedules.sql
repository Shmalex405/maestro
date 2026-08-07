-- =============================================================================
-- Scan schedules — continuous-DAST cadence (consolidation-roadmap Phase 4 data
-- model). 2026-06-08
-- =============================================================================
--
-- One row per (org, target) scheduled deterministic scan. This is the cadence
-- DATA MODEL the Scheduled DAST page reads/writes; the firing mechanism (a cron
-- that runs runDeterministic when next_run_at passes) is a separate component —
-- its home (desktop MVP vs the cloud-hosted runner in the infra repo) is the
-- open decision. With this table present, the UI ships cadence as a real
-- editable field instead of a hardcoded "Manual".
--
-- Continuous scans are the cheap DETERMINISTIC tier (~$0 tokens); the on-demand
-- LLM "prove this finding" exploit is triggered separately and is where tokens
-- are spent intentionally.
-- =============================================================================

CREATE TABLE IF NOT EXISTS scan_schedules (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL,
    target_id TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,

    /* MVP cadence buckets (a cron expression can replace this later without a
       table change — the firing component owns interpretation). */
    cadence TEXT NOT NULL
        CHECK (cadence IN ('hourly', 'daily', 'weekly', 'monthly')),

    scan_type TEXT NOT NULL DEFAULT 'deterministic'
        CHECK (scan_type IN ('dast', 'sast', 'full', 'deterministic')),

    enabled BOOLEAN NOT NULL DEFAULT TRUE,

    last_run_at TIMESTAMPTZ,
    next_run_at TIMESTAMPTZ,

    created_by TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- One schedule per (org, target, scan_type) — the upsert key.
CREATE UNIQUE INDEX IF NOT EXISTS scan_schedules_key_idx
    ON scan_schedules (org_id, target_id, scan_type);

-- The firing component's query: "what's due?" — enabled schedules past next_run_at.
CREATE INDEX IF NOT EXISTS scan_schedules_due_idx
    ON scan_schedules (enabled, next_run_at);
