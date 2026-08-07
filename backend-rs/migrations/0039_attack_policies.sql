-- =============================================================================
-- Scan policies (attack-library subsets) + schedule policy/blackout windows. 2026-06-23
-- =============================================================================
--
-- A scan policy is a reusable named selection from the attack library
-- (config/test-matrix.yml): a set of categories and/or explicit test_ids the
-- deterministic pipeline runs (everything else is SKIPPED "Excluded by scan
-- policy"). Schedules can pin a policy and a blackout window (the external
-- runner + the due-query both honor the window).
-- =============================================================================

CREATE TABLE IF NOT EXISTS scan_policies (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL,
    name        TEXT NOT NULL,
    description TEXT,
    -- Category prefixes (RECON, INJ, …) and/or explicit test_ids. Empty both =
    -- "everything" (full assessment).
    categories  TEXT[] NOT NULL DEFAULT '{}',
    test_ids    TEXT[] NOT NULL DEFAULT '{}',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_scan_policies_org ON scan_policies (org_id);

-- Schedules can pin a policy (which attacks) + a blackout window (when not to run).
ALTER TABLE scan_schedules ADD COLUMN IF NOT EXISTS policy_id TEXT REFERENCES scan_policies(id) ON DELETE SET NULL;
ALTER TABLE scan_schedules ADD COLUMN IF NOT EXISTS window_start TIME;
ALTER TABLE scan_schedules ADD COLUMN IF NOT EXISTS window_end   TIME;
ALTER TABLE scan_schedules ADD COLUMN IF NOT EXISTS timezone     TEXT;
