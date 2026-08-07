-- =============================================================================
-- Applications grouping + webhook notifications (Scheduled DAST Phase 4). 2026-06-23
-- =============================================================================
--
-- Enterprise DAST tools group scannable targets under an "Application" that
-- carries ownership + business context (team, criticality, environment). This
-- adds that layer above the flat `targets` table, plus a generic outbound
-- webhook (Slack-compatible) the scan pipeline posts to on new Crit/High.
-- =============================================================================

CREATE TABLE IF NOT EXISTS applications (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL,
    name        TEXT NOT NULL,
    description TEXT,
    team        TEXT,
    -- Business criticality: 'low' | 'medium' | 'high' | 'critical'.
    criticality TEXT NOT NULL DEFAULT 'medium',
    environment TEXT,            -- e.g. 'production' | 'staging'
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_applications_org ON applications (org_id);

-- A target may belong to one application. ON DELETE SET NULL so removing an app
-- never deletes its targets (they just become unassigned).
ALTER TABLE targets ADD COLUMN IF NOT EXISTS application_id TEXT REFERENCES applications(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS idx_targets_application ON targets (application_id) WHERE application_id IS NOT NULL;

-- Outbound notification webhook (Slack incoming-webhook compatible: {text}).
ALTER TABLE org_settings ADD COLUMN IF NOT EXISTS dast_webhook_url TEXT;
