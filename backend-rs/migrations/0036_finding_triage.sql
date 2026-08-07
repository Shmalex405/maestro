-- =============================================================================
-- Vulnerability-management triage layer + SLA + AI auto-escalate. 2026-06-23
-- =============================================================================
--
-- Phase 1 (workbench): findings gain triage fields — an owner (assigned_to),
-- free-form tags, and a separate comments/activity table. Phase 2 (AI bridge):
-- a "human-attested" timestamp completes the validation tier
-- (unproven candidate → AI-confirmed exploitable → human-attested), and
-- org_settings gains SLA thresholds + the cost-safe auto-escalate toggle.
--
-- All additive + nullable/defaulted; existing rows are unaffected.
-- =============================================================================

-- --- Triage fields on findings ------------------------------------------------
ALTER TABLE findings ADD COLUMN IF NOT EXISTS assigned_to TEXT;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS tags TEXT[] NOT NULL DEFAULT '{}';
-- Human attestation = the top validation tier: a person confirmed this is real
-- (beyond the AI's exploitable verdict). NULL = not attested.
ALTER TABLE findings ADD COLUMN IF NOT EXISTS attested_at TIMESTAMPTZ;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS attested_by TEXT;

CREATE INDEX IF NOT EXISTS idx_findings_assigned
    ON findings (org_id, assigned_to) WHERE assigned_to IS NOT NULL;

-- --- Comments / activity feed (mirrors assessment_events) ----------------------
CREATE TABLE IF NOT EXISTS finding_comments (
    id         TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    org_id     TEXT,
    author     TEXT,
    body       TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_finding_comments_finding
    ON finding_comments (finding_id, created_at);

-- --- SLA thresholds + auto-escalate (org_settings) ----------------------------
-- Per-severity days-to-remediate; aging/breach is derived from first_seen_at.
ALTER TABLE org_settings ADD COLUMN IF NOT EXISTS sla_critical_days INT NOT NULL DEFAULT 7;
ALTER TABLE org_settings ADD COLUMN IF NOT EXISTS sla_high_days     INT NOT NULL DEFAULT 14;
ALTER TABLE org_settings ADD COLUMN IF NOT EXISTS sla_medium_days   INT NOT NULL DEFAULT 30;
ALTER TABLE org_settings ADD COLUMN IF NOT EXISTS sla_low_days      INT NOT NULL DEFAULT 90;
-- When enabled, a scheduled scan that surfaces a NEW finding in the configured
-- severity set auto-CREATES a not-started "Prove it" assessment (cost-safe —
-- the user starts it). dast_auto_escalate_severities is a CSV of severities.
ALTER TABLE org_settings ADD COLUMN IF NOT EXISTS dast_auto_escalate_enabled BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE org_settings ADD COLUMN IF NOT EXISTS dast_auto_escalate_severities TEXT NOT NULL DEFAULT 'critical,high';
