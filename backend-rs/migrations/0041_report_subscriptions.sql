-- =============================================================================
-- Scheduled DAST report-delivery subscriptions (WS6 — data model only). 2026-06-23
-- =============================================================================
--
-- Stores who wants a DAST report emailed on what cadence. The actual SEND path
-- needs an email provider (SES/SendGrid) that lives outside this repo, so these
-- rows are persisted + manageable but not yet delivered — the UI flags this.
-- =============================================================================

CREATE TABLE IF NOT EXISTS report_subscriptions (
    id           TEXT PRIMARY KEY,
    org_id       TEXT NOT NULL,
    -- Optional scoping: a whole application or a single target. Both NULL = org-wide.
    application_id TEXT REFERENCES applications(id) ON DELETE CASCADE,
    target_id    TEXT,
    recipients   TEXT[] NOT NULL DEFAULT '{}',
    -- 'daily' | 'weekly' | 'monthly'.
    cadence      TEXT NOT NULL DEFAULT 'weekly',
    enabled      BOOLEAN NOT NULL DEFAULT TRUE,
    last_sent_at TIMESTAMPTZ,
    created_by   TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_report_subs_org ON report_subscriptions (org_id);
