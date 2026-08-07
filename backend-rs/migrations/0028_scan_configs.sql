-- =============================================================================
-- Scan configs — authenticated-scan setup + scope/exclusions per target.
-- 2026-06-08. (DAST page enterprise features.)
-- =============================================================================
--
-- One config per (org, target). The DAST page edits it; the deterministic scan
-- run reads it and passes auth + scope into the pipeline. Stored as JSONB so the
-- shape can grow (auth methods, scope rules) without a migration.
--
--   auth  : { type: 'none'|'header'|'basic'|'bearer'|'form',
--             headers?: {k:v}, username?, password?, token?,
--             login_url?, username_field?, password_field? }
--   scope : { include?: [url/path globs], exclude?: [url/path globs] }
-- =============================================================================

CREATE TABLE IF NOT EXISTS scan_configs (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL,
    target_id TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,

    auth JSONB NOT NULL DEFAULT '{}',
    scope JSONB NOT NULL DEFAULT '{}',

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- One config per (org, target) — the upsert key.
CREATE UNIQUE INDEX IF NOT EXISTS scan_configs_key_idx
    ON scan_configs (org_id, target_id);
