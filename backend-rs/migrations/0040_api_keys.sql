-- =============================================================================
-- API keys for CI / non-interactive scan triggering (Scheduled DAST WS5). 2026-06-23
-- =============================================================================
--
-- Long-lived org-scoped tokens for calling the API from CI (e.g. trigger a DAST
-- scan on deploy). The plaintext token (`dast_<prefix>_<secret>`) is shown ONCE
-- at mint time; only its SHA-256 is stored. Auth resolves the org_id from the
-- key and runs as a `service_caller = "ci"` principal.
-- =============================================================================

CREATE TABLE IF NOT EXISTS api_keys (
    id           TEXT PRIMARY KEY,
    org_id       TEXT NOT NULL,
    name         TEXT NOT NULL,
    -- Display prefix (the `dast_<prefix>` part) so the UI can show which key is
    -- which without revealing the secret.
    prefix       TEXT NOT NULL,
    -- SHA-256 hex of the full plaintext token. Looked up at auth time.
    key_hash     TEXT NOT NULL UNIQUE,
    created_by   TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ,
    revoked_at   TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_api_keys_org ON api_keys (org_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys (key_hash) WHERE revoked_at IS NULL;
