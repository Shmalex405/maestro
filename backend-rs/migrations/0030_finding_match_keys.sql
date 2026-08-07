-- =============================================================================
-- Structured correlation keys on findings (P2 Phase 2) — DAST correlation. 2026-06-10
-- =============================================================================
--
-- The deterministic correlation engine joins (reachable surface) × (vulnerable
-- component). For cloud that key is image_digest (migration 0024 captured it on
-- cloud_assets). For network/web DAST the join keys — the port a finding lives on,
-- the service/version, the package/component — were buried in free-text `target`
-- and `evidence`, so no deterministic join was possible.
--
-- These nullable columns surface those keys structurally so `correlate_dast` can
-- join findings against recon-discovered open ports/services. Populated going
-- forward at finding-creation; backfilled for existing rows via the best-effort
-- POST /findings/backfill-keys extractor.
-- =============================================================================

ALTER TABLE findings ADD COLUMN IF NOT EXISTS port INTEGER;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS service TEXT;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS component TEXT;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS image_digest TEXT;

-- Join performance: correlate_dast filters by (org, port) and (org, service).
CREATE INDEX IF NOT EXISTS findings_port_idx ON findings (org_id, port) WHERE port IS NOT NULL;
CREATE INDEX IF NOT EXISTS findings_service_idx ON findings (org_id, service) WHERE service IS NOT NULL;
