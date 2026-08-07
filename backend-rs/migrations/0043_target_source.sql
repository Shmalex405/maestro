-- The Scheduled DAST "Targets" page manages its own targets, distinct from the
-- AI-assessment scope. `source` records how a target was created:
--   'dast'        — user-added on the Scheduled DAST Targets page
--   'assessment'  — spawned by an LLM assessment (per-endpoint targets)
--   'scope'       — from the scope-configuration page
--   NULL          — legacy / unknown
-- The DAST page lists source='dast' so assessment-spawned per-endpoint targets
-- (and repo/cloud targets) no longer pollute it.
ALTER TABLE targets ADD COLUMN IF NOT EXISTS source VARCHAR(32);
