-- =============================================================================
-- Attribute findings to the scheduled-DAST scan that produced them. 2026-06-23
-- =============================================================================
--
-- Until now a finding carried only `assessment_id` (the LLM exploitation /
-- validation run) — there was NO link from a finding to a deterministic
-- "scheduled DAST" scan (the scans table, migration 0025). Worse, the
-- deterministic pipeline never even persisted its individual findings to this
-- table; only the aggregate scans row (with severity counts) was written. So
-- the per-scan findings view (GET /scans/:id/findings) had to fake attribution
-- via a lossy time-window correlation that could surface unrelated LLM findings
-- for the same target.
--
-- This column is the discriminator that makes the dedicated "Scheduled DAST →
-- Vulnerabilities" view possible, separate from the normal LLM-assessment
-- findings:
--
--   scan_id IS NOT NULL  ⇒  produced by a scheduled/deterministic DAST scan
--   scan_id = '<id>'     ⇒  produced by that specific scan run
--   scan_id IS NULL      ⇒  legacy row OR an LLM-assessment finding (assessment_id)
--
-- Nullable + ON DELETE SET NULL so deleting a scan never cascades away the
-- vulnerability record (the finding outlives the run that found it). All
-- existing rows get NULL automatically.
-- =============================================================================

ALTER TABLE findings ADD COLUMN IF NOT EXISTS scan_id TEXT REFERENCES scans(id) ON DELETE SET NULL;

-- Per-scan drill-down (GET /scans/:id/findings → WHERE scan_id = $1).
CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings (scan_id);

-- DAST-only vulnerabilities list (WHERE org_id = ? AND scan_id IS NOT NULL).
-- Partial index keeps it small — only DAST-attributed rows are indexed.
CREATE INDEX IF NOT EXISTS idx_findings_org_scan
    ON findings (org_id, scan_id)
    WHERE scan_id IS NOT NULL;
