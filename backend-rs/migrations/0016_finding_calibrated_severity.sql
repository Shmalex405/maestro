-- =============================================================================
-- Calibrated severity (severity-calibrator agent output) — Shape A follow-up
-- =============================================================================
--
-- Adds three nullable columns to `findings` so the severity-calibrator's
-- per-finding output can be persisted alongside the scanner's original
-- severity. The dashboard renders calibrated as the primary value (via
-- COALESCE) and shows the original alongside when they differ.
--
-- Semantics:
--   calibrated_severity      — the post-calibration value. NULL when the
--                              calibrator didn't run, or when the rule
--                              kept the original (no delta). The list /
--                              stats endpoints use COALESCE(calibrated_severity, severity)
--                              so a NULL transparently falls back.
--   calibration_rule         — which of the 6 calibration rules fired
--                              (free text — e.g. "Rule 1 — outcome anchored").
--                              Surfaced in the finding detail view.
--   calibration_justification — short prose explanation (e.g. "live-exploited
--                              as data dump", "JS-only, not loaded by FastAPI
--                              backend"). One sentence per finding.
--
-- All three are nullable on purpose — older assessments (pre-2026-05-21)
-- predate the calibrator agent, and assessments that skip calibration for
-- speed remain valid; their findings just render with original severity.
-- =============================================================================

ALTER TABLE findings
    ADD COLUMN IF NOT EXISTS calibrated_severity severity,
    ADD COLUMN IF NOT EXISTS calibration_rule TEXT,
    ADD COLUMN IF NOT EXISTS calibration_justification TEXT;

-- Index supports the COALESCE-based severity filter on /findings/stats.
-- Without it the by_severity tile counts would do a sequential scan once
-- the table grows beyond a few thousand rows. Partial — only indexes
-- rows where calibration actually exists, since the COALESCE only
-- matters there.
CREATE INDEX IF NOT EXISTS findings_calibrated_severity_idx
    ON findings (calibrated_severity)
    WHERE calibrated_severity IS NOT NULL;
