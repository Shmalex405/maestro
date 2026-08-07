-- =============================================================================
-- Remediation / "patched" tracking on findings. 2026-06-21
-- =============================================================================
--
-- We already dedup a vulnerability to a single row per (fingerprint, org_id)
-- and bump last_seen_at / occurrence_count on every re-confirmation. What we
-- did NOT capture was the inverse: a finding that WAS exploitable in a prior
-- run and, on re-test, no longer reproduces ("appears patched / NOT
-- EXPLOITABLE"). The create_finding upsert overwrites `exploitable` true→false
-- in place, so that remediation transition was silently lost — the dashboard
-- couldn't tell "fixed since last run" from "never confirmed".
--
-- These nullable columns capture the transition at upsert time (see the
-- ON CONFLICT branch in routes/findings.rs::create_finding). They are computed
-- purely from the existing-row vs incoming `exploitable` values — no new bind
-- parameters, no behavior change for findings that never flip:
--
--   remediated_at               — NOW() at the moment exploitable went
--                                 ('true'|'potentially') → 'false'. Cleared
--                                 back to NULL on regression (it came back
--                                 exploitable in a later run).
--   prior_exploitable           — the exploitable value the finding HELD before
--                                 being patched ('true' | 'potentially'), so the
--                                 UI can say "was fully exploited, now fixed".
--   remediated_in_assessment_id — the assessment whose re-test proved the fix.
--
-- A finding is "remediated/patched" iff remediated_at IS NOT NULL. We do NOT
-- auto-mutate `status` (open/in_progress/accepted) — that field stays the
-- user's manual triage state; remediation is a separate, derived signal.
-- =============================================================================

ALTER TABLE findings ADD COLUMN IF NOT EXISTS remediated_at TIMESTAMPTZ;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS prior_exploitable TEXT;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS remediated_in_assessment_id TEXT;

-- Powers the "Remediated" tab filter + stats count (remediated_at IS NOT NULL).
CREATE INDEX IF NOT EXISTS findings_remediated_idx
    ON findings (org_id, remediated_at)
    WHERE remediated_at IS NOT NULL;
