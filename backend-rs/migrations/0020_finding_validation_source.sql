-- =============================================================================
-- Finding validation source (Phase 3 of caching plan) — 2026-05-22
-- =============================================================================
--
-- Adds three columns to `findings` so the crossval-qa agent can record
-- whether each finding was:
--   - VALIDATED_FROM_BASELINE: a prior assessment validated it, and the
--     baseline-aware decision tree said "trust that result; don't re-test"
--   - RE_VALIDATED: actively re-tested in this run, regardless of baseline
--   - NEW_FINDING: discovered for the first time in this assessment
--
-- This is what makes the cache *visible* in the report: the assessment
-- writeup can show which findings were re-confirmed vs. trusted from
-- the prior run, which closes the accountability gap that would
-- otherwise make caching feel like "did we actually test this or not?"
--
-- Defaults to NULL on existing rows (pre-Phase 3 assessments don't have
-- this concept). Going forward, crossval-qa MUST populate it on every
-- finding it touches; the no-skip enforcement at report-writer time
-- treats NULL as "not yet evaluated" and flags it as a bug.
-- =============================================================================

-- PostgreSQL ENUM types — declared at the schema level, so add via
-- CREATE TYPE before column ADD.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'validationsource') THEN
        CREATE TYPE validationsource AS ENUM (
            'RE_VALIDATED',
            'VALIDATED_FROM_BASELINE',
            'NEW_FINDING'
        );
    END IF;
END$$;

ALTER TABLE findings
    -- crossval-qa output. NULL when calibration didn't run (pre-Phase 3
    -- assessments, or quick scans that skip cross-validation).
    ADD COLUMN IF NOT EXISTS validation_source validationsource,
    -- When VALIDATED_FROM_BASELINE, points to the assessment whose
    -- evidence we're trusting. Useful for "show me the actual exploit
    -- proof" links in the report. No FK because soft-deleted (archived)
    -- assessments should keep their references intact for audit.
    ADD COLUMN IF NOT EXISTS prior_assessment_id TEXT,
    -- Human-readable explanation of the skip decision (e.g., "validated
    -- 7 days ago, no code change in src/auth/login.py, severity below
    -- threshold"). Surfaced verbatim in the report so the reader can
    -- judge whether to trust the cached result.
    ADD COLUMN IF NOT EXISTS baseline_skip_reason TEXT;

-- Composite index supports the report-writer's per-assessment query:
-- "list all VALIDATED_FROM_BASELINE findings so I can render them in
-- the cache-reuse summary table". Partial — only indexes rows that
-- actually have a validation_source set, since the COALESCE-with-NULL
-- query plan benefits from skipping pre-Phase 3 rows.
CREATE INDEX IF NOT EXISTS findings_validation_source_idx
    ON findings (assessment_id, validation_source)
    WHERE validation_source IS NOT NULL;

-- Lookup index: "show me all findings that were ever validated from
-- this baseline" — useful for the drift-detection cron in Phase 6.4.
CREATE INDEX IF NOT EXISTS findings_prior_assessment_idx
    ON findings (prior_assessment_id)
    WHERE prior_assessment_id IS NOT NULL;
