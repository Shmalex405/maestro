-- =============================================================================
-- Expand `assessmenttype` enum to match the frontend's AssessmentType.
-- =============================================================================
--
-- The original enum (migrations/0001_initial.sql) shipped with 7 values, but
-- the desktop wizard's TypeScript `AssessmentType` (frontend/lib/types.ts)
-- declares 11. The four missing values caused `POST /assessments` to 500
-- whenever the user picked a capability that mapped to one of them:
--
--   - api_security      — single-cap "API" pick
--   - cloud_assessment  — single-cap "Cloud" pick
--   - combined          — multi-cap pick (Web + API, Web + Cloud, etc.)
--   - custom            — assessment_config-driven runs
--
-- The SQL cast `$2::assessmenttype` in routes/assessments.rs rejected those
-- strings with "invalid input value for enum", which sqlx surfaced as a
-- `Database` error that error.rs deliberately masks behind a generic
-- "Internal server error" detail. Users saw a 500 with no actionable info.
--
-- `ADD VALUE IF NOT EXISTS` is idempotent and supported on Postgres 9.6+,
-- so this migration is safe to re-run if anything ever rolls it back.
-- It also runs outside a transaction implicitly (Postgres enforces this for
-- ALTER TYPE ADD VALUE), which is why each statement is its own line — sqlx
-- migrate splits on `;` and executes each separately.

ALTER TYPE assessmenttype ADD VALUE IF NOT EXISTS 'api_security';
ALTER TYPE assessmenttype ADD VALUE IF NOT EXISTS 'cloud_assessment';
ALTER TYPE assessmenttype ADD VALUE IF NOT EXISTS 'combined';
ALTER TYPE assessmenttype ADD VALUE IF NOT EXISTS 'custom';
