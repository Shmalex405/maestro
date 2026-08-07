-- 0011_reports_keep_after_assessment_delete.sql
--
-- Reports are durable artifacts; assessments are ephemeral runtime
-- containers. The previous behavior (0009 added ON DELETE CASCADE to
-- reports.assessment_id) deleted every report whenever a user cleaned
-- up an old assessment — which surprised the user on 2026-05-18 when
-- the 2 PDFs we'd manually uploaded earlier in the evening vanished
-- the moment they deleted the parent assessment.
--
-- This migration:
--   1. Drops the NOT NULL constraint on reports.assessment_id so the
--      column can hold orphan rows after the assessment is gone.
--   2. Replaces the CASCADE foreign key with SET NULL so deleting an
--      assessment leaves its reports intact, with assessment_id flipped
--      to NULL. The Reports page is org-scoped, not assessment-scoped,
--      so orphan reports still list normally.
--
-- Companion changes in the same commit:
--   - models/report.rs::Report.assessment_id is now Option<String>
--   - schemas/report.rs::ReportResponse.assessment_id is Option<String>
--   - ReportCreate.assessment_id stays required at create time (it's
--     still useful as provenance metadata, just no longer load-bearing
--     for the row's survival).
--
-- Findings still cascade with the assessment (0009 left that alone) —
-- intentional for now; if the user later asks for findings to also
-- persist past assessment delete, a parallel migration would mirror
-- this pattern on findings.assessment_id.

ALTER TABLE reports ALTER COLUMN assessment_id DROP NOT NULL;

ALTER TABLE reports DROP CONSTRAINT IF EXISTS reports_assessment_id_fkey;
ALTER TABLE reports
    ADD CONSTRAINT reports_assessment_id_fkey
    FOREIGN KEY (assessment_id) REFERENCES assessments(id) ON DELETE SET NULL;
