-- =============================================================================
-- Cascade assessment deletes through findings + reports.
-- =============================================================================
--
-- Before this migration, `DELETE FROM assessments WHERE id = $1` would 500
-- whenever the assessment had findings or reports — the two child tables
-- had plain `REFERENCES assessments(id)` FKs with no cascade behavior, so
-- Postgres rejected the parent delete with `findings_assessment_id_fkey`
-- / `reports_assessment_id_fkey` constraint violations. The desktop UI
-- offered no way to recover except deleting each finding by hand first.
--
-- Other child tables already cascade correctly:
--   - assessment_events  → ON DELETE CASCADE  (0001 + 0004)
--   - scan_snapshots     → ON DELETE CASCADE  (0003)
--   - imports.linked_assessment_id → ON DELETE SET NULL (preserves import)
--   - conversations.assessment_id  → ON DELETE SET NULL (keeps chat history)
--
-- For findings and reports, CASCADE is the right semantics: both are
-- conceptually owned by the assessment (vulns scoped to a run, the run's
-- final report). Deleting the parent without them would leave orphaned
-- rows pointing at a non-existent assessment id.
--
-- The rename-drop-add pattern is required because Postgres has no
-- `ALTER CONSTRAINT … ON DELETE CASCADE` syntax for foreign keys.

-- findings.assessment_id ----------------------------------------------------
ALTER TABLE findings DROP CONSTRAINT IF EXISTS findings_assessment_id_fkey;
ALTER TABLE findings
    ADD CONSTRAINT findings_assessment_id_fkey
    FOREIGN KEY (assessment_id) REFERENCES assessments(id) ON DELETE CASCADE;

-- reports.assessment_id -----------------------------------------------------
ALTER TABLE reports DROP CONSTRAINT IF EXISTS reports_assessment_id_fkey;
ALTER TABLE reports
    ADD CONSTRAINT reports_assessment_id_fkey
    FOREIGN KEY (assessment_id) REFERENCES assessments(id) ON DELETE CASCADE;
