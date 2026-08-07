-- =============================================================================
-- Live scan progress + coverage telemetry (Scheduled DAST Phase 3). 2026-06-23
-- =============================================================================
--
-- Until now a scan row was written once, AFTER the deterministic pipeline
-- finished — so the Scans view could only ever show completed runs. These
-- columns let the pipeline create the row at START (status 'running') and emit
-- throttled progress heartbeats, so the UI shows a live progress bar + the
-- current phase, and test-coverage (tests_done / tests_total) per run.
--
-- All additive + defaulted; existing rows read as 0 / NULL (already finished).
-- =============================================================================

ALTER TABLE scans ADD COLUMN IF NOT EXISTS progress_pct INT NOT NULL DEFAULT 0;
-- Current pipeline phase + the specific test/activity in flight.
ALTER TABLE scans ADD COLUMN IF NOT EXISTS phase TEXT;
ALTER TABLE scans ADD COLUMN IF NOT EXISTS current_activity TEXT;
-- Coverage: how many of the in-scope tests have run.
ALTER TABLE scans ADD COLUMN IF NOT EXISTS tests_total INT NOT NULL DEFAULT 0;
ALTER TABLE scans ADD COLUMN IF NOT EXISTS tests_done  INT NOT NULL DEFAULT 0;
