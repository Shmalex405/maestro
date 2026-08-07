-- Add created_at / updated_at to assessments.
--
-- The frontend `Assessment` type has always expected these fields and
-- the sidebar's relative-time formatter ("Just now", "5m", "2h"…) reads
-- them via `assessment.updated_at || assessment.created_at`. The
-- original 0001 migration only added `started_at` / `completed_at`,
-- which left the sidebar showing "Invalid Date" for fresh rows.
--
-- Backfill strategy:
--   - existing rows: created_at  = COALESCE(started_at, NOW())
--                    updated_at  = COALESCE(started_at, NOW())
--   - new rows:       DEFAULT NOW() (set on INSERT if not bound)
--
-- The CREATE OR REPLACE TRIGGER keeps updated_at fresh on every UPDATE.

ALTER TABLE assessments
    ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

-- Backfill: pre-existing rows had only started_at populated. The DEFAULT
-- NOW() above already filled created_at/updated_at with the migration
-- run-time, so override with started_at where it's older to preserve
-- chronological ordering in the sidebar.
UPDATE assessments
SET created_at = started_at,
    updated_at = COALESCE(completed_at, started_at)
WHERE started_at IS NOT NULL;

-- Auto-bump updated_at on UPDATE. Every PATCH /assessments/<id> sets
-- this implicitly so the sidebar's relative-time stays current without
-- the route handler having to bind it manually.
CREATE OR REPLACE FUNCTION assessments_set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS assessments_set_updated_at_trigger ON assessments;
CREATE TRIGGER assessments_set_updated_at_trigger
    BEFORE UPDATE ON assessments
    FOR EACH ROW
    EXECUTE FUNCTION assessments_set_updated_at();
