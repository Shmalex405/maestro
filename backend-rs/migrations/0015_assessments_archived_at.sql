-- 0015_assessments_archived_at.sql
--
-- Soft-delete for assessments. The user "closes out" assessments
-- when a run finishes, which today goes through DELETE FROM assessments
-- — wiping the row outright. That removes the historical record of
-- "we ran this engagement, here's when it happened", which the user
-- wants to keep for tracking.
--
-- This migration adds an archived_at timestamp that captures soft-
-- deletion without losing the row. The companion code change in
-- routes/assessments.rs:
--   - DELETE handler now sets archived_at = NOW() instead of removing
--     the row outright.
--   - list_assessments filters `archived_at IS NULL` by default; the
--     dashboard passes `include_archived=true` so closed-out runs
--     stay visible in the Recent Assessments rail.
--
-- Reports already survive assessment delete via migration 0011 (FK
-- with ON DELETE SET NULL). Archiving is strictly a softer behavior
-- for the assessments row itself — reports were never the issue.

ALTER TABLE assessments ADD COLUMN IF NOT EXISTS archived_at TIMESTAMPTZ;
CREATE INDEX IF NOT EXISTS assessments_archived_at_idx
    ON assessments (archived_at)
    WHERE archived_at IS NOT NULL;
