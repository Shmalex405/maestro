-- 0010_projects_status_backfill.sql
--
-- Bug fix for Shmalex405/kali-mcp-pentest-infra#18:
--   GET /api/v1/projects?status=active returned [] even though
--   GET /api/v1/projects returned 5+ projects with status="active" in
--   the response body. Root cause: the response serializer
--   (schemas/project.rs::ProjectResponse::from_row) defaults NULL →
--   "active", but the column itself was NULL for every legacy row, so
--   `WHERE status = 'active'::projectstatus` never matched. Symptom:
--   newly-created projects didn't appear in the Maestro desktop
--   sidebar because the sidebar query asked for status=active.
--
-- This migration:
--   1. Backfills every NULL projects.status to 'active' so the table
--      matches what the response has always claimed.
--   2. Enforces NOT NULL going forward so this can't drift again. The
--      column already has DEFAULT 'active' from 0001_initial.sql, so
--      no INSERT path can produce NULL accidentally as long as it
--      omits the column. Defensive: routes/projects.rs::create_project
--      now also passes status explicitly.
--
-- Safe to run on prod: the UPDATE only touches NULL rows, then the
-- ALTER will succeed because no NULLs remain.

UPDATE projects SET status = 'active' WHERE status IS NULL;

ALTER TABLE projects ALTER COLUMN status SET NOT NULL;
