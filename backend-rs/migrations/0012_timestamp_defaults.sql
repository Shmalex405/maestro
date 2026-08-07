-- 0012_timestamp_defaults.sql
--
-- Restore DB-side DEFAULT NOW() on every created_at/updated_at column.
--
-- The prod tables were originally created by the Python backend's
-- SQLAlchemy models, which used Python-side defaults
-- (`default=lambda: datetime.now(timezone.utc)`) rather than DB-side
-- DEFAULT NOW(). When backend-rs took over, its INSERTs simply omit
-- created_at / updated_at and rely on the column default — which
-- doesn't exist on the inherited tables. The result: every row
-- inserted via backend-rs has NULL timestamps, which the frontend
-- renders as "Jan 1, 1970" via new Date(null).
--
-- The 0001_initial.sql migration *does* declare DEFAULT NOW() on these
-- columns, but it's wrapped in `CREATE TABLE IF NOT EXISTS …`, so on
-- prod where the tables already existed it was a no-op.
--
-- Fix: ALTER each column to add the missing default, then backfill any
-- existing NULL rows so the UI stops showing the epoch for old data.
-- Backfill preference: keep the existing value if any, else use
-- updated_at (so created_at lines up with the row's last write rather
-- than the migration time), else NOW().

ALTER TABLE reports        ALTER COLUMN created_at SET DEFAULT NOW();
ALTER TABLE reports        ALTER COLUMN updated_at SET DEFAULT NOW();
ALTER TABLE assessments    ALTER COLUMN created_at SET DEFAULT NOW();
ALTER TABLE assessments    ALTER COLUMN updated_at SET DEFAULT NOW();
ALTER TABLE findings       ALTER COLUMN created_at SET DEFAULT NOW();
ALTER TABLE findings       ALTER COLUMN updated_at SET DEFAULT NOW();
ALTER TABLE projects       ALTER COLUMN created_at SET DEFAULT NOW();
ALTER TABLE projects       ALTER COLUMN updated_at SET DEFAULT NOW();
ALTER TABLE organizations  ALTER COLUMN created_at SET DEFAULT NOW();
ALTER TABLE organizations  ALTER COLUMN updated_at SET DEFAULT NOW();
ALTER TABLE users          ALTER COLUMN created_at SET DEFAULT NOW();
ALTER TABLE users          ALTER COLUMN updated_at SET DEFAULT NOW();
ALTER TABLE conversations  ALTER COLUMN created_at SET DEFAULT NOW();
ALTER TABLE conversations  ALTER COLUMN updated_at SET DEFAULT NOW();
ALTER TABLE chat_messages  ALTER COLUMN created_at SET DEFAULT NOW();
ALTER TABLE audit_logs     ALTER COLUMN created_at SET DEFAULT NOW();

-- Backfill NULL rows. For tables that have both columns, populate
-- updated_at first so the COALESCE on created_at can prefer it.
UPDATE reports        SET updated_at = COALESCE(updated_at, NOW());
UPDATE reports        SET created_at = COALESCE(created_at, updated_at);
UPDATE assessments    SET updated_at = COALESCE(updated_at, NOW());
UPDATE assessments    SET created_at = COALESCE(created_at, updated_at);
UPDATE findings       SET updated_at = COALESCE(updated_at, NOW());
UPDATE findings       SET created_at = COALESCE(created_at, updated_at);
UPDATE projects       SET updated_at = COALESCE(updated_at, NOW());
UPDATE projects       SET created_at = COALESCE(created_at, updated_at);
UPDATE organizations  SET updated_at = COALESCE(updated_at, NOW());
UPDATE organizations  SET created_at = COALESCE(created_at, updated_at);
UPDATE users          SET updated_at = COALESCE(updated_at, NOW());
UPDATE users          SET created_at = COALESCE(created_at, updated_at);
UPDATE conversations  SET updated_at = COALESCE(updated_at, NOW());
UPDATE conversations  SET created_at = COALESCE(created_at, updated_at);
UPDATE chat_messages  SET created_at = COALESCE(created_at, NOW());
UPDATE audit_logs     SET created_at = COALESCE(created_at, NOW());
