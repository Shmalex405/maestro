-- 0014_reports_s3_key.sql
--
-- Adds the s3_key column so report PDFs can live in object storage
-- instead of being NULL-bytes-on-disk. The bytes go to the
-- per-customer S3 bucket (configured via the S3_BUCKET env var the
-- ECS task is launched with); the DB row only stores the key.
-- Downloads are served via short-lived presigned URLs, never directly
-- from the backend — the bucket is private with no public access.
--
-- Backwards-compatible: existing rows have s3_key = NULL. The
-- frontend falls back to the legacy local-file path for those, and a
-- one-shot backfill flow uploads them once the user opts in.

ALTER TABLE reports ADD COLUMN IF NOT EXISTS s3_key VARCHAR(1000);
