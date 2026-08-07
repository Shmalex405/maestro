-- 0013_reports_medium_low_counts.sql
--
-- The MCP server's report-creation payload includes medium_count and
-- low_count alongside critical/high — both for the Reports page stat
-- chips and so the table is the single source of truth for severity
-- totals without a separate findings fetch.
--
-- The reports table inherited from the Python backend never had these
-- columns (only critical/high/exploitable), so the values were silently
-- dropped on INSERT. The frontend reads them back, gets undefined, and
-- shows "—" or 0 in the per-row stat chips.
--
-- This migration adds the columns with a 0 default so existing rows
-- become consistent with the implied (incorrect-but-tolerable) state
-- they were already in. The companion code change in
-- routes/reports.rs binds the values on INSERT going forward.

ALTER TABLE reports ADD COLUMN IF NOT EXISTS medium_count INTEGER DEFAULT 0;
ALTER TABLE reports ADD COLUMN IF NOT EXISTS low_count INTEGER DEFAULT 0;
