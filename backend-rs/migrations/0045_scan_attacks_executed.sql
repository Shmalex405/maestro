-- 0045: runtime attack volume on a scan ("attacks executed").
--
-- The 234-technique catalog is the menu; this is the bill. The deterministic
-- pipeline now reports the real number of HTTP requests fired at the target,
-- plus a per-tool breakdown, so the Scheduled DAST → Scans Statistics view can
-- show the apples-to-apples figure (vs other DAST tools that report "N attacks
-- per scan"). `attacks_estimated` is true when any contributing tool's count
-- was a calibrated estimate rather than a measured value.

ALTER TABLE scans ADD COLUMN IF NOT EXISTS attacks_executed INT NOT NULL DEFAULT 0;
ALTER TABLE scans ADD COLUMN IF NOT EXISTS attacks_estimated BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE scans ADD COLUMN IF NOT EXISTS attacks_by_tool JSONB NOT NULL DEFAULT '{}';
