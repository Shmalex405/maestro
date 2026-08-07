-- Scheduled DAST: authed/unauthed scans + application-level (fan-out) schedules.
--
-- auth_mode: 'authed' applies the target's scan-config auth; 'unauthed' scans
-- anonymously. Both can coexist on one target (so the unique key includes it).
ALTER TABLE scan_schedules ADD COLUMN IF NOT EXISTS auth_mode TEXT NOT NULL DEFAULT 'authed';

-- application_id: a schedule may be keyed to an APPLICATION (fan out to all its
-- current targets at run time — dynamic) instead of a single target. Exactly one
-- of target_id / application_id is set.
ALTER TABLE scan_schedules ADD COLUMN IF NOT EXISTS application_id TEXT
    REFERENCES applications(id) ON DELETE CASCADE;
ALTER TABLE scan_schedules ALTER COLUMN target_id DROP NOT NULL;

-- Exactly one of target_id / application_id (XOR).
ALTER TABLE scan_schedules DROP CONSTRAINT IF EXISTS scan_schedules_target_xor_app;
ALTER TABLE scan_schedules ADD CONSTRAINT scan_schedules_target_xor_app
    CHECK ((target_id IS NOT NULL) <> (application_id IS NOT NULL));

-- Uniqueness now spans the scoped entity (target OR app) + scan_type + auth_mode,
-- so a target can have one authed + one unauthed schedule, and apps get their own.
DROP INDEX IF EXISTS scan_schedules_key_idx;
CREATE UNIQUE INDEX IF NOT EXISTS scan_schedules_key_idx
    ON scan_schedules (org_id, COALESCE(application_id, target_id), scan_type, auth_mode);
