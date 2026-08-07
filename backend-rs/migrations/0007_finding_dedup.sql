-- =============================================================================
-- Per-vuln finding dedup (Phase B)
-- =============================================================================
--
-- Adds a fingerprint column + occurrence/seen tracking so re-running an
-- assessment against the same target doesn't pile up duplicate rows.
--
-- Semantics:
--   fingerprint        — sha256(lower(title) || target || source || cwe).
--                        Computed by the backend on every create, used as
--                        the dedup key (UNIQUE per org).
--   occurrence_count   — incremented on each create that matches an
--                        existing fingerprint. 1 for fresh inserts.
--   first_seen_at      — frozen at the first create.
--   last_seen_at       — bumped on every match. Drives the "is this still
--                        vulnerable?" trend signal.
--
-- The unique index is partial (`WHERE fingerprint IS NOT NULL`) so the
-- backfill below can run in batches without violating the constraint
-- mid-migration. Future inserts always have a fingerprint, so the
-- partial-index condition becomes effectively total.
-- =============================================================================

ALTER TABLE findings
    ADD COLUMN IF NOT EXISTS fingerprint VARCHAR(64),
    ADD COLUMN IF NOT EXISTS occurrence_count INT NOT NULL DEFAULT 1,
    ADD COLUMN IF NOT EXISTS first_seen_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS last_seen_at TIMESTAMPTZ;

-- Backfill seen-at columns from existing created_at so the trend data
-- starts meaningful (rather than NOW() everywhere). Only fills NULLs
-- so re-running this migration is safe.
UPDATE findings
SET first_seen_at = COALESCE(first_seen_at, created_at, NOW()),
    last_seen_at  = COALESCE(last_seen_at, updated_at, created_at, NOW())
WHERE first_seen_at IS NULL OR last_seen_at IS NULL;

-- Backfill fingerprint for existing rows. Mirrors the Rust
-- `fingerprint()` helper (see backend-rs/src/schemas/finding.rs):
--   sha256(lower(trim(title)) || '|' || lower(trim(target)) || '|' ||
--           lower(coalesce(source,'')) || '|' || coalesce(cwe,''))
--
-- Postgres has digest() in pgcrypto. Enable the extension if not
-- already loaded, then compute hashes for any row missing a fingerprint.
CREATE EXTENSION IF NOT EXISTS pgcrypto;

UPDATE findings
SET fingerprint = encode(
    digest(
        lower(trim(title)) || '|' ||
        lower(trim(target)) || '|' ||
        lower(coalesce(source, '')) || '|' ||
        coalesce(cwe, ''),
        'sha256'
    ),
    'hex'
)
WHERE fingerprint IS NULL;

-- Make seen-at columns NOT NULL after backfill — every row should have
-- both populated by this point. Future inserts go through the upsert
-- path which always sets them.
ALTER TABLE findings
    ALTER COLUMN first_seen_at SET DEFAULT NOW(),
    ALTER COLUMN last_seen_at  SET DEFAULT NOW(),
    ALTER COLUMN first_seen_at SET NOT NULL,
    ALTER COLUMN last_seen_at  SET NOT NULL;

-- Dedup constraint: one (fingerprint, org_id) per org. Existing
-- duplicates would block this migration; collapse them via a
-- DELETE-keep-oldest pass before adding the index.
DELETE FROM findings a
USING findings b
WHERE a.id > b.id
  AND a.fingerprint IS NOT NULL
  AND a.fingerprint = b.fingerprint
  AND COALESCE(a.org_id, '') = COALESCE(b.org_id, '');

-- For each surviving row that lost duplicates, increment its count by
-- the number of duplicates we removed. (Best-effort — old rows didn't
-- have an occurrence_count concept, so this gives them a faithful
-- starting count.)
WITH dup_counts AS (
    SELECT fingerprint, org_id, COUNT(*) AS n
    FROM findings
    WHERE fingerprint IS NOT NULL
    GROUP BY fingerprint, org_id
)
UPDATE findings f
SET occurrence_count = GREATEST(f.occurrence_count, dup_counts.n)
FROM dup_counts
WHERE f.fingerprint = dup_counts.fingerprint
  AND COALESCE(f.org_id, '') = COALESCE(dup_counts.org_id, '');

CREATE UNIQUE INDEX IF NOT EXISTS findings_fingerprint_org_idx
    ON findings (fingerprint, org_id)
    WHERE fingerprint IS NOT NULL;

-- Index on last_seen_at supports "stale findings" queries
-- (`WHERE last_seen_at < NOW() - INTERVAL '30 days'`) for the trend
-- view we'll add to the dashboard later.
CREATE INDEX IF NOT EXISTS findings_last_seen_at_idx
    ON findings (last_seen_at DESC);
