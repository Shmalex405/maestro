-- =============================================================================
-- Target identity layer (Phase 2 of caching plan) — 2026-05-22
-- =============================================================================
--
-- Adds a normalized `targets` table so the cross-assessment caching layers
-- (baseline-aware findings, SAST cache, recon delta) can key off a stable
-- `target_id` instead of the raw `targets` JSONB array on assessments.
--
-- WHY THIS EXISTS:
--   Today: `assessments.targets` is JSONB like `["https://example.com",
--   "10.0.0.0/24"]` and `findings.target` is the raw string. There's no
--   stable concept of "the same target across multiple assessments" —
--   minor variations (trailing slash, default port, www. prefix) split
--   what should be one logical target into many.
--
--   Caching needs target identity to ask "what did we find on this target
--   last week?". Without target_id, we can't.
--
-- DEPLOYMENT NOTE — DO NOT AUTO-APPLY YET:
--   This migration creates new infrastructure but DOES NOT delete the
--   existing JSONB columns. Applying it is safe (additive). However, the
--   backfill at the bottom does a one-time pass over existing findings
--   and assessments to populate the new normalized rows. On a customer
--   with 10K+ findings, that backfill could take 30-60 seconds.
--
--   Recommended rollout:
--     1. Apply this migration to staging FIRST
--     2. Run the dry-run report (see comments below) to see what target
--        collisions / canonicalization changes would happen
--     3. Review report manually
--     4. Apply to prod, monitoring `targets` row count + collision rate
--     5. Once Phase 3-5 endpoints land, deprecate `assessments.targets`
--        in a later migration (Phase 7+)
--
-- SCHEMA:
--   targets       — normalized target rows, one per logical target per org
--   target_ids    — JSONB on assessments listing this assessment's targets
--   target_id     — FK on findings pointing at the canonical target
--
-- CANONICALIZATION:
--   The `targets.canonical_value` column holds the output of the shared
--   target_canonical helper (see backend-rs/src/util/target_canonical.rs
--   and mcp-server/src/integrations/finding-fingerprint.ts). The fingerprint
--   is SHA256(org_id|target_type|canonical_value), keyed UNIQUE per org.
--
--   Rules (mirror both implementations exactly):
--     web:           lowercase host, strip default ports (80/443), normalize
--                    trailing slashes, sort query params, lowercase scheme
--     host:          lowercase, no port
--     cidr:          normalized CIDR notation
--     repo:          git URL → HTTPS form, trailing .git stripped,
--                    lowercase host
--     cloud_account: provider + ":" + account_id
-- =============================================================================

CREATE TABLE IF NOT EXISTS targets (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL,

    /* Target classification — determines which canonicalizer runs. */
    target_type TEXT NOT NULL CHECK (target_type IN (
        'web',
        'host',
        'cidr',
        'repo',
        'cloud_account'
    )),

    /* Normalized form (post-canonicalization). One per (org_id, target_type, canonical_value). */
    canonical_value TEXT NOT NULL,

    /* All raw input strings that resolved to this canonical. Helps the
       desktop show "you've also called this target 'example.com:443/'" etc.
       Stored as a JSONB array of strings. */
    raw_values JSONB NOT NULL DEFAULT '[]',

    /* SHA256(org_id || '|' || target_type || '|' || canonical_value).
       Keyed UNIQUE per org so cross-org lookups can never collide. */
    fingerprint TEXT NOT NULL,

    /* Per-target_type extra context that downstream caches need:
         web   → { "scheme": "https", "host": "example.com", "port": null }
         repo  → { "git_url": "https://github.com/org/repo", "default_branch": "main" }
         cloud → { "provider": "aws", "account_id": "1234..." }
       Stored as JSONB so we can extend without migrations. */
    metadata JSONB NOT NULL DEFAULT '{}',

    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    archived_at TIMESTAMPTZ,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Unique per org: one canonical target per (org_id, fingerprint). The
-- partial index excludes archived rows so re-adding an old target after
-- archival works cleanly.
CREATE UNIQUE INDEX IF NOT EXISTS targets_org_fingerprint_idx
    ON targets (org_id, fingerprint)
    WHERE archived_at IS NULL;

-- Fast lookup: "list all repo-type targets for org X"
CREATE INDEX IF NOT EXISTS targets_org_type_idx
    ON targets (org_id, target_type)
    WHERE archived_at IS NULL;

-- Fast lookup: "show recent targets"
CREATE INDEX IF NOT EXISTS targets_last_seen_idx
    ON targets (last_seen_at DESC)
    WHERE archived_at IS NULL;

-- ─── findings.target_id ──────────────────────────────────────────────
-- Add nullable column first (existing rows have NULL until backfill).
-- The Phase 3+ endpoints (GET /findings/baseline?target_id=X) require
-- this column to be populated.

ALTER TABLE findings
    ADD COLUMN IF NOT EXISTS target_id TEXT REFERENCES targets(id);

CREATE INDEX IF NOT EXISTS findings_target_id_idx
    ON findings (target_id)
    WHERE target_id IS NOT NULL;

-- ─── assessments.target_ids ──────────────────────────────────────────
-- JSONB array of target_id strings (parallel to existing targets JSONB).
-- The existing targets JSONB stays unchanged for backward compat — the
-- Tauri command path still writes to it. New code (Phase 3+) reads
-- target_ids.

ALTER TABLE assessments
    ADD COLUMN IF NOT EXISTS target_ids JSONB NOT NULL DEFAULT '[]';

CREATE INDEX IF NOT EXISTS assessments_target_ids_gin_idx
    ON assessments USING GIN (target_ids);

-- ─── Backfill (one-time pass) ────────────────────────────────────────
--
-- Walks existing assessments + findings and populates the new tables.
-- Idempotent: only writes rows that don't exist; only updates findings
-- where target_id IS NULL.
--
-- LIMITATION: The SQL canonicalization here is a SIMPLIFIED form of the
-- Rust helper (it can't run the full URL parsing in SQL). For canonical
-- equivalence, the Rust application should re-run the backfill on
-- startup using the full target_canonical helper. This SQL pass is a
-- "good enough" first cut so the new tables aren't empty post-migration.
--
-- The simplified SQL canonicalizer:
--   web/host → lower(trim(target))
--   repo     → lower(trim(target))
--   cidr     → trim(target) (already normalized by ipaddr crate upstream)
--   cloud    → not backfilled (no existing rows have this type)

-- Step 1: extract distinct (org_id, target) pairs from findings
-- Step 2: classify each as web/host/cidr/repo (best-effort guess)
-- Step 3: upsert into targets table
-- Step 4: link findings.target_id

WITH distinct_targets AS (
    SELECT DISTINCT
        COALESCE(org_id, '') AS org_id,
        target AS raw_target,
        CASE
            WHEN target ~* '^(https?|ws|wss)://' THEN 'web'
            WHEN target ~* '^(git@|ssh://|https://github\.com|https://gitlab\.com|/mnt/host-home)' THEN 'repo'
            WHEN target ~ '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$' THEN 'cidr'
            ELSE 'host'
        END AS target_type
    FROM findings
    WHERE target IS NOT NULL AND target != ''
),
canonicalized AS (
    SELECT
        org_id,
        raw_target,
        target_type,
        -- Simplified canonical (lowercase, trim). Full canonicalization
        -- happens in the Rust app at startup. SQL ~= "best effort".
        lower(trim(raw_target)) AS canonical_value,
        encode(
            digest(
                COALESCE(org_id, '') || '|' || target_type || '|' || lower(trim(raw_target)),
                'sha256'
            ),
            'hex'
        ) AS fingerprint
    FROM distinct_targets
)
INSERT INTO targets (
    id, org_id, target_type, canonical_value, raw_values,
    fingerprint, metadata, first_seen_at, last_seen_at,
    created_at, updated_at
)
SELECT
    gen_random_uuid()::text,
    org_id,
    target_type,
    canonical_value,
    jsonb_build_array(raw_target),
    fingerprint,
    '{"backfill":"sql-simplified","needs_rust_repair":true}'::jsonb,
    NOW(),
    NOW(),
    NOW(),
    NOW()
FROM canonicalized
ON CONFLICT (org_id, fingerprint) WHERE archived_at IS NULL
DO UPDATE SET
    raw_values = (
        SELECT jsonb_agg(DISTINCT v)
        FROM jsonb_array_elements_text(
            targets.raw_values || EXCLUDED.raw_values
        ) AS v
    ),
    last_seen_at = NOW(),
    updated_at = NOW();

-- Step 4: link findings to their newly-created targets
UPDATE findings f
SET target_id = t.id
FROM targets t
WHERE f.target_id IS NULL
  AND t.canonical_value = lower(trim(f.target))
  AND COALESCE(t.org_id, '') = COALESCE(f.org_id, '')
  AND t.archived_at IS NULL;

-- Step 5: populate assessments.target_ids from each assessment's findings
WITH assessment_targets AS (
    SELECT
        a.id AS assessment_id,
        jsonb_agg(DISTINCT f.target_id) FILTER (WHERE f.target_id IS NOT NULL) AS tids
    FROM assessments a
    LEFT JOIN findings f ON f.assessment_id = a.id
    GROUP BY a.id
)
UPDATE assessments a
SET target_ids = COALESCE(at.tids, '[]'::jsonb)
FROM assessment_targets at
WHERE a.id = at.assessment_id
  AND a.target_ids = '[]'::jsonb;

-- ─── Dry-run report (run separately to inspect backfill quality) ─────
-- The following SELECTs are NOT executed by the migration but documented
-- here so operators can verify backfill quality before going live:
--
--   -- 1. Count distinct targets created per org:
--   SELECT org_id, target_type, COUNT(*) FROM targets GROUP BY 1, 2 ORDER BY 1, 2;
--
--   -- 2. Findings still missing target_id (should be 0 after backfill):
--   SELECT COUNT(*) FROM findings WHERE target_id IS NULL;
--
--   -- 3. Targets needing Rust-side re-canonicalization (the metadata
--   --    flag is set by the simplified SQL pass above; the Rust app on
--   --    next startup walks these rows and applies full canonicalization,
--   --    potentially merging duplicates):
--   SELECT COUNT(*) FROM targets
--   WHERE metadata->>'needs_rust_repair' = 'true';
--
--   -- 4. Cross-check: same canonical, different fingerprint = bug:
--   SELECT canonical_value, target_type, org_id, COUNT(*) FROM targets
--   GROUP BY 1, 2, 3 HAVING COUNT(*) > 1;
