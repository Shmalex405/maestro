-- =============================================================================
-- Scan run history — continuous-DAST foundation (consolidation-roadmap Phase 0)
-- 2026-06-08
-- =============================================================================
--
-- One row per deterministic/scheduled scan run, keyed per (org, target). This is
-- the run-history spine that makes "new vs fixed since last scan" trends
-- computable (the findings dedup substrate — fingerprint / first_seen_at /
-- last_seen_at / occurrence_count from 0007 — supplies the actual deltas; this
-- table anchors the timestamps + frozen severity counts per run).
--
-- WHY A NEW TABLE (vs scan_snapshots / assessments):
--   - `scan_snapshots` (0003) is an assessment-tied, user-triggered severity-count
--     freeze — not a per-target run log.
--   - `assessments` is the heavy, LLM-driven full assessment record.
--   A continuous scan is the cheap DETERMINISTIC pipeline (runDeterministic — no
--   inner LLM, ~$0 Anthropic) run on a schedule. It needs its own lightweight
--   run record, distinct from a full assessment, so the deterministic tier can
--   run often and cheaply while the LLM exploitation stays on-demand.
--
-- Two-engine model: `scan_type='deterministic'` + `trigger_kind='scheduled'` rows
-- are the cheap continuous DAST (Rapid7 InsightAppSec / StackHawk class); the
-- on-demand LLM exploitation is recorded elsewhere (assessments) and is where
-- tokens are spent intentionally.
-- =============================================================================

CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL,
    target_id TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,

    /* Nullable: a scheduled deterministic scan is not necessarily a full
       assessment. When it is part of one, link it. */
    assessment_id TEXT,

    /* What ran. 'deterministic' = the cheap continuous pipeline. */
    scan_type TEXT NOT NULL
        CHECK (scan_type IN ('dast', 'sast', 'full', 'deterministic')),

    /* How it was kicked off. (Avoids the reserved word `trigger`.) */
    trigger_kind TEXT NOT NULL DEFAULT 'manual'
        CHECK (trigger_kind IN ('manual', 'scheduled', 'ci')),

    status TEXT NOT NULL DEFAULT 'completed'
        CHECK (status IN ('running', 'completed', 'failed')),

    /* Which scanners/tests ran this scan (e.g. ["nuclei","nikto","sqlmap"]). */
    scanner_set JSONB NOT NULL DEFAULT '[]',

    /* Frozen severity-bucket counts at scan end. */
    critical_count INTEGER NOT NULL DEFAULT 0,
    high_count INTEGER NOT NULL DEFAULT 0,
    medium_count INTEGER NOT NULL DEFAULT 0,
    low_count INTEGER NOT NULL DEFAULT 0,
    info_count INTEGER NOT NULL DEFAULT 0,
    total_count INTEGER NOT NULL DEFAULT 0,

    started_at TIMESTAMPTZ NOT NULL,
    finished_at TIMESTAMPTZ,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- History lookups + "what was the previous scan?" ordering, per target.
CREATE INDEX IF NOT EXISTS scans_target_idx
    ON scans (org_id, target_id, started_at DESC);
