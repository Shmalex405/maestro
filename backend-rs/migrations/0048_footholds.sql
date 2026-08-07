-- =============================================================================
-- Post-exploitation Layer C — the foothold / loot store. 2026-06-29
-- =============================================================================
--
-- An assessment-scoped record of ACQUIRED access — the persistent analog of "the
-- access we got". Exploit tools deposit on acquire (a session/token/credential/
-- assumed-role/shell); the post-exploit-operator operates THROUGH a held foothold
-- on later steps (executeThroughFoothold) instead of re-supplying the material as a
-- per-call argument. Internal-only, same trust model as findings — `material` (the
-- real token/cred/role) is never redacted. Revoked wholesale at end-of-run.
--
-- See docs/RFC-POST-EXPLOITATION-LAYER.md §6.1. Multi-tenant: org_id on every row.
-- =============================================================================

CREATE TABLE IF NOT EXISTS footholds (
    id             TEXT PRIMARY KEY,
    org_id         TEXT NOT NULL,
    assessment_id  TEXT NOT NULL,

    /* session | token | credential | assumed_role | shell */
    kind           TEXT NOT NULL,
    /* where this foothold grants access (host / arn / tenant / url) */
    target         TEXT NOT NULL,
    /* the held material the operator injects per call (token / cookie-jar / temp
       creds / role-arn). Internal — never redacted. */
    material       JSONB NOT NULL DEFAULT '{}',
    /* capabilities this foothold confers — seeds the planner's `held` set. */
    grants         TEXT[] NOT NULL DEFAULT '{}',

    /* provenance: the finding / step that yielded it. */
    how_acquired   TEXT,
    /* the graph `foothold` node this backs (loose ref, no FK). */
    node_key       TEXT,

    /* live | expired | revoked. */
    status         TEXT NOT NULL DEFAULT 'live',

    established_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    /* time-bounded access (assumed-role / OTP session) expires here. */
    expires_at     TIMESTAMPTZ,
    evidence_ref   TEXT
);

CREATE INDEX IF NOT EXISTS footholds_assessment_idx ON footholds (org_id, assessment_id);
CREATE INDEX IF NOT EXISTS footholds_status_idx     ON footholds (org_id, assessment_id, status);
