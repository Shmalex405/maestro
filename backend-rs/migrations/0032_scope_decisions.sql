-- =============================================================================
-- Scope decisions (Option B) — every in/out-of-scope target verdict. 2026-06-10
-- =============================================================================
--
-- The MCP server captures, at each validateToolScope call during the run, which
-- target a tool resolved to and whether it was in scope (and why not, when out).
-- At end-of-run the `promote_execution_meta` MCP tool pushes the per-target
-- summary here (Shape A: local-first capture, curated promotion at the end).
--
-- The desktop "Assessment Execution Overview" reads this via
-- GET /assessments/:id/scope-decisions to show which targets were tested, which
-- were rejected as out-of-scope (with the violation reason), and how many times
-- each verdict was hit — making the scope boundary the run actually enforced
-- visible after the fact.
--
-- One row per (org, assessment, target, in_scope). The ingest route replaces the
-- prior set for an assessment (delete-then-insert) so re-promotion refreshes
-- rather than accumulates. Per-org scoped via JWT custom:org_id.
-- =============================================================================

CREATE TABLE IF NOT EXISTS assessment_scope_decisions (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL,
    assessment_id TEXT NOT NULL,

    /* The resolved target the decision was made about (IP / CIDR / host / domain /
       cloud account id / cluster id / identity tenant id). */
    target TEXT NOT NULL,
    /* network | cloud | k8s | identity, when determinable; NULL otherwise. */
    dimension TEXT,
    in_scope BOOLEAN NOT NULL,
    /* The violation message when out-of-scope; NULL when in scope. */
    reason TEXT,
    /* How many times this same (target, verdict) decision was hit during the run. */
    attempts INTEGER NOT NULL DEFAULT 1,

    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE (org_id, assessment_id, target, in_scope)
);

CREATE INDEX IF NOT EXISTS assessment_scope_decisions_assessment_idx
    ON assessment_scope_decisions (org_id, assessment_id);
