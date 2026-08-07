-- =============================================================================
-- Per-test execution overview (Option B) — every test's verdict. 2026-06-10
-- =============================================================================
--
-- The MCP server imports the agents' reports/*-results.json checkpoints into a
-- local table during the run, runs them through the deterministic provenance
-- gate, and at end-of-run the `promote_execution_meta` MCP tool pushes the
-- per-test summary here (Shape A: local-first capture, curated promotion at the
-- end).
--
-- The desktop "Assessment Execution Overview" reads this via
-- GET /assessments/:id/test-results to show every test's PASS/FAIL/N_A/BLOCKED
-- verdict alongside the gate's enforced flag + reason — turning "118 tests ran"
-- into a per-test, per-agent audit.
--
-- One row per (org, assessment, agent, test_id). The ingest route replaces the
-- prior set for an assessment (delete-then-insert) so re-promotion refreshes
-- rather than accumulates. Per-org scoped via JWT custom:org_id.
-- =============================================================================

CREATE TABLE IF NOT EXISTS assessment_test_results (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL,
    assessment_id TEXT NOT NULL,

    /* The agent that reported the test (e.g. recon-infra). NULL if unattributed. */
    agent TEXT,
    /* Test id from config/test-matrix.yml, e.g. RECON-01. */
    test_id TEXT NOT NULL,
    /* PASS | FAIL | N_A | BLOCKED. */
    status TEXT NOT NULL,

    /* The deterministic provenance gate's verdict: TRUE when the reported PASS/N_A
       was forced to BLOCKED because its backing tool was absent / never ran. */
    enforced BOOLEAN NOT NULL DEFAULT FALSE,
    enforced_reason TEXT,

    finding_count INTEGER NOT NULL DEFAULT 0,
    notes TEXT,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE (org_id, assessment_id, agent, test_id)
);

CREATE INDEX IF NOT EXISTS assessment_test_results_assessment_idx
    ON assessment_test_results (org_id, assessment_id);
