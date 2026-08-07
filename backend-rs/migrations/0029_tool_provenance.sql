-- =============================================================================
-- Tool-execution provenance (P1) — proof that each test's backing tool ran. 2026-06-10
-- =============================================================================
--
-- The MCP server captures, per assessment, which security tool ran for each test,
-- whether its binary was actually installed, and the exit codes the handler
-- soft-fail pattern (|| echo failed) would otherwise hide. At end-of-run the
-- `promote_tool_provenance` MCP tool pushes a per-tool summary here (Shape A:
-- local-first capture, curated promotion at the end).
--
-- The desktop "Tools" view (per-assessment) reads this via
-- GET /assessments/:id/tool-executions to show exactly which tools ran — turning
-- "tested and clean" vs "tool silently absent" into a visible distinction.
--
-- One row per (org, assessment, tool). The ingest route replaces the prior set
-- for an assessment (delete-then-insert) so re-promotion refreshes rather than
-- accumulates. Per-org scoped via JWT custom:org_id.
-- =============================================================================

CREATE TABLE IF NOT EXISTS tool_executions (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL,
    assessment_id TEXT NOT NULL,

    /* MCP tool name (the value of `tool:` in test-matrix.yml), e.g. scan_ports. */
    tool_name TEXT NOT NULL,
    /* Underlying security binary, e.g. nmap. NULL for pure-API tools.
       Quoted because `binary` is a reserved word in Postgres. */
    "binary" TEXT,
    /* Independent availability probe result; NULL when the binary is unknown. */
    installed BOOLEAN,
    version TEXT,

    run_count INTEGER NOT NULL DEFAULT 0,
    ok_count INTEGER NOT NULL DEFAULT 0,
    fail_count INTEGER NOT NULL DEFAULT 0,
    last_exit_code INTEGER,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE (org_id, assessment_id, tool_name)
);

CREATE INDEX IF NOT EXISTS tool_executions_assessment_idx
    ON tool_executions (org_id, assessment_id);
