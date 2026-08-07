-- =============================================================================
-- Attack-path / escalation graphs — Coverage Dashboard W5 enrichment. 2026-06-08
-- =============================================================================
--
-- Persists the structured escalation graphs that today live only in LLM-authored
-- Cloud Companion Reports / agent checkpoints: PMapper IAM-privesc paths
-- (cloud-analysis) and chain-analysis multi-step attack chains. The MCP
-- `record_attack_paths` tool promotes them here at end-of-run (Shape A); the
-- dashboard W5 graph reads them via GET /cloud/attack-paths and merges them with
-- the reachability paths it already derives from cloud_assets.
--
-- nodes / edges are stored as opaque JSONB arrays in the exact frontend shape
-- (GraphNode {id,label,kind,layer,severity?,sub?} / GraphEdge {from,to,exploited?})
-- so the round-trip needs no transformation. The backend is a passthrough store.
--
-- One graph per (org, target, source): the ingest route replaces the prior graph
-- for that key (delete-then-insert) so re-runs refresh rather than accumulate.
-- =============================================================================

CREATE TABLE IF NOT EXISTS attack_path_graphs (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL,
    /* Nullable: a graph can be org-wide (e.g. IAM privesc) rather than per-target. */
    target_id TEXT REFERENCES targets(id) ON DELETE CASCADE,
    assessment_id TEXT,

    /* Which producer: 'cloud-analysis' | 'chain-analysis' | 'reachability'. */
    source TEXT NOT NULL,
    label TEXT,

    /* GraphNode[] / GraphEdge[] in the frontend's exact shape. */
    nodes JSONB NOT NULL DEFAULT '[]',
    edges JSONB NOT NULL DEFAULT '[]',

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS attack_path_graphs_lookup_idx
    ON attack_path_graphs (org_id, target_id);
