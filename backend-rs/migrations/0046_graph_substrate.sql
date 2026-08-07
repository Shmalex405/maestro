-- =============================================================================
-- Attack-graph substrate — normalized, accumulating node/edge union. 2026-06-25
-- =============================================================================
--
-- Migration 0027 (attack_path_graphs) stores each producer's graph as one opaque
-- JSONB snapshot, replaced wholesale on every re-run. That is fine for rendering
-- the dashboard W5 widget, but it cannot answer "can the internet reach a crown
-- jewel?" across findings, across producers, or across assessments — every query
-- would have to re-explode the JSONB and the union is lost the moment a producer
-- re-runs.
--
-- This migration adds the PERSISTENT, ACCUMULATING substrate underneath that
-- snapshot. The JSONB table is kept (back-compat; the dashboard still reads it),
-- and `ingest_graph` / the reachability producer now DUAL-WRITE: the snapshot AND
-- these normalized rows. Re-runs accumulate (sources/assessments arrays grow,
-- last_seen_at advances) instead of wiping — the cross-assessment union is the
-- whole point.
--
-- Three tables:
--   graph_kinds  — the kind registry (the OpenGraph analog). 7 built-in kinds
--                  seeded here (org_id = '' sentinel = global); orgs may register
--                  custom node/edge kinds. Powers FE styling + goal detection.
--   graph_nodes  — union of every node ever ingested, keyed (org_id, node_key).
--                  Cross-target by design: lateral-movement paths emerge when the
--                  same key appears from two targets.
--   graph_edges  — union of every edge, keyed (org_id, src_key, dst_key, kind).
--
-- Multi-tenant: org_id on every row, every query/join filters on it. Built-in
-- kinds use the '' sentinel so (org_id, kind) stays a clean composite PK and
-- ON CONFLICT seeding works without NULL-uniqueness gymnastics.
-- =============================================================================

-- ─── Kind registry ──────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS graph_kinds (
    /* '' = built-in (global, visible to every org); else the owning org. */
    org_id      TEXT NOT NULL DEFAULT '',
    kind        TEXT NOT NULL,

    is_builtin  BOOLEAN NOT NULL DEFAULT FALSE,
    /* node-kind vs edge-kind (a kind bundle can define both). */
    is_edge     BOOLEAN NOT NULL DEFAULT FALSE,
    /* default crown-jewel flag for nodes of this kind; per-node override wins. */
    is_goal     BOOLEAN NOT NULL DEFAULT FALSE,

    label       TEXT NOT NULL DEFAULT '',
    /* {fill,stroke,text,icon,layer?} — drives FE styling straight from the registry. */
    display     JSONB NOT NULL DEFAULT '{}',
    /* optional JSON-schema describing the attrs blob nodes/edges of this kind carry. */
    schema      JSONB NOT NULL DEFAULT '{}',

    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    PRIMARY KEY (org_id, kind)
);

-- ─── Node union ───────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS graph_nodes (
    org_id        TEXT NOT NULL,
    /* the GraphNode.id — stable across runs; THE union key. */
    node_key      TEXT NOT NULL,

    kind          TEXT NOT NULL,
    label         TEXT NOT NULL DEFAULT '',
    layer         INTEGER NOT NULL DEFAULT 0,
    severity      TEXT,
    sub           TEXT,
    /* per-node crown-jewel override; NULL = inherit graph_kinds.is_goal. */
    is_goal       BOOLEAN,

    /* last target that produced/touched this node (loose ref, NO FK — accumulation
       must survive target deletion; PR4 prune handles staleness). */
    target_id     TEXT,
    attrs         JSONB NOT NULL DEFAULT '{}',

    /* accumulated producers + assessment ids across every ingest of this node. */
    sources       TEXT[] NOT NULL DEFAULT '{}',
    assessments   TEXT[] NOT NULL DEFAULT '{}',

    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    PRIMARY KEY (org_id, node_key)
);

CREATE INDEX IF NOT EXISTS graph_nodes_kind_idx      ON graph_nodes (org_id, kind);
CREATE INDEX IF NOT EXISTS graph_nodes_target_idx    ON graph_nodes (org_id, target_id);
CREATE INDEX IF NOT EXISTS graph_nodes_last_seen_idx ON graph_nodes (org_id, last_seen_at);

-- ─── Edge union ───────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS graph_edges (
    org_id        TEXT NOT NULL,
    src_key       TEXT NOT NULL,
    dst_key       TEXT NOT NULL,
    /* default generic escalation edge; identity includes kind so two relationship
       types between the same pair are distinct edges. */
    kind          TEXT NOT NULL DEFAULT 'leads_to',

    /* sticky-true: once any run exploits this edge it stays exploited (solid red). */
    exploited     BOOLEAN NOT NULL DEFAULT FALSE,

    target_id     TEXT,
    attrs         JSONB NOT NULL DEFAULT '{}',

    sources       TEXT[] NOT NULL DEFAULT '{}',
    assessments   TEXT[] NOT NULL DEFAULT '{}',

    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    PRIMARY KEY (org_id, src_key, dst_key, kind)
);

-- Traversal walks src → dst; src_key is the hot lookup. dst index supports the
-- reverse "what reaches this node" query.
CREATE INDEX IF NOT EXISTS graph_edges_src_idx       ON graph_edges (org_id, src_key);
CREATE INDEX IF NOT EXISTS graph_edges_dst_idx       ON graph_edges (org_id, dst_key);
CREATE INDEX IF NOT EXISTS graph_edges_last_seen_idx ON graph_edges (org_id, last_seen_at);

-- ─── Built-in kinds (the 7 the producers + FE already use) ────────────────────
-- 6 node kinds (mirror components/viz/attack-path-graph.tsx KIND_STYLE) + 1 edge
-- kind. `asset` is the default crown jewel (is_goal). display = the offline-seed
-- styling; the FE caches GET /graph/kinds and falls back to this.
INSERT INTO graph_kinds (org_id, kind, is_builtin, is_edge, is_goal, label, display) VALUES
    ('', 'source',        TRUE, FALSE, FALSE, 'Source / Internet',
        '{"fill":"#1e293b","stroke":"#64748b","text":"#cbd5e1","layer":0}'),
    ('', 'exposure',      TRUE, FALSE, FALSE, 'Internet-facing exposure',
        '{"fill":"#3f2d10","stroke":"#f59e0b","text":"#fcd34d","layer":1}'),
    ('', 'workload',      TRUE, FALSE, FALSE, 'Workload / service',
        '{"fill":"#0c2a3a","stroke":"#38bdf8","text":"#7dd3fc","layer":2}'),
    ('', 'vulnerability', TRUE, FALSE, FALSE, 'Vulnerability / CVE',
        '{"fill":"#3a1014","stroke":"#ef4444","text":"#fca5a5","layer":3}'),
    ('', 'identity',      TRUE, FALSE, FALSE, 'Identity / principal',
        '{"fill":"#2a1a3a","stroke":"#a855f7","text":"#d8b4fe","layer":2}'),
    ('', 'asset',         TRUE, FALSE, TRUE,  'Crown-jewel asset',
        '{"fill":"#0c2a3a","stroke":"#38bdf8","text":"#7dd3fc","layer":4}'),
    ('', 'leads_to',      TRUE, TRUE,  FALSE, 'Leads to (escalation edge)',
        '{"stroke":"#475569"}')
ON CONFLICT (org_id, kind) DO NOTHING;

-- ─── Backfill: explode existing JSONB snapshots into the union ────────────────
-- Every node/edge in attack_path_graphs becomes a union row, tagged with the
-- snapshot's source + assessment + target. ON CONFLICT accumulates so two
-- snapshots sharing a node merge their sources/assessments rather than collide.
INSERT INTO graph_nodes
    (org_id, node_key, kind, label, layer, severity, sub, target_id,
     sources, assessments, first_seen_at, last_seen_at)
SELECT g.org_id,
       n->>'id',
       COALESCE(NULLIF(n->>'kind', ''), 'asset'),
       COALESCE(n->>'label', ''),
       COALESCE((n->>'layer')::int, 0),
       n->>'severity',
       n->>'sub',
       g.target_id,
       ARRAY[g.source],
       CASE WHEN g.assessment_id IS NOT NULL THEN ARRAY[g.assessment_id] ELSE ARRAY[]::text[] END,
       g.created_at,
       g.updated_at
FROM attack_path_graphs g,
     LATERAL jsonb_array_elements(g.nodes) AS n
WHERE jsonb_typeof(g.nodes) = 'array'
  AND COALESCE(n->>'id', '') <> ''
ON CONFLICT (org_id, node_key) DO UPDATE SET
    sources       = ARRAY(SELECT DISTINCT e FROM unnest(graph_nodes.sources || EXCLUDED.sources) AS e),
    assessments   = ARRAY(SELECT DISTINCT e FROM unnest(graph_nodes.assessments || EXCLUDED.assessments) AS e),
    last_seen_at  = GREATEST(graph_nodes.last_seen_at, EXCLUDED.last_seen_at),
    first_seen_at = LEAST(graph_nodes.first_seen_at, EXCLUDED.first_seen_at);

INSERT INTO graph_edges
    (org_id, src_key, dst_key, kind, exploited, target_id,
     sources, assessments, first_seen_at, last_seen_at)
SELECT g.org_id,
       e->>'from',
       e->>'to',
       'leads_to',
       COALESCE((e->>'exploited')::boolean, FALSE),
       g.target_id,
       ARRAY[g.source],
       CASE WHEN g.assessment_id IS NOT NULL THEN ARRAY[g.assessment_id] ELSE ARRAY[]::text[] END,
       g.created_at,
       g.updated_at
FROM attack_path_graphs g,
     LATERAL jsonb_array_elements(g.edges) AS e
WHERE jsonb_typeof(g.edges) = 'array'
  AND COALESCE(e->>'from', '') <> ''
  AND COALESCE(e->>'to', '') <> ''
ON CONFLICT (org_id, src_key, dst_key, kind) DO UPDATE SET
    exploited     = graph_edges.exploited OR EXCLUDED.exploited,
    sources       = ARRAY(SELECT DISTINCT x FROM unnest(graph_edges.sources || EXCLUDED.sources) AS x),
    assessments   = ARRAY(SELECT DISTINCT x FROM unnest(graph_edges.assessments || EXCLUDED.assessments) AS x),
    last_seen_at  = GREATEST(graph_edges.last_seen_at, EXCLUDED.last_seen_at),
    first_seen_at = LEAST(graph_edges.first_seen_at, EXCLUDED.first_seen_at);
