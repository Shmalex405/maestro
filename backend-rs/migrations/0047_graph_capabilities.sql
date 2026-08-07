-- =============================================================================
-- Post-exploitation Layer A — capability attrs on the graph substrate. 2026-06-29
-- =============================================================================
--
-- The grants/requires capability model (config/chain-patterns.yml) currently lives
-- only as prose inside an LLM prompt and is discarded after one inference. This
-- migration promotes it to first-class graph state so the capability-gated planner
-- (Layer B, the WALK_CTE `held` accumulator) can reason over it deterministically.
--
--   graph_edges.requires  — preconditions an action needs (⊆ held to traverse)
--   graph_edges.grants     — capabilities an action yields on success
--   graph_nodes.grants     — capabilities LANDING on a node yields (loot pickup)
--
-- All nullable-with-default '{}' → existing rows + existing reachability queries are
-- unaffected (an edge with no `requires` is always traversable, matching today's
-- plain reachability). See docs/RFC-POST-EXPLOITATION-LAYER.md §4.1 / §5.1.
--
-- Plus three new built-in node kinds for the concrete things an attacker acquires
-- (RFC §3 hybrid model — durable loot is a node, abstract caps are edge attrs):
--   foothold   (layer 2) — an established access position (session/token/role)
--   credential (layer 2) — an acquired secret/cred, provenance = how_acquired
--   loot       (layer 4) — data/material actually obtained (is_goal-eligible per-node)
-- =============================================================================

-- ─── Capability attrs ─────────────────────────────────────────────────────────
ALTER TABLE graph_edges ADD COLUMN IF NOT EXISTS requires TEXT[] NOT NULL DEFAULT '{}';
ALTER TABLE graph_edges ADD COLUMN IF NOT EXISTS grants   TEXT[] NOT NULL DEFAULT '{}';
ALTER TABLE graph_nodes ADD COLUMN IF NOT EXISTS grants   TEXT[] NOT NULL DEFAULT '{}';

-- GIN indexes support the planner's `requires <@ held` containment gate.
CREATE INDEX IF NOT EXISTS graph_edges_requires_idx ON graph_edges USING GIN (requires);
CREATE INDEX IF NOT EXISTS graph_edges_grants_idx   ON graph_edges USING GIN (grants);

-- ─── New built-in node kinds (the attacker-state vertices) ────────────────────
-- Mirror the 0046 seed style; `display` carries offline FE styling (the FE caches
-- GET /graph/kinds and falls back to this). org_id = '' sentinel = global built-in.
INSERT INTO graph_kinds (org_id, kind, is_builtin, is_edge, is_goal, label, display) VALUES
    ('', 'foothold',   TRUE, FALSE, FALSE, 'Foothold / access position',
        '{"fill":"#3a2410","stroke":"#b45309","text":"#fcd34d","icon":"anchor","layer":2}'),
    ('', 'credential', TRUE, FALSE, FALSE, 'Acquired credential',
        '{"fill":"#2a1a3a","stroke":"#7c3aed","text":"#d8b4fe","icon":"key","layer":2}'),
    ('', 'loot',       TRUE, FALSE, FALSE, 'Loot / exfiltrated material',
        '{"fill":"#3a1014","stroke":"#dc2626","text":"#fca5a5","icon":"gem","layer":4}')
ON CONFLICT (org_id, kind) DO NOTHING;
