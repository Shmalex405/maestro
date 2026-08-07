-- 0050: per-edge receipts — the provably-traversable attack graph.
--
-- `graph_edges.exploited` records that some run WALKED this edge. That is an
-- agent's report, and 0049 established that an agent's report is a claim, not a
-- proof. This migration gives an edge the same evidence tier its finding has.
--
-- The edge verdict is deliberately NOT a column. It is DERIVED by joining to the
-- finding named in `verified_by_finding_id`:
--
--     edge is verified  ⟺  its backing finding's verdict = 'verified'
--
-- Storing it would create a second place to keep in sync and, worse, a column an
-- agent could write. A pointer to a finding is harmless — an agent may point an
-- edge at any finding it likes, but it cannot make that finding verified, so the
-- earned-verdict invariant holds transitively across the graph.
--
-- With this, `find_attack_paths(verified_only: true)` returns only paths where
-- EVERY edge is backed by an oracle receipt: a path you can hand to a customer
-- and say "each of these steps was re-proven, here are the capsules."

ALTER TABLE graph_edges
  ADD COLUMN IF NOT EXISTS verified_by_finding_id TEXT;

COMMENT ON COLUMN graph_edges.verified_by_finding_id IS
  'Finding whose oracle receipt backs this edge (migration 0049/0050). The edge''s verdict is derived from that finding, never stored here — see 0050 header.';

-- The traversal joins findings on this column for every candidate edge, so it
-- needs to be cheap. Partial: most edges have no backing finding.
CREATE INDEX IF NOT EXISTS graph_edges_verified_by_idx
  ON graph_edges (org_id, verified_by_finding_id)
  WHERE verified_by_finding_id IS NOT NULL;
