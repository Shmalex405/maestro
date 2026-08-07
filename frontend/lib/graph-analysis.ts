// =============================================================================
// Pure attack-graph analysis — path enumeration, choke-point centrality, and
// reachability (blast radius). No React, no DOM: trivially unit-testable.
//
// These power the explorer's choke-point lens ("fix this node, break N paths to
// M crown jewels" — the XM Cyber / Tenable / Microsoft prioritization model) and
// the blast-radius focus. Operates on the loaded (client-side) graph; our graphs
// are small enough that full enumeration is fine, with hard caps as a backstop.
// =============================================================================

export interface AnalysisEdge {
  from: string;
  to: string;
  exploited?: boolean;
}

const MAX_PATHS = 4000; // backstop against combinatorial blow-up
const MAX_DEPTH = 12;

/** Adjacency (out-edges) keyed by source node. */
function buildAdjacency(edges: AnalysisEdge[]): Map<string, string[]> {
  const adj = new Map<string, string[]>();
  for (const e of edges) {
    const a = adj.get(e.from);
    if (a) a.push(e.to);
    else adj.set(e.from, [e.to]);
  }
  return adj;
}

/** Reverse adjacency (in-edges) keyed by destination node. */
function buildReverse(edges: AnalysisEdge[]): Map<string, string[]> {
  const radj = new Map<string, string[]>();
  for (const e of edges) {
    const a = radj.get(e.to);
    if (a) a.push(e.from);
    else radj.set(e.to, [e.from]);
  }
  return radj;
}

/** All nodes reachable downstream from `start` (the blast radius). */
export function reachableDownstream(start: string, edges: AnalysisEdge[]): Set<string> {
  const adj = buildAdjacency(edges);
  const seen = new Set<string>([start]);
  const stack = [start];
  while (stack.length) {
    const cur = stack.pop()!;
    for (const nxt of adj.get(cur) ?? []) {
      if (!seen.has(nxt)) { seen.add(nxt); stack.push(nxt); }
    }
  }
  return seen;
}

/** All nodes upstream of `start` (everything that can reach it). */
export function reachableUpstream(start: string, edges: AnalysisEdge[]): Set<string> {
  const radj = buildReverse(edges);
  const seen = new Set<string>([start]);
  const stack = [start];
  while (stack.length) {
    const cur = stack.pop()!;
    for (const prev of radj.get(cur) ?? []) {
      if (!seen.has(prev)) { seen.add(prev); stack.push(prev); }
    }
  }
  return seen;
}

/** A concrete source→goal path as an ordered list of node keys. */
export type EnumeratedPath = string[];

/**
 * Enumerate every acyclic path from any source node to any goal node, bounded by
 * depth and a global path cap (returns `{ paths, truncated }`). Cycle-guarded via
 * the visited set on each branch.
 */
export function enumeratePaths(
  edges: AnalysisEdge[],
  sources: Set<string>,
  goals: Set<string>,
  maxDepth = 8,
  cap = MAX_PATHS,
): { paths: EnumeratedPath[]; truncated: boolean } {
  const depthCap = Math.min(maxDepth, MAX_DEPTH);
  const adj = buildAdjacency(edges);
  const paths: EnumeratedPath[] = [];
  let truncated = false;

  const dfs = (node: string, trail: string[], visited: Set<string>) => {
    if (truncated) return;
    if (goals.has(node) && trail.length > 1) {
      paths.push([...trail]);
      if (paths.length >= cap) truncated = true;
      return; // stop at goal (don't traverse through a goal)
    }
    if (trail.length - 1 >= depthCap) return;
    for (const nxt of adj.get(node) ?? []) {
      if (visited.has(nxt)) continue; // cycle guard
      visited.add(nxt);
      trail.push(nxt);
      dfs(nxt, trail, visited);
      trail.pop();
      visited.delete(nxt);
    }
  };

  for (const s of sources) {
    if (truncated) break;
    dfs(s, [s], new Set([s]));
  }
  return { paths, truncated };
}

export interface ChokePoint {
  key: string;
  /** How many distinct source→goal paths cross this node. */
  pathCount: number;
  /** How many distinct goals those paths reach. */
  goalsCovered: number;
}

/**
 * Choke-point centrality over enumerated paths: for each INTERMEDIATE node (not a
 * source or goal endpoint), count the distinct paths that pass through it and the
 * distinct goals those paths reach. Ranked desc by pathCount then goalsCovered —
 * the node at the top is the highest-leverage single fix ("break N paths").
 */
export function computeChokePoints(
  paths: EnumeratedPath[],
  goals: Set<string>,
): ChokePoint[] {
  const pathCount = new Map<string, number>();
  const goalsByNode = new Map<string, Set<string>>();
  for (const p of paths) {
    if (p.length < 2) continue;
    const goal = p[p.length - 1];
    // intermediate nodes only: exclude the start (entry) and the goal itself.
    for (let i = 1; i < p.length - 1; i++) {
      const k = p[i];
      pathCount.set(k, (pathCount.get(k) ?? 0) + 1);
      let g = goalsByNode.get(k);
      if (!g) goalsByNode.set(k, (g = new Set()));
      g.add(goal);
    }
  }
  const out: ChokePoint[] = [];
  for (const [key, count] of pathCount) {
    out.push({ key, pathCount: count, goalsCovered: goalsByNode.get(key)?.size ?? 0 });
  }
  out.sort((a, b) => (b.pathCount - a.pathCount) || (b.goalsCovered - a.goalsCovered) || a.key.localeCompare(b.key));
  // silence unused-param lint in builds that tree-shake `goals` away
  void goals;
  return out;
}

/** Convenience: enumerate paths then rank choke points in one call. */
export function analyzeChokePoints(
  edges: AnalysisEdge[],
  sources: Set<string>,
  goals: Set<string>,
  maxDepth = 8,
): { chokePoints: ChokePoint[]; paths: EnumeratedPath[]; truncated: boolean } {
  const { paths, truncated } = enumeratePaths(edges, sources, goals, maxDepth);
  return { chokePoints: computeChokePoints(paths, goals), paths, truncated };
}
