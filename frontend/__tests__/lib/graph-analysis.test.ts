/**
 * Tests for the pure attack-graph analysis helpers (lib/graph-analysis).
 *
 * Covers reachability (blast radius, upstream), acyclic path enumeration with
 * depth/cap/cycle guards, and choke-point centrality ranking. No React/DOM.
 */

import { describe, it, expect } from 'vitest';
import {
  reachableDownstream,
  reachableUpstream,
  enumeratePaths,
  computeChokePoints,
  analyzeChokePoints,
  type AnalysisEdge,
} from '../../lib/graph-analysis';

// internet → app → db → crown   (a simple linear chain, plus a side branch)
//   app → cache
const CHAIN: AnalysisEdge[] = [
  { from: 'internet', to: 'app' },
  { from: 'app', to: 'db' },
  { from: 'db', to: 'crown' },
  { from: 'app', to: 'cache' },
];

// Two entries funnelling through one choke, then fanning to two crowns:
//   e1 → choke → crownA
//   e2 → choke → crownB
const FUNNEL: AnalysisEdge[] = [
  { from: 'e1', to: 'choke' },
  { from: 'e2', to: 'choke' },
  { from: 'choke', to: 'crownA' },
  { from: 'choke', to: 'crownB' },
];

describe('reachableDownstream', () => {
  it('returns the full blast radius including the start node', () => {
    expect(reachableDownstream('app', CHAIN)).toEqual(new Set(['app', 'db', 'crown', 'cache']));
  });

  it('returns just the start when it has no out-edges', () => {
    expect(reachableDownstream('crown', CHAIN)).toEqual(new Set(['crown']));
  });

  it('terminates on cycles', () => {
    const cyclic: AnalysisEdge[] = [
      { from: 'a', to: 'b' },
      { from: 'b', to: 'c' },
      { from: 'c', to: 'a' },
    ];
    expect(reachableDownstream('a', cyclic)).toEqual(new Set(['a', 'b', 'c']));
  });
});

describe('reachableUpstream', () => {
  it('returns everything that can reach the start node', () => {
    expect(reachableUpstream('crown', CHAIN)).toEqual(new Set(['crown', 'db', 'app', 'internet']));
  });

  it('excludes side branches that do not lead to the start', () => {
    // cache is downstream of app but nothing upstream of cache reaches crown
    expect(reachableUpstream('cache', CHAIN)).toEqual(new Set(['cache', 'app', 'internet']));
  });
});

describe('enumeratePaths', () => {
  it('enumerates each source→goal path once', () => {
    const { paths, truncated } = enumeratePaths(
      CHAIN,
      new Set(['internet']),
      new Set(['crown']),
    );
    expect(truncated).toBe(false);
    expect(paths).toEqual([['internet', 'app', 'db', 'crown']]);
  });

  it('finds every path when multiple sources reach multiple goals', () => {
    const { paths } = enumeratePaths(FUNNEL, new Set(['e1', 'e2']), new Set(['crownA', 'crownB']));
    expect(paths).toHaveLength(4);
    expect(paths).toContainEqual(['e1', 'choke', 'crownA']);
    expect(paths).toContainEqual(['e2', 'choke', 'crownB']);
  });

  it('does not traverse through a goal node', () => {
    // if `db` is itself a goal, the path stops there and never reaches crown
    const { paths } = enumeratePaths(CHAIN, new Set(['internet']), new Set(['db', 'crown']));
    expect(paths).toEqual([['internet', 'app', 'db']]);
  });

  it('respects the depth bound', () => {
    const { paths } = enumeratePaths(CHAIN, new Set(['internet']), new Set(['crown']), 2);
    // depth 2 = at most 2 hops from the entry; crown is 3 hops away → no path
    expect(paths).toEqual([]);
  });

  it('respects the path cap and reports truncation', () => {
    const { paths, truncated } = enumeratePaths(FUNNEL, new Set(['e1', 'e2']), new Set(['crownA', 'crownB']), 8, 2);
    expect(paths).toHaveLength(2);
    expect(truncated).toBe(true);
  });

  it('does not loop forever on cycles', () => {
    const cyclic: AnalysisEdge[] = [
      { from: 's', to: 'a' },
      { from: 'a', to: 'b' },
      { from: 'b', to: 'a' },
      { from: 'b', to: 'g' },
    ];
    const { paths } = enumeratePaths(cyclic, new Set(['s']), new Set(['g']));
    expect(paths).toEqual([['s', 'a', 'b', 'g']]);
  });
});

describe('computeChokePoints', () => {
  it('counts paths and distinct goals crossing each intermediate node', () => {
    const paths = [
      ['e1', 'choke', 'crownA'],
      ['e2', 'choke', 'crownB'],
    ];
    const chokes = computeChokePoints(paths, new Set(['crownA', 'crownB']));
    expect(chokes).toHaveLength(1);
    expect(chokes[0]).toEqual({ key: 'choke', pathCount: 2, goalsCovered: 2 });
  });

  it('excludes source and goal endpoints from the ranking', () => {
    const chokes = computeChokePoints([['internet', 'app', 'db', 'crown']], new Set(['crown']));
    const keys = chokes.map((c) => c.key).sort();
    expect(keys).toEqual(['app', 'db']);
  });

  it('ranks by pathCount then goalsCovered (highest-leverage first)', () => {
    const paths = [
      ['e1', 'hub', 'x', 'g1'],
      ['e2', 'hub', 'y', 'g2'],
      ['e3', 'hub', 'z', 'g1'],
    ];
    const chokes = computeChokePoints(paths, new Set(['g1', 'g2']));
    // hub is on all 3 paths → ranked first
    expect(chokes[0].key).toBe('hub');
    expect(chokes[0].pathCount).toBe(3);
    expect(chokes[0].goalsCovered).toBe(2);
  });
});

describe('analyzeChokePoints', () => {
  it('enumerates and ranks in one call', () => {
    const { chokePoints, paths, truncated } = analyzeChokePoints(
      FUNNEL,
      new Set(['e1', 'e2']),
      new Set(['crownA', 'crownB']),
    );
    expect(truncated).toBe(false);
    expect(paths).toHaveLength(4);
    expect(chokePoints[0].key).toBe('choke');
    expect(chokePoints[0].pathCount).toBe(4);
    expect(chokePoints[0].goalsCovered).toBe(2);
  });
});
