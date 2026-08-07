'use client';

// Embedded "Attack paths" card for the Coverage dashboard + Cloud surface page.
//
// Single source of truth with the /graph explorer: both read the SAME persistent
// substrate (GET /graph/nodes + /graph/edges) and the SAME kind registry for
// styling — no more divergent per-page derivation. This card is the glance view
// (capped, read-only, in-context); the explorer is the deep dive, reached via the
// "Open in Attack Graph →" link. Uses GET-only endpoints so read-only users see
// it too (POST /graph/paths is blocked for them by the global guard).

import { useMemo } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useQuery } from '@tanstack/react-query';
import { Workflow, ArrowRight } from 'lucide-react';
import { api } from '@/lib/tauri-api';
import { useGraphKinds } from '@/lib/hooks/use-graph-kinds';
import { AttackPathGraph, type GraphNode, type GraphEdge } from '@/components/viz/attack-path-graph';
import type { GraphSubstrateNode } from '@/lib/types';

const NODE_LIMIT = 80;
const EDGE_LIMIT = 400;

export function AttackPathCard({ targetId }: { targetId?: string }) {
  const router = useRouter();
  const { kindStyles, kindByName } = useGraphKinds();

  const { data: nodes = [] } = useQuery({
    queryKey: ['attack-card-nodes', targetId ?? null],
    queryFn: () => api.graph.nodes({ target_id: targetId, limit: NODE_LIMIT }),
  });
  const { data: edges = [] } = useQuery({
    queryKey: ['attack-card-edges', targetId ?? null],
    queryFn: () => api.graph.edges({ limit: EDGE_LIMIT }),
  });

  const isGoal = (n: GraphSubstrateNode) =>
    n.is_goal ?? kindByName.get(n.kind)?.is_goal ?? false;

  const nodeById = useMemo(() => new Map(nodes.map((n) => [n.id, n])), [nodes]);

  const gnodes: GraphNode[] = useMemo(
    () =>
      nodes.map((n) => ({
        id: n.id,
        label: n.label || n.id,
        kind: n.kind as GraphNode['kind'],
        layer: n.layer,
        severity: n.severity ?? undefined,
        sub: n.sub ?? undefined,
        isGoal: isGoal(n),
      })),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [nodes, kindByName],
  );

  const gedges: GraphEdge[] = useMemo(() => {
    const visible = new Set(nodes.map((n) => n.id));
    return edges
      .filter((e) => visible.has(e.from) && visible.has(e.to))
      .map((e) => ({ from: e.from, to: e.to, exploited: e.exploited }));
  }, [edges, nodes]);

  // Self-gate: nothing meaningful to show with 0-1 nodes (matches the old
  // `attackGraph.nodes.length > 1` guard on both pages).
  if (gnodes.length < 2) return null;

  const explorerHref = '/graph';
  const truncated = nodes.length >= NODE_LIMIT;

  function handleNodeClick(n: GraphNode) {
    if (n.kind !== 'vulnerability') return;
    const sub = nodeById.get(n.id);
    const fromAttrs = sub?.attrs?.finding_id;
    const findingId =
      typeof fromAttrs === 'string' && fromAttrs
        ? fromAttrs
        : n.id.startsWith('v:')
          ? n.id.slice(2)
          : null;
    router.push(findingId ? `/findings?id=${encodeURIComponent(findingId)}` : '/findings');
  }

  return (
    <div className="glass-card rounded-xl overflow-hidden">
      <div className="flex flex-wrap items-center gap-2 border-b border-border/50 px-4 py-3">
        <Workflow className="h-4 w-4 text-purple-400" />
        <span className="text-sm font-medium">Attack paths</span>
        <span className="text-[10px] text-muted-foreground">
          how findings chain into paths — source → … → ★ crown jewel
        </span>
        <div className="ml-auto flex items-center gap-3 text-[10px] text-muted-foreground">
          <span className="flex items-center gap-1.5">
            <span className="inline-block w-4 border-t-2 border-red-500" /> exploited
          </span>
          <span className="flex items-center gap-1.5">
            <span className="inline-block w-4 border-t border-dashed border-slate-500" /> detected
          </span>
          <span className="flex items-center gap-1">★ crown jewel</span>
          <Link
            href={explorerHref}
            className="flex items-center gap-1 rounded border border-border/60 px-1.5 py-0.5 font-medium text-foreground hover:bg-accent"
          >
            Open in Attack Graph <ArrowRight className="h-3 w-3" />
          </Link>
        </div>
      </div>
      <div className="p-4">
        <AttackPathGraph nodes={gnodes} edges={gedges} kindStyles={kindStyles} onNodeClick={handleNodeClick} />
        <div className="mt-2 text-[10px] text-muted-foreground">
          {truncated
            ? `Showing the ${NODE_LIMIT} most-recently-seen nodes — open the explorer to filter, search, and pathfind the full graph.`
            : 'Click a node to highlight it; open the explorer to filter, search, and pathfind.'}
        </div>
      </div>
    </div>
  );
}
