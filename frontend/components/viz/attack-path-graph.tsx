'use client';

// Coverage Dashboard W5 — attack-path / escalation graph. A hand-rolled SVG
// layered DAG (left → right by node.layer). Generic over {nodes, edges} so it
// renders the cloud reachability paths today (Internet → exposure → workload →
// vulnerability) and generalizes to IAM-privesc / identity paths later.
//
// Edges: EXPLOITED = solid red, DETECTED-ONLY = dashed muted (the cloud-analysis
// escalation-graph convention).

import { useMemo } from 'react';
import { severityStyle } from '@/lib/severity';

export type GraphNodeKind =
  | 'source'
  | 'exposure'
  | 'workload'
  | 'vulnerability'
  | 'identity'
  | 'asset';

export interface GraphNode {
  id: string;
  label: string;
  kind: GraphNodeKind;
  /** Column index, 0 = leftmost. */
  layer: number;
  /** Colors vulnerability nodes by severity. */
  severity?: string;
  /** Subtitle line. */
  sub?: string;
  /** Crown jewel — drawn with a ★ marker (parity with the /graph explorer). */
  isGoal?: boolean;
}

export interface GraphEdge {
  from: string;
  to: string;
  /** Solid red when the path was actually exploited; dashed when detected-only. */
  exploited?: boolean;
}

export interface KindStyle {
  fill: string;
  stroke: string;
  text: string;
}

/** Offline seed — the built-in kind styling shipped in the bundle. The kind
 *  registry (GET /graph/kinds) overrides/extends this at runtime via the
 *  `kindStyles` prop; this seed is the fallback when the registry hasn't loaded
 *  or doesn't define a kind. Mirrors the built-in `display` rows in migration
 *  0046 so the offline render matches the registry render. */
export const SEED_KIND_STYLE: Record<string, KindStyle> = {
  source: { fill: '#1e293b', stroke: '#64748b', text: '#cbd5e1' },
  exposure: { fill: '#3f2d10', stroke: '#f59e0b', text: '#fcd34d' },
  workload: { fill: '#0c2a3a', stroke: '#38bdf8', text: '#7dd3fc' },
  vulnerability: { fill: '#3a1014', stroke: '#ef4444', text: '#fca5a5' },
  identity: { fill: '#2a1a3a', stroke: '#a855f7', text: '#d8b4fe' },
  asset: { fill: '#0c2a3a', stroke: '#38bdf8', text: '#7dd3fc' },
};

/** Neutral fallback for an unknown/new kind — renders gracefully, never crashes. */
export const NEUTRAL_KIND_STYLE: KindStyle = {
  fill: '#1f2937',
  stroke: '#6b7280',
  text: '#d1d5db',
};

/** Resolve a kind's style: runtime registry → offline seed → neutral fallback. */
export function resolveKindStyle(
  kind: string,
  registry?: Record<string, KindStyle>,
): KindStyle {
  return registry?.[kind] ?? SEED_KIND_STYLE[kind] ?? NEUTRAL_KIND_STYLE;
}

const NODE_W = 152;
const NODE_H = 44;
const COL_GAP = 64;
const ROW_GAP = 16;

function truncate(s: string, n: number): string {
  return s.length > n ? `${s.slice(0, n - 1)}…` : s;
}

export function AttackPathGraph({
  nodes,
  edges,
  onNodeClick,
  kindStyles,
}: {
  nodes: GraphNode[];
  edges: GraphEdge[];
  onNodeClick?: (n: GraphNode) => void;
  /** Runtime kind→style map from the registry (GET /graph/kinds). Omit to use
   *  the offline seed — existing dashboard/cloud widgets pass nothing and render
   *  identically; the explorer passes the registry so custom kinds get styled. */
  kindStyles?: Record<string, KindStyle>;
}) {
  const layout = useMemo(() => {
    const layers = new Map<number, GraphNode[]>();
    for (const n of nodes) {
      const bucket = layers.get(n.layer);
      if (bucket) bucket.push(n);
      else layers.set(n.layer, [n]);
    }
    const layerKeys = [...layers.keys()].sort((a, b) => a - b);
    const colWidth = NODE_W + COL_GAP;
    const width = Math.max(layerKeys.length * colWidth + 20, 600);
    let maxRows = 1;
    for (const lk of layerKeys) maxRows = Math.max(maxRows, layers.get(lk)!.length);
    const height = Math.max(240, maxRows * (NODE_H + ROW_GAP) + 24);

    const pos = new Map<string, { x: number; y: number }>();
    layerKeys.forEach((lk, ci) => {
      const ns = layers.get(lk)!;
      const colHeight = ns.length * NODE_H + (ns.length - 1) * ROW_GAP;
      const startY = (height - colHeight) / 2;
      ns.forEach((n, ri) => {
        pos.set(n.id, { x: ci * colWidth + 10, y: startY + ri * (NODE_H + ROW_GAP) });
      });
    });
    return { pos, width, height };
  }, [nodes]);

  if (nodes.length === 0) return null;
  const { pos, width, height } = layout;

  return (
    <div className="overflow-x-auto">
      <svg width={width} height={height} viewBox={`0 0 ${width} ${height}`} className="min-w-full">
        {/* edges first (under nodes) */}
        {edges.map((e, i) => {
          const a = pos.get(e.from);
          const b = pos.get(e.to);
          if (!a || !b) return null;
          const x1 = a.x + NODE_W;
          const y1 = a.y + NODE_H / 2;
          const x2 = b.x;
          const y2 = b.y + NODE_H / 2;
          const mx = (x1 + x2) / 2;
          return (
            <path
              key={`${e.from}->${e.to}-${i}`}
              d={`M ${x1} ${y1} C ${mx} ${y1}, ${mx} ${y2}, ${x2} ${y2}`}
              fill="none"
              stroke={e.exploited ? '#ef4444' : '#475569'}
              strokeWidth={e.exploited ? 2 : 1.25}
              strokeDasharray={e.exploited ? undefined : '4 4'}
              opacity={e.exploited ? 0.9 : 0.55}
            />
          );
        })}
        {/* nodes */}
        {nodes.map((n) => {
          const p = pos.get(n.id);
          if (!p) return null;
          // Guard: persisted graphs come from an LLM agent, so a kind outside the
          // known set falls back to a neutral style rather than crashing. Registry
          // (when provided) → offline seed → neutral.
          const ks = resolveKindStyle(n.kind, kindStyles);
          const stroke =
            n.kind === 'vulnerability' && n.severity ? severityStyle(n.severity).hex : ks.stroke;
          return (
            <g
              key={n.id}
              transform={`translate(${p.x}, ${p.y})`}
              className={onNodeClick ? 'cursor-pointer' : undefined}
              onClick={onNodeClick ? () => onNodeClick(n) : undefined}
            >
              <rect
                width={NODE_W}
                height={NODE_H}
                rx={6}
                fill={ks.fill}
                stroke={stroke}
                strokeWidth={1.25}
              />
              <text x={10} y={n.sub ? 18 : 27} fontSize={11} fontWeight={600} fill={ks.text}>
                {n.isGoal ? '★ ' : ''}
                {truncate(n.label, n.isGoal ? 18 : 20)}
              </text>
              {n.sub && (
                <text x={10} y={33} fontSize={9} fill="#94a3b8">
                  {truncate(n.sub, 24)}
                </text>
              )}
            </g>
          );
        })}
      </svg>
    </div>
  );
}
