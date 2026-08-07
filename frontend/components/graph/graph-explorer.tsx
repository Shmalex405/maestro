'use client';

// =============================================================================
// Interactive attack-graph explorer (/graph) — "Wiz-grade" view.
//
// A premium, glassmorphic DAG over the persistent node/edge union (/graph/*):
//   • Top bar     — pill-chip filters, posture stats, layout + Graph/Table toggle,
//                   fit, PNG/SVG export.
//   • Left rail   — collapsible. Overview (top choke points / targets / entries),
//                   Insight Layers (lenses), Find paths, legend.
//   • Canvas      — radial-glow bg, sticky pill lane headers, glowing icon-chip
//                   nodes, gradient edges with flowing particle on exploited paths.
//   • Inspector   — reaches / reached-by, choke-point leverage, foothold flag,
//                   finding drill-through, blast-radius isolate.
//
// Insight Layers (competitive-research grounded — XM Cyber/Tenable/MS/Wiz/BloodHound):
//   severity heat · exploited paths · reachable-from-internet · crown-jewels-at-risk
//   · CHOKE POINTS ("fix this node, break N paths") · paths-from-footholds · all-findings.
// Choke-point centrality + path enumeration live in lib/graph-analysis (unit-tested).
// =============================================================================

import { useCallback, useEffect, useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useRouter } from 'next/navigation';
import {
  ReactFlow,
  ReactFlowProvider,
  Background,
  BackgroundVariant,
  Controls,
  Panel,
  Handle,
  Position,
  MarkerType,
  BaseEdge,
  getBezierPath,
  useReactFlow,
  useViewport,
  getNodesBounds,
  getViewportForBounds,
} from '@xyflow/react';
import type { Node as RFNode, Edge as RFEdge, NodeProps, EdgeProps } from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import dagre from '@dagrejs/dagre';
import { toast } from 'sonner';
import {
  Workflow,
  Search,
  Crosshair,
  ExternalLink,
  X,
  Globe,
  Radio,
  Server,
  ShieldAlert,
  KeyRound,
  Database,
  Circle,
  Crown,
  ArrowRight,
  ArrowLeftRight,
  Layers,
  Columns3,
  Network,
  Image as ImageIcon,
  Focus,
  Maximize2,
  Flame,
  Zap,
  ChevronDown,
  Skull,
  Target,
  Table2,
  GitBranch,
  PanelLeftClose,
  PanelLeftOpen,
} from 'lucide-react';
import type { LucideIcon } from 'lucide-react';
import { api } from '@/lib/tauri-api';
import { severityStyle } from '@/lib/severity';
import { useGraphKinds } from '@/lib/hooks/use-graph-kinds';
import { resolveKindStyle } from '@/components/viz/attack-path-graph';
import {
  analyzeChokePoints,
  reachableDownstream,
  type ChokePoint,
  type AnalysisEdge,
} from '@/lib/graph-analysis';
import type {
  GraphSubstrateNode,
  GraphSubstrateEdge,
  GraphPathsResponse,
} from '@/lib/types';

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
const ACTIVE_WINDOWS: { label: string; days: number }[] = [
  { label: 'All time', days: 0 },
  { label: 'Last 7 days', days: 7 },
  { label: 'Last 30 days', days: 30 },
  { label: 'Last 90 days', days: 90 },
];
const DEPTHS = [3, 4, 5, 6, 8, 10, 12];

const COL_W = 300;
const ROW_H = 108;
const NODE_W = 228;
const NODE_H = 66;
const ROW_Y0 = 56;
const CANVAS_BG = '#080a10';
const GOLD = '#fbbf24';
const CHOKE = '#fb923c'; // orange — choke-point accent
const TOP_CHOKES = 8;

type LayoutMode = 'layered' | 'hierarchical';
type ViewMode = 'graph' | 'table';

const ICON_BY_KIND: Record<string, LucideIcon> = {
  source: Globe,
  exposure: Radio,
  workload: Server,
  vulnerability: ShieldAlert,
  identity: KeyRound,
  asset: Database,
};
function iconForKind(kind: string, isGoal: boolean): LucideIcon {
  return ICON_BY_KIND[kind] ?? (isGoal ? Crown : Circle);
}

// Render a dynamically-selected icon component. Passing the component as a prop
// to this stable wrapper keeps the icon choice out of the caller's render body,
// which the React Compiler lint requires (no component bindings created inline).
function KindGlyph({ icon: Icon, className, style }: { icon: LucideIcon; className?: string; style?: React.CSSProperties }) {
  return <Icon className={className} style={style} />;
}

function edgeKey(from: string, to: string, kind: string): string {
  return `${from}→${to}→${kind}`;
}

function withAlpha(hex: string, a: number): string {
  const h = hex.replace('#', '');
  const n = h.length === 3 ? h.split('').map((c) => c + c).join('') : h;
  const r = parseInt(n.slice(0, 2), 16);
  const g = parseInt(n.slice(2, 4), 16);
  const b = parseInt(n.slice(4, 6), 16);
  return `rgba(${r},${g},${b},${a})`;
}

// ── glowing icon-chip node ────────────────────────────────────────────────────
interface GlowNodeData {
  label: string;
  sub?: string | null;
  kind: string;
  kindLabel: string;
  severity?: string | null;
  isGoal: boolean;
  isFoothold: boolean;
  isFinding: boolean;
  chokeCount: number; // >0 → choke point (paths through it)
  tint: string;
  badge?: number;
  dimmed: boolean;
  matched: boolean;
  selected: boolean;
  [key: string]: unknown;
}

function GlowNode({ data }: NodeProps) {
  const d = data as GlowNodeData;
  const accent = d.isFoothold ? '#f87171' : d.chokeCount > 0 ? CHOKE : d.isGoal ? GOLD : d.tint;
  const glow = d.selected
    ? `0 0 0 1.5px ${accent}, 0 0 22px ${withAlpha(accent, 0.55)}`
    : d.matched
      ? `0 0 0 1.5px ${accent}, 0 0 16px ${withAlpha(accent, 0.4)}`
      : d.chokeCount > 0
        ? `0 0 0 1.5px ${withAlpha(CHOKE, 0.7)}, 0 0 18px ${withAlpha(CHOKE, 0.3)}`
        : d.isGoal
          ? `0 0 18px ${withAlpha(GOLD, 0.28)}`
          : `0 6px 18px rgba(0,0,0,0.45)`;
  return (
    <div
      className={`rf-glow-node group relative rounded-xl border backdrop-blur-md transition-all ${d.isGoal ? 'rf-crown' : ''}`}
      style={{
        width: NODE_W,
        background: d.isFinding
          ? 'linear-gradient(180deg, rgba(30,27,38,0.8), rgba(17,16,24,0.8))'
          : 'linear-gradient(180deg, rgba(22,27,38,0.92), rgba(13,16,24,0.92))',
        borderColor: d.selected ? accent : withAlpha(accent, d.isFinding ? 0.3 : 0.45),
        borderStyle: d.isFinding ? 'dashed' : 'solid',
        boxShadow: glow,
        opacity: d.dimmed ? 0.18 : d.isFinding ? 0.92 : 1,
      }}
    >
      <Handle type="target" position={Position.Left} style={{ opacity: 0 }} />
      <div className="flex items-center gap-2.5 px-2.5 py-2">
        <div
          className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full border"
          style={{
            background: withAlpha(accent, 0.16),
            borderColor: withAlpha(accent, 0.5),
            boxShadow: `0 0 12px ${withAlpha(accent, 0.35)}`,
          }}
        >
          <KindGlyph icon={d.isFoothold ? Skull : iconForKind(d.kind, d.isGoal)} className="h-4 w-4" style={{ color: accent }} />
        </div>
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-1 text-[12px] font-semibold leading-tight text-slate-100">
            {d.isGoal && <Crown className="h-3 w-3 shrink-0" style={{ color: GOLD }} />}
            <span className="truncate">{d.label || d.kind}</span>
          </div>
          {d.sub ? (
            <div className="truncate text-[10px] text-slate-400">{d.sub}</div>
          ) : (
            <div className="truncate text-[10px] uppercase tracking-wide text-slate-500">{d.kindLabel}</div>
          )}
        </div>
        <div className="flex shrink-0 flex-col items-end gap-1">
          {d.chokeCount > 0 ? (
            <span
              className="flex items-center gap-0.5 rounded-full px-1.5 text-[9px] font-bold leading-4"
              style={{ background: withAlpha(CHOKE, 0.22), color: CHOKE }}
              title={`Choke point — ${d.chokeCount} paths cross this node`}
            >
              <Zap className="h-2.5 w-2.5" />
              {d.chokeCount}
            </span>
          ) : (
            typeof d.badge === 'number' &&
            d.badge > 0 && (
              <span className="rounded-full px-1.5 text-[9px] font-semibold leading-4" style={{ background: withAlpha(accent, 0.2), color: accent }}>
                {d.badge}
              </span>
            )
          )}
          {d.severity && <span className="h-2 w-2 rounded-full" style={{ background: severityStyle(d.severity).hex }} title={d.severity} />}
        </div>
      </div>
      <Handle type="source" position={Position.Right} style={{ opacity: 0 }} />
    </div>
  );
}

const nodeTypes = { glow: GlowNode };

// ── gradient bezier edge with flowing particle on exploited paths ─────────────
interface FlowEdgeData {
  exploited: boolean;
  dimmed: boolean;
  particle: boolean;
  [key: string]: unknown;
}
function FlowEdge({ id, sourceX, sourceY, targetX, targetY, sourcePosition, targetPosition, markerEnd, data }: EdgeProps) {
  const [path] = getBezierPath({ sourceX, sourceY, sourcePosition, targetX, targetY, targetPosition });
  const d = (data ?? {}) as FlowEdgeData;
  const stroke = d.exploited ? '#ef4444' : '#64748b';
  return (
    <>
      <BaseEdge
        id={id}
        path={path}
        markerEnd={markerEnd}
        style={{
          stroke,
          strokeWidth: d.exploited ? 2 : 1.25,
          strokeDasharray: d.exploited ? undefined : '5 5',
          opacity: d.dimmed ? 0.07 : d.exploited ? 0.95 : 0.4,
          filter: d.exploited && !d.dimmed ? 'drop-shadow(0 0 4px rgba(239,68,68,0.65))' : undefined,
        }}
      />
      {d.exploited && !d.dimmed && d.particle && (
        <circle r={3} fill="#fecaca" style={{ filter: 'drop-shadow(0 0 3px rgba(239,68,68,0.9))' }}>
          <animateMotion dur="2.4s" repeatCount="indefinite" path={path} />
        </circle>
      )}
    </>
  );
}
const edgeTypes = { flow: FlowEdge };

// ── sticky pill lane headers ──────────────────────────────────────────────────
interface Lane {
  x: number;
  label: string;
  count: number;
  color: string;
}
function LaneOverlay({ lanes }: { lanes: Lane[] }) {
  const { x, zoom } = useViewport();
  if (!lanes.length) return null;
  return (
    <div className="pointer-events-none absolute inset-x-0 top-0 z-[2] h-9 overflow-hidden">
      {lanes.map((l) => (
        <div key={l.x} className="absolute top-1.5 flex justify-center" style={{ left: l.x * zoom + x, width: NODE_W * zoom }}>
          <span
            className="inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-[10px] font-semibold uppercase tracking-wider backdrop-blur"
            style={{ background: 'rgba(15,18,28,0.75)', borderColor: withAlpha(l.color, 0.4), color: '#cbd5e1' }}
          >
            <span className="h-1.5 w-1.5 rounded-full" style={{ background: l.color, boxShadow: `0 0 6px ${l.color}` }} />
            {l.label} <span className="text-slate-500">{l.count}</span>
          </span>
        </div>
      ))}
    </div>
  );
}

function FilterPill({ icon: Icon, value, onChange, children }: { icon: LucideIcon; value: string | number; onChange: (v: string) => void; children: React.ReactNode }) {
  return (
    <div className="relative flex items-center gap-1.5 rounded-full border border-white/10 bg-white/5 pl-2.5 pr-1 backdrop-blur transition-colors hover:bg-white/10">
      <Icon className="h-3.5 w-3.5 text-slate-400" />
      <select value={value} onChange={(e) => onChange(e.target.value)} className="appearance-none bg-transparent py-1 pr-5 text-[11px] text-slate-200 outline-none">
        {children}
      </select>
      <ChevronDown className="pointer-events-none absolute right-2 h-3 w-3 text-slate-500" />
    </div>
  );
}

function StatChip({ icon: Icon, value, accent, title }: { icon: LucideIcon; value: number | string; accent?: string; title: string }) {
  return (
    <div className="flex items-center gap-1 rounded-full border border-white/10 bg-white/5 px-2 py-1 backdrop-blur" title={title}>
      <Icon className="h-3 w-3" style={accent ? { color: accent } : { color: '#94a3b8' }} />
      <span className="text-[11px] font-semibold text-slate-200">{value}</span>
    </div>
  );
}

function layoutDagre(nodes: GraphSubstrateNode[], edges: GraphSubstrateEdge[]): Map<string, { x: number; y: number }> {
  const g = new dagre.graphlib.Graph();
  g.setGraph({ rankdir: 'LR', nodesep: 30, ranksep: 110, marginx: 30, marginy: 30 });
  g.setDefaultEdgeLabel(() => ({}));
  for (const n of nodes) g.setNode(n.id, { width: NODE_W, height: NODE_H });
  for (const e of edges) if (g.hasNode(e.from) && g.hasNode(e.to)) g.setEdge(e.from, e.to);
  dagre.layout(g);
  const m = new Map<string, { x: number; y: number }>();
  for (const n of nodes) {
    const p = g.node(n.id);
    if (p) m.set(n.id, { x: p.x - NODE_W / 2, y: p.y - NODE_H / 2 });
  }
  return m;
}

function GraphExplorerInner() {
  const router = useRouter();
  const rf = useReactFlow();
  const { kindStyles, kindByName } = useGraphKinds();

  const { data: nodes = [], isLoading: nodesLoading } = useQuery({
    queryKey: ['graph-nodes-all'],
    queryFn: () => api.graph.nodes({ limit: 2000 }),
  });
  const { data: edges = [], isLoading: edgesLoading } = useQuery({
    queryKey: ['graph-edges-all'],
    queryFn: () => api.graph.edges({ limit: 5000 }),
  });

  // ── view state ───────────────────────────────────────────────────────────────
  const [layout, setLayout] = useState<LayoutMode>('layered');
  const [view, setView] = useState<ViewMode>('graph');
  const [railOpen, setRailOpen] = useState(true);
  const [kindFilter, setKindFilter] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [activeDays, setActiveDays] = useState(0);
  const [search, setSearch] = useState('');
  const [exporting, setExporting] = useState(false);
  const [lenses, setLenses] = useState({
    heat: false,
    exploited: false,
    internet: false,
    crown: false,
    choke: false,
    footholds: false,
    allFindings: false,
  });

  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [focusId, setFocusId] = useState<string | null>(null);
  const [highlight, setHighlight] = useState<{ nodes: Set<string>; edges: Set<string> } | null>(null);

  // Lazy data for two lenses (only fetched when toggled on).
  const { data: footholds = [] } = useQuery({
    queryKey: ['graph-footholds'],
    queryFn: () => api.graph.footholds(),
    enabled: lenses.footholds,
  });
  const { data: findingsPage } = useQuery({
    queryKey: ['graph-all-findings'],
    queryFn: () => api.findings.list({ limit: 500 }),
    enabled: lenses.allFindings,
  });

  const isGoalNode = useCallback((n: GraphSubstrateNode) => n.is_goal ?? kindByName.get(n.kind)?.is_goal ?? false, [kindByName]);
  const labelForKind = useCallback((kind: string) => kindByName.get(kind)?.label || kind, [kindByName]);

  const presentKinds = useMemo(() => {
    const counts = new Map<string, number>();
    for (const n of nodes) counts.set(n.kind, (counts.get(n.kind) ?? 0) + 1);
    return [...counts.entries()]
      .map(([kind, count]) => ({ kind, count, label: kindByName.get(kind)?.label || kind, isGoal: kindByName.get(kind)?.is_goal ?? false }))
      .sort((a, b) => (a.isGoal === b.isGoal ? a.label.localeCompare(b.label) : a.isGoal ? -1 : 1));
  }, [nodes, kindByName]);

  // ── filter pipeline ────────────────────────────────────────────────────────
  const cutoff = useMemo(() => (activeDays ? Date.now() - activeDays * 86400000 : 0), [activeDays]);
  const filteredNodes = useMemo(
    () =>
      nodes.filter((n) => {
        if (kindFilter && n.kind !== kindFilter) return false;
        if (severityFilter && n.severity && n.severity !== severityFilter) return false;
        if (cutoff && new Date(n.last_seen_at).getTime() < cutoff) return false;
        return true;
      }),
    [nodes, kindFilter, severityFilter, cutoff],
  );
  const filteredIds = useMemo(() => new Set(filteredNodes.map((n) => n.id)), [filteredNodes]);
  const filteredEdges = useMemo(
    () =>
      edges.filter((e) => {
        if (!filteredIds.has(e.from) || !filteredIds.has(e.to)) return false;
        if (cutoff && new Date(e.last_seen_at).getTime() < cutoff) return false;
        return true;
      }),
    [edges, filteredIds, cutoff],
  );

  const focusSet = useMemo(() => {
    if (!focusId || !filteredIds.has(focusId)) return null;
    const out = new Map<string, string[]>();
    const inc = new Map<string, string[]>();
    for (const e of filteredEdges) {
      (out.get(e.from) ?? out.set(e.from, []).get(e.from)!).push(e.to);
      (inc.get(e.to) ?? inc.set(e.to, []).get(e.to)!).push(e.from);
    }
    const walk = (adj: Map<string, string[]>) => {
      const seen = new Set<string>([focusId]);
      const stack = [focusId];
      while (stack.length) {
        const cur = stack.pop()!;
        for (const nxt of adj.get(cur) ?? []) if (!seen.has(nxt)) { seen.add(nxt); stack.push(nxt); }
      }
      return seen;
    };
    const set = walk(out);
    for (const id of walk(inc)) set.add(id);
    return set;
  }, [focusId, filteredEdges, filteredIds]);

  const visibleNodes = useMemo(() => (focusSet ? filteredNodes.filter((n) => focusSet.has(n.id)) : filteredNodes), [filteredNodes, focusSet]);
  const visibleIds = useMemo(() => new Set(visibleNodes.map((n) => n.id)), [visibleNodes]);
  const visibleEdges = useMemo(() => filteredEdges.filter((e) => visibleIds.has(e.from) && visibleIds.has(e.to)), [filteredEdges, visibleIds]);
  const analysisEdges: AnalysisEdge[] = useMemo(() => visibleEdges.map((e) => ({ from: e.from, to: e.to, exploited: e.exploited })), [visibleEdges]);

  const degreeOut = useMemo(() => {
    const m = new Map<string, number>();
    for (const e of visibleEdges) m.set(e.from, (m.get(e.from) ?? 0) + 1);
    return m;
  }, [visibleEdges]);

  // ── lens sets ──────────────────────────────────────────────────────────────
  const sourceIds = useMemo(() => new Set(visibleNodes.filter((n) => n.kind === 'source' || n.layer === 0).map((n) => n.id)), [visibleNodes]);
  const goalIds = useMemo(() => new Set(visibleNodes.filter(isGoalNode).map((n) => n.id)), [visibleNodes, isGoalNode]);

  const internetReach = useMemo(() => {
    const out = new Map<string, { to: string; k: string }[]>();
    for (const e of visibleEdges) (out.get(e.from) ?? out.set(e.from, []).get(e.from)!).push({ to: e.to, k: e.kind });
    const es = new Set<string>();
    const seen = new Set<string>(sourceIds);
    const stack = [...sourceIds];
    while (stack.length) {
      const c = stack.pop()!;
      for (const { to, k } of out.get(c) ?? []) {
        es.add(edgeKey(c, to, k));
        if (!seen.has(to)) { seen.add(to); stack.push(to); }
      }
    }
    return { nodes: seen, edges: es };
  }, [visibleEdges, sourceIds]);

  const exploitedSet = useMemo(() => {
    const ns = new Set<string>();
    const es = new Set<string>();
    for (const e of visibleEdges) if (e.exploited) { ns.add(e.from); ns.add(e.to); es.add(edgeKey(e.from, e.to, e.kind)); }
    return { nodes: ns, edges: es };
  }, [visibleEdges]);

  const crownRisk = useMemo(() => {
    const ns = new Set<string>();
    for (const n of visibleNodes) if (isGoalNode(n) && internetReach.nodes.has(n.id)) ns.add(n.id);
    return { nodes: ns, edges: internetReach.edges };
  }, [visibleNodes, internetReach, isGoalNode]);

  // Choke-point analysis (enumerate source→goal paths; rank by paths-crossed).
  const chokeAnalysis = useMemo(() => {
    if (!sourceIds.size || !goalIds.size) return { chokePoints: [] as ChokePoint[], paths: [] as string[][], truncated: false };
    return analyzeChokePoints(analysisEdges, sourceIds, goalIds, 8);
  }, [analysisEdges, sourceIds, goalIds]);

  const chokeRank = useMemo(() => {
    const m = new Map<string, number>();
    chokeAnalysis.chokePoints.slice(0, TOP_CHOKES).forEach((c) => m.set(c.key, c.pathCount));
    return m;
  }, [chokeAnalysis]);

  const chokeSet = useMemo(() => {
    // spotlight = all nodes/edges on enumerated source→goal paths
    const ns = new Set<string>();
    const pairSet = new Set<string>();
    for (const p of chokeAnalysis.paths) {
      for (let i = 0; i < p.length; i++) {
        ns.add(p[i]);
        if (i > 0) pairSet.add(`${p[i - 1]} ${p[i]}`);
      }
    }
    const es = new Set<string>();
    for (const e of visibleEdges) if (pairSet.has(`${e.from} ${e.to}`)) es.add(edgeKey(e.from, e.to, e.kind));
    return { nodes: ns, edges: es };
  }, [chokeAnalysis, visibleEdges]);

  // Footholds → mark nodes by node_key + spotlight their downstream blast radius.
  const footholdKeys = useMemo(() => new Set(footholds.map((f) => f.node_key).filter((k): k is string => !!k && visibleIds.has(k))), [footholds, visibleIds]);
  const footholdSet = useMemo(() => {
    if (!footholdKeys.size) return { nodes: new Set<string>(), edges: new Set<string>() };
    const out = new Map<string, { to: string; k: string }[]>();
    for (const e of visibleEdges) (out.get(e.from) ?? out.set(e.from, []).get(e.from)!).push({ to: e.to, k: e.kind });
    const ns = new Set<string>(footholdKeys);
    const es = new Set<string>();
    const stack = [...footholdKeys];
    while (stack.length) {
      const c = stack.pop()!;
      for (const { to, k } of out.get(c) ?? []) {
        es.add(edgeKey(c, to, k));
        if (!ns.has(to)) { ns.add(to); stack.push(to); }
      }
    }
    return { nodes: ns, edges: es };
  }, [footholdKeys, visibleEdges]);

  const emphasisActive = lenses.exploited || lenses.internet || lenses.crown || lenses.choke || lenses.footholds;
  const lit = useMemo(() => {
    if (!emphasisActive) return null;
    const n = new Set<string>();
    const e = new Set<string>();
    const add = (s: { nodes: Set<string>; edges: Set<string> }) => {
      for (const x of s.nodes) n.add(x);
      for (const x of s.edges) e.add(x);
    };
    if (lenses.exploited) add(exploitedSet);
    if (lenses.internet) add(internetReach);
    if (lenses.crown) add(crownRisk);
    if (lenses.choke) add(chokeSet);
    if (lenses.footholds) add(footholdSet);
    return { nodes: n, edges: e };
  }, [emphasisActive, lenses, exploitedSet, internetReach, crownRisk, chokeSet, footholdSet]);

  // ── All-findings lens: synthesize standalone nodes for findings not in the graph ─
  const syntheticFindings = useMemo(() => {
    if (!lenses.allFindings || !findingsPage?.data) return [] as GraphSubstrateNode[];
    const already = new Set<string>();
    for (const n of nodes) {
      const fid = n.attrs?.finding_id;
      if (typeof fid === 'string') already.add(fid);
    }
    const maxLayer = visibleNodes.reduce((m, n) => Math.max(m, n.layer), 0);
    return findingsPage.data
      .filter((f) => !already.has(f.id))
      .map<GraphSubstrateNode>((f) => ({
        id: `finding:${f.id}`,
        kind: 'vulnerability',
        label: f.title?.slice(0, 40) || f.cve || 'finding',
        layer: maxLayer + 1,
        severity: f.severity ?? null,
        sub: f.cve ?? null,
        is_goal: null,
        target_id: null,
        attrs: { finding_id: f.id },
        sources: ['findings'],
        assessments: [],
        last_seen_at: new Date().toISOString(),
      }));
  }, [lenses.allFindings, findingsPage, nodes, visibleNodes]);

  const displayNodes = useMemo(() => [...visibleNodes, ...syntheticFindings], [visibleNodes, syntheticFindings]);
  const isSynthetic = useMemo(() => new Set(syntheticFindings.map((n) => n.id)), [syntheticFindings]);

  // ── interactions ──────────────────────────────────────────────────────────────
  const reachableFrom = useCallback(
    (startId: string) => ({ nodes: reachableDownstream(startId, analysisEdges), edges: new Set<string>(edgeSetDownstream(startId, visibleEdges)) }),
    [analysisEdges, visibleEdges],
  );
  const selectNode = useCallback(
    (id: string) => {
      setSelectedId(id);
      setHighlight(reachableFrom(id));
    },
    [reachableFrom],
  );
  const onNodeClick = useCallback((_: unknown, node: RFNode) => selectNode(node.id), [selectNode]);
  const clearSelection = useCallback(() => {
    setSelectedId(null);
    setHighlight(null);
  }, []);
  const highlightPathNodes = useCallback(
    (nodeKeys: string[]) => {
      setSelectedId(null);
      const ns = new Set(nodeKeys);
      const pairs = new Set<string>();
      for (let i = 1; i < nodeKeys.length; i++) pairs.add(`${nodeKeys[i - 1]} ${nodeKeys[i]}`);
      const es = new Set<string>();
      for (const e of visibleEdges) if (pairs.has(`${e.from} ${e.to}`)) es.add(edgeKey(e.from, e.to, e.kind));
      setHighlight({ nodes: ns, edges: es });
      setView('graph');
    },
    [visibleEdges],
  );

  // ── positions + lanes (over displayNodes) ─────────────────────────────────────
  const { nodePos, laneLayout } = useMemo(() => {
    if (layout === 'hierarchical') {
      return { nodePos: layoutDagre(displayNodes, visibleEdges), laneLayout: [] as Lane[] };
    }
    const byLayer = new Map<number, GraphSubstrateNode[]>();
    for (const n of displayNodes) {
      const b = byLayer.get(n.layer);
      if (b) b.push(n);
      else byLayer.set(n.layer, [n]);
    }
    const layers = [...byLayer.keys()].sort((a, b) => a - b);
    const pos = new Map<string, { x: number; y: number }>();
    const lanes: Lane[] = [];
    layers.forEach((lk, ci) => {
      const colNodes = byLayer.get(lk)!;
      const x = ci * COL_W + 60;
      const kc = new Map<string, number>();
      for (const n of colNodes) kc.set(n.kind, (kc.get(n.kind) ?? 0) + 1);
      const dom = [...kc.entries()].sort((a, b) => b[1] - a[1])[0]?.[0] ?? '';
      const allSynthetic = colNodes.every((n) => isSynthetic.has(n.id));
      lanes.push({ x, label: allSynthetic ? 'Findings' : labelForKind(dom), count: colNodes.length, color: allSynthetic ? '#a78bfa' : resolveKindStyle(dom, kindStyles).stroke });
      colNodes.forEach((n, ri) => pos.set(n.id, { x, y: ri * ROW_H + ROW_Y0 }));
    });
    return { nodePos: pos, laneLayout: lanes };
  }, [layout, displayNodes, visibleEdges, labelForKind, kindStyles, isSynthetic]);

  const searchLower = search.trim().toLowerCase();

  const rfNodes: RFNode[] = useMemo(() => {
    return displayNodes.map((n) => {
      const synthetic = isSynthetic.has(n.id);
      const matched = !!searchLower && (n.label.toLowerCase().includes(searchLower) || n.id.toLowerCase().includes(searchLower));
      // synthetic finding nodes are an additive completeness layer — exempt from
      // emphasis/highlight dimming (they have no edges); only search dims them.
      const dimmed = synthetic
        ? !!searchLower && !matched
        : (!!searchLower && !matched) || (highlight ? !highlight.nodes.has(n.id) : false) || (lit ? !lit.nodes.has(n.id) : false);
      const tint = lenses.heat ? (n.severity ? severityStyle(n.severity).hex : '#64748b') : resolveKindStyle(n.kind, kindStyles).stroke;
      return {
        id: n.id,
        type: 'glow',
        position: nodePos.get(n.id) ?? { x: 0, y: 0 },
        data: {
          label: n.label,
          sub: n.sub,
          kind: n.kind,
          kindLabel: labelForKind(n.kind),
          severity: n.severity,
          isGoal: isGoalNode(n),
          isFoothold: footholdKeys.has(n.id),
          isFinding: synthetic,
          chokeCount: chokeRank.get(n.id) ?? 0,
          tint,
          badge: degreeOut.get(n.id),
          dimmed,
          matched,
          selected: n.id === selectedId,
        } satisfies GlowNodeData,
      };
    });
  }, [displayNodes, isSynthetic, nodePos, highlight, lit, lenses.heat, searchLower, selectedId, kindStyles, isGoalNode, labelForKind, degreeOut, footholdKeys, chokeRank]);

  const exploitedCount = useMemo(() => visibleEdges.filter((e) => e.exploited).length, [visibleEdges]);
  const rfEdges: RFEdge[] = useMemo(() => {
    const particlesOn = exploitedCount <= 60;
    return visibleEdges.map((e) => {
      const k = edgeKey(e.from, e.to, e.kind);
      const dimmed = (highlight ? !highlight.edges.has(k) : false) || (lit ? !lit.edges.has(k) : false);
      const color = e.exploited ? '#ef4444' : '#64748b';
      return {
        id: k,
        source: e.from,
        target: e.to,
        type: 'flow',
        label: e.kind !== 'leads_to' ? e.kind : undefined,
        labelStyle: { fontSize: 9, fill: '#94a3b8' },
        labelBgStyle: { fill: 'transparent' },
        markerEnd: { type: MarkerType.ArrowClosed, color, width: 14, height: 14 },
        data: { exploited: e.exploited, dimmed, particle: particlesOn } satisfies FlowEdgeData,
      };
    });
  }, [visibleEdges, highlight, lit, exploitedCount]);

  useEffect(() => {
    if (view !== 'graph' || !rfNodes.length) return;
    const t = setTimeout(() => rf.fitView({ duration: 350, padding: 0.2 }), 60);
    return () => clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [layout, focusId, view, lenses.allFindings]);

  // ── pathfinding ──────────────────────────────────────────────────────────────
  const [pq, setPq] = useState({ source_kind: 'source', goal_kind: 'asset', exploited_only: false, reachable_only: false, max_depth: 6 });
  const [pathResult, setPathResult] = useState<GraphPathsResponse | null>(null);
  const [pathLoading, setPathLoading] = useState(false);
  const [pathOpen, setPathOpen] = useState(false);

  useEffect(() => {
    if (!presentKinds.length) return;
    const has = (k: string) => presentKinds.some((p) => p.kind === k);
    setPq((prev) => ({
      ...prev,
      source_kind: has(prev.source_kind) ? prev.source_kind : has('source') ? 'source' : presentKinds[presentKinds.length - 1].kind,
      goal_kind: prev.goal_kind && !has(prev.goal_kind) ? (has('asset') ? 'asset' : '') : prev.goal_kind,
    }));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [presentKinds.length]);

  const runPathQuery = useCallback(async () => {
    setPathLoading(true);
    try {
      const res = await api.graph.paths({
        source_kind: pq.source_kind || undefined,
        goal_kind: pq.goal_kind || undefined,
        exploited_only: pq.exploited_only,
        reachable_only: pq.reachable_only,
        max_depth: pq.max_depth,
        limit: 200,
      });
      setPathResult(res);
    } finally {
      setPathLoading(false);
    }
  }, [pq]);

  // ── inspector data ────────────────────────────────────────────────────────────
  const nodeLabel = useMemo(() => {
    const m = new Map<string, string>();
    for (const n of displayNodes) m.set(n.id, n.label || n.id);
    return (key: string) => m.get(key) ?? key;
  }, [displayNodes]);
  const selectedNode = useMemo(() => (selectedId ? displayNodes.find((n) => n.id === selectedId) ?? null : null), [selectedId, displayNodes]);
  const selectedNeighbors = useMemo(() => {
    if (!selectedId) return { out: [], inc: [] };
    const out: { key: string; exploited: boolean }[] = [];
    const inc: { key: string; exploited: boolean }[] = [];
    for (const e of visibleEdges) {
      if (e.from === selectedId) out.push({ key: e.to, exploited: e.exploited });
      if (e.to === selectedId) inc.push({ key: e.from, exploited: e.exploited });
    }
    return { out, inc };
  }, [selectedId, visibleEdges]);
  const selectedChoke = useMemo(() => chokeAnalysis.chokePoints.find((c) => c.key === selectedId) ?? null, [chokeAnalysis, selectedId]);
  const findingId = useMemo(() => {
    if (!selectedNode || selectedNode.kind !== 'vulnerability') return null;
    const fromAttrs = selectedNode.attrs?.finding_id;
    if (typeof fromAttrs === 'string' && fromAttrs) return fromAttrs;
    if (selectedNode.id.startsWith('v:')) return selectedNode.id.slice(2);
    return null;
  }, [selectedNode]);

  // ── overview (top choke / targets / entry points) ─────────────────────────────
  const overview = useMemo(() => {
    const targetCount = new Map<string, number>();
    const entryCount = new Map<string, number>();
    for (const p of chokeAnalysis.paths) {
      if (p.length < 2) continue;
      targetCount.set(p[p.length - 1], (targetCount.get(p[p.length - 1]) ?? 0) + 1);
      entryCount.set(p[0], (entryCount.get(p[0]) ?? 0) + 1);
    }
    const top = (m: Map<string, number>) => [...m.entries()].sort((a, b) => b[1] - a[1]).slice(0, 3);
    return { chokes: chokeAnalysis.chokePoints.slice(0, 3), targets: top(targetCount), entries: top(entryCount), pathTotal: chokeAnalysis.paths.length, truncated: chokeAnalysis.truncated };
  }, [chokeAnalysis]);

  // ── export ────────────────────────────────────────────────────────────────────
  const doExport = useCallback(
    async (type: 'png' | 'svg') => {
      const viewportEl = document.querySelector('.react-flow__viewport') as HTMLElement | null;
      if (!viewportEl || !rfNodes.length) {
        toast.error('Nothing to export yet.');
        return;
      }
      setExporting(true);
      try {
        const { toPng, toSvg } = await import('html-to-image');
        const W = 1800;
        const H = 1100;
        const bounds = getNodesBounds(rfNodes);
        const vp = getViewportForBounds(bounds, W, H, 0.2, 2, 0.12);
        const opts = { backgroundColor: CANVAS_BG, width: W, height: H, pixelRatio: 2, style: { width: `${W}px`, height: `${H}px`, transform: `translate(${vp.x}px, ${vp.y}px) scale(${vp.zoom})` } };
        const dataUrl = type === 'png' ? await toPng(viewportEl, opts) : await toSvg(viewportEl, opts);
        const a = document.createElement('a');
        a.href = dataUrl;
        a.download = `attack-graph.${type}`;
        a.click();
        toast.success(`Exported ${type.toUpperCase()}`);
      } catch {
        toast.error('Export failed.');
      } finally {
        setExporting(false);
      }
    },
    [rfNodes],
  );

  const stats = useMemo(() => ({ crown: goalIds.size, exploited: exploitedCount, chokes: chokeAnalysis.chokePoints.length }), [goalIds, exploitedCount, chokeAnalysis]);
  const focusNode = useMemo(() => (focusId ? nodes.find((n) => n.id === focusId) ?? null : null), [focusId, nodes]);

  const loading = nodesLoading || edgesLoading;
  const empty = !loading && nodes.length === 0;

  const glassPanel = 'rounded-2xl border border-white/10 bg-[#0d1018]/85 shadow-[0_8px_30px_rgba(0,0,0,0.5)] backdrop-blur-xl';
  const selectCls = 'rounded-lg border border-white/10 bg-white/5 px-2 py-1 text-xs text-slate-200 outline-none';

  const LENSES: { key: keyof typeof lenses; label: string; desc: string; icon: LucideIcon; color: string }[] = [
    { key: 'choke', label: 'Choke points', desc: 'Nodes where many paths converge', icon: Zap, color: CHOKE },
    { key: 'exploited', label: 'Exploited paths', desc: 'Spotlight proven kill-chains', icon: GitBranch, color: '#ef4444' },
    { key: 'internet', label: 'Reachable from internet', desc: 'What an external attacker can touch', icon: Globe, color: '#38bdf8' },
    { key: 'crown', label: 'Crown jewels at risk', desc: 'Goals reachable from the internet', icon: Crown, color: GOLD },
    { key: 'footholds', label: 'Paths from footholds', desc: 'From where we actually landed', icon: Skull, color: '#f87171' },
    { key: 'heat', label: 'Severity heat', desc: 'Recolor nodes by severity', icon: Flame, color: '#fb7185' },
    { key: 'allFindings', label: 'All findings', desc: 'Add every finding as a node', icon: ShieldAlert, color: '#a78bfa' },
  ];

  // Enumerated paths for the table view (reuse choke enumeration).
  const tablePaths = useMemo(() => {
    return chokeAnalysis.paths
      .map((p) => {
        const pairs = new Set<string>();
        for (let i = 1; i < p.length; i++) pairs.add(`${p[i - 1]} ${p[i]}`);
        let exploited = p.length > 1;
        for (let i = 1; i < p.length; i++) {
          const e = visibleEdges.find((ed) => ed.from === p[i - 1] && ed.to === p[i]);
          if (!e?.exploited) exploited = false;
        }
        return { nodes: p, depth: p.length - 1, target: p[p.length - 1], exploited };
      })
      .sort((a, b) => a.depth - b.depth);
  }, [chokeAnalysis, visibleEdges]);

  return (
    <div className="flex h-full w-full flex-col bg-[#080a10]">
      <style>{`
        @keyframes rfCrownPulse { 0%,100% { box-shadow: 0 0 16px rgba(251,191,36,0.25); } 50% { box-shadow: 0 0 26px rgba(251,191,36,0.5); } }
        .rf-crown { animation: rfCrownPulse 3.2s ease-in-out infinite; }
        .rf-glow-node:hover { transform: translateY(-1px); }
      `}</style>

      {/* ── Top bar ──────────────────────────────────────────────────────────── */}
      <div className="z-10 flex shrink-0 flex-wrap items-center gap-x-3 gap-y-2 border-b border-white/10 bg-[#0b0e16]/80 px-4 py-2.5 backdrop-blur-xl">
        <div className="flex items-center gap-2">
          <div className="flex h-7 w-7 items-center justify-center rounded-lg bg-purple-500/20 shadow-[0_0_14px_rgba(168,85,247,0.4)]">
            <Workflow className="h-4 w-4 text-purple-300" />
          </div>
          <div className="text-sm font-semibold text-slate-100">Attack Graph</div>
        </div>

        <div className="flex flex-wrap items-center gap-1.5">
          <FilterPill icon={Search} value={kindFilter} onChange={setKindFilter}>
            <option value="">All kinds ({nodes.length})</option>
            {presentKinds.map((k) => (
              <option key={k.kind} value={k.kind}>
                {k.isGoal ? '★ ' : ''}
                {k.label} ({k.count})
              </option>
            ))}
          </FilterPill>
          <FilterPill icon={ShieldAlert} value={severityFilter} onChange={setSeverityFilter}>
            <option value="">Any severity</option>
            {SEVERITIES.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </FilterPill>
          <FilterPill icon={Layers} value={activeDays} onChange={(v) => setActiveDays(Number(v))}>
            {ACTIVE_WINDOWS.map((w) => (
              <option key={w.days} value={w.days}>
                {w.label}
              </option>
            ))}
          </FilterPill>
          <div className="relative flex items-center gap-1 rounded-full border border-white/10 bg-white/5 px-2.5 backdrop-blur">
            <Search className="h-3.5 w-3.5 text-slate-400" />
            <input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search…" className="w-24 bg-transparent py-1 text-[11px] text-slate-200 outline-none placeholder:text-slate-500" />
          </div>
        </div>

        {focusNode && (
          <button onClick={() => setFocusId(null)} className="flex items-center gap-1 rounded-full border border-amber-500/40 bg-amber-500/10 px-2.5 py-1 text-[11px] font-medium text-amber-300 hover:bg-amber-500/20">
            <Focus className="h-3 w-3" /> {focusNode.label || focusNode.id}
            <span className="opacity-60">· {visibleNodes.length}</span>
            <X className="h-3 w-3" />
          </button>
        )}

        <div className="ml-auto flex flex-wrap items-center gap-1.5">
          <StatChip icon={Circle} value={`${visibleNodes.length}${visibleNodes.length !== nodes.length ? `/${nodes.length}` : ''}`} title="nodes" />
          <StatChip icon={Zap} value={stats.chokes} accent={stats.chokes ? CHOKE : undefined} title="choke points" />
          <StatChip icon={Crown} value={stats.crown} accent={GOLD} title="crown jewels" />
          <StatChip icon={GitBranch} value={stats.exploited} accent={stats.exploited ? '#ef4444' : undefined} title="exploited edges" />

          {/* Graph / Table */}
          <div className="ml-1 flex items-center rounded-full border border-white/10 bg-white/5 p-0.5 backdrop-blur">
            <button onClick={() => setView('graph')} className={`flex items-center gap-1 rounded-full px-2 py-0.5 text-[11px] ${view === 'graph' ? 'bg-purple-500/30 text-purple-100' : 'text-slate-400 hover:text-slate-200'}`} title="Graph view">
              <Workflow className="h-3 w-3" /> Graph
            </button>
            <button onClick={() => setView('table')} className={`flex items-center gap-1 rounded-full px-2 py-0.5 text-[11px] ${view === 'table' ? 'bg-purple-500/30 text-purple-100' : 'text-slate-400 hover:text-slate-200'}`} title="Paths table">
              <Table2 className="h-3 w-3" /> Table
            </button>
          </div>

          {/* layered / auto (graph only) */}
          {view === 'graph' && (
            <div className="flex items-center rounded-full border border-white/10 bg-white/5 p-0.5 backdrop-blur">
              <button onClick={() => setLayout('layered')} className={`flex items-center gap-1 rounded-full px-2 py-0.5 text-[11px] ${layout === 'layered' ? 'bg-purple-500/30 text-purple-100' : 'text-slate-400 hover:text-slate-200'}`} title="Layered columns">
                <Columns3 className="h-3 w-3" /> Layered
              </button>
              <button onClick={() => setLayout('hierarchical')} className={`flex items-center gap-1 rounded-full px-2 py-0.5 text-[11px] ${layout === 'hierarchical' ? 'bg-purple-500/30 text-purple-100' : 'text-slate-400 hover:text-slate-200'}`} title="dagre auto-layout">
                <Network className="h-3 w-3" /> Auto
              </button>
            </div>
          )}
          {view === 'graph' && (
            <button onClick={() => rf.fitView({ duration: 300, padding: 0.2 })} className="rounded-full border border-white/10 bg-white/5 p-1.5 text-slate-300 hover:bg-white/10" title="Fit to view">
              <Maximize2 className="h-3.5 w-3.5" />
            </button>
          )}
          <button onClick={() => doExport('png')} disabled={exporting} className="flex items-center gap-1 rounded-full border border-white/10 bg-white/5 px-2 py-1 text-[11px] text-slate-300 hover:bg-white/10 disabled:opacity-50" title="Export PNG">
            <ImageIcon className="h-3 w-3" /> PNG
          </button>
          <button onClick={() => doExport('svg')} disabled={exporting} className="rounded-full border border-white/10 bg-white/5 px-2 py-1 text-[11px] text-slate-300 hover:bg-white/10 disabled:opacity-50" title="Export SVG">
            SVG
          </button>
        </div>
      </div>

      {/* ── Body ─────────────────────────────────────────────────────────────── */}
      <div className="relative flex-1" style={{ background: `radial-gradient(1200px 600px at 30% 0%, rgba(76,29,149,0.18), transparent 60%), radial-gradient(900px 500px at 90% 100%, rgba(8,47,73,0.25), transparent 60%), ${CANVAS_BG}` }}>
        {view === 'table' ? (
          <PathsTable paths={tablePaths} nodeLabel={nodeLabel} onPick={highlightPathNodes} />
        ) : (
          <ReactFlow
            nodes={rfNodes}
            edges={rfEdges}
            nodeTypes={nodeTypes}
            edgeTypes={edgeTypes}
            onNodeClick={onNodeClick}
            onPaneClick={clearSelection}
            nodesDraggable={false}
            fitView
            minZoom={0.1}
            colorMode="dark"
            proOptions={{ hideAttribution: true }}
            style={{ background: 'transparent' }}
          >
            <Background variant={BackgroundVariant.Dots} gap={26} size={1} color="#1b2233" />
            <LaneOverlay lanes={laneLayout} />
            <Controls className="!rounded-xl !border !border-white/10 !bg-[#0d1018]/85 !shadow-lg !backdrop-blur-xl [&_button]:!border-white/10 [&_button]:!bg-transparent [&_button:hover]:!bg-white/10 [&_button_svg]:!fill-slate-300" showInteractive={false} />

            {/* Left rail — collapsible */}
            {railOpen ? (
              <Panel position="top-left" className={`flex max-h-[calc(100%-1.5rem)] w-60 flex-col gap-3 overflow-y-auto p-3 text-xs ${glassPanel}`}>
                <div className="flex items-center justify-between">
                  <span className="text-[11px] font-semibold uppercase tracking-wide text-slate-300">Insights</span>
                  <button onClick={() => setRailOpen(false)} className="text-slate-400 hover:text-slate-200" title="Collapse">
                    <PanelLeftClose className="h-4 w-4" />
                  </button>
                </div>

                {/* Overview */}
                {overview.pathTotal > 0 && (
                  <div className="flex flex-col gap-1 rounded-lg border border-white/10 bg-white/5 p-2">
                    <div className="flex items-center gap-1 text-[10px] font-semibold uppercase tracking-wide text-slate-400">
                      <Target className="h-3 w-3" /> Overview
                    </div>
                    {overview.chokes.length > 0 && (
                      <button onClick={() => selectNode(overview.chokes[0].key)} className="flex items-center justify-between gap-2 rounded px-1 py-0.5 text-left hover:bg-white/10">
                        <span className="truncate text-[10px] text-slate-300"><Zap className="mr-0.5 inline h-2.5 w-2.5" style={{ color: CHOKE }} /> top choke: {nodeLabel(overview.chokes[0].key)}</span>
                        <span className="shrink-0 text-[10px] font-semibold" style={{ color: CHOKE }}>{overview.chokes[0].pathCount}</span>
                      </button>
                    )}
                    <div className="text-[10px] text-slate-500">{overview.pathTotal}{overview.truncated ? '+' : ''} source→goal paths · {overview.targets.length} targets · {overview.entries.length} entries</div>
                  </div>
                )}

                {/* Insight Layers */}
                <div className="flex flex-col gap-1.5">
                  <div className="flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wide text-slate-400">
                    <Layers className="h-3.5 w-3.5" /> Insight Layers
                  </div>
                  {LENSES.map((l) => {
                    const on = lenses[l.key];
                    return (
                      <button key={l.key} onClick={() => setLenses((p) => ({ ...p, [l.key]: !p[l.key] }))} className={`flex items-center gap-2 rounded-lg border px-2 py-1.5 text-left transition-colors ${on ? 'border-white/20 bg-white/10' : 'border-transparent hover:bg-white/5'}`}>
                        <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-md" style={{ background: withAlpha(l.color, on ? 0.25 : 0.1), boxShadow: on ? `0 0 10px ${withAlpha(l.color, 0.4)}` : undefined }}>
                          <l.icon className="h-3.5 w-3.5" style={{ color: l.color }} />
                        </span>
                        <span className="min-w-0 flex-1">
                          <span className={`block text-[11px] font-medium ${on ? 'text-slate-100' : 'text-slate-300'}`}>{l.label}</span>
                          <span className="block truncate text-[9px] text-slate-500">{l.desc}</span>
                        </span>
                        <span className={`h-2 w-2 shrink-0 rounded-full ${on ? '' : 'opacity-30'}`} style={{ background: on ? l.color : '#64748b', boxShadow: on ? `0 0 8px ${l.color}` : undefined }} />
                      </button>
                    );
                  })}
                </div>

                {/* Find paths */}
                <div className="flex flex-col gap-2 border-t border-white/10 pt-2.5">
                  <button onClick={() => setPathOpen((o) => !o)} className="flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wide text-slate-400">
                    <Crosshair className="h-3.5 w-3.5" /> Find paths
                    <ChevronDown className={`ml-auto h-3.5 w-3.5 transition-transform ${pathOpen ? '' : '-rotate-90'}`} />
                  </button>
                  {pathOpen && (
                    <>
                      <label className="flex items-center justify-between gap-2 text-slate-300">
                        From
                        <select className={`${selectCls} w-32`} value={pq.source_kind} onChange={(e) => setPq({ ...pq, source_kind: e.target.value })}>
                          {presentKinds.map((k) => (<option key={k.kind} value={k.kind}>{k.label} ({k.count})</option>))}
                        </select>
                      </label>
                      <label className="flex items-center justify-between gap-2 text-slate-300">
                        Goal
                        <select className={`${selectCls} w-32`} value={pq.goal_kind} onChange={(e) => setPq({ ...pq, goal_kind: e.target.value })}>
                          <option value="">Any crown jewel ★</option>
                          {presentKinds.map((k) => (<option key={k.kind} value={k.kind}>{k.isGoal ? '★ ' : ''}{k.label} ({k.count})</option>))}
                        </select>
                      </label>
                      <label className="flex items-center justify-between gap-2 text-slate-300">
                        Max depth
                        <select className={`${selectCls} w-32`} value={pq.max_depth} onChange={(e) => setPq({ ...pq, max_depth: Number(e.target.value) })}>
                          {DEPTHS.map((d) => (<option key={d} value={d}>{d} hops</option>))}
                        </select>
                      </label>
                      <label className="flex items-center gap-1.5 text-slate-300"><input type="checkbox" checked={pq.exploited_only} onChange={(e) => setPq({ ...pq, exploited_only: e.target.checked })} /> Exploited only</label>
                      <label className="flex items-center gap-1.5 text-slate-300"><input type="checkbox" checked={pq.reachable_only} onChange={(e) => setPq({ ...pq, reachable_only: e.target.checked })} /> Reachable-only (fast)</label>
                      <button onClick={runPathQuery} disabled={pathLoading} className="rounded-lg bg-gradient-to-r from-purple-600 to-fuchsia-600 px-2 py-1.5 text-xs font-medium text-white shadow-[0_0_14px_rgba(168,85,247,0.4)] disabled:opacity-50">
                        {pathLoading ? 'Searching…' : 'Find paths'}
                      </button>
                      {pathResult && (
                        <div className="max-h-48 overflow-y-auto rounded-lg border border-white/10 bg-black/30 p-1">
                          {pathResult.truncated && <div className="mb-1 px-1 text-[10px] text-amber-400">Truncated — narrow the query.</div>}
                          {pathResult.reachable ? (
                            pathResult.reachable.length === 0 ? (
                              <div className="px-1 py-0.5 text-[10px] text-slate-500">No reachable goals.</div>
                            ) : (
                              pathResult.reachable.map((r) => (
                                <button key={r.goal_key} onClick={() => selectNode(r.goal_key)} className="block w-full truncate rounded px-1 py-0.5 text-left text-[11px] text-slate-300 hover:bg-white/10" title={r.goal_key}>
                                  <span className="font-medium text-amber-300">★ {nodeLabel(r.goal_key)}</span>
                                  <span className="text-slate-500"> ← {r.reached_from.length} src</span>
                                </button>
                              ))
                            )
                          ) : (pathResult.paths ?? []).length === 0 ? (
                            <div className="px-1 py-0.5 text-[10px] text-slate-500">No paths found.</div>
                          ) : (
                            (pathResult.paths ?? []).map((p, i) => (
                              <button key={`${p.start_key}-${i}`} onClick={() => highlightPathNodes(p.nodes)} className="block w-full truncate rounded px-1 py-0.5 text-left text-[11px] text-slate-300 hover:bg-white/10" title={p.nodes.map(nodeLabel).join(' → ')}>
                                <span className="text-slate-500">{p.depth}h:</span> {p.nodes.map(nodeLabel).join(' → ')}
                              </button>
                            ))
                          )}
                        </div>
                      )}
                    </>
                  )}
                </div>

                <div className="flex flex-col gap-1 border-t border-white/10 pt-2 text-[10px] text-slate-400">
                  <span className="flex items-center gap-1.5"><span className="inline-block w-4 border-t-2 border-red-500" /> exploited <span className="ml-1 inline-block w-4 border-t border-dashed border-slate-500" /> detected</span>
                  <span className="flex items-center gap-2">
                    <span className="flex items-center gap-1"><Crown className="h-3 w-3" style={{ color: GOLD }} /> crown</span>
                    <span className="flex items-center gap-1"><Zap className="h-3 w-3" style={{ color: CHOKE }} /> choke</span>
                    <span className="flex items-center gap-1"><Skull className="h-3 w-3 text-red-400" /> foothold</span>
                  </span>
                </div>
              </Panel>
            ) : (
              <Panel position="top-left">
                <button onClick={() => setRailOpen(true)} className={`flex items-center gap-1 px-2 py-2 text-slate-300 hover:text-white ${glassPanel}`} title="Open insights">
                  <PanelLeftOpen className="h-4 w-4" />
                </button>
              </Panel>
            )}

            {/* Right inspector */}
            {selectedNode && (
              <Panel position="top-right" className={`flex max-h-[calc(100%-1.5rem)] w-72 flex-col gap-2 overflow-y-auto p-3 text-xs ${glassPanel}`}>
                <div className="flex items-start justify-between gap-2">
                  <div className="flex min-w-0 items-center gap-2">
                    <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full" style={{ background: withAlpha(footholdKeys.has(selectedNode.id) ? '#f87171' : isGoalNode(selectedNode) ? GOLD : resolveKindStyle(selectedNode.kind, kindStyles).stroke, 0.16) }}>
                      <KindGlyph
                        icon={footholdKeys.has(selectedNode.id) ? Skull : iconForKind(selectedNode.kind, isGoalNode(selectedNode))}
                        className="h-3.5 w-3.5"
                        style={{ color: footholdKeys.has(selectedNode.id) ? '#f87171' : isGoalNode(selectedNode) ? GOLD : resolveKindStyle(selectedNode.kind, kindStyles).stroke }}
                      />
                    </span>
                    <span className="truncate text-sm font-semibold text-slate-100">{selectedNode.label || selectedNode.id}</span>
                  </div>
                  <button onClick={clearSelection} className="shrink-0 text-slate-400 hover:text-slate-200"><X className="h-3.5 w-3.5" /></button>
                </div>

                <div className="flex flex-wrap items-center gap-1.5">
                  <span className="rounded-full border border-white/10 px-2 py-0.5 text-[10px] uppercase tracking-wide text-slate-300">{labelForKind(selectedNode.kind)}</span>
                  {isGoalNode(selectedNode) && <span className="flex items-center gap-1 rounded-full px-2 py-0.5 text-[10px]" style={{ background: withAlpha(GOLD, 0.15), color: GOLD }}><Crown className="h-3 w-3" /> crown jewel</span>}
                  {footholdKeys.has(selectedNode.id) && <span className="flex items-center gap-1 rounded-full px-2 py-0.5 text-[10px]" style={{ background: 'rgba(248,113,113,0.15)', color: '#f87171' }}><Skull className="h-3 w-3" /> foothold</span>}
                  {selectedNode.severity && <span className="rounded-full px-2 py-0.5 text-[10px] font-medium uppercase" style={{ background: `${severityStyle(selectedNode.severity).hex}22`, color: severityStyle(selectedNode.severity).hex }}>{selectedNode.severity}</span>}
                </div>

                {/* choke-point leverage */}
                {selectedChoke && (
                  <div className="rounded-lg border px-2 py-1.5" style={{ borderColor: withAlpha(CHOKE, 0.4), background: withAlpha(CHOKE, 0.08) }}>
                    <div className="flex items-center gap-1 text-[11px] font-semibold" style={{ color: CHOKE }}><Zap className="h-3 w-3" /> Choke point</div>
                    <div className="text-[10px] text-slate-300">Fixing this breaks <b>{selectedChoke.pathCount}</b> attack path{selectedChoke.pathCount === 1 ? '' : 's'} to <b>{selectedChoke.goalsCovered}</b> crown jewel{selectedChoke.goalsCovered === 1 ? '' : 's'}.</div>
                  </div>
                )}

                <div className="grid grid-cols-2 gap-2 border-t border-white/10 pt-2">
                  <div>
                    <div className="mb-1 flex items-center gap-1 text-[10px] font-medium text-slate-400"><ArrowRight className="h-3 w-3" /> Reaches ({selectedNeighbors.out.length})</div>
                    {selectedNeighbors.out.length === 0 ? <div className="text-[10px] text-slate-600">—</div> : selectedNeighbors.out.slice(0, 8).map((n) => (
                      <button key={`o-${n.key}`} onClick={() => selectNode(n.key)} className="block w-full truncate rounded px-1 py-0.5 text-left text-[10px] hover:bg-white/10" style={{ color: n.exploited ? '#fca5a5' : '#cbd5e1' }} title={n.key}>{nodeLabel(n.key)}</button>
                    ))}
                  </div>
                  <div>
                    <div className="mb-1 flex items-center gap-1 text-[10px] font-medium text-slate-400"><ArrowLeftRight className="h-3 w-3" /> Reached by ({selectedNeighbors.inc.length})</div>
                    {selectedNeighbors.inc.length === 0 ? <div className="text-[10px] text-slate-600">—</div> : selectedNeighbors.inc.slice(0, 8).map((n) => (
                      <button key={`i-${n.key}`} onClick={() => selectNode(n.key)} className="block w-full truncate rounded px-1 py-0.5 text-left text-[10px] text-slate-300 hover:bg-white/10" title={n.key}>{nodeLabel(n.key)}</button>
                    ))}
                  </div>
                </div>

                <dl className="space-y-0.5 border-t border-white/10 pt-2 text-[11px] text-slate-300">
                  <div className="flex justify-between gap-2"><dt className="text-slate-500">sources</dt><dd className="truncate">{selectedNode.sources.join(', ') || '—'}</dd></div>
                  <div className="flex justify-between gap-2"><dt className="text-slate-500">assessments</dt><dd>{selectedNode.assessments.length}</dd></div>
                  <div className="flex justify-between gap-2"><dt className="text-slate-500">last seen</dt><dd>{new Date(selectedNode.last_seen_at).toLocaleDateString()}</dd></div>
                </dl>

                <div className="flex flex-col gap-1.5">
                  <button onClick={() => setFocusId(focusId === selectedNode.id ? null : selectedNode.id)} className="flex items-center justify-center gap-1 rounded-lg border border-white/10 px-2 py-1.5 text-[11px] font-medium text-slate-200 hover:bg-white/10">
                    <Focus className="h-3 w-3" /> {focusId === selectedNode.id ? 'Exit focus' : 'Isolate blast radius (↑↓)'}
                  </button>
                  {findingId && (
                    <button onClick={() => router.push(`/findings?id=${encodeURIComponent(findingId)}`)} className="flex items-center justify-center gap-1 rounded-lg bg-gradient-to-r from-purple-600 to-fuchsia-600 px-2 py-1.5 text-[11px] font-medium text-white shadow-[0_0_12px_rgba(168,85,247,0.4)]">
                      <ExternalLink className="h-3 w-3" /> View finding
                    </button>
                  )}
                </div>
                {highlight && <div className="text-[10px] text-slate-500">Highlighting blast radius (everything this node reaches).</div>}
              </Panel>
            )}

            {(loading || empty) && (
              <Panel position="top-center" className="pointer-events-none mt-20">
                <div className={`flex flex-col items-center gap-2 px-7 py-6 text-center ${glassPanel}`}>
                  {loading ? (
                    <>
                      <Layers className="h-6 w-6 animate-pulse text-purple-300" />
                      <div className="text-sm font-medium text-slate-200">Loading attack graph…</div>
                    </>
                  ) : (
                    <>
                      <div className="flex h-12 w-12 items-center justify-center rounded-full bg-purple-500/15 shadow-[0_0_22px_rgba(168,85,247,0.35)]"><Workflow className="h-6 w-6 text-purple-300" /></div>
                      <div className="text-sm font-medium text-slate-100">No attack-graph data yet</div>
                      <div className="max-w-xs text-xs text-slate-400">Run an assessment or a cloud/DAST correlation — discovered findings, exposures, and escalation paths accumulate into this graph automatically.</div>
                    </>
                  )}
                </div>
              </Panel>
            )}
          </ReactFlow>
        )}
      </div>
    </div>
  );
}

// ── paths table view ──────────────────────────────────────────────────────────
function PathsTable({
  paths,
  nodeLabel,
  onPick,
}: {
  paths: { nodes: string[]; depth: number; target: string; exploited: boolean }[];
  nodeLabel: (k: string) => string;
  onPick: (nodes: string[]) => void;
}) {
  if (!paths.length) {
    return <div className="flex h-full items-center justify-center text-sm text-slate-400">No source→goal paths in the current view.</div>;
  }
  return (
    <div className="h-full overflow-auto p-4">
      <table className="w-full border-separate border-spacing-y-1 text-xs">
        <thead className="sticky top-0">
          <tr className="text-left text-[10px] uppercase tracking-wide text-slate-500">
            <th className="px-2 py-1">Path (entry → crown jewel)</th>
            <th className="px-2 py-1">Hops</th>
            <th className="px-2 py-1">Status</th>
            <th className="px-2 py-1">Target</th>
          </tr>
        </thead>
        <tbody>
          {paths.map((p, i) => (
            <tr key={i} onClick={() => onPick(p.nodes)} className="cursor-pointer rounded-lg bg-white/5 hover:bg-white/10">
              <td className="max-w-xl truncate px-2 py-1.5 text-slate-200" title={p.nodes.map(nodeLabel).join(' → ')}>{p.nodes.map(nodeLabel).join(' → ')}</td>
              <td className="px-2 py-1.5 text-slate-400">{p.depth}</td>
              <td className="px-2 py-1.5">
                {p.exploited ? <span className="rounded-full bg-red-500/15 px-2 py-0.5 text-[10px] font-medium text-red-300">EXPLOITED</span> : <span className="rounded-full bg-slate-500/15 px-2 py-0.5 text-[10px] text-slate-400">detected</span>}
              </td>
              <td className="px-2 py-1.5 text-amber-300">★ {nodeLabel(p.target)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// Downstream edge keys from a start node (for click-highlight blast radius).
function edgeSetDownstream(start: string, edges: GraphSubstrateEdge[]): Set<string> {
  const adj = new Map<string, GraphSubstrateEdge[]>();
  for (const e of edges) (adj.get(e.from) ?? adj.set(e.from, []).get(e.from)!).push(e);
  const seen = new Set<string>([start]);
  const es = new Set<string>();
  const stack = [start];
  while (stack.length) {
    const cur = stack.pop()!;
    for (const e of adj.get(cur) ?? []) {
      es.add(edgeKey(e.from, e.to, e.kind));
      if (!seen.has(e.to)) { seen.add(e.to); stack.push(e.to); }
    }
  }
  return es;
}

export default function GraphExplorer() {
  return (
    <ReactFlowProvider>
      <GraphExplorerInner />
    </ReactFlowProvider>
  );
}
