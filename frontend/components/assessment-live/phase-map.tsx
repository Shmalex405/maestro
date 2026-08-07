'use client';

// The assessment skeleton as an interactive left-to-right pipeline: one node
// per phase, each holding its agents as clickable chips. Live ProgressEvent
// state colours the chips (pending/active/done/error) and pulses the active
// phase. Reuses the project's @xyflow/react + @dagrejs/dagre conventions
// (see components/graph/graph-explorer.tsx).

import { useMemo } from 'react';
import {
  ReactFlow,
  ReactFlowProvider,
  Background,
  Controls,
  Handle,
  Position,
  type Node as RFNode,
  type Edge as RFEdge,
  type NodeProps,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import dagre from '@dagrejs/dagre';
import { motion } from 'framer-motion';
import { cn } from '@/lib/utils';
import type { AgentState, AssessmentPlan, PlanPhase } from '@/lib/assessment-progress/types';

const NODE_W = 240;
const ROW_H = 34;
const HEADER_H = 52;

type AgentChip = {
  name: string;
  testCount: number;
  inScope: boolean;
  state: AgentState | undefined;
};

interface PhaseNodeData extends Record<string, unknown> {
  phase: PlanPhase;
  isActivePhase: boolean;
  chips: AgentChip[];
  onSelectAgent: (name: string) => void;
  selectedAgent: string | null;
}

const STATUS_DOT: Record<string, string> = {
  pending: 'bg-muted-foreground/30',
  active: 'bg-cyan-400',
  done: 'bg-emerald-500',
  error: 'bg-amber-500',
};

function chipStatus(chip: AgentChip): 'pending' | 'active' | 'done' | 'error' {
  if (!chip.inScope) return 'pending';
  const s = chip.state?.status ?? 'pending';
  if (s === 'active' && (chip.state?.errorCount ?? 0) > 0) return 'error';
  return s;
}

function PhaseNode({ data }: NodeProps) {
  const { phase, isActivePhase, chips, onSelectAgent, selectedAgent } =
    data as PhaseNodeData;

  return (
    <motion.div
      initial={false}
      animate={
        isActivePhase
          ? { boxShadow: '0 0 0 2px rgba(34,211,238,0.55)', scale: 1 }
          : { boxShadow: '0 0 0 1px rgba(255,255,255,0.06)', scale: 1 }
      }
      transition={{ duration: 0.4 }}
      className="rounded-xl bg-card/95 backdrop-blur-sm overflow-hidden"
      style={{ width: NODE_W }}
    >
      <Handle type="target" position={Position.Left} className="!bg-transparent !border-0" />
      <Handle type="source" position={Position.Right} className="!bg-transparent !border-0" />

      <div
        className={cn(
          'px-3 py-2 flex items-center justify-between',
          isActivePhase ? 'bg-cyan-500/15' : 'bg-muted/40'
        )}
      >
        <div className="min-w-0">
          <div className="text-[10px] uppercase tracking-wide text-muted-foreground">
            Phase {phase.phase}
            {phase.parallel && ' · parallel'}
          </div>
          <div className="text-xs font-semibold text-foreground truncate">
            {phase.name}
          </div>
        </div>
        {isActivePhase && (
          <motion.span
            className="h-2 w-2 rounded-full bg-cyan-400 shrink-0"
            animate={{ opacity: [1, 0.3, 1] }}
            transition={{ duration: 1.4, repeat: Infinity }}
          />
        )}
      </div>

      <div className="p-1.5 space-y-0.5">
        {chips.map((chip) => {
          const status = chipStatus(chip);
          const selected = selectedAgent === chip.name;
          return (
            <button
              key={chip.name}
              onClick={(e) => {
                e.stopPropagation();
                onSelectAgent(chip.name);
              }}
              className={cn(
                'w-full flex items-center gap-2 px-2 rounded-md text-left transition-colors',
                'hover:bg-muted/60',
                selected && 'bg-muted ring-1 ring-cyan-500/40',
                !chip.inScope && 'opacity-40'
              )}
              style={{ height: ROW_H }}
            >
              <span className="relative flex h-2 w-2 shrink-0">
                {status === 'active' && (
                  <motion.span
                    className="absolute inline-flex h-full w-full rounded-full bg-cyan-400"
                    animate={{ opacity: [0.7, 0, 0.7], scale: [1, 2.2, 1] }}
                    transition={{ duration: 1.6, repeat: Infinity }}
                  />
                )}
                <span className={cn('relative inline-flex h-2 w-2 rounded-full', STATUS_DOT[status])} />
              </span>
              <span className="text-[11px] font-medium text-foreground truncate flex-1">
                {chip.name}
              </span>
              {chip.testCount > 0 && (
                <span className="text-[10px] text-muted-foreground tabular-nums">
                  {chip.testCount}
                </span>
              )}
            </button>
          );
        })}
      </div>
    </motion.div>
  );
}

const nodeTypes = { phaseNode: PhaseNode };

function phaseHeight(phase: PlanPhase): number {
  return HEADER_H + phase.agents.length * (ROW_H + 2) + 12;
}

function PhaseMapInner({
  plan,
  agentState,
  activePhase,
  selectedAgent,
  onSelectAgent,
}: {
  plan: AssessmentPlan;
  agentState: Map<string, AgentState>;
  activePhase: string | undefined;
  selectedAgent: string | null;
  onSelectAgent: (name: string) => void;
}) {
  const { nodes, edges } = useMemo(() => {
    // dagre LR layout over phase nodes; linear backbone edges phase[i]→[i+1].
    const g = new dagre.graphlib.Graph();
    g.setGraph({ rankdir: 'LR', nodesep: 26, ranksep: 70, marginx: 24, marginy: 24 });
    g.setDefaultEdgeLabel(() => ({}));
    for (const p of plan.phases) g.setNode(p.phase, { width: NODE_W, height: phaseHeight(p) });
    for (let i = 0; i < plan.phases.length - 1; i++) {
      g.setEdge(plan.phases[i].phase, plan.phases[i + 1].phase);
    }
    dagre.layout(g);

    const rfNodes: RFNode[] = plan.phases.map((phase) => {
      const pos = g.node(phase.phase);
      const chips: AgentChip[] = phase.agents.map((a) => ({
        name: a.name,
        testCount: a.testCount,
        inScope: a.inScope,
        state: agentState.get(a.name),
      }));
      return {
        id: phase.phase,
        type: 'phaseNode',
        position: { x: pos.x - NODE_W / 2, y: pos.y - phaseHeight(phase) / 2 },
        data: {
          phase,
          isActivePhase: phase.phase === activePhase,
          chips,
          onSelectAgent,
          selectedAgent,
        } satisfies PhaseNodeData,
        draggable: false,
      };
    });

    const rfEdges: RFEdge[] = [];
    for (let i = 0; i < plan.phases.length - 1; i++) {
      const from = plan.phases[i].phase;
      const to = plan.phases[i + 1].phase;
      const reached =
        activePhase != null &&
        (plan.phases.findIndex((p) => p.phase === activePhase) ?? -1) >= i + 1;
      rfEdges.push({
        id: `${from}->${to}`,
        source: from,
        target: to,
        animated: reached,
        style: {
          stroke: reached ? 'rgba(34,211,238,0.6)' : 'rgba(148,163,184,0.25)',
          strokeWidth: 2,
        },
      });
    }
    return { nodes: rfNodes, edges: rfEdges };
  }, [plan, agentState, activePhase, selectedAgent, onSelectAgent]);

  return (
    <ReactFlow
      nodes={nodes}
      edges={edges}
      nodeTypes={nodeTypes}
      fitView
      proOptions={{ hideAttribution: true }}
      nodesDraggable={false}
      nodesConnectable={false}
      elementsSelectable
      minZoom={0.3}
      maxZoom={1.5}
    >
      <Background gap={20} color="rgba(148,163,184,0.12)" />
      <Controls showInteractive={false} className="!shadow-none" />
    </ReactFlow>
  );
}

export function PhaseMap(props: {
  plan: AssessmentPlan;
  agentState: Map<string, AgentState>;
  activePhase: string | undefined;
  selectedAgent: string | null;
  onSelectAgent: (name: string) => void;
}) {
  return (
    <ReactFlowProvider>
      <PhaseMapInner {...props} />
    </ReactFlowProvider>
  );
}
