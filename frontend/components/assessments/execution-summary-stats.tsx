'use client';

import { Wrench, Layers, AlertTriangle, Clock, DollarSign, CheckCircle2 } from 'lucide-react';
import type { ExecutionOverview, ExecutionPhase } from '@/lib/types';

interface ExecutionSummaryStatsProps {
  overview: ExecutionOverview;
  /** Phases derived once by the panel and shared with PhaseTimeline — the
   *  ExecutionOverview shape doesn't carry phases as a top-level array. */
  phases: ExecutionPhase[];
}

/**
 * The glass-card stat grid at the top of the execution overview. Six headline
 * tiles: tool executions, phases, findings, duration, cost, execution success.
 * Mirrors the Reports-page stat grid styling (glass-card rounded-xl p-4,
 * tabular-nums).
 */
export function ExecutionSummaryStats({ overview, phases }: ExecutionSummaryStatsProps) {
  const phaseCount = phases.length;

  return (
    <div className="grid gap-3 grid-cols-2 md:grid-cols-3 lg:grid-cols-6">
      <StatTile
        label="Tool Executions"
        value={overview.counts.toolExecutions.toLocaleString()}
        sublabel={`${overview.counts.distinctTools} distinct`}
        icon={<Wrench className="h-4 w-4 text-muted-foreground" />}
      />
      <StatTile
        label="Phases"
        value={phaseCount.toLocaleString()}
        sublabel="derived from events"
        icon={<Layers className="h-4 w-4 text-muted-foreground" />}
      />
      <StatTile
        label="Findings"
        value={overview.findingsTotal.toLocaleString()}
        sublabel={severitySublabel(overview)}
        icon={<AlertTriangle className="h-4 w-4 text-muted-foreground" />}
      />
      <StatTile
        label="Duration"
        value={formatDuration(overview.duration.wallMs)}
        sublabel={overview.duration.endTs ? 'wall clock' : 'running'}
        icon={<Clock className="h-4 w-4 text-muted-foreground" />}
      />
      <StatTile
        label="Cost"
        value={formatCost(overview.costUsd)}
        sublabel={overview.model ? overview.model : 'no LLM telemetry'}
        icon={<DollarSign className="h-4 w-4 text-muted-foreground" />}
      />
      <StatTile
        label="Execution"
        value={verdictLabel(overview)}
        sublabel={`${overview.testRollup.pass}/${overview.testRollup.total || 0} pass`}
        icon={<CheckCircle2 className={`h-4 w-4 ${verdictColor(overview)}`} />}
        valueClass={verdictColor(overview)}
      />
    </div>
  );
}

function StatTile({
  label,
  value,
  sublabel,
  icon,
  valueClass,
}: {
  label: string;
  value: string;
  sublabel?: string;
  icon?: React.ReactNode;
  valueClass?: string;
}) {
  return (
    <div className="glass-card rounded-xl p-4">
      <div className="flex items-center justify-between mb-2">
        <span className="text-xs font-medium uppercase tracking-wider text-muted-foreground truncate">
          {label}
        </span>
        {icon}
      </div>
      <div className={`text-2xl font-bold tabular-nums ${valueClass || ''}`}>{value}</div>
      {sublabel && <p className="text-[11px] text-muted-foreground mt-1 truncate">{sublabel}</p>}
    </div>
  );
}

function severitySublabel(o: ExecutionOverview): string {
  const s = o.findingsBySeverity;
  const parts: string[] = [];
  if (s.critical) parts.push(`${s.critical}C`);
  if (s.high) parts.push(`${s.high}H`);
  if (s.medium) parts.push(`${s.medium}M`);
  if (s.low) parts.push(`${s.low}L`);
  return parts.length ? parts.join(' · ') : 'none';
}

function verdictLabel(o: ExecutionOverview): string {
  const v = o.success.verdict || 'unknown';
  return v.charAt(0).toUpperCase() + v.slice(1);
}

function verdictColor(o: ExecutionOverview): string {
  switch (o.success.verdict) {
    case 'complete':
      return 'text-green-600 dark:text-green-400';
    case 'partial':
      return 'text-amber-600 dark:text-amber-400';
    case 'blocked':
    case 'failed':
      return 'text-red-600 dark:text-red-400';
    default:
      return 'text-muted-foreground';
  }
}

function formatDuration(ms: number | null): string {
  if (ms == null) return '—';
  const totalSec = Math.floor(ms / 1000);
  const h = Math.floor(totalSec / 3600);
  const m = Math.floor((totalSec % 3600) / 60);
  const s = totalSec % 60;
  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m ${s}s`;
  return `${s}s`;
}

function formatCost(n: number | null | undefined): string {
  if (n == null) return '—';
  if (n === 0) return '$0';
  if (n < 0.01) return '<$0.01';
  if (n < 1) return `$${n.toFixed(3)}`;
  if (n < 100) return `$${n.toFixed(2)}`;
  return `$${Math.round(n).toLocaleString()}`;
}
