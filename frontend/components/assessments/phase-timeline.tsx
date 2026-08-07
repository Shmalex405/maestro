'use client';

import { Layers, Wrench, AlertTriangle } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { cn } from '@/lib/utils';
import { statusConfig } from '@/lib/assessment-display';
import type { ExecutionPhase } from '@/lib/types';

interface PhaseTimelineProps {
  phases: ExecutionPhase[];
}

// Map the ExecutionPhase status enum onto the shared assessment statusConfig
// (which is keyed by AssessmentStatus). 'partial' has no statusConfig key so
// it gets a bespoke amber treatment.
const PHASE_STATUS_KEY: Record<string, string> = {
  completed: 'completed',
  running: 'running',
  blocked: 'failed',
};

/**
 * Vertical timeline of the assessment's execution phases. Each phase shows a
 * status icon (reusing the shared statusConfig), its tool-call / finding counts,
 * and duration. Phases are derived from assessment_events (phase_change spans)
 * by the hook; this is a pure renderer.
 */
export function PhaseTimeline({ phases }: PhaseTimelineProps) {
  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="text-base flex items-center gap-2">
          <Layers className="h-4 w-4" />
          Phase timeline
          <span className="text-xs font-normal text-muted-foreground">· {phases.length}</span>
        </CardTitle>
      </CardHeader>
      <CardContent>
        {phases.length === 0 ? (
          <div className="text-sm text-muted-foreground">
            No phase activity recorded for this run.
          </div>
        ) : (
          <ol className="relative ml-3 border-l border-border">
            {phases.map((phase, i) => (
              <PhaseRow key={`${phase.name}-${i}`} phase={phase} />
            ))}
          </ol>
        )}
      </CardContent>
    </Card>
  );
}

function PhaseRow({ phase }: { phase: ExecutionPhase }) {
  const statusKey = phase.status ? PHASE_STATUS_KEY[phase.status] : undefined;
  const meta = statusKey ? statusConfig[statusKey] : undefined;
  const Icon = meta?.icon;
  const isPartial = phase.status === 'partial';
  const iconColor = isPartial ? 'text-amber-500' : meta?.color || 'text-muted-foreground';

  return (
    <li className="mb-4 ml-6 last:mb-0">
      <span
        className={cn(
          'absolute -left-3 flex h-6 w-6 items-center justify-center rounded-full bg-background ring-1 ring-border',
        )}
      >
        {Icon ? (
          <Icon
            className={cn('h-3.5 w-3.5', iconColor, phase.status === 'running' && 'animate-spin')}
          />
        ) : (
          <span className={cn('h-2 w-2 rounded-full', isPartial ? 'bg-amber-500' : 'bg-muted-foreground')} />
        )}
      </span>
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
        <span className="text-sm font-medium text-foreground">{phase.name}</span>
        {phase.status && (
          <span className={cn('text-[10px] font-medium uppercase tracking-wide', iconColor)}>
            {phase.status}
          </span>
        )}
      </div>
      <div className="mt-1 flex flex-wrap items-center gap-3 text-xs text-muted-foreground">
        {phase.tool_call_count != null && (
          <span className="flex items-center gap-1 tabular-nums">
            <Wrench className="h-3 w-3" />
            {phase.tool_call_count} tool call{phase.tool_call_count === 1 ? '' : 's'}
          </span>
        )}
        {phase.finding_count != null && (
          <span className="flex items-center gap-1 tabular-nums">
            <AlertTriangle className="h-3 w-3" />
            {phase.finding_count} finding{phase.finding_count === 1 ? '' : 's'}
          </span>
        )}
        {phaseDuration(phase) && (
          <span className="tabular-nums">{phaseDuration(phase)}</span>
        )}
      </div>
    </li>
  );
}

function phaseDuration(phase: ExecutionPhase): string | null {
  if (!phase.started_at || !phase.ended_at) return null;
  const start = new Date(phase.started_at).getTime();
  const end = new Date(phase.ended_at).getTime();
  if (!Number.isFinite(start) || !Number.isFinite(end) || end < start) return null;
  const sec = Math.round((end - start) / 1000);
  if (sec < 60) return `${sec}s`;
  const m = Math.floor(sec / 60);
  const s = sec % 60;
  return `${m}m ${s}s`;
}
