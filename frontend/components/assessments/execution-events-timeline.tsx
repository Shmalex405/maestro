'use client';

import { useEffect, useState } from 'react';
import {
  Activity,
  Wrench,
  CheckCircle2,
  AlertTriangle,
  GitBranch,
  HelpCircle,
  MessageSquare,
  XCircle,
  AlertCircle,
} from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Skeleton } from '@/components/ui/skeleton';
import { cn } from '@/lib/utils';
import { api } from '@/lib/tauri-api';
import type { AssessmentEvent, AssessmentEventType } from '@/lib/types';

interface ExecutionEventsTimelineProps {
  assessmentId: string;
  /** Max events to render (most-recent-first). Default 200. */
  limit?: number;
}

const EVENT_META: Record<AssessmentEventType, { icon: typeof Activity; cls: string }> = {
  tool_call: { icon: Wrench, cls: 'text-primary' },
  tool_result: { icon: CheckCircle2, cls: 'text-green-600 dark:text-green-400' },
  finding_detected: { icon: AlertTriangle, cls: 'text-amber-600 dark:text-amber-400' },
  phase_change: { icon: GitBranch, cls: 'text-blue-500' },
  guidance_request: { icon: HelpCircle, cls: 'text-purple-500' },
  orchestrator_message: { icon: MessageSquare, cls: 'text-muted-foreground' },
  error: { icon: XCircle, cls: 'text-red-600 dark:text-red-400' },
};

/**
 * A simple post-run timeline of the persisted assessment_events. Renders one
 * row per event (icon + type + tool/target + relative time). Self-fetches via
 * the graceful-404 listEvents endpoint, so older backends / runs with no
 * persisted events show an empty state rather than an error.
 */
export function ExecutionEventsTimeline({ assessmentId, limit = 200 }: ExecutionEventsTimelineProps) {
  const [events, setEvents] = useState<AssessmentEvent[] | undefined>(undefined);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    api.assessments
      .listEvents(assessmentId, { limit })
      .then((rows) => {
        if (cancelled) return;
        // Most-recent-first.
        const sorted = [...rows].sort((a, b) =>
          (b.created_at || '').localeCompare(a.created_at || ''),
        );
        setEvents(sorted);
        setError(null);
      })
      .catch((e: unknown) => {
        if (cancelled) return;
        const msg = typeof e === 'string' ? e : (e as Error)?.message ?? String(e);
        if (msg.toLowerCase().includes('not authenticated') || msg.toLowerCase().includes('not enabled')) {
          setEvents([]);
          setError(null);
        } else {
          setError(msg);
        }
      });
    return () => {
      cancelled = true;
    };
  }, [assessmentId, limit]);

  const header = (
    <CardHeader className="pb-3">
      <CardTitle className="text-base flex items-center gap-2">
        <Activity className="h-4 w-4" />
        Event timeline
        {events && events.length > 0 && (
          <span className="text-xs font-normal text-muted-foreground">· {events.length}</span>
        )}
      </CardTitle>
    </CardHeader>
  );

  if (events === undefined) {
    return (
      <Card>
        {header}
        <CardContent>
          <div className="space-y-2">
            {[0, 1, 2, 3].map((i) => (
              <Skeleton key={i} className="h-4 w-full" />
            ))}
          </div>
        </CardContent>
      </Card>
    );
  }

  if (error) {
    return (
      <Card>
        {header}
        <CardContent>
          <div className="flex items-center gap-2 text-sm text-muted-foreground">
            <AlertCircle className="h-4 w-4" />
            <span>Couldn&apos;t load events: {error}</span>
          </div>
        </CardContent>
      </Card>
    );
  }

  if (events.length === 0) {
    return (
      <Card>
        {header}
        <CardContent>
          <div className="text-sm text-muted-foreground">
            No timeline events were recorded for this run.
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      {header}
      <CardContent>
        <ul className="max-h-[28rem] space-y-1 overflow-y-auto pr-1">
          {events.map((e) => (
            <EventRow key={e.id} event={e} />
          ))}
        </ul>
      </CardContent>
    </Card>
  );
}

function EventRow({ event }: { event: AssessmentEvent }) {
  const meta = EVENT_META[event.event_type] ?? { icon: Activity, cls: 'text-muted-foreground' };
  const Icon = meta.icon;
  const label = event.event_type.replace(/_/g, ' ');
  const detail = event.tool || event.target || summarizeDetails(event.details);

  return (
    <li className="flex items-start gap-2 rounded-md px-2 py-1.5 hover:bg-muted/30">
      <Icon className={cn('h-3.5 w-3.5 mt-0.5 shrink-0', meta.cls)} />
      <div className="min-w-0 flex-1">
        <div className="flex items-baseline justify-between gap-2">
          <span className="text-xs font-medium capitalize text-foreground">{label}</span>
          <span className="text-[10px] text-muted-foreground tabular-nums shrink-0">
            {formatTime(event.created_at)}
          </span>
        </div>
        {detail && <p className="text-[11px] text-muted-foreground truncate font-mono">{detail}</p>}
      </div>
    </li>
  );
}

function summarizeDetails(details?: Record<string, unknown> | null): string | null {
  if (!details) return null;
  const d = details as Record<string, unknown>;
  const phase = typeof d.phase === 'string' ? d.phase : typeof d.name === 'string' ? d.name : null;
  if (phase) return phase;
  const msg = typeof d.message === 'string' ? d.message : null;
  return msg;
}

function formatTime(ts?: string): string {
  if (!ts) return '';
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return '';
  return d.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}
