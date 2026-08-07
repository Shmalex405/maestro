'use client';

import { useEffect, useMemo, useState } from 'react';
import Link from 'next/link';
import {
  AlertOctagon,
  AlertTriangle,
  AlertCircle,
  Info,
  ChevronDown,
  ChevronUp,
  Activity,
  CheckCircle2,
  X,
  ExternalLink,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { cn } from '@/lib/utils';
import {
  useLiveAssessmentsStore,
  type LiveAssessment,
  type LiveSeverityCounts,
} from '@/lib/stores/live-assessments-store';

/**
 * Floating live-findings panel anchored to the bottom-right of the viewport.
 *
 * Renders one card per running assessment, with severity counts streamed
 * from the terminal parser (no extra HTTP polling). When two or more
 * assessments are running concurrently the cards stack vertically. The
 * whole stack can be collapsed to a single header pill via the master
 * toggle; each card also has its own collapse for showing/hiding its
 * severity breakdown.
 *
 * Mount once at the root layout — visible globally so a user who started
 * an assessment on /assessments and navigated to /dashboard still sees
 * live counts in the corner.
 *
 * Data source: `useLiveAssessmentsStore`. Cards are added when an
 * AssessmentTerminalView registers via the effect in that component;
 * cards are removed ~8s after the assessment status flips out of
 * 'running' (gives the user a moment to see final counts).
 */
export function LiveAssessmentsPopup() {
  // Subscribe to the *Map reference* — stable across renders that don't
  // touch the store. Deriving the sorted array via useMemo here (rather
  // than inside a Zustand selector) sidesteps useSyncExternalStore's
  // "getSnapshot should be cached" infinite-loop trap: a selector like
  // `Array.from(s.byId.values()).sort(...)` would return a fresh array
  // every call, fail Object.is equality, and stall the React tree. The
  // first symptom of that stall is sidebar nav links going "not
  // clickable" — caught by Desktop E2E run 26243489462 on v1.0.14.
  const byId = useLiveAssessmentsStore((s) => s.byId);
  const masterCollapsed = useLiveAssessmentsStore((s) => s.masterCollapsed);
  const setMasterCollapsed = useLiveAssessmentsStore((s) => s.setMasterCollapsed);
  const setCollapsed = useLiveAssessmentsStore((s) => s.setCollapsed);
  const unregister = useLiveAssessmentsStore((s) => s.unregister);

  const assessments = useMemo<LiveAssessment[]>(
    () => Array.from(byId.values()).sort((a, b) => b.startedAt - a.startedAt),
    [byId],
  );

  const totalFindings = useMemo(() => {
    let total = 0;
    for (const a of assessments) {
      total +=
        a.counts.critical + a.counts.high + a.counts.medium + a.counts.low + a.counts.info;
    }
    return total;
  }, [assessments]);

  // Don't mount any DOM when there's nothing live — avoids a blank
  // anchor in the corner during normal browsing.
  if (assessments.length === 0) return null;

  const runningCount = assessments.filter((a) => a.status === 'running').length;

  return (
    <div
      className={cn(
        'fixed bottom-4 right-4 z-50 w-[320px] max-w-[calc(100vw-2rem)]',
        'flex flex-col gap-2',
      )}
      role="region"
      aria-label="Live assessments"
    >
      {/* Master header pill — clickable to toggle master collapse */}
      <button
        type="button"
        onClick={() => setMasterCollapsed(!masterCollapsed)}
        className={cn(
          'flex items-center gap-2 px-3 py-2 rounded-lg border bg-background/95 backdrop-blur-sm shadow-md',
          'hover:bg-accent transition-colors text-left',
        )}
        aria-expanded={!masterCollapsed}
        aria-controls="live-assessments-stack"
      >
        <span className="relative flex h-2 w-2 shrink-0">
          {runningCount > 0 && (
            <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-green-500 opacity-75" />
          )}
          <span
            className={cn(
              'relative inline-flex rounded-full h-2 w-2',
              runningCount > 0 ? 'bg-green-500' : 'bg-muted-foreground/50',
            )}
          />
        </span>
        <Activity className="h-3.5 w-3.5 text-muted-foreground" />
        <span className="text-xs font-medium flex-1 truncate">
          {runningCount > 0
            ? `Live · ${assessments.length} assessment${assessments.length > 1 ? 's' : ''}`
            : `${assessments.length} recent`}
        </span>
        {totalFindings > 0 && (
          <Badge
            variant="outline"
            className="h-5 px-1.5 text-[10px] font-mono shrink-0"
          >
            {totalFindings}
          </Badge>
        )}
        {masterCollapsed ? (
          <ChevronUp className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
        ) : (
          <ChevronDown className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
        )}
      </button>

      {/* Stack of assessment cards — hidden when master is collapsed */}
      {!masterCollapsed && (
        <div
          id="live-assessments-stack"
          className="flex flex-col gap-2 max-h-[60vh] overflow-y-auto custom-scrollbar"
        >
          {assessments.map((a) => (
            <LiveAssessmentCard
              key={a.id}
              assessment={a}
              onToggleCollapse={() => setCollapsed(a.id, !a.collapsed)}
              onDismiss={() => unregister(a.id)}
            />
          ))}
        </div>
      )}
    </div>
  );
}

const SEVERITY_ROWS: Array<{
  key: keyof LiveSeverityCounts;
  label: string;
  color: string;
  textColor: string;
  Icon: typeof AlertOctagon;
}> = [
  { key: 'critical', label: 'Critical', color: 'bg-red-500', textColor: 'text-red-400', Icon: AlertOctagon },
  { key: 'high', label: 'High', color: 'bg-orange-500', textColor: 'text-orange-400', Icon: AlertTriangle },
  { key: 'medium', label: 'Medium', color: 'bg-yellow-500', textColor: 'text-yellow-400', Icon: AlertCircle },
  { key: 'low', label: 'Low', color: 'bg-blue-500', textColor: 'text-blue-400', Icon: Info },
  { key: 'info', label: 'Info', color: 'bg-zinc-400', textColor: 'text-zinc-400', Icon: Info },
];

interface LiveAssessmentCardProps {
  assessment: LiveAssessment;
  onToggleCollapse: () => void;
  onDismiss: () => void;
}

function LiveAssessmentCard({
  assessment,
  onToggleCollapse,
  onDismiss,
}: LiveAssessmentCardProps) {
  const { id, name, counts, collapsed, status } = assessment;
  const total =
    counts.critical + counts.high + counts.medium + counts.low + counts.info;

  // Elapsed time since registration — useful "the assessment has been
  // running for N minutes" indicator. Tick once per minute.
  const [, force] = useTickEveryMinute();
  void force;
  const elapsedMin = Math.max(0, Math.floor((Date.now() - assessment.startedAt) / 60_000));

  return (
    <div
      className={cn(
        'rounded-lg border bg-background/95 backdrop-blur-sm shadow-md overflow-hidden',
        status === 'completed' && 'border-green-500/30',
        status === 'failed' && 'border-red-500/30',
      )}
    >
      <div className="flex items-center gap-2 px-3 py-2 border-b">
        {status === 'running' ? (
          <span className="relative flex h-2 w-2 shrink-0">
            <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-green-500 opacity-75" />
            <span className="relative inline-flex rounded-full h-2 w-2 bg-green-500" />
          </span>
        ) : status === 'completed' ? (
          <CheckCircle2 className="h-3 w-3 text-green-500 shrink-0" />
        ) : (
          <span className="inline-flex h-2 w-2 rounded-full bg-muted-foreground/50 shrink-0" />
        )}
        <Link
          href={`/assessments?id=${id}`}
          className="text-xs font-medium flex-1 truncate hover:underline"
          title={name}
        >
          {name}
        </Link>
        <button
          type="button"
          onClick={onToggleCollapse}
          className="text-muted-foreground hover:text-foreground rounded p-0.5"
          aria-label={collapsed ? 'Expand' : 'Collapse'}
        >
          {collapsed ? (
            <ChevronUp className="h-3.5 w-3.5" />
          ) : (
            <ChevronDown className="h-3.5 w-3.5" />
          )}
        </button>
        <button
          type="button"
          onClick={onDismiss}
          className="text-muted-foreground hover:text-foreground rounded p-0.5"
          aria-label="Dismiss"
        >
          <X className="h-3.5 w-3.5" />
        </button>
      </div>

      {!collapsed && (
        <div className="px-3 py-2 space-y-2">
          {/* Severity rows */}
          {total === 0 ? (
            <p className="text-[11px] text-muted-foreground italic">
              No findings yet · {status === 'running' ? 'scanning' : status}
            </p>
          ) : (
            <div className="space-y-1">
              {SEVERITY_ROWS.map(({ key, label, color, textColor, Icon }) => {
                const n = counts[key];
                if (n === 0) return null;
                return (
                  <div key={key} className="flex items-center justify-between text-[11px]">
                    <div className="flex items-center gap-1.5">
                      <span className={cn('h-1.5 w-1.5 rounded-full', color)} />
                      <Icon className={cn('h-3 w-3', textColor)} />
                      <span>{label}</span>
                    </div>
                    <span className="font-mono tabular-nums">{n}</span>
                  </div>
                );
              })}

              {/* Stacked bar */}
              <div className="flex h-1.5 rounded-full overflow-hidden bg-muted mt-1">
                {SEVERITY_ROWS.map(({ key, color }) => {
                  const n = counts[key];
                  if (n === 0) return null;
                  return (
                    <div
                      key={key}
                      className={cn('h-full', color)}
                      style={{ width: `${(n / total) * 100}%` }}
                    />
                  );
                })}
              </div>
            </div>
          )}

          <div className="flex items-center justify-between pt-1">
            <span className="text-[10px] text-muted-foreground">
              {status === 'running'
                ? elapsedMin > 0
                  ? `Running · ${elapsedMin}m`
                  : 'Running'
                : status === 'completed'
                  ? 'Completed'
                  : status === 'failed'
                    ? 'Failed'
                    : 'Idle'}
              {total > 0 && ` · ${total} finding${total > 1 ? 's' : ''}`}
            </span>
            <Button
              variant="ghost"
              size="sm"
              className="h-6 px-2 text-[10px]"
              asChild
            >
              <Link href={`/assessments?id=${id}`}>
                Open
                <ExternalLink className="ml-1 h-2.5 w-2.5" />
              </Link>
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}

/** Re-render every minute so the "Running · Nm" label stays current. */
function useTickEveryMinute(): [number, () => void] {
  // Pure re-render trigger — caller can ignore the returned value.
  const [tick, setTick] = useState(0);
  useEffect(() => {
    const i = setInterval(() => setTick((t) => t + 1), 60_000);
    return () => clearInterval(i);
  }, []);
  return [tick, () => setTick((t) => t + 1)];
}
