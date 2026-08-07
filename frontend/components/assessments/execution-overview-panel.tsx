'use client';

import { AlertCircle } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent } from '@/components/ui/card';
import { Skeleton } from '@/components/ui/skeleton';
import { cn } from '@/lib/utils';
import { useAssessmentExecution } from '@/lib/hooks/use-assessment-execution';
import { getDisplayTitle } from '@/lib/assessment-display';
import type { ExecutionVerdict } from '@/lib/types';
import { ExecutionSummaryStats } from './execution-summary-stats';
import { PhaseTimeline } from './phase-timeline';
import { CoverageBreakdown } from './coverage-breakdown';
import { TargetScopeSummary } from './target-scope-summary';
import { ToolProvenancePanel } from './tool-provenance-panel';
import { CostPanel } from './cost-panel';
import { ExecutionEventsTimeline } from './execution-events-timeline';

interface ExecutionOverviewPanelProps {
  assessmentId: string;
}

const VERDICT_BADGE: Record<ExecutionVerdict, string> = {
  complete: 'bg-green-500/10 text-green-600 dark:text-green-400 border-green-500/30',
  partial: 'bg-amber-500/10 text-amber-600 dark:text-amber-400 border-amber-500/30',
  blocked: 'bg-red-500/10 text-red-600 dark:text-red-400 border-red-500/30',
  failed: 'bg-red-500/10 text-red-600 dark:text-red-400 border-red-500/30',
  unknown: 'bg-muted text-muted-foreground border-border',
};

/**
 * Per-assessment execution overview — the in-app render of an ExecutionOverview.
 * Orchestrates the summary tiles, phase timeline, test-coverage matrix, target
 * scope, the reused tool-provenance + cost panels, and an event timeline.
 *
 * All reads — no mutating actions, so it's safe for read-only users. Each block
 * degrades gracefully (empty / placeholder) so an un-promoted run still renders.
 */
export function ExecutionOverviewPanel({ assessmentId }: ExecutionOverviewPanelProps) {
  const {
    overview,
    assessment,
    phases,
    testResults,
    scopeDecisions,
    isLoading,
    isError,
    error,
  } = useAssessmentExecution(assessmentId);

  if (isLoading) {
    return <ExecutionOverviewSkeleton />;
  }

  if (isError || !overview || !assessment) {
    const msg = typeof error === 'string' ? error : (error as Error)?.message;
    return (
      <Card>
        <CardContent className="flex flex-col items-center justify-center py-12 text-center">
          <AlertCircle className="h-10 w-10 text-muted-foreground mb-3" />
          <h3 className="text-base font-medium mb-1">Execution overview unavailable</h3>
          <p className="text-sm text-muted-foreground max-w-md">
            {msg ? msg : 'This assessment could not be loaded.'}
          </p>
        </CardContent>
      </Card>
    );
  }

  const verdict = overview.success.verdict || 'unknown';

  return (
    <div className="space-y-6">
      {/* Header: title + verdict badge + one-line summary */}
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <h2 className="text-xl font-semibold tracking-tight truncate">
              {getDisplayTitle(assessment)}
            </h2>
            <Badge variant="outline" className={cn('uppercase text-[10px]', VERDICT_BADGE[verdict])}>
              {verdict}
            </Badge>
            {assessment.archived_at && (
              <Badge variant="outline" className="text-[10px] text-muted-foreground">
                Archived
              </Badge>
            )}
          </div>
          <p className="text-sm text-muted-foreground mt-0.5">{overview.success.summary}</p>
        </div>
      </div>

      {/* Soft warnings (absent / failing tools, etc.) */}
      {overview.success.softWarnings.length > 0 && (
        <div className="rounded-lg border border-amber-500/30 bg-amber-500/5 px-4 py-2.5">
          <ul className="space-y-0.5 text-xs text-amber-700 dark:text-amber-400">
            {overview.success.softWarnings.map((w, i) => (
              <li key={i} className="flex items-center gap-1.5">
                <AlertCircle className="h-3 w-3 shrink-0" />
                {w}
              </li>
            ))}
          </ul>
        </div>
      )}

      <ExecutionSummaryStats overview={overview} phases={phases} />

      <div className="grid gap-6 lg:grid-cols-2">
        <PhaseTimeline phases={phases} />
        <TargetScopeSummary
          scopeDecisions={scopeDecisions}
          provenance={overview.provenance?.scope}
        />
      </div>

      <CoverageBreakdown
        testResults={testResults}
        assessment={assessment}
        provenance={overview.provenance?.test_results}
      />

      <div className="grid gap-6 lg:grid-cols-2">
        <ToolProvenancePanel assessmentId={assessmentId} refreshIntervalMs={0} />
        <ExecutionEventsTimeline assessmentId={assessmentId} />
      </div>

      <CostPanel assessmentId={assessmentId} refreshIntervalMs={0} />
    </div>
  );
}

function ExecutionOverviewSkeleton() {
  return (
    <div className="space-y-6">
      <div className="space-y-2">
        <Skeleton className="h-7 w-72" />
        <Skeleton className="h-4 w-96" />
      </div>
      <div className="grid gap-3 grid-cols-2 md:grid-cols-3 lg:grid-cols-6">
        {Array.from({ length: 6 }).map((_, i) => (
          <div key={i} className="glass-card rounded-xl p-4">
            <Skeleton className="h-4 w-20 mb-3" />
            <Skeleton className="h-8 w-12" />
          </div>
        ))}
      </div>
      <div className="grid gap-6 lg:grid-cols-2">
        <Skeleton className="h-48 w-full" />
        <Skeleton className="h-48 w-full" />
      </div>
      <Skeleton className="h-40 w-full" />
    </div>
  );
}
