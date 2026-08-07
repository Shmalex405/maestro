'use client';

import { useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { toast } from 'sonner';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import {
  AlertOctagon,
  AlertTriangle,
  AlertCircle,
  Info,
  FileText,
  Download,
  ExternalLink,
  Target,
  Calendar,
  Hash,
  CloudUpload,
  Loader2,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { api } from '@/lib/tauri-api';
import type { Assessment } from '@/lib/types';
import { CostPanel } from '@/components/assessments/cost-panel';
import { BaselineReusePanel } from '@/components/assessments/baseline-reuse-panel';
import { ToolProvenancePanel } from '@/components/assessments/tool-provenance-panel';

type FindingsBySeverity = Record<string, number>;

interface AssessmentDetailSidebarProps {
  assessment: Assessment | null;
  findingsBySeverity: FindingsBySeverity;
  onExport?: () => void;
  onViewReport?: () => void;
}

const SEVERITY_CONFIG = [
  { key: 'critical' as const, label: 'Critical', color: 'bg-red-500', icon: AlertOctagon },
  { key: 'high' as const, label: 'High', color: 'bg-orange-500', icon: AlertTriangle },
  { key: 'medium' as const, label: 'Medium', color: 'bg-yellow-500', icon: AlertCircle },
  { key: 'low' as const, label: 'Low', color: 'bg-blue-500', icon: Info },
  { key: 'info' as const, label: 'Info', color: 'bg-zinc-400', icon: Info },
];

export function AssessmentDetailSidebar({
  assessment,
  findingsBySeverity,
  onExport,
  onViewReport,
}: AssessmentDetailSidebarProps) {
  const totalFindings = Object.values(findingsBySeverity).reduce((a, b) => a + b, 0);
  const queryClient = useQueryClient();
  const [completing, setCompleting] = useState(false);

  // Manual "Complete & Push to dashboard" button. Available while the
  // assessment is running. Calls the MCP `complete_assessment` tool via
  // the Tauri command, which promotes local findings to the cloud DB
  // and flips status to 'completed'. Without finding_ids, pushes every
  // local finding (uncurated fallback). The agent-driven path passes a
  // curated subset and is the recommended way to finalize.
  const handleCompleteAndPush = async () => {
    if (!assessment) return;
    const proceed = window.confirm(
      'Push all findings from this run to the dashboard and mark the assessment as completed?\n\n' +
        'This is the manual fallback. If the report agent ran, it should have already done this with the curated finding set.',
    );
    if (!proceed) return;
    setCompleting(true);
    try {
      const result = await api.assessments.complete(assessment.id);
      const pushed = result.pushed ?? 0;
      const failed = result.failed ?? 0;
      if (failed > 0) {
        toast.warning(
          `Pushed ${pushed} finding${pushed === 1 ? '' : 's'}, ${failed} failed`,
          { description: 'See logs for the failed IDs. Dashboard may be incomplete.' },
        );
      } else {
        toast.success(`Pushed ${pushed} finding${pushed === 1 ? '' : 's'} to dashboard`, {
          description: 'Assessment marked completed.',
        });
      }
      // Refresh dashboard data so the user sees their findings appear.
      queryClient.invalidateQueries({ queryKey: ['assessments'] });
      queryClient.invalidateQueries({ queryKey: ['findings'] });
      queryClient.invalidateQueries({ queryKey: ['findings-stats'] });
      queryClient.invalidateQueries({ queryKey: ['findings-stats-global'] });
    } catch (err) {
      const message = typeof err === 'string' ? err : err instanceof Error ? err.message : String(err);
      toast.error('Could not complete assessment', { description: message });
    } finally {
      setCompleting(false);
    }
  };

  // Completable while running, OR after the reaper auto-closed an unfinished
  // run as 'incomplete' — the manual finalize is how you recover that run
  // (promote its findings + flip to 'completed') without re-running it.
  const canComplete =
    assessment !== null &&
    (assessment.status === 'running' || assessment.status === 'incomplete') &&
    !completing;

  return (
    <div className="flex flex-col">
      {/* Metadata */}
      {assessment && (
        <section className="p-3 border-b">
          <h4 className="text-[10px] font-medium text-muted-foreground uppercase tracking-wider mb-2">
            Metadata
          </h4>
          <div className="space-y-1.5 text-xs">
            <div className="flex items-center gap-2">
              <Hash className="h-3 w-3 text-muted-foreground shrink-0" />
              <span className="text-muted-foreground">ID:</span>
              <span className="font-mono truncate">{assessment.id.slice(0, 8)}</span>
            </div>
            <div className="flex items-center gap-2">
              <Calendar className="h-3 w-3 text-muted-foreground shrink-0" />
              <span className="text-muted-foreground">Created:</span>
              <span>{new Date(assessment.created_at).toLocaleDateString()}</span>
            </div>
            {assessment.targets && assessment.targets.length > 0 && (
              <div className="flex items-start gap-2">
                <Target className="h-3 w-3 text-muted-foreground shrink-0 mt-0.5" />
                <div className="flex flex-col gap-0.5">
                  <span className="text-muted-foreground">Targets:</span>
                  {assessment.targets.map((t) => (
                    <span key={t} className="font-mono text-[10px] truncate">{t}</span>
                  ))}
                </div>
              </div>
            )}
          </div>
        </section>
      )}

      {/* Finding severity breakdown */}
      <section className="p-3 border-b">
        <h4 className="text-[10px] font-medium text-muted-foreground uppercase tracking-wider mb-2">
          Findings ({totalFindings})
        </h4>
        {totalFindings === 0 ? (
          <p className="text-xs text-muted-foreground italic">No findings yet</p>
        ) : (
          <div className="space-y-1.5">
            {SEVERITY_CONFIG.map(({ key, label, color, icon: Icon }) => {
              const count = findingsBySeverity[key] || 0;
              if (count === 0) return null;
              return (
                <div key={key} className="flex items-center justify-between">
                  <div className="flex items-center gap-1.5">
                    <div className={cn('h-2 w-2 rounded-full', color)} />
                    <Icon className="h-3 w-3 text-muted-foreground" />
                    <span className="text-xs">{label}</span>
                  </div>
                  <Badge variant="outline" className="text-[10px] px-1.5 py-0 font-mono">
                    {count}
                  </Badge>
                </div>
              );
            })}
            {/* Bar chart */}
            <div className="flex h-2 rounded-full overflow-hidden bg-muted mt-2">
              {SEVERITY_CONFIG.map(({ key, color }) => {
                const count = findingsBySeverity[key] || 0;
                if (count === 0 || totalFindings === 0) return null;
                return (
                  <div
                    key={key}
                    className={cn('h-full', color)}
                    style={{ width: `${(count / totalFindings) * 100}%` }}
                  />
                );
              })}
            </div>
          </div>
        )}
      </section>

      {/* LLM cost & cache hit telemetry (Phase 0 of caching plan).
          Renders an empty state when no LLM activity has been recorded
          yet — won't surface noise on quick recon-only runs. */}
      {assessment?.id && (
        <section className="p-3 border-b">
          <CostPanel assessmentId={assessment.id} />
        </section>
      )}

      {/* Baseline reuse panel (Phase 3 of caching plan).
          Shows how many prior findings this run could trust vs.
          re-validate, plus the Nth-run forced-revalidation counter.
          Only renders for assessments that have resolved target_ids —
          first-ever assessments of a target have no baseline yet, and
          the component itself shows an empty state if the endpoint
          returns null. */}
      {assessment?.target_ids?.[0] && (
        <section className="p-3 border-b">
          <BaselineReusePanel targetId={assessment.target_ids[0]} />
        </section>
      )}

      {/* Tool-execution provenance (P1). Proof of which security tools actually
          ran this assessment — absent/failing tools are flagged so a silently
          missing scanner can't masquerade as clean coverage. Reads the promoted
          cloud summary, so it populates once the run completes. */}
      {assessment?.id && (
        <section className="p-3 border-b">
          <ToolProvenancePanel assessmentId={assessment.id} />
        </section>
      )}

      {/* Quick actions */}
      <section className="p-3">
        <div className="space-y-1">
          {/* Manual finalize. Shows while the run is 'running', and also for an
              'incomplete' run (reaper auto-closed it before it completed) so the
              user can recover it. After this fires, the cloud dashboard will
              contain this assessment's findings and the status flips to
              'completed' (which also dismisses the live popup card). */}
          {(assessment?.status === 'running' || assessment?.status === 'incomplete') && (
            <Button
              variant="default"
              size="sm"
              className="w-full justify-start h-7 text-xs"
              onClick={handleCompleteAndPush}
              disabled={!canComplete}
              title="Promote local findings to the dashboard and mark this assessment completed"
            >
              {completing ? (
                <Loader2 className="h-3 w-3 mr-2 animate-spin" />
              ) : (
                <CloudUpload className="h-3 w-3 mr-2" />
              )}
              Complete & push to dashboard
            </Button>
          )}
          {onViewReport && (
            <Button
              variant="outline"
              size="sm"
              className="w-full justify-start h-7 text-xs"
              onClick={onViewReport}
            >
              <FileText className="h-3 w-3 mr-2" />
              View Report
            </Button>
          )}
          {onExport && (
            <Button
              variant="outline"
              size="sm"
              className="w-full justify-start h-7 text-xs"
              onClick={onExport}
            >
              <Download className="h-3 w-3 mr-2" />
              Export Findings
            </Button>
          )}
          {assessment?.id && (
            <Button
              variant="outline"
              size="sm"
              className="w-full justify-start h-7 text-xs"
              onClick={() => window.open(`/findings?assessment_id=${assessment.id}`, '_blank')}
            >
              <ExternalLink className="h-3 w-3 mr-2" />
              All Findings
            </Button>
          )}
        </div>
      </section>

      {/* Completion banner */}
      {assessment?.status === 'completed' && (
        <div className="border-t px-3 py-2 bg-green-500/5">
          <div className="flex items-center gap-1.5 text-xs text-green-600 dark:text-green-400">
            <svg className="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            <span className="font-medium">Assessment Complete</span>
          </div>
          <div className="text-[10px] text-muted-foreground mt-0.5">
            {totalFindings} finding{totalFindings !== 1 ? 's' : ''} detected
          </div>
        </div>
      )}
    </div>
  );
}
