'use client';

// The structured Assessment View: the full assessment as a live pipeline map
// (phases → agents), a plain-English activity ticker, and a per-agent
// drill-down. Driven by a ProgressFeed (mock during development, the live SSE
// stream in production) folded into derived state by useAssessmentProgress.
//
// This component is feed-agnostic and terminal-agnostic — the caret toggle that
// reveals the raw Claude Code xterm lives in the parent (assessment-terminal-view).

import { useMemo, useState } from 'react';
import { AnimatePresence } from 'framer-motion';
import { Activity } from 'lucide-react';
import { cn } from '@/lib/utils';
import type { ProgressFeed } from '@/lib/assessment-progress/feed';
import type { AssessmentPlan } from '@/lib/assessment-progress/types';
import { useAssessmentProgress } from '@/lib/assessment-progress/use-assessment-progress';
import { useAssessmentTestResults } from '@/lib/assessment-progress/use-assessment-test-results';
import { PhaseMap } from './phase-map';
import { ActivityTicker } from './activity-ticker';
import { AgentDrilldown } from './agent-drilldown';

export function AssessmentLiveView({
  plan,
  feed,
  findingsBySeverity,
  assessmentId,
  className,
}: {
  plan: AssessmentPlan;
  feed: ProgressFeed | null;
  /** Live finding counts from the parent's terminal parser (optional). */
  findingsBySeverity?: Record<string, number>;
  /** When set, overlays authoritative PASS/FAIL/BLOCKED/N_A from checkpoints. */
  assessmentId?: string;
  className?: string;
}) {
  const { agentState, activePhase, ticker, eventCount, testStatus } =
    useAssessmentProgress(plan, feed);
  // Authoritative per-test verdicts from the agent checkpoints. Polled while the
  // view is open so mid-run checkpoints appear; falls back to the live SSE
  // tool-status in the drilldown when a test has no verdict yet.
  const { data: authoritativeTests } = useAssessmentTestResults(assessmentId, {
    poll: true,
  });
  const [selectedAgent, setSelectedAgent] = useState<string | null>(null);

  const selectedPlanAgent = useMemo(() => {
    if (!selectedAgent) return null;
    for (const p of plan.phases) {
      const a = p.agents.find((x) => x.name === selectedAgent);
      if (a) return a;
    }
    return null;
  }, [selectedAgent, plan]);

  // Phase progress for the header ribbon.
  const { activePhaseName, phaseIdx, phaseTotal } = useMemo(() => {
    const total = plan.phases.length;
    const idx = activePhase
      ? plan.phases.findIndex((p) => p.phase === activePhase)
      : -1;
    const name = idx >= 0 ? plan.phases[idx].name : 'Not started';
    return { activePhaseName: name, phaseIdx: idx, phaseTotal: total };
  }, [plan, activePhase]);

  const doneAgents = useMemo(() => {
    let n = 0;
    for (const s of agentState.values()) if (s.status === 'done') n++;
    return n;
  }, [agentState]);
  const totalAgents = agentState.size;

  const findingTotal = useMemo(
    () =>
      findingsBySeverity
        ? Object.values(findingsBySeverity).reduce((a, b) => a + b, 0)
        : 0,
    [findingsBySeverity]
  );

  return (
    <div className={cn('flex flex-col h-full', className)}>
      {/* Header ribbon — where we are, at a glance */}
      <div className="flex items-center justify-between px-4 py-2 border-b bg-background/95">
        <div className="flex items-center gap-2 min-w-0">
          <Activity className="h-4 w-4 text-cyan-400 shrink-0" />
          <div className="min-w-0">
            <div className="text-[10px] uppercase tracking-wide text-muted-foreground">
              {phaseIdx >= 0
                ? `Phase ${plan.phases[phaseIdx].phase} of ${phaseTotal}`
                : `${phaseTotal} phases`}
            </div>
            <div className="text-xs font-semibold text-foreground truncate">
              {activePhaseName}
            </div>
          </div>
        </div>
        <div className="flex items-center gap-4 text-[11px] text-muted-foreground tabular-nums">
          {findingTotal > 0 && (
            <span className="flex items-center gap-1.5">
              {(findingsBySeverity?.critical ?? 0) > 0 && (
                <span className="text-red-500 font-semibold">
                  {findingsBySeverity!.critical} crit
                </span>
              )}
              {(findingsBySeverity?.high ?? 0) > 0 && (
                <span className="text-orange-500 font-semibold">
                  {findingsBySeverity!.high} high
                </span>
              )}
              <span>
                <span className="text-foreground font-semibold">{findingTotal}</span>{' '}
                findings
              </span>
            </span>
          )}
          <span>
            <span className="text-foreground font-semibold">{doneAgents}</span>/
            {totalAgents} agents
          </span>
          <span>
            <span className="text-foreground font-semibold">{eventCount}</span> events
          </span>
        </div>
      </div>

      {/* Map + side panel */}
      <div className="flex-1 min-h-0 flex">
        <div className="flex-1 min-w-0 relative">
          <PhaseMap
            plan={plan}
            agentState={agentState}
            activePhase={activePhase}
            selectedAgent={selectedAgent}
            onSelectAgent={(name) =>
              setSelectedAgent((cur) => (cur === name ? null : name))
            }
          />
        </div>

        <div className="w-80 shrink-0 border-l flex flex-col min-h-0">
          <AnimatePresence mode="wait">
            {selectedPlanAgent ? (
              <div key="drill" className="flex-1 min-h-0">
                <AgentDrilldown
                  agent={selectedPlanAgent}
                  state={agentState.get(selectedPlanAgent.name)}
                  lines={ticker}
                  testStatus={testStatus}
                  authoritativeTests={authoritativeTests}
                  onClose={() => setSelectedAgent(null)}
                />
              </div>
            ) : (
              <div key="ticker" className="flex-1 min-h-0">
                <ActivityTicker lines={ticker} />
              </div>
            )}
          </AnimatePresence>
        </div>
      </div>
    </div>
  );
}
