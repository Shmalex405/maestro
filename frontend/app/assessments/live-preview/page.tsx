'use client';

// Dev preview for the structured Assessment View, driven by the scripted mock
// feed. Visit /assessments/live-preview. Fetches the real plan from the MCP
// server when reachable; falls back to an embedded sample so it renders offline.
//
// This page is for development/QA of the view in isolation — the production
// integration mounts <AssessmentLiveView> inside assessment-terminal-view with
// the live SSE feed and the caret-to-terminal toggle.

import { useEffect, useMemo, useState } from 'react';
import { RotateCcw } from 'lucide-react';
import { AssessmentLiveView } from '@/components/assessment-live/assessment-live-view';
import { createMockFeed } from '@/lib/assessment-progress/mock-feed';
import { fetchAssessmentPlan } from '@/lib/assessment-progress/use-assessment-plan';
import type { AssessmentPlan, PlanAgent } from '@/lib/assessment-progress/types';

const agent = (
  name: string,
  testCount: number,
  inScope = true,
  requiresDimension: PlanAgent['requiresDimension'] = null
): PlanAgent => ({
  name,
  description: `${name} agent`,
  tests: Array.from({ length: testCount }, (_, i) => `${name.toUpperCase()}-${i + 1}`),
  testCount,
  checkpointFile: `reports/${name}-results.json`,
  requiresDimension,
  inScope,
});

// Embedded fallback (subset of team-assessment.yml) so the preview always renders.
const FALLBACK_PLAN: AssessmentPlan = {
  activeDimensions: ['cloud', 'ai'],
  totalInScopeTests: 0,
  phases: [
    { phase: '1', name: 'Authentication', parallel: false, blockedBy: [], requiresDimension: null, agents: [agent('team-lead', 8)] },
    {
      phase: '2a', name: 'Recon + SAST + Cloud + AI Recon', parallel: true, blockedBy: [], requiresDimension: null,
      agents: [agent('recon-infra', 10), agent('sast-scan', 14), agent('cloud-recon', 15, true, 'cloud'), agent('ai-recon', 5, true, 'ai')],
    },
    { phase: '2b', name: 'SAST Analysis', parallel: false, blockedBy: ['sast-scan'], requiresDimension: null, agents: [agent('sast-analysis', 10)] },
    {
      phase: '3', name: 'Web + API + Cloud + AI Exploitation', parallel: true, blockedBy: ['recon-infra'], requiresDimension: null,
      agents: [agent('web-security', 28), agent('api-graphql', 27), agent('cloud-exploit', 14, true, 'cloud'), agent('ai-redteam', 18, true, 'ai')],
    },
    { phase: '3.5', name: 'Chain Hypothesize', parallel: false, blockedBy: ['web-security'], requiresDimension: null, agents: [agent('chain-analysis', 8)] },
    { phase: '4', name: 'Cross-Validation + QA', parallel: false, blockedBy: ['chain-analysis'], requiresDimension: null, agents: [agent('crossval-qa', 15)] },
    { phase: '4.75', name: 'Severity Calibration', parallel: false, blockedBy: ['crossval-qa'], requiresDimension: null, agents: [agent('severity-calibrator', 0)] },
    { phase: '5a', name: 'Compliance Mapping', parallel: false, blockedBy: ['crossval-qa'], requiresDimension: null, agents: [agent('compliance', 0)] },
    { phase: '5b', name: 'Report Writing', parallel: false, blockedBy: ['compliance'], requiresDimension: null, agents: [agent('report-writer', 0)] },
    { phase: '5c', name: 'PDF Rendering', parallel: false, blockedBy: ['report-writer'], requiresDimension: null, agents: [agent('pdf-renderer', 0)] },
  ],
};

export default function LivePreviewPage() {
  const [plan, setPlan] = useState<AssessmentPlan | null>(null);
  const [runKey, setRunKey] = useState(0);

  useEffect(() => {
    let cancelled = false;
    fetchAssessmentPlan({ dims: ['cloud', 'ai'], inScopeOnly: true })
      .then((p) => {
        if (!cancelled) setPlan(p.phases.length ? p : FALLBACK_PLAN);
      })
      .catch(() => {
        if (!cancelled) setPlan(FALLBACK_PLAN);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  // New mock feed per run (and per plan); runKey restarts the scripted run.
  const feed = useMemo(
    () => (plan ? createMockFeed(plan, { stepMs: 450 }) : null),
    [plan, runKey]
  );

  return (
    <div className="flex flex-col h-screen">
      <div className="flex items-center justify-between px-4 py-2 border-b">
        <div>
          <h1 className="text-sm font-semibold text-foreground">
            Assessment View — preview
          </h1>
          <p className="text-[11px] text-muted-foreground">
            Driven by the scripted mock feed. {plan === FALLBACK_PLAN && '(embedded fallback plan)'}
          </p>
        </div>
        <button
          onClick={() => setRunKey((k) => k + 1)}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium border hover:bg-muted/60 transition-colors"
        >
          <RotateCcw className="h-3.5 w-3.5" />
          Restart run
        </button>
      </div>
      <div className="flex-1 min-h-0">
        {plan ? (
          <AssessmentLiveView key={runKey} plan={plan} feed={feed} />
        ) : (
          <div className="flex items-center justify-center h-full text-sm text-muted-foreground">
            Loading plan…
          </div>
        )}
      </div>
    </div>
  );
}
