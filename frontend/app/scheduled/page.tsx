'use client';

import { TeamOnlyNotice } from '@/components/layout/team-only-notice';
import { isFeatureAvailable } from '@/lib/deployment-mode';

// Scheduled DAST → Overview. KPIs + DAST-only severity distribution + recent
// scans. The section shell (sidebar, header actions, dialogs) is in layout.tsx.

import { DastOverview, RecentScans } from '@/components/scheduled/dast-shared';
import { useScheduledDast } from '@/components/scheduled/dast-context';

function ScheduledOverviewPageInner() {
  const { targetById, openScan } = useScheduledDast();
  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-xl font-bold tracking-tight">Overview</h1>
        <p className="mt-0.5 text-sm text-muted-foreground">
          Deterministic web/API scanning — runs, schedules, and findings at a glance. Scheduled-DAST
          vulnerabilities are kept separate from LLM exploitation findings.
        </p>
      </div>
      <DastOverview />
      <RecentScans targetById={targetById} onSelectScan={openScan} />
    </div>
  );
}


// Local mode has no scheduled dast backing store, so render the
// explanation instead of letting the page fire cloud requests that cannot
// succeed. See lib/deployment-mode.ts for why this is absent rather than broken.
export default function ScheduledOverviewPage() {
  if (!isFeatureAvailable('scheduled-dast')) {
    return (
      <TeamOnlyNotice
        feature="scheduled-dast"
        title="Scheduled DAST"
        description="Always-on scans on a cadence"
      />
    );
  }
  return <ScheduledOverviewPageInner />;
}
