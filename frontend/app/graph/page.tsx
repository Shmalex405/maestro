'use client';

import { TeamOnlyNotice } from '@/components/layout/team-only-notice';
import { isFeatureAvailable } from '@/lib/deployment-mode';

// /graph — the interactive attack-graph explorer (org-wide surface). The
// @xyflow/react canvas is client-only (touches window/measurement), so it's
// dynamically imported with ssr:false. `-m-5` cancels the layout's main padding
// so the graph runs edge-to-edge; the height fills the viewport minus the
// header + environment status bar.

import dynamic from 'next/dynamic';

const GraphExplorer = dynamic(() => import('@/components/graph/graph-explorer'), {
  ssr: false,
  loading: () => (
    <div className="flex h-full w-full items-center justify-center text-sm text-muted-foreground">
      Loading attack graph…
    </div>
  ),
});

function GraphPageInner() {
  return (
    <div className="-m-5 h-[calc(100vh-7rem)]">
      <GraphExplorer />
    </div>
  );
}


// Local mode has no attack graph backing store, so render the
// explanation instead of letting the page fire cloud requests that cannot
// succeed. See lib/deployment-mode.ts for why this is absent rather than broken.
export default function GraphPage() {
  if (!isFeatureAvailable('attack-graph')) {
    return (
      <TeamOnlyNotice
        feature="attack-graph"
        title="Attack Graph"
        description="Traversable attack paths across every assessment"
      />
    );
  }
  return <GraphPageInner />;
}
