'use client';

// Scheduled DAST → Targets. Per-target DAST posture (all DAST-eligible targets,
// scheduled or not) with last run, trend, and crit/high. Row → per-target drill-in.

import { Plus } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import { TargetsTab } from '@/components/scheduled/dast-shared';
import { useScheduledDast } from '@/components/scheduled/dast-context';

export default function ScheduledTargetsPage() {
  const { targets, scheduledIds, runScan, openConfig, openSchedule, openNewTarget } =
    useScheduledDast();
  return (
    <div className="space-y-5">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold tracking-tight">Targets</h1>
          <p className="mt-0.5 text-sm text-muted-foreground">
            Web / host targets you add for DAST. Drill into one for its full scan history and
            trend. (Managed here — separate from the AI-assessment scope.)
          </p>
        </div>
        <Button size="sm" onClick={openNewTarget}>
          <Plus className="mr-1.5 h-4 w-4" />
          New target
        </Button>
      </div>
      <Card className="glass-card overflow-hidden">
        <CardContent className="p-0">
          <TargetsTab
            targets={targets}
            scheduledIds={scheduledIds}
            onRunNow={runScan}
            onConfigure={openConfig}
            onAdd={openSchedule}
          />
        </CardContent>
      </Card>
    </div>
  );
}
