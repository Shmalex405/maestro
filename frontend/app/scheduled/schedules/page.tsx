'use client';

// Scheduled DAST → Schedules. Recurring-cadence management.

import { Card, CardContent } from '@/components/ui/card';
import { SchedulesTab } from '@/components/scheduled/dast-shared';
import { useScheduledDast } from '@/components/scheduled/dast-context';

export default function ScheduledSchedulesPage() {
  const {
    schedules,
    schedulesLoading,
    targetById,
    scheduleSelection,
    runSelection,
    removeSchedule,
    openSchedule,
    openConfig,
  } = useScheduledDast();

  // A schedule is target- or application-scoped; build the picker-style value.
  const selFor = (s: { target_id?: string | null; application_id?: string | null }) =>
    s.application_id ? `app:${s.application_id}` : `target:${s.target_id}`;

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-xl font-bold tracking-tight">Schedules</h1>
        <p className="mt-0.5 text-sm text-muted-foreground">
          Recurring deterministic DAST cadences. Findings trend over time; prove any one on-demand.
        </p>
      </div>
      <Card className="glass-card overflow-hidden">
        <CardContent className="p-0">
          <SchedulesTab
            schedules={schedules}
            isLoading={schedulesLoading}
            targetById={targetById}
            onUpsert={(s, cadence) =>
              scheduleSelection(selFor(s), cadence, s.policy_id ?? undefined, s.auth_mode ?? undefined)
            }
            onRemove={removeSchedule}
            onRunNow={(s) => runSelection(selFor(s), s.policy_id ?? undefined, s.auth_mode ?? undefined)}
            onAdd={openSchedule}
            onConfigure={(s) => {
              if (s.target_id) openConfig(s.target_id);
            }}
          />
        </CardContent>
      </Card>
    </div>
  );
}
