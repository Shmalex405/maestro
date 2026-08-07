'use client';

// Scheduled DAST → Scans. Org-wide scan-run history + aggregate statistics.

import { useQuery } from '@tanstack/react-query';
import { Card, CardContent } from '@/components/ui/card';
import { ScansTab } from '@/components/scheduled/dast-shared';
import { ScansOverview } from '@/components/scheduled/scan-stats';
import { useScheduledDast } from '@/components/scheduled/dast-context';
import { api } from '@/lib/tauri-api';
import type { Scan } from '@/lib/types';

export default function ScheduledScansPage() {
  const { targetById, openScan, openConfig } = useScheduledDast();

  // Shares the ['scans','all'] cache with ScansTab (same key) — no extra fetch.
  const { data: scans } = useQuery({
    queryKey: ['scans', 'all'],
    queryFn: () => api.scans.list({ limit: 200 }),
    refetchInterval: (q) => {
      const d = q.state.data as Scan[] | undefined;
      return d?.some((s) => s.status === 'running') ? 4000 : false;
    },
  });

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-xl font-bold tracking-tight">Scans</h1>
        <p className="mt-0.5 text-sm text-muted-foreground">
          Every DAST run — scheduled or on-demand. Click a row to view its statistics and findings.
        </p>
      </div>

      <ScansOverview scans={scans ?? []} />

      <Card className="glass-card overflow-hidden">
        <CardContent className="p-0">
          <ScansTab targetById={targetById} onSelectScan={openScan} onConfigure={openConfig} />
        </CardContent>
      </Card>
    </div>
  );
}
