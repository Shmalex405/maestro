'use client';

// =============================================================================
// Cloud surface (/surfaces/cloud) — the cloud posture drill-down.
//
// Per docs/ui-coverage-dashboard-plan.md Part 2 (W4 + W5) and §1.2: reuses the
// W4 CorrelationCard ("deployed + reachable + vulnerable") and the W5
// AttackPathCard, which reads the shared attack-graph substrate (GET /graph/*) —
// the SAME source of truth as the /graph explorer. Aggregation view — cloud
// findings link into /findings?surface=cloud; the "Prove it" action escalates to
// the on-demand LLM exploit via lib/prove-finding.ts. No parallel data path.
// =============================================================================

import { Suspense, useEffect, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { toast } from 'sonner';
import {
  Cloud,
  ArrowRight,
  ShieldAlert,
  ShieldCheck,
} from 'lucide-react';
import { Skeleton } from '@/components/ui/skeleton';
import { Button } from '@/components/ui/button';
import { FilterBar } from '@/components/dashboard/filter-bar';
import { DashboardFindingsTable } from '@/components/dashboard/dashboard-findings-table';
import { SurfaceAnalytics } from '@/components/dashboard/surface-analytics';
import { FindingsOverTime } from '@/components/dashboard/findings-over-time';
import { CorrelationCard } from '@/components/cloud/correlation-card';
import { AttackPathCard } from '@/components/graph/attack-path-card';
import { createProveRun } from '@/lib/prove-finding';
import { api } from '@/lib/tauri-api';
import { surfaceCategoryParam } from '@/lib/surface';
import { useDashboardFilterStore } from '@/lib/stores/dashboard-filter-store';
import type { CloudCorrelation } from '@/lib/types';

function CloudSurface() {
  const router = useRouter();
  const setSurface = useDashboardFilterStore((s) => s.setSurface);
  const filterTarget = useDashboardFilterStore((s) => s.target);

  // Pin the FilterBar to the cloud surface on mount.
  useEffect(() => {
    setSurface('cloud');
  }, [setSurface]);

  const { data: correlations, isLoading: correlationsLoading } = useQuery({
    queryKey: ['cloud-correlations', filterTarget],
    queryFn: () =>
      api.cloudInventory.correlations(filterTarget ? { target_id: filterTarget } : undefined),
  });


  const [provingId, setProvingId] = useState<string | null>(null);

  async function handleProve(c: CloudCorrelation) {
    if (!c.endpoint) return;
    setProvingId(c.finding_id);
    try {
      const assetLabel = c.asset_name ?? c.resource_type;
      const id = await createProveRun({
        findingId: c.finding_id,
        title: c.cve
          ? `Reachable vulnerable workload: ${c.cve} on ${assetLabel}`
          : `Reachable vulnerable workload on ${assetLabel}`,
        severity: c.severity,
        cve: c.cve,
        targetValue: c.endpoint,
        context: [
          `- Reachable workload: ${c.resource_arn} (${c.resource_type})`,
          `- Vulnerable image: ${c.image_ref}`,
          c.exposed_via ? `- Exposure: ${c.exposed_via}` : '',
        ].filter(Boolean),
      });
      router.push(`/assessments?id=${id}`);
    } catch (err) {
      toast.error(
        `Couldn't launch the exploit run: ${err instanceof Error ? err.message : String(err)}`,
      );
      setProvingId(null);
    }
  }

  return (
    <div className="space-y-5 max-w-[1400px] mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <div className="flex items-center gap-3">
          <div className="rounded-lg bg-primary/10 p-2">
            <Cloud className="h-5 w-5 text-primary" />
          </div>
          <div>
            <h1 className="text-2xl font-bold tracking-tight">Cloud</h1>
            <p className="text-sm text-muted-foreground mt-0.5">
              Cloud posture + reachability correlation + escalation paths.
            </p>
          </div>
        </div>
        <Link href="/findings?surface=cloud">
          <Button variant="outline" size="sm" className="gap-1.5">
            All cloud findings <ArrowRight className="h-3.5 w-3.5" />
          </Button>
        </Link>
      </div>

      {/* Shared FilterBar — surface pinned to cloud */}
      <div className="glass-card rounded-xl p-3">
        <FilterBar showSurface={false} />
      </div>

      {/* Analytics strip — severity tiles (clickable filters) + donut + breakdown */}
      <SurfaceAnalytics />

      {/* W4 — Deployed + Reachable + Vulnerable */}
      <div className="glass-card rounded-xl overflow-hidden">
        <div className="flex flex-wrap items-center gap-2 border-b border-border/50 px-4 py-3">
          <ShieldAlert className="h-4 w-4 text-red-400" />
          <span className="text-sm font-medium">Deployed · Reachable · Vulnerable</span>
          <span className="text-[10px] text-muted-foreground">
            internet-facing cloud workloads running a CVE-bearing image
          </span>
          {correlations && correlations.length > 0 && (
            <span className="ml-auto text-xs font-semibold text-red-400">{correlations.length}</span>
          )}
        </div>
        <div className="p-4">
          {correlationsLoading ? (
            <Skeleton className="h-24 w-full" />
          ) : !correlations || correlations.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-8 text-center text-muted-foreground">
              <ShieldCheck className="mb-2 h-8 w-8 opacity-40" />
              <p className="text-sm">No deployed + reachable + vulnerable correlations.</p>
              <p className="mt-1 max-w-md text-xs">
                No internet-facing cloud workload is running a CVE-bearing image — or no cloud
                inventory has been promoted yet (run a cloud assessment).
              </p>
            </div>
          ) : (
            <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
              {correlations.map((c) => (
                <CorrelationCard
                  key={`${c.finding_id}:${c.resource_arn}`}
                  c={c}
                  onProve={handleProve}
                  proving={provingId === c.finding_id}
                />
              ))}
            </div>
          )}
        </div>
      </div>

      {/* W5 — Attack-path graph (shared substrate; single source of truth with /graph) */}
      <AttackPathCard targetId={filterTarget || undefined} />

      {/* Findings over time (trend) — locked to the cloud surface. Uses the
          surface's full category union (cloud + infrastructure) so the trend
          total matches the surface donut / table, which scope off the same
          SURFACE_CATEGORIES.cloud set. */}
      <FindingsOverTime initialDays={30} category={surfaceCategoryParam('cloud')} />

      {/* Cloud findings (surface lens) */}
      <div className="glass-card rounded-xl overflow-hidden">
        <div className="flex items-center gap-2 border-b border-border/50 px-4 py-3">
          <Cloud className="h-4 w-4 text-muted-foreground" />
          <span className="text-sm font-medium">Cloud findings</span>
        </div>
        <DashboardFindingsTable />
      </div>
    </div>
  );
}

export default function CloudSurfacePage() {
  return (
    <Suspense fallback={<div className="p-6"><Skeleton className="h-40 w-full" /></div>}>
      <CloudSurface />
    </Suspense>
  );
}
