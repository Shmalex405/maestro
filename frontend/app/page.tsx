'use client';

import { Suspense, useEffect, useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import Link from 'next/link';
import { useSearchParams, useRouter } from 'next/navigation';
import { toast } from 'sonner';
import { api } from '@/lib/tauri-api';
import type { Report, PaginatedResult, Severity, CloudCorrelation } from '@/lib/types';
import { Badge } from '@/components/ui/badge';
import { Skeleton } from '@/components/ui/skeleton';
import { Progress } from '@/components/ui/progress';
import { Button } from '@/components/ui/button';
import {
  Radar,
  ArrowRight,
  Plus,
  FileText,
  Loader2,
  Server,
  Shield,
  Activity,
  Globe,
  Cloud,
  KeyRound,
  Bot,
  FileCode2,
  PieChart,
  TrendingUp,
  ShieldAlert,
  ShieldCheck,
  LayoutGrid,
} from 'lucide-react';
import type { LucideIcon } from 'lucide-react';
import { cn } from '@/lib/utils';
import { useFindingsTrend } from '@/hooks/use-findings-trend';
import { FilterBar } from '@/components/dashboard/filter-bar';
import { ViewToggle, type DashboardView } from '@/components/dashboard/view-toggle';
import { SurfaceHealthTile } from '@/components/dashboard/surface-health-tile';
import { SeverityDonut } from '@/components/viz/severity-donut';
import { TrendChart, type TrendSeries } from '@/components/dashboard/trend-chart';
import { CorrelationCard } from '@/components/cloud/correlation-card';
import { AttackPathCard } from '@/components/graph/attack-path-card';
import { CoverageHeatmap } from '@/components/viz/coverage-heatmap';
import { BoardView } from '@/components/dashboard/board-view';
import { DashboardFindingsTable } from '@/components/dashboard/dashboard-findings-table';
import { createProveRun } from '@/lib/prove-finding';
import { SEVERITY_ORDER, SEVERITY_STYLES } from '@/lib/severity';
import { surfaceCount, surfaceCategoryParam, SURFACE_ORDER } from '@/lib/surface';
import { useDashboardFilterStore, type Surface } from '@/lib/stores/dashboard-filter-store';

// Surface-health strip — one tile per surface lens, in SURFACE_ORDER. Icon +
// label live here; counts/recency are wired per-surface in CoverageDashboard.
const SURFACE_TILES: { key: Exclude<Surface, 'all'>; label: string; icon: LucideIcon }[] = [
  { key: 'web', label: 'Web & API', icon: Globe },
  { key: 'cloud', label: 'Cloud / Infra', icon: Cloud },
  { key: 'identity', label: 'Identity / IDP', icon: KeyRound },
  { key: 'ai', label: 'AI / LLM', icon: Bot },
  { key: 'code', label: 'Code Security', icon: FileCode2 },
];

/* ============================================
   Sub-Components (rails — reused from prior dashboard)
   ============================================ */

function StatusIndicator({ active, label }: { active: boolean; label: string }) {
  return (
    <div className="flex items-center gap-2">
      <div className={cn(
        'status-dot shrink-0',
        active ? 'bg-emerald-400 text-emerald-400 status-dot-pulse' : 'bg-red-400 text-red-400',
      )} />
      <span className="text-xs text-muted-foreground">{label}</span>
      <span className={cn(
        'ml-auto text-xs font-medium',
        active ? 'text-emerald-400' : 'text-red-400',
      )}>
        {active ? 'Online' : 'Offline'}
      </span>
    </div>
  );
}

function EmptyState({ icon: Icon, title, subtitle, action }: {
  icon: React.ElementType;
  title: string;
  subtitle: string;
  action?: { label: string; href: string };
}) {
  return (
    <div className="flex flex-col items-center justify-center py-10 text-center">
      <div className="mb-3 rounded-xl bg-muted/50 p-3">
        <Icon className="h-6 w-6 text-muted-foreground/50" />
      </div>
      <p className="text-sm font-medium text-muted-foreground">{title}</p>
      <p className="mt-0.5 text-xs text-muted-foreground/70">{subtitle}</p>
      {action && (
        <Link href={action.href}>
          <Button variant="link" size="sm" className="mt-2 text-primary">
            {action.label}
          </Button>
        </Link>
      )}
    </div>
  );
}

/* ============================================
   Coverage Dashboard
   ============================================ */

function CoverageDashboard() {
  const searchParams = useSearchParams();
  const [view, setView] = useState<DashboardView>('trend');

  // ---- Filter store (drives every widget) ----
  const surface = useDashboardFilterStore((s) => s.surface);
  const setSurface = useDashboardFilterStore((s) => s.setSurface);
  const severities = useDashboardFilterStore((s) => s.severities);
  const status = useDashboardFilterStore((s) => s.status);
  const filterTarget = useDashboardFilterStore((s) => s.target);
  const win = useDashboardFilterStore((s) => s.window);
  const hydrateFromParams = useDashboardFilterStore((s) => s.hydrateFromParams);
  const toQuery = useDashboardFilterStore((s) => s.toQuery);

  // Hydrate filter state from the URL once on mount.
  useEffect(() => {
    hydrateFromParams(new URLSearchParams(searchParams.toString()));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Push filter changes back into the URL (shareable + deep-linkable).
  useEffect(() => {
    const qs = toQuery();
    window.history.replaceState(null, '', `/${qs}`);
  }, [surface, severities, status, filterTarget, win, toQuery]);

  // The surface lens maps to its backend finding category set (comma-joined
  // union for multi-category surfaces like Cloud / Infra) for the stats query.
  const surfaceCategory = surfaceCategoryParam(surface);

  // ---- Data ----
  // Global stats (unfiltered) for the surface-health strip's per-surface counts.
  const { data: globalStats } = useQuery({
    queryKey: ['findings-stats'],
    queryFn: () => api.findings.stats(),
  });

  // Filtered stats (by surface) for the W1 donut.
  const { data: surfaceStats, isLoading: surfaceStatsLoading } = useQuery({
    queryKey: ['findings-stats', surface],
    queryFn: () => api.findings.stats(surfaceCategory),
  });

  // Targets — to resolve the filter's target_id → canonical value for the
  // target-scoped W2 trend, and for the surface strip recency.
  const { data: targets } = useQuery({
    queryKey: ['targets'],
    queryFn: () => api.targets.list(),
  });

  const selectedTarget = useMemo(
    () => targets?.find((t) => t.id === filterTarget),
    [targets, filterTarget],
  );

  // When a target is selected, build the signed new-vs-fixed trend from its
  // scan history; otherwise show "new findings observed" from the trend hook.
  const { data: targetScans } = useQuery({
    queryKey: ['scans', filterTarget, 100],
    queryFn: () => api.scans.list({ target_id: filterTarget, limit: 100 }),
    enabled: !!filterTarget,
  });

  const { data: trend } = useFindingsTrend(win);

  const { data: recentAssessments, isLoading: assessmentsLoading } = useQuery({
    queryKey: ['assessments', { limit: 5, include_archived: true }],
    queryFn: () => api.assessments.list({ limit: 5, include_archived: true }),
    // Assessments are started/transitioned outside this page (in the terminal,
    // by the reaper, by complete_assessment). Without an interval this widget
    // showed a stale list — a run kicked off elsewhere never appeared until a
    // hard refresh. Poll + refetch on focus so it tracks live state.
    refetchInterval: 30_000,
    refetchOnWindowFocus: true,
  });

  const { data: recentReports, isLoading: reportsLoading } = useQuery<PaginatedResult<Report>>({
    queryKey: ['reports', { limit: 5 }],
    queryFn: () => api.reports.list({ limit: 5 }),
  });

  const { data: systemStatus } = useQuery({
    queryKey: ['system-status'],
    queryFn: () => api.system.getStatus(),
    refetchInterval: 15000,
  });

  // W4 — deployed + reachable + vulnerable correlations (cloud-only lens).
  const cloudVisible = surface === 'all' || surface === 'cloud';
  const { data: correlations, isLoading: correlationsLoading } = useQuery({
    queryKey: ['cloud-correlations', filterTarget],
    queryFn: () =>
      api.cloudInventory.correlations(filterTarget ? { target_id: filterTarget } : undefined),
    enabled: cloudVisible,
  });

  // W3 — coverage heatmap: findings by (category, surface).
  const { data: coverageCells, isLoading: coverageLoading } = useQuery({
    queryKey: ['findings-coverage'],
    queryFn: () => api.findings.coverage(),
  });

  const router = useRouter();
  const [provingId, setProvingId] = useState<string | null>(null);

  async function handleProveCorrelation(c: CloudCorrelation) {
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


  // ---- Derived ----
  // An assessment stuck in `running` with no heartbeat for a while is a dead /
  // abandoned run — nothing reconciles crashed runs to a terminal state, so the
  // status alone is unreliable. Treat it as actively running only if its last
  // activity (updated_at, else started_at) is recent. Without this the rail
  // shows weeks-old 0% "Test" runs as "running". (See the screenshot bug.)
  const RUNNING_STALE_MS = 3 * 60 * 60 * 1000; // 3h with no update = stale
  const runningAssessments =
    recentAssessments?.data?.filter((a) => {
      if (a.status !== 'running') return false;
      const last = new Date(a.updated_at || a.started_at || a.created_at).getTime();
      return Number.isFinite(last) && Date.now() - last < RUNNING_STALE_MS;
    }) || [];

  // Donut counts respect the severity multi-select; an empty set = all.
  const donutCounts = useMemo<Record<Severity, number>>(() => {
    const base = surfaceStats?.by_severity ?? { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    if (severities.size === 0) return base as Record<Severity, number>;
    const out = { critical: 0, high: 0, medium: 0, low: 0, info: 0 } as Record<Severity, number>;
    for (const sev of SEVERITY_ORDER) if (severities.has(sev)) out[sev] = base[sev] || 0;
    return out;
  }, [surfaceStats, severities]);

  // Surface-strip recency: most recent target last_seen per surface family.
  const surfaceRecency = useMemo(() => {
    const out: Record<Exclude<Surface, 'all'>, string | null> = {
      web: null,
      cloud: null,
      identity: null,
      ai: null,
      code: null,
    };
    for (const t of targets ?? []) {
      const fam: Exclude<Surface, 'all'> | null =
        t.target_type === 'cloud_account' ? 'cloud' : t.target_type === 'repo' ? 'code' : 'web';
      if (fam && (!out[fam] || t.last_seen_at > out[fam]!)) out[fam] = t.last_seen_at;
    }
    return out;
  }, [targets]);

  // W2 trend series. Target-scoped → signed new-vs-fixed from scan deltas.
  // Global → per-severity stacked positive ("new findings observed").
  const trendData = useMemo<{ labels: string[]; series: TrendSeries[] }>(() => {
    if (filterTarget && targetScans && targetScans.length > 0) {
      const ordered = [...targetScans].reverse();
      const labels = ordered.map((s) =>
        new Date(s.started_at).toLocaleDateString(undefined, { month: 'short', day: 'numeric' }),
      );
      const newVals: number[] = [];
      const fixedVals: number[] = [];
      for (let i = 0; i < ordered.length; i++) {
        if (i === 0) {
          newVals.push(ordered[i].total_count);
          fixedVals.push(0);
        } else {
          const delta = ordered[i].total_count - ordered[i - 1].total_count;
          newVals.push(delta > 0 ? delta : 0);
          fixedVals.push(delta < 0 ? -delta : 0);
        }
      }
      return {
        labels,
        series: [
          { key: 'new', label: 'New', values: newVals, color: SEVERITY_STYLES.high.hex },
          { key: 'fixed', label: 'Fixed', values: fixedVals, color: '#10b981', signed: true },
        ],
      };
    }

    // Global: stacked per-severity, respecting the severity filter.
    const buckets = trend?.buckets ?? [];
    const labels = buckets.map((b) =>
      new Date(b.iso).toLocaleDateString(undefined, { month: 'short', day: 'numeric' }),
    );
    const series: TrendSeries[] = SEVERITY_ORDER.filter(
      (sev) => severities.size === 0 || severities.has(sev),
    ).map((sev) => ({
      key: sev,
      label: SEVERITY_STYLES[sev].label,
      values: buckets.map((b) => b[sev] as number),
      color: SEVERITY_STYLES[sev].hex,
    }));
    return { labels, series };
  }, [filterTarget, targetScans, trend, severities]);

  const totalFindings = globalStats
    ? Object.values(globalStats.by_severity).reduce((a: number, b: number) => a + b, 0)
    : 0;

  const isFreshOrg =
    !!globalStats &&
    !assessmentsLoading &&
    totalFindings === 0 &&
    (recentAssessments?.data?.length ?? 0) === 0;

  // Per-surface crit+high + total from the global category rollup.
  const surfaceTotals = useMemo(() => {
    const byCat = globalStats?.by_category;
    const bySev = globalStats?.by_severity;
    // crit+high needs a per-category severity split the stats endpoint doesn't
    // expose, so approximate: weight each surface's share of crit+high by its
    // share of the total. Good enough for the at-a-glance tile.
    const critHighTotal = (bySev?.critical ?? 0) + (bySev?.high ?? 0);
    const grandTotal = byCat
      ? Object.values(byCat).reduce((a, b) => a + b, 0)
      : 0;
    const tile = (s: Exclude<Surface, 'all'>) => {
      const total = surfaceCount(byCat, s);
      const critHigh = grandTotal > 0 ? Math.round(critHighTotal * (total / grandTotal)) : 0;
      return { total, critHigh };
    };
    return Object.fromEntries(SURFACE_ORDER.map((s) => [s, tile(s)])) as Record<
      Exclude<Surface, 'all'>,
      { total: number; critHigh: number }
    >;
  }, [globalStats]);

  return (
    <div className="space-y-5 max-w-[1600px] mx-auto">
      {/* Page header + sticky FilterBar */}
      <div className="sticky top-0 z-20 -mx-6 px-6 pt-1 pb-3 bg-background/80 backdrop-blur-md border-b border-border/40">
        <div className="flex items-center justify-between gap-3 flex-wrap mb-3">
          <div>
            <h1 className="text-2xl font-bold tracking-tight">Coverage</h1>
            <p className="text-sm text-muted-foreground mt-0.5">
              Posture across every surface — exposed, reachable, and vulnerable.
            </p>
          </div>
          <div className="flex items-center gap-2">
            <ViewToggle value={view} onChange={setView} />
            <Link href="/assessments">
              <Button size="sm" className="gap-1.5 rounded-lg bg-primary hover:bg-primary/90">
                <Plus className="h-3.5 w-3.5" />
                New Assessment
              </Button>
            </Link>
          </div>
        </div>
        <FilterBar />
      </div>

      {/* Fresh-org welcome */}
      {isFreshOrg && (
        <div className="glass-card rounded-xl p-6 bg-gradient-to-br from-primary/10 via-primary/5 to-transparent border border-primary/20">
          <div className="flex items-start gap-4">
            <div className="rounded-lg bg-primary/15 p-3">
              <Shield className="h-6 w-6 text-primary" />
            </div>
            <div className="flex-1">
              <h2 className="text-lg font-semibold mb-1">Welcome to Maestro</h2>
              <p className="text-sm text-muted-foreground mb-4">
                Your org&apos;s cloud is ready. Kick off a security assessment, hook up a code repo for SAST, or import findings — everything flows into your team&apos;s shared cloud database.
              </p>
              <div className="flex flex-wrap gap-2">
                <Link href="/assessments">
                  <Button size="sm" className="gap-1.5 rounded-lg bg-primary hover:bg-primary/90">
                    <Plus className="h-3.5 w-3.5" />
                    Run your first assessment
                  </Button>
                </Link>
                <Link href="/import">
                  <Button size="sm" variant="outline" className="gap-1.5 rounded-lg">
                    <ArrowRight className="h-3.5 w-3.5" />
                    Import findings
                  </Button>
                </Link>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Surface health strip — one tile per surface lens (SURFACE_ORDER) */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-3">
        {SURFACE_TILES.map(({ key, label, icon }) => (
          <SurfaceHealthTile
            key={key}
            label={label}
            icon={icon}
            critHigh={surfaceTotals[key].critHigh}
            total={surfaceTotals[key].total}
            lastActivity={surfaceRecency[key]}
            active={surface === key}
            onClick={() => setSurface(surface === key ? 'all' : key)}
          />
        ))}
      </div>

      {/* Primary panel — switches Table ⇄ Board ⇄ Trend via the ViewToggle.
          Board (status kanban) + Table (dense grid) are the triage lenses;
          Trend is the W1 donut + W2 trend "are we getting better" view. */}
      {view === 'board' && (
        <BoardView />
      )}

      {view === 'table' && (
        <div className="glass-card rounded-xl overflow-hidden">
          <DashboardFindingsTable />
        </div>
      )}

      {/* W1 donut + W2 trend */}
      <div className={cn('grid grid-cols-12 gap-3', view !== 'trend' && 'hidden')}>
        {/* W1 — Severity rollup donut */}
        <div className="col-span-12 lg:col-span-4 glass-card rounded-xl overflow-hidden">
          <div className="px-4 py-3 border-b border-border/50 flex items-center gap-2">
            <PieChart className="h-4 w-4 text-muted-foreground" />
            <span className="text-sm font-medium">Severity rollup</span>
            <span className="ml-auto text-[10px] text-muted-foreground bg-muted/50 px-1.5 py-0.5 rounded-md capitalize">
              {surface === 'all' ? 'all surfaces' : surface}
            </span>
          </div>
          <div className="p-5 flex items-center justify-center min-h-[200px]">
            {surfaceStatsLoading ? (
              <Skeleton className="h-40 w-full" />
            ) : (
              <SeverityDonut counts={donutCounts} />
            )}
          </div>
        </div>

        {/* W2 — New-vs-Fixed / findings trend */}
        <div className="col-span-12 lg:col-span-8 glass-card rounded-xl overflow-hidden">
          <div className="px-4 py-3 border-b border-border/50 flex items-center gap-2 flex-wrap">
            <TrendingUp className="h-4 w-4 text-muted-foreground" />
            <span className="text-sm font-medium">
              {filterTarget ? 'New vs Fixed' : 'Findings over time'}
            </span>
            <span className="text-[10px] text-muted-foreground bg-muted/50 px-1.5 py-0.5 rounded-md">
              last {win}d
            </span>
            {selectedTarget && (
              <span className="text-[11px] text-muted-foreground truncate max-w-[220px]">
                · {selectedTarget.canonical_value}
              </span>
            )}
            {/* Legend */}
            <div className="ml-auto flex items-center gap-3">
              {trendData.series.map((s) => (
                <span key={s.key} className="flex items-center gap-1.5 text-[11px] text-muted-foreground">
                  <span className="h-2 w-2 rounded-sm" style={{ backgroundColor: s.color }} />
                  {s.label}
                </span>
              ))}
            </div>
          </div>
          <div className="p-4">
            <TrendChart
              labels={trendData.labels}
              series={trendData.series}
              emptyMessage={`No scan activity in the last ${win} days`}
            />
          </div>
        </div>
      </div>

      {/* W3 — Coverage heatmap (findings by category × surface) */}
      <div className="glass-card rounded-xl overflow-hidden">
        <div className="px-4 py-3 border-b border-border/50 flex items-center gap-2 flex-wrap">
          <LayoutGrid className="h-4 w-4 text-muted-foreground" />
          <span className="text-sm font-medium">Coverage</span>
          <span className="text-[10px] text-muted-foreground">
            findings by test category × surface — empty cells are gaps
          </span>
        </div>
        <div className="p-4">
          {coverageLoading ? (
            <Skeleton className="h-48 w-full" />
          ) : (
            <CoverageHeatmap cells={coverageCells ?? []} />
          )}
        </div>
      </div>

      {/* W4 — Deployed + Reachable + Vulnerable (cloud reachability correlation) */}
      {cloudVisible && (
        <div className="glass-card rounded-xl overflow-hidden">
          <div className="px-4 py-3 border-b border-border/50 flex items-center gap-2 flex-wrap">
            <ShieldAlert className="h-4 w-4 text-red-400" />
            <span className="text-sm font-medium">Deployed · Reachable · Vulnerable</span>
            <span className="text-[10px] text-muted-foreground">
              internet-facing cloud workloads running a CVE-bearing image
            </span>
            {correlations && correlations.length > 0 && (
              <span className="ml-auto text-xs font-semibold text-red-400">
                {correlations.length}
              </span>
            )}
          </div>
          <div className="p-4">
            {correlationsLoading ? (
              <Skeleton className="h-24 w-full" />
            ) : !correlations || correlations.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-8 text-center text-muted-foreground">
                <ShieldCheck className="h-8 w-8 mb-2 opacity-40" />
                <p className="text-sm">No deployed + reachable + vulnerable correlations.</p>
                <p className="text-xs mt-1 max-w-md">
                  No internet-facing cloud workload is running a CVE-bearing image — or no cloud
                  inventory has been promoted yet (run a cloud assessment).
                </p>
              </div>
            ) : (
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
                {correlations.map((c) => (
                  <CorrelationCard
                    key={`${c.finding_id}:${c.resource_arn}`}
                    c={c}
                    onProve={handleProveCorrelation}
                    proving={provingId === c.finding_id}
                  />
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* W5 — Attack-path graph. Now reads the shared substrate (single source of
          truth with /graph) and spans every surface, not just cloud. */}
      <AttackPathCard targetId={filterTarget || undefined} />

      {/* Demoted rails (W6) — Active Assessments / System Health / Recent Reports */}
      <div className="grid grid-cols-12 gap-3">
        {/* Active Assessments */}
        {runningAssessments.length > 0 && (
          <div className="col-span-12 lg:col-span-8 glass-card rounded-xl overflow-hidden">
            <div className="px-4 py-3 border-b border-border/50 flex items-center gap-2">
              <Activity className="h-4 w-4 text-primary" />
              <span className="text-sm font-medium">Active Assessments</span>
              <div className="ml-auto flex items-center gap-1.5">
                <Loader2 className="h-3 w-3 animate-spin text-primary" />
                <span className="text-xs text-muted-foreground">{runningAssessments.length} running</span>
              </div>
            </div>
            <div className="p-3 space-y-2">
              {runningAssessments.map((assessment) => (
                <Link
                  key={assessment.id}
                  href={`/assessments?id=${assessment.id}`}
                  className="flex items-center gap-3 p-2.5 rounded-lg hover:bg-white/[0.03] transition-colors"
                >
                  <div className="rounded-lg bg-primary/10 p-2">
                    <Radar className="h-4 w-4 text-primary" />
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center justify-between mb-1.5">
                      <span className="text-sm font-medium truncate">
                        {assessment.name || assessment.type.replace('_', ' ')}
                      </span>
                      <span className="text-xs font-medium tabular-nums text-primary">
                        {assessment.progress || 0}%
                      </span>
                    </div>
                    <Progress value={assessment.progress || 0} className="h-1" />
                    {assessment.current_step && (
                      <p className="text-[11px] text-muted-foreground mt-1.5 truncate">
                        {assessment.current_step}
                      </p>
                    )}
                  </div>
                </Link>
              ))}
            </div>
          </div>
        )}

        {/* System Health */}
        {systemStatus && (
          <div className={cn(
            'glass-card rounded-xl overflow-hidden col-span-12',
            runningAssessments.length > 0 ? 'lg:col-span-4' : '',
          )}>
            <div className="px-4 py-3 border-b border-border/50 flex items-center gap-2">
              <Server className="h-4 w-4 text-muted-foreground" />
              <span className="text-sm font-medium">System Health</span>
            </div>
            <div className={cn(
              'p-4',
              runningAssessments.length > 0 ? 'space-y-3' : 'flex gap-8'
            )}>
              <StatusIndicator active={systemStatus.docker?.kali_running} label="Docker" />
              <StatusIndicator active={systemStatus.mcp_server_connected} label="MCP Server" />
              <StatusIndicator active={systemStatus.database_connected} label="Database" />
            </div>
          </div>
        )}

        {/* Recent Assessments */}
        <div className="col-span-12 lg:col-span-6 glass-card rounded-xl overflow-hidden">
          <div className="px-4 py-3 border-b border-border/50 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Radar className="h-4 w-4 text-muted-foreground" />
              <span className="text-sm font-medium">Recent Assessments</span>
            </div>
            <Link href="/assessments" className="text-xs text-muted-foreground hover:text-primary transition-colors flex items-center gap-1">
              View all <ArrowRight className="h-3 w-3" />
            </Link>
          </div>
          <div className="p-2">
            {assessmentsLoading ? (
              <div className="space-y-2 p-2">
                {Array.from({ length: 3 }).map((_, i) => (
                  <div key={i} className="flex items-center gap-3 p-2">
                    <Skeleton className="h-9 w-9 rounded-lg" />
                    <div className="flex-1 space-y-1.5">
                      <Skeleton className="h-3.5 w-32" />
                      <Skeleton className="h-3 w-20" />
                    </div>
                  </div>
                ))}
              </div>
            ) : recentAssessments?.data?.length ? (
              <div className="stagger-children">
                {recentAssessments.data.map((assessment) => (
                  <Link
                    key={assessment.id}
                    href={`/assessments?id=${assessment.id}`}
                    className="flex items-center gap-3 p-2.5 rounded-lg hover:bg-white/[0.03] transition-colors"
                  >
                    <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-primary/8 shrink-0">
                      <Radar className="h-4 w-4 text-primary/80" />
                    </div>
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium truncate capitalize">
                        {assessment.name || assessment.type.replace('_', ' ')}
                      </p>
                      <p className="text-[11px] text-muted-foreground">
                        {new Date(assessment.started_at || assessment.created_at).toLocaleDateString()}
                      </p>
                    </div>
                    <Badge
                      variant="outline"
                      className={cn(
                        'text-[10px] px-2 py-0.5 border-0 font-medium',
                        assessment.status === 'completed' && 'bg-emerald-500/10 text-emerald-400',
                        assessment.status === 'running' && 'bg-primary/10 text-primary',
                        assessment.status === 'failed' && 'bg-red-500/10 text-red-400',
                        assessment.status === 'incomplete' && 'bg-amber-500/10 text-amber-400',
                        !['completed', 'running', 'failed', 'incomplete'].includes(assessment.status) && 'bg-muted text-muted-foreground',
                      )}
                    >
                      {assessment.status}
                    </Badge>
                  </Link>
                ))}
              </div>
            ) : (
              <EmptyState
                icon={Radar}
                title="No assessments yet"
                subtitle="Start your first security assessment"
                action={{ label: 'New Assessment', href: '/assessments' }}
              />
            )}
          </div>
        </div>

        {/* Recent Reports */}
        <div className="col-span-12 lg:col-span-6 glass-card rounded-xl overflow-hidden">
          <div className="px-4 py-3 border-b border-border/50 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <FileText className="h-4 w-4 text-muted-foreground" />
              <span className="text-sm font-medium">Recent Reports</span>
            </div>
            <Link href="/reports" className="text-xs text-muted-foreground hover:text-primary transition-colors flex items-center gap-1">
              View all <ArrowRight className="h-3 w-3" />
            </Link>
          </div>
          <div className="p-2">
            {reportsLoading ? (
              <div className="space-y-2 p-2">
                {Array.from({ length: 3 }).map((_, i) => (
                  <div key={i} className="flex items-center gap-3 p-2">
                    <Skeleton className="h-9 w-9 rounded-lg" />
                    <div className="flex-1 space-y-1.5">
                      <Skeleton className="h-3.5 w-48" />
                      <Skeleton className="h-3 w-24" />
                    </div>
                  </div>
                ))}
              </div>
            ) : recentReports?.data && recentReports.data.length > 0 ? (
              <div className="stagger-children">
                {recentReports.data.slice(0, 5).map((report) => (
                  <Link
                    key={report.id}
                    href="/reports"
                    className="flex items-center gap-3 p-2.5 rounded-lg hover:bg-white/[0.03] transition-colors"
                  >
                    <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-primary/8 shrink-0">
                      <FileText className="h-4 w-4 text-primary/80" />
                    </div>
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium truncate">
                        {report.title || report.name}
                      </p>
                      <p className="text-[11px] text-muted-foreground">
                        {report.created_at ? new Date(report.created_at).toLocaleDateString() : '—'}
                      </p>
                    </div>
                    <Badge
                      variant="outline"
                      className={cn(
                        'text-[10px] px-2 py-0.5 border-0 font-medium',
                        report.format === 'pdf' ? 'bg-red-500/10 text-red-400' : 'bg-primary/10 text-primary',
                      )}
                    >
                      {report.format === 'pdf' ? 'PDF' : 'MD'}
                    </Badge>
                  </Link>
                ))}
              </div>
            ) : (
              <EmptyState
                icon={FileText}
                title="No reports yet"
                subtitle="Reports appear after assessments complete"
              />
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

export default function CoverageDashboardPage() {
  // useSearchParams (read by the FilterBar URL-hydration) requires a Suspense
  // boundary under the Next.js App Router.
  return (
    <Suspense fallback={<div className="p-6"><Skeleton className="h-40 w-full" /></div>}>
      <CoverageDashboard />
    </Suspense>
  );
}
