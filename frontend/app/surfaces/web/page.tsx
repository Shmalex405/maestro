'use client';

// =============================================================================
// Web & API surface (/surfaces/web) — the application/network attack surface.
//
// Per docs/ui-coverage-dashboard-plan.md §1.2 / Part 1 (surface = lens, not a
// data silo): this is an AGGREGATION view that links into the existing pages.
// It pins the shared FilterBar to the `web` surface, renders the dashboard
// findings grid scoped to that lens (reusing DashboardFindingsTable), and lists
// recent web/API assessments + scan history for web targets. No new data path —
// every drill-down links into /findings, /assessments, /scheduled.
// =============================================================================

import { Suspense, useEffect } from 'react';
import { useQuery } from '@tanstack/react-query';
import Link from 'next/link';
import {
  Globe,
  ArrowRight,
  Radar,
  CalendarClock,
  ExternalLink,
} from 'lucide-react';
import { Skeleton } from '@/components/ui/skeleton';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { FilterBar } from '@/components/dashboard/filter-bar';
import { DashboardFindingsTable } from '@/components/dashboard/dashboard-findings-table';
import { SurfaceAnalytics } from '@/components/dashboard/surface-analytics';
import { FindingsOverTime } from '@/components/dashboard/findings-over-time';
import { Sparkline } from '@/components/dashboard/sparkline';
import { api } from '@/lib/tauri-api';
import { cn } from '@/lib/utils';
import { useDashboardFilterStore } from '@/lib/stores/dashboard-filter-store';
import type { Target, Scan, Assessment } from '@/lib/types';

function relativeTime(iso: string | null | undefined): string {
  if (!iso) return '—';
  const t = new Date(iso).getTime();
  if (!Number.isFinite(t)) return '—';
  const days = Math.floor((Date.now() - t) / 86_400_000);
  if (days <= 0) return 'today';
  if (days === 1) return 'yesterday';
  if (days < 30) return `${days}d ago`;
  return `${Math.floor(days / 30)}mo ago`;
}

/** Web targets are everything that isn't a cloud account or a code repo. */
function isWebTarget(t: Target): boolean {
  return t.target_type !== 'cloud_account' && t.target_type !== 'repo';
}

/** An assessment is web/API-flavored when it has network targets (not purely
 *  a repo-only SAST run). */
function isWebAssessment(a: Assessment): boolean {
  return (a.targets?.length ?? 0) > 0;
}

function ScanRow({ target }: { target: Target }) {
  const { data: scans, isLoading } = useQuery({
    queryKey: ['scans', target.id, 12],
    queryFn: () => api.scans.list({ target_id: target.id, limit: 12 }),
  });
  const latest: Scan | undefined = scans?.[0];
  const trend = (scans ?? []).map((s) => s.total_count).reverse();
  const critHigh = latest ? latest.critical_count + latest.high_count : 0;

  return (
    <Link
      href={`/scheduled/detail?id=${target.id}`}
      className="flex items-center gap-3 rounded-lg p-2.5 transition-colors hover:bg-white/[0.03]"
    >
      <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-primary/8">
        <Globe className="h-4 w-4 text-primary/80" />
      </div>
      <div className="min-w-0 flex-1">
        <p className="truncate text-sm font-medium">{target.canonical_value}</p>
        <p className="text-[11px] text-muted-foreground">
          {isLoading ? '…' : latest ? `last scan ${relativeTime(latest.finished_at ?? latest.started_at)}` : 'no scans yet'}
        </p>
      </div>
      {trend.length >= 2 && (
        <Sparkline data={trend} width={80} height={20} className="h-[20px] w-[80px]" />
      )}
      <span
        className={cn(
          'w-12 text-right text-sm font-semibold tabular-nums',
          critHigh > 0 ? 'text-orange-400' : 'text-muted-foreground/50',
        )}
        title="open critical + high"
      >
        {latest ? critHigh : '—'}
      </span>
    </Link>
  );
}

function WebSurface() {
  // Pin the FilterBar to the web surface for this page on mount.
  const setSurface = useDashboardFilterStore((s) => s.setSurface);
  useEffect(() => {
    setSurface('web');
  }, [setSurface]);

  const { data: targets, isLoading: targetsLoading } = useQuery({
    queryKey: ['targets'],
    queryFn: () => api.targets.list(),
  });

  const { data: assessments, isLoading: assessmentsLoading } = useQuery({
    queryKey: ['assessments', { limit: 8, include_archived: true }],
    queryFn: () => api.assessments.list({ limit: 8, include_archived: true }),
  });

  const webTargets = (targets ?? []).filter(isWebTarget);
  const webAssessments = (assessments?.data ?? []).filter(isWebAssessment).slice(0, 6);

  return (
    <div className="space-y-5 max-w-[1400px] mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <div className="flex items-center gap-3">
          <div className="rounded-lg bg-primary/10 p-2">
            <Globe className="h-5 w-5 text-primary" />
          </div>
          <div>
            <h1 className="text-2xl font-bold tracking-tight">Web &amp; API</h1>
            <p className="text-sm text-muted-foreground mt-0.5">
              Application and network attack surface — injection, auth, headers, API.
            </p>
          </div>
        </div>
        <Link href="/findings?surface=web">
          <Button variant="outline" size="sm" className="gap-1.5">
            All web findings <ArrowRight className="h-3.5 w-3.5" />
          </Button>
        </Link>
      </div>

      {/* Shared FilterBar — surface pinned to web */}
      <div className="glass-card rounded-xl p-3">
        <FilterBar showSurface={false} />
      </div>

      {/* Analytics strip — severity tiles (clickable filters) + donut + breakdown */}
      <SurfaceAnalytics />

      {/* Findings over time (trend) — locked to the web surface */}
      <FindingsOverTime initialDays={30} category="web_app" />

      {/* Findings (web surface lens) */}
      <div className="glass-card rounded-xl overflow-hidden">
        <div className="flex items-center gap-2 border-b border-border/50 px-4 py-3">
          <Globe className="h-4 w-4 text-muted-foreground" />
          <span className="text-sm font-medium">Web &amp; API findings</span>
        </div>
        <DashboardFindingsTable />
      </div>

      <div className="grid grid-cols-12 gap-3">
        {/* Recent web/API assessments */}
        <div className="col-span-12 lg:col-span-6 glass-card rounded-xl overflow-hidden">
          <div className="flex items-center justify-between border-b border-border/50 px-4 py-3">
            <div className="flex items-center gap-2">
              <Radar className="h-4 w-4 text-muted-foreground" />
              <span className="text-sm font-medium">Recent assessments</span>
            </div>
            <Link href="/assessments" className="flex items-center gap-1 text-xs text-muted-foreground transition-colors hover:text-primary">
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
            ) : webAssessments.length > 0 ? (
              <div className="stagger-children">
                {webAssessments.map((a) => (
                  <Link
                    key={a.id}
                    href={`/assessments?id=${a.id}`}
                    className="flex items-center gap-3 rounded-lg p-2.5 transition-colors hover:bg-white/[0.03]"
                  >
                    <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-primary/8">
                      <Radar className="h-4 w-4 text-primary/80" />
                    </div>
                    <div className="min-w-0 flex-1">
                      <p className="truncate text-sm font-medium capitalize">
                        {a.name || a.type.replace('_', ' ')}
                      </p>
                      <p className="text-[11px] text-muted-foreground">
                        {new Date(a.started_at || a.created_at).toLocaleDateString()}
                      </p>
                    </div>
                    <Badge
                      variant="outline"
                      className={cn(
                        'border-0 px-2 py-0.5 text-[10px] font-medium capitalize',
                        a.status === 'completed' && 'bg-emerald-500/10 text-emerald-400',
                        a.status === 'running' && 'bg-primary/10 text-primary',
                        a.status === 'failed' && 'bg-red-500/10 text-red-400',
                        !['completed', 'running', 'failed'].includes(a.status) && 'bg-muted text-muted-foreground',
                      )}
                    >
                      {a.status}
                    </Badge>
                  </Link>
                ))}
              </div>
            ) : (
              <div className="flex flex-col items-center justify-center py-10 text-center">
                <div className="mb-3 rounded-xl bg-muted/50 p-3">
                  <Radar className="h-6 w-6 text-muted-foreground/50" />
                </div>
                <p className="text-sm font-medium text-muted-foreground">No web assessments yet</p>
                <Link href="/assessments">
                  <Button variant="link" size="sm" className="mt-1 text-primary">
                    New Assessment <ExternalLink className="ml-1 h-3 w-3" />
                  </Button>
                </Link>
              </div>
            )}
          </div>
        </div>

        {/* Scan history for web targets */}
        <div className="col-span-12 lg:col-span-6 glass-card rounded-xl overflow-hidden">
          <div className="flex items-center justify-between border-b border-border/50 px-4 py-3">
            <div className="flex items-center gap-2">
              <CalendarClock className="h-4 w-4 text-muted-foreground" />
              <span className="text-sm font-medium">Scan history</span>
            </div>
            <Link href="/scheduled" className="flex items-center gap-1 text-xs text-muted-foreground transition-colors hover:text-primary">
              Scheduled DAST <ArrowRight className="h-3 w-3" />
            </Link>
          </div>
          <div className="p-2">
            {targetsLoading ? (
              <div className="space-y-2 p-2">
                {Array.from({ length: 3 }).map((_, i) => (
                  <div key={i} className="flex items-center gap-3 p-2">
                    <Skeleton className="h-8 w-8 rounded-lg" />
                    <div className="flex-1 space-y-1.5">
                      <Skeleton className="h-3.5 w-40" />
                      <Skeleton className="h-3 w-24" />
                    </div>
                  </div>
                ))}
              </div>
            ) : webTargets.length > 0 ? (
              <div className="stagger-children">
                {webTargets.slice(0, 8).map((t) => (
                  <ScanRow key={t.id} target={t} />
                ))}
              </div>
            ) : (
              <div className="flex flex-col items-center justify-center py-10 text-center">
                <div className="mb-3 rounded-xl bg-muted/50 p-3">
                  <Globe className="h-6 w-6 text-muted-foreground/50" />
                </div>
                <p className="text-sm font-medium text-muted-foreground">No web targets yet</p>
                <p className="mt-0.5 text-xs text-muted-foreground/70">
                  Targets appear after an assessment resolves them.
                </p>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

export default function WebSurfacePage() {
  return (
    <Suspense fallback={<div className="p-6"><Skeleton className="h-40 w-full" /></div>}>
      <WebSurface />
    </Suspense>
  );
}
