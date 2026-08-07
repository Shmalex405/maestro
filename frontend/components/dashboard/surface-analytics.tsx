'use client';

// =============================================================================
// SurfaceAnalytics — the chart strip shared by every surface page (web / cloud /
// identity). Turns the bare "filter bar + table" surface view into something you
// can actually read at a glance:
//
//   • a row of clickable severity tiles (CRITICAL…INFO) that toggle the shared
//     severity filter — click HIGH and the donut, breakdown, and the table below
//     all narrow to HIGH. The tiles are the fast "show me the vulnerabilities"
//     control the surface pages were missing.
//   • a SeverityDonut (open-by-severity distribution).
//   • a "by scanner / source" horizontal breakdown — which tools are surfacing
//     the findings, ranked, tinted by their worst severity.
//
// It reads the SAME dashboard-filter-store + findings query (same key/fn) as
// DashboardFindingsTable, so there's one fetch and the FilterBar drives the
// whole page. Status + target narrow the dataset; severity selection DIMS the
// non-selected tiles rather than hiding them, so the counts stay visible and the
// tiles remain togglable.
// =============================================================================

import { useMemo } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Crosshair } from 'lucide-react';
import { cn } from '@/lib/utils';
import { SeverityDonut } from '@/components/viz/severity-donut';
import { Skeleton } from '@/components/ui/skeleton';
import { SEVERITY_ORDER, SEVERITY_RANK, SEVERITY_STYLES } from '@/lib/severity';
import { surfaceCategoryParam } from '@/lib/surface';
import { api } from '@/lib/tauri-api';
import { useDashboardFilterStore, type ExploitedFilter } from '@/lib/stores/dashboard-filter-store';
import type { Finding, FindingStatus, Severity } from '@/lib/types';

const STATUS_BUCKET: Record<string, FindingStatus[]> = {
  open: ['open', 'in_progress'],
  fixed: ['remediated'],
  suppressed: ['accepted', 'false_positive'],
};

function matchesExploited(f: Finding, exploited: ExploitedFilter): boolean {
  if (exploited === 'all') return true;
  const e = (f.exploitable ?? '').toLowerCase();
  if (exploited === 'any') return e === 'true' || e === 'potentially';
  if (exploited === 'fully') return e === 'true';
  if (exploited === 'partial') return e === 'potentially';
  return true;
}

function matchesSeverity(f: Finding, severities: Set<Severity>): boolean {
  return severities.size === 0 || severities.has(f.severity as Severity);
}

export function SurfaceAnalytics() {
  const surface = useDashboardFilterStore((s) => s.surface);
  const severities = useDashboardFilterStore((s) => s.severities);
  const statusFilter = useDashboardFilterStore((s) => s.status);
  const exploited = useDashboardFilterStore((s) => s.exploited);
  const target = useDashboardFilterStore((s) => s.target);
  const toggleSeverity = useDashboardFilterStore((s) => s.toggleSeverity);
  const setExploited = useDashboardFilterStore((s) => s.setExploited);

  const category: string | undefined = surfaceCategoryParam(surface);

  // Same query key + fn as DashboardFindingsTable → react-query serves both from
  // one fetch.
  const { data, isLoading } = useQuery({
    queryKey: ['dashboard-table-findings', surface, target, category],
    queryFn: () =>
      api.findings.list({
        category,
        target: target || undefined,
        limit: 200,
      } as Record<string, unknown>),
  });

  // Narrow by status + target only — severity stays full so the tiles can show
  // every bucket's count and remain clickable.
  const findings = useMemo(() => {
    const all: Finding[] = data?.data ?? [];
    const bucket = statusFilter !== 'all' ? STATUS_BUCKET[statusFilter] : undefined;
    return all.filter((f) => !bucket || bucket.includes((f.status ?? 'open') as FindingStatus));
  }, [data?.data, statusFilter]);

  // Cross-filtering so selecting a control updates the whole view (mirrors the
  // Findings page). A control reflects the OTHER active filters but not its own
  // dimension, so it stays fully visible + clickable:
  //  - severity tiles + donut → reflect the exploited filter (forSeverity)
  //  - exploited pills        → reflect the severity filter   (forExploit)
  //  - breakdowns + table     → reflect both                  (filtered)
  const forSeverity = useMemo(
    () => findings.filter((f) => matchesExploited(f, exploited)),
    [findings, exploited],
  );
  const forExploit = useMemo(
    () => findings.filter((f) => matchesSeverity(f, severities)),
    [findings, severities],
  );
  const filtered = useMemo(
    () => findings.filter((f) => matchesExploited(f, exploited) && matchesSeverity(f, severities)),
    [findings, exploited, severities],
  );

  const counts = useMemo(() => {
    const c: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const f of forSeverity) {
      const s = (f.severity as Severity) ?? 'info';
      c[s] = (c[s] ?? 0) + 1;
    }
    return c;
  }, [forSeverity]);

  // Exploitation split for THIS surface — fully ('true') / partial
  // ('potentially'), computed from the same surface-scoped findings so the
  // counts track the surface correctly (the global /findings/stats split is
  // category-unscoped, so we cannot use it here).
  const exploit = useMemo(() => {
    let fully = 0;
    let partial = 0;
    for (const f of forExploit) {
      const e = (f.exploitable ?? '').toLowerCase();
      if (e === 'true') fully += 1;
      else if (e === 'potentially') partial += 1;
    }
    return { fully, partial, any: fully + partial };
  }, [forExploit]);

  // Breakdown by scanner/source, ranked, tagged with its worst severity.
  const bySource = useMemo(() => {
    const m = new Map<string, { count: number; top: Severity }>();
    for (const f of filtered) {
      const key = f.source || f.source_tool || 'unknown';
      const cur = m.get(key) ?? { count: 0, top: 'info' as Severity };
      cur.count += 1;
      if ((SEVERITY_RANK[f.severity] ?? 0) > (SEVERITY_RANK[cur.top] ?? 0)) cur.top = f.severity;
      m.set(key, cur);
    }
    return Array.from(m.entries())
      .map(([label, v]) => ({ label, ...v }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 6);
  }, [filtered]);

  // Top vulnerable targets — ranked by open crit+high, then total. Tagged with
  // the worst severity seen on that target.
  const byTarget = useMemo(() => {
    const m = new Map<string, { count: number; critHigh: number; top: Severity }>();
    for (const f of filtered) {
      const key = f.target || 'unknown';
      const cur = m.get(key) ?? { count: 0, critHigh: 0, top: 'info' as Severity };
      cur.count += 1;
      if (f.severity === 'critical' || f.severity === 'high') cur.critHigh += 1;
      if ((SEVERITY_RANK[f.severity] ?? 0) > (SEVERITY_RANK[cur.top] ?? 0)) cur.top = f.severity;
      m.set(key, cur);
    }
    return Array.from(m.entries())
      .map(([label, v]) => ({ label, ...v }))
      .sort((a, b) => b.critHigh - a.critHigh || b.count - a.count)
      .slice(0, 6);
  }, [filtered]);

  const total = filtered.length;
  const severityTotal = forSeverity.length; // donut basis (reflects exploited, not severity)
  const maxSourceBar = Math.max(1, ...bySource.map((b) => b.count));
  const maxTargetBar = Math.max(1, ...byTarget.map((b) => b.count));

  if (isLoading) {
    return (
      <div className="glass-card rounded-xl p-4">
        <Skeleton className="h-[180px] w-full" />
      </div>
    );
  }

  return (
    <div className="glass-card rounded-xl overflow-hidden">
      {/* Severity tiles — clickable filters */}
      <div className="grid grid-cols-2 gap-px bg-border/40 sm:grid-cols-5">
        {SEVERITY_ORDER.map((sev) => {
          const style = SEVERITY_STYLES[sev];
          const count = counts[sev] || 0;
          const active = severities.has(sev);
          const anySelected = severities.size > 0;
          return (
            <button
              key={sev}
              type="button"
              onClick={() => toggleSeverity(sev)}
              title={active ? `Clear ${style.label} filter` : `Filter to ${style.label}`}
              className={cn(
                'group relative flex flex-col gap-1 bg-card px-4 py-3 text-left transition-colors hover:bg-white/[0.03]',
                anySelected && !active && 'opacity-45',
                active && 'bg-white/[0.04]',
              )}
            >
              {/* Active accent bar */}
              <span
                className={cn(
                  'absolute inset-x-0 top-0 h-0.5 transition-opacity',
                  style.bg,
                  active ? 'opacity-100' : 'opacity-0 group-hover:opacity-40',
                )}
              />
              <div className="flex items-center gap-1.5">
                <span className={cn('h-2 w-2 rounded-sm', style.bg)} />
                <span className="text-[10px] font-medium uppercase tracking-wider text-muted-foreground">
                  {style.label}
                </span>
              </div>
              <span className={cn('text-2xl font-bold tabular-nums leading-none', count > 0 ? style.text : 'text-muted-foreground/40')}>
                {count}
              </span>
            </button>
          );
        })}
      </div>

      {/* Exploited lens — fully / partial, scoped to this surface. Clickable
          pills that filter the surface findings table (mirrors the Findings
          page's Exploited sub-pills). */}
      <div className="flex flex-wrap items-center gap-2 border-t border-border/40 bg-white/[0.01] px-4 py-2.5">
        <span className="flex items-center gap-1.5 text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
          <Crosshair className="h-3.5 w-3.5" /> Exploited
        </span>
        {([
          { key: 'any' as const, label: 'Exploited', count: exploit.any, tone: 'text-orange-400', dot: 'bg-orange-400' },
          { key: 'fully' as const, label: 'Fully', count: exploit.fully, tone: 'text-red-400', dot: 'bg-red-500' },
          { key: 'partial' as const, label: 'Partial', count: exploit.partial, tone: 'text-amber-400', dot: 'bg-amber-400' },
        ]).map((p) => {
          const active = exploited === p.key;
          return (
            <button
              key={p.key}
              type="button"
              onClick={() => setExploited(p.key)}
              title={active ? `Clear ${p.label} filter` : `Filter to ${p.label} exploited`}
              className={cn(
                'flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs transition-colors',
                active
                  ? 'border-primary/40 bg-primary/10'
                  : 'border-border/50 hover:bg-white/[0.04]',
              )}
            >
              <span className={cn('h-1.5 w-1.5 rounded-full', p.dot)} />
              <span className="text-muted-foreground">{p.label}</span>
              <span className={cn('font-semibold tabular-nums', p.count > 0 ? p.tone : 'text-muted-foreground/50')}>
                {p.count}
              </span>
            </button>
          );
        })}
        {exploited !== 'all' && (
          <button
            type="button"
            onClick={() => setExploited('all')}
            className="ml-auto text-[11px] text-muted-foreground/70 hover:text-primary"
          >
            Clear
          </button>
        )}
      </div>

      {/* Donut + breakdowns */}
      <div className="grid grid-cols-1 gap-4 p-4 lg:grid-cols-[auto_1fr_1fr]">
        {/* Distribution donut */}
        <div className="flex items-center justify-center rounded-lg bg-white/[0.015] p-3">
          {severityTotal > 0 ? (
            <SeverityDonut counts={counts} size={148} centerLabel="findings" />
          ) : (
            <div className="px-8 py-10 text-center text-sm text-muted-foreground">No findings match the filter.</div>
          )}
        </div>

        {/* By scanner / source */}
        <BreakdownPanel
          title="By scanner / source"
          subtitle={`${total} total`}
          items={bySource.map((b) => ({ label: b.label, count: b.count, top: b.top, mono: true }))}
          max={maxSourceBar}
          empty="No scanner data."
        />

        {/* Top vulnerable targets */}
        <BreakdownPanel
          title="Top vulnerable targets"
          subtitle="by crit + high"
          items={byTarget.map((b) => ({
            label: b.label,
            count: b.count,
            top: b.top,
            badge: b.critHigh > 0 ? `${b.critHigh}` : undefined,
          }))}
          max={maxTargetBar}
          empty="No target data."
        />
      </div>
    </div>
  );
}

interface BreakdownItem {
  label: string;
  count: number;
  top: Severity;
  mono?: boolean;
  /** Optional crit+high count chip shown before the bar. */
  badge?: string;
}

function BreakdownPanel({
  title,
  subtitle,
  items,
  max,
  empty,
}: {
  title: string;
  subtitle?: string;
  items: BreakdownItem[];
  max: number;
  empty: string;
}) {
  return (
    <div className="rounded-lg bg-white/[0.015] p-3">
      <div className="mb-2.5 flex items-center justify-between">
        <span className="text-xs font-medium text-muted-foreground">{title}</span>
        {subtitle && <span className="text-[10px] text-muted-foreground/60">{subtitle}</span>}
      </div>
      {items.length > 0 ? (
        <div className="space-y-2">
          {items.map((b) => {
            const style = SEVERITY_STYLES[b.top];
            return (
              <div key={b.label} className="flex items-center gap-2">
                <span
                  className={cn('w-28 shrink-0 truncate text-[11px] text-muted-foreground', b.mono && 'font-mono')}
                  title={b.label}
                >
                  {b.label}
                </span>
                <div className="relative h-3.5 flex-1 overflow-hidden rounded-sm bg-muted/30">
                  <div
                    className={cn('h-full rounded-sm', style.bg)}
                    style={{ width: `${(b.count / max) * 100}%`, opacity: 0.7 }}
                  />
                </div>
                {b.badge && (
                  <span className={cn('shrink-0 text-[10px] font-semibold tabular-nums', SEVERITY_STYLES.high.text)} title="critical + high">
                    {b.badge}
                  </span>
                )}
                <span className="w-7 shrink-0 text-right text-xs font-semibold tabular-nums">{b.count}</span>
              </div>
            );
          })}
        </div>
      ) : (
        <div className="py-8 text-center text-xs text-muted-foreground/70">{empty}</div>
      )}
    </div>
  );
}
