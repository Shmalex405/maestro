'use client';

// =============================================================================
// BoardView — Coverage Dashboard "Board" view (the triage kanban).
//
// Per docs/ui-coverage-dashboard-plan.md §2.3: columns by finding status
// (Open / In-Progress / Fixed / Suppressed), cards colored by severity, fed by
// the findings list filtered through the shared dashboard-filter-store
// (surface / severity / status / target). It's the triage lens over the same
// single findings store the Table + Trend views read.
//
// Status mapping (matches the backend FindingStatus enum):
//   Open        ← status 'open'
//   In-Progress ← status 'in_progress'
//   Fixed       ← status 'remediated'
//   Suppressed  ← status 'accepted'
// =============================================================================

import { useMemo } from 'react';
import { useQuery } from '@tanstack/react-query';
import Link from 'next/link';
import { CircleDot, Loader2, ShieldCheck, BellOff, Crosshair } from 'lucide-react';
import { Skeleton } from '@/components/ui/skeleton';
import { api } from '@/lib/tauri-api';
import { cn } from '@/lib/utils';
import { SEVERITY_RANK, severityStyle } from '@/lib/severity';
import { surfaceCategoryParam } from '@/lib/surface';
import type { Finding, FindingStatus, Severity } from '@/lib/types';
import {
  useDashboardFilterStore,
  type StatusFilter,
} from '@/lib/stores/dashboard-filter-store';

interface BoardColumn {
  key: 'open' | 'in_progress' | 'remediated' | 'suppressed';
  /** Which FindingStatus values land in this column. */
  statuses: FindingStatus[];
  /** Which dashboard StatusFilter value selects this column exclusively. */
  filter: Exclude<StatusFilter, 'all'>;
  label: string;
  icon: typeof CircleDot;
  accent: string;
}

// Suppressed folds in both 'accepted' (risk accepted) and 'false_positive' so
// no finding hides — every FindingStatus lands in exactly one column.
const COLUMNS: BoardColumn[] = [
  { key: 'open', statuses: ['open'], filter: 'open', label: 'Open', icon: CircleDot, accent: 'text-red-400' },
  { key: 'in_progress', statuses: ['in_progress'], filter: 'open', label: 'In-Progress', icon: Loader2, accent: 'text-amber-400' },
  { key: 'remediated', statuses: ['remediated'], filter: 'fixed', label: 'Fixed', icon: ShieldCheck, accent: 'text-emerald-400' },
  { key: 'suppressed', statuses: ['accepted', 'false_positive'], filter: 'suppressed', label: 'Suppressed', icon: BellOff, accent: 'text-slate-400' },
];

function FindingCard({ f }: { f: Finding }) {
  const sev = severityStyle(f.severity);
  const exploited =
    f.exploitable === 'true' || f.exploitable === 'potentially';
  return (
    <Link
      href={`/findings/detail?id=${f.id}`}
      className={cn(
        'block rounded-lg border bg-card/40 p-2.5 transition-colors hover:bg-white/[0.04]',
        sev.border,
      )}
    >
      <div className="flex items-center gap-1.5">
        <span
          className={cn(
            'rounded px-1.5 py-0.5 text-[9px] font-semibold uppercase tracking-wide',
            sev.badge,
          )}
        >
          {sev.label}
        </span>
        {exploited && (
          <span
            className="inline-flex items-center gap-0.5 text-[9px] font-semibold uppercase tracking-wide text-red-400"
            title="Proven exploitable"
          >
            <Crosshair className="h-2.5 w-2.5" /> exploited
          </span>
        )}
        {(f.occurrence_count ?? 1) > 1 && (
          <span className="ml-auto font-mono text-[10px] text-muted-foreground">
            ×{f.occurrence_count}
          </span>
        )}
      </div>
      <p className="mt-1.5 line-clamp-2 text-xs font-medium leading-snug">{f.title}</p>
      {f.target && (
        <p className="mt-1 truncate font-mono text-[10px] text-muted-foreground">{f.target}</p>
      )}
    </Link>
  );
}

export function BoardView() {
  const surface = useDashboardFilterStore((s) => s.surface);
  const severities = useDashboardFilterStore((s) => s.severities);
  const statusFilter = useDashboardFilterStore((s) => s.status);
  const target = useDashboardFilterStore((s) => s.target);

  // Map the surface lens → backend category set (comma-joined union for
  // multi-category surfaces like Cloud / Infra). 'all' → no category filter.
  const category: string | undefined = surfaceCategoryParam(surface);

  // Pull a wide page once; the board groups client-side so cards land in their
  // status columns without four separate requests.
  const { data, isLoading } = useQuery({
    queryKey: ['board-findings', surface, target, category],
    queryFn: () =>
      api.findings.list({
        category,
        target: target || undefined,
        limit: 500,
      } as Record<string, unknown>),
  });

  const columns = useMemo(() => {
    const all: Finding[] = data?.data ?? [];
    const filtered = all.filter((f) => {
      if (severities.size > 0 && !severities.has(f.severity as Severity)) return false;
      return true;
    });
    // Map each FindingStatus → the column key that owns it.
    const statusToCol = new Map<FindingStatus, BoardColumn['key']>();
    for (const col of COLUMNS) for (const s of col.statuses) statusToCol.set(s, col.key);

    const byCol: Record<BoardColumn['key'], Finding[]> = {
      open: [],
      in_progress: [],
      remediated: [],
      suppressed: [],
    };
    for (const f of filtered) {
      const s = (f.status ?? 'open') as FindingStatus;
      const col = statusToCol.get(s) ?? 'open';
      byCol[col].push(f);
    }
    // Highest severity first inside each column.
    for (const k of Object.keys(byCol) as BoardColumn['key'][]) {
      byCol[k].sort(
        (a, b) => (SEVERITY_RANK[b.severity] ?? 0) - (SEVERITY_RANK[a.severity] ?? 0),
      );
    }
    return byCol;
  }, [data?.data, severities]);

  // Honor the FilterBar's status select: when not 'all', only show the matching
  // column(s) (Open also surfaces In-Progress, mirroring the FilterBar mapping).
  const visibleColumns = COLUMNS.filter(
    (c) => statusFilter === 'all' || c.filter === statusFilter,
  );

  if (isLoading) {
    return (
      <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-4">
        {Array.from({ length: 4 }).map((_, i) => (
          <div key={i} className="space-y-2">
            <Skeleton className="h-6 w-28" />
            <Skeleton className="h-20 w-full" />
            <Skeleton className="h-20 w-full" />
          </div>
        ))}
      </div>
    );
  }

  return (
    <div
      className={cn(
        'grid grid-cols-1 gap-3',
        visibleColumns.length >= 4
          ? 'md:grid-cols-2 xl:grid-cols-4'
          : visibleColumns.length === 3
            ? 'md:grid-cols-3'
            : visibleColumns.length === 2
              ? 'md:grid-cols-2'
              : 'md:grid-cols-1',
      )}
    >
      {visibleColumns.map((col) => {
        const items = columns[col.key];
        const Icon = col.icon;
        return (
          <div key={col.key} className="flex flex-col">
            <div className="mb-2 flex items-center gap-2 px-1">
              <Icon className={cn('h-3.5 w-3.5', col.accent)} />
              <span className="text-xs font-semibold uppercase tracking-wide">{col.label}</span>
              <span className="ml-auto rounded-full bg-muted/60 px-1.5 py-0.5 text-[10px] font-medium tabular-nums text-muted-foreground">
                {items.length}
              </span>
            </div>
            <div className="flex-1 space-y-2 rounded-lg bg-muted/20 p-2 min-h-[120px]">
              {items.length > 0 ? (
                items.map((f) => <FindingCard key={f.id} f={f} />)
              ) : (
                <div className="flex h-full min-h-[80px] items-center justify-center text-[11px] text-muted-foreground/50">
                  None
                </div>
              )}
            </div>
          </div>
        );
      })}
    </div>
  );
}
