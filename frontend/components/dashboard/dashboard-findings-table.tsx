'use client';

// =============================================================================
// DashboardFindingsTable — the Coverage Dashboard "Table" view.
//
// A dense findings grid driven by the shared dashboard-filter-store (surface /
// severity / status / target), per docs/ui-coverage-dashboard-plan.md §2.3
// ("the dense findings grid filtered by the bar"). It's a read-only summary
// grid — the canonical drill-down list with sorting / bulk-actions / pagination
// stays at /findings, which every row deep-links into. A "View all in Findings"
// header link carries the active filter straight through.
// =============================================================================

import { useMemo } from 'react';
import { useQuery } from '@tanstack/react-query';
import Link from 'next/link';
import { ArrowRight } from 'lucide-react';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { Skeleton } from '@/components/ui/skeleton';
import { Badge } from '@/components/ui/badge';
import { api } from '@/lib/tauri-api';
import { cn } from '@/lib/utils';
import { SEVERITY_RANK, severityStyle } from '@/lib/severity';
import { surfaceCategoryParam } from '@/lib/surface';
import type { Finding, FindingStatus, Severity } from '@/lib/types';
import { useDashboardFilterStore } from '@/lib/stores/dashboard-filter-store';

// Which FindingStatus values each FilterBar status bucket covers.
const STATUS_BUCKET: Record<string, FindingStatus[]> = {
  open: ['open', 'in_progress'],
  fixed: ['remediated'],
  suppressed: ['accepted', 'false_positive'],
};

const STATUS_STYLE: Record<FindingStatus, string> = {
  open: 'bg-red-500/10 text-red-400',
  in_progress: 'bg-amber-500/10 text-amber-400',
  remediated: 'bg-emerald-500/10 text-emerald-400',
  accepted: 'bg-slate-500/10 text-slate-400',
  false_positive: 'bg-slate-500/10 text-slate-400',
};

export function DashboardFindingsTable() {
  const surface = useDashboardFilterStore((s) => s.surface);
  const severities = useDashboardFilterStore((s) => s.severities);
  const statusFilter = useDashboardFilterStore((s) => s.status);
  const exploited = useDashboardFilterStore((s) => s.exploited);
  const target = useDashboardFilterStore((s) => s.target);
  const toQuery = useDashboardFilterStore((s) => s.toQuery);

  const category: string | undefined = surfaceCategoryParam(surface);

  const { data, isLoading } = useQuery({
    queryKey: ['dashboard-table-findings', surface, target, category],
    queryFn: () =>
      api.findings.list({
        category,
        target: target || undefined,
        limit: 200,
      } as Record<string, unknown>),
  });

  const rows = useMemo(() => {
    const all: Finding[] = data?.data ?? [];
    const bucket = statusFilter !== 'all' ? STATUS_BUCKET[statusFilter] : undefined;
    return all
      .filter((f) => {
        if (severities.size > 0 && !severities.has(f.severity as Severity)) return false;
        if (bucket && !bucket.includes((f.status ?? 'open') as FindingStatus)) return false;
        if (exploited !== 'all') {
          const e = (f.exploitable ?? '').toLowerCase();
          if (exploited === 'any' && e !== 'true' && e !== 'potentially') return false;
          if (exploited === 'fully' && e !== 'true') return false;
          if (exploited === 'partial' && e !== 'potentially') return false;
        }
        return true;
      })
      .sort((a, b) => (SEVERITY_RANK[b.severity] ?? 0) - (SEVERITY_RANK[a.severity] ?? 0))
      .slice(0, 100);
  }, [data?.data, severities, statusFilter, exploited]);

  // Carry the dashboard filter into the /findings deep link.
  const findingsHref = `/findings${toQuery()}`;

  return (
    <div>
      <div className="flex items-center justify-between border-b border-border/50 px-4 py-2.5">
        <span className="text-xs text-muted-foreground">
          {isLoading ? 'Loading…' : `${rows.length} finding${rows.length === 1 ? '' : 's'}`}
          {rows.length === 100 && ' (showing first 100)'}
        </span>
        <Link
          href={findingsHref}
          className="flex items-center gap-1 text-xs text-muted-foreground transition-colors hover:text-primary"
        >
          View all in Findings <ArrowRight className="h-3 w-3" />
        </Link>
      </div>
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead className="w-[100px]">Severity</TableHead>
            <TableHead>Title</TableHead>
            <TableHead className="w-[200px]">Target</TableHead>
            <TableHead className="w-[110px]">Source</TableHead>
            <TableHead className="w-[120px]">Status</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {isLoading ? (
            Array.from({ length: 6 }).map((_, i) => (
              <TableRow key={i}>
                <TableCell><Skeleton className="h-5 w-16" /></TableCell>
                <TableCell><Skeleton className="h-4 w-56" /></TableCell>
                <TableCell><Skeleton className="h-4 w-32" /></TableCell>
                <TableCell><Skeleton className="h-4 w-16" /></TableCell>
                <TableCell><Skeleton className="h-4 w-20" /></TableCell>
              </TableRow>
            ))
          ) : rows.length > 0 ? (
            rows.map((f) => {
              const sev = severityStyle(f.severity);
              const status = (f.status ?? 'open') as FindingStatus;
              return (
                <TableRow key={f.id} className={cn(sev.border, 'hover:bg-white/[0.02] transition-colors')}>
                  <TableCell>
                    <span
                      className={cn(
                        'rounded-md px-2 py-1 text-[10px] font-semibold uppercase',
                        sev.badge,
                      )}
                    >
                      {f.severity}
                    </span>
                  </TableCell>
                  <TableCell>
                    <Link href={`/findings/detail?id=${f.id}`} className="font-medium hover:underline">
                      {f.title}
                    </Link>
                  </TableCell>
                  <TableCell className="max-w-[200px] truncate text-muted-foreground">{f.target}</TableCell>
                  <TableCell>
                    {f.source || f.source_tool ? (
                      <Badge variant="outline" className="font-mono text-xs">
                        {f.source || f.source_tool}
                      </Badge>
                    ) : (
                      <span className="text-sm text-muted-foreground">-</span>
                    )}
                  </TableCell>
                  <TableCell>
                    <Badge
                      variant="outline"
                      className={cn('border-0 text-[10px] font-medium capitalize', STATUS_STYLE[status])}
                    >
                      {status.replace('_', ' ')}
                    </Badge>
                  </TableCell>
                </TableRow>
              );
            })
          ) : (
            <TableRow>
              <TableCell colSpan={5} className="py-8 text-center text-muted-foreground">
                No findings match the current filters
              </TableCell>
            </TableRow>
          )}
        </TableBody>
      </Table>
    </div>
  );
}
