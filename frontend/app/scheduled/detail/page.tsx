'use client';

import { Suspense, useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useRouter, useSearchParams } from 'next/navigation';
import Link from 'next/link';
import {
  ChevronLeft,
  History,
  TrendingUp,
  AlertTriangle,
  Crosshair,
  Loader2,
  ArrowRight,
} from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Skeleton } from '@/components/ui/skeleton';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { toast } from 'sonner';
import { ScanHistoryTable } from '@/components/scheduled/scan-history-table';
import { TrendChart, type TrendSeries } from '@/components/dashboard/trend-chart';
import { api } from '@/lib/tauri-api';
import { cn } from '@/lib/utils';
import { SEVERITY_STYLES, severityStyle } from '@/lib/severity';
import type { Finding, Scan } from '@/lib/types';
import { createProveRun } from '@/lib/prove-finding';

// =============================================================================
// Scheduled DAST — drill-in (plan §3.2).
//
// Scan-history table + new-vs-fixed signed timeline + embedded findings for the
// target + the "Prove this finding" LLM bridge.
//
// The "Prove this finding" button is the differentiator: it escalates a cheap
// deterministic scanner hit to an on-demand LLM exploit. It creates an
// assessment pre-scoped to the single finding + target with a seeded prompt,
// then navigates to the assessment terminal (which auto-types the prompt).
// =============================================================================

function fmtBucket(iso: string): string {
  const d = new Date(iso);
  return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
}

/** Build a signed new-vs-fixed timeline from scan history.
 *
 *  /scans/diff is a single latest snapshot, so the per-bucket timeline is
 *  derived from the deltas in each scan's frozen total_count vs the previous
 *  scan: a rise = new findings (up), a fall = fixed findings (down). Scans
 *  arrive newest-first, so we reverse to oldest→newest first. */
function buildNewVsFixed(scans: Scan[]): { labels: string[]; series: TrendSeries[] } {
  const ordered = [...scans].reverse(); // oldest → newest
  const labels: string[] = [];
  const newVals: number[] = [];
  const fixedVals: number[] = [];

  for (let i = 0; i < ordered.length; i++) {
    const s = ordered[i];
    labels.push(fmtBucket(s.started_at));
    if (i === 0) {
      // First scan: everything it found is "new".
      newVals.push(s.total_count);
      fixedVals.push(0);
    } else {
      const delta = s.total_count - ordered[i - 1].total_count;
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

export default function ScheduledTargetDrillInPage() {
  // Static-export route (output: export) — the target id comes from the query
  // string (?id=), not a dynamic [param] segment (which would need
  // generateStaticParams and can't be pre-generated for runtime ids).
  return (
    <Suspense fallback={<div className="p-6 text-sm text-muted-foreground">Loading…</div>}>
      <ScheduledTargetDrillInContent />
    </Suspense>
  );
}

function ScheduledTargetDrillInContent() {
  const searchParams = useSearchParams();
  const targetId = searchParams.get('id') ?? '';
  const router = useRouter();
  const [provingId, setProvingId] = useState<string | null>(null);

  const { data: target, isLoading: targetLoading } = useQuery({
    queryKey: ['target', targetId],
    queryFn: () => api.targets.get(targetId),
  });

  const { data: scans, isLoading: scansLoading } = useQuery({
    queryKey: ['scans', targetId, 100],
    queryFn: () => api.scans.list({ target_id: targetId, limit: 100 }),
  });

  const { data: diff } = useQuery({
    queryKey: ['scan-diff', targetId],
    queryFn: () => api.scans.diff({ target_id: targetId }),
  });

  // Findings for this target — keyed off the canonical value (the findings
  // store's `target` column holds the raw/canonical string). Only fetch once
  // we know the target's canonical value.
  const targetValue = target?.canonical_value;
  const { data: findings, isLoading: findingsLoading } = useQuery({
    queryKey: ['findings', { target: targetValue }],
    queryFn: () =>
      api.findings.list({ search: targetValue, limit: 100 } as Record<string, unknown>),
    enabled: !!targetValue,
  });

  const timeline = useMemo(() => buildNewVsFixed(scans ?? []), [scans]);

  /** Create a single-finding-exploit assessment and jump into its terminal. */
  async function proveFinding(finding: Finding) {
    if (!target) return;
    setProvingId(finding.id);
    try {
      const id = await createProveRun({
        findingId: finding.id,
        title: finding.title,
        severity: finding.severity,
        cve: finding.cve,
        description: finding.description || undefined,
        targetValue: target.canonical_value,
        context: [
          finding.file_path
            ? `- Location: ${finding.file_path}${finding.line_start != null ? `:${finding.line_start}` : ''}`
            : '',
        ].filter(Boolean),
        type: 'web_app',
        capabilities: ['web_app'],
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
      <div className="flex items-center gap-3">
        <Link href="/scheduled">
          <Button variant="ghost" size="sm" className="gap-1.5">
            <ChevronLeft className="h-4 w-4" />
            Scheduled
          </Button>
        </Link>
      </div>

      <div className="flex items-center justify-between gap-3 flex-wrap">
        <div className="min-w-0">
          {targetLoading ? (
            <Skeleton className="h-7 w-64" />
          ) : (
            <>
              <h1 className="text-2xl font-bold tracking-tight truncate">
                {target?.canonical_value ?? 'Target'}
              </h1>
              <p className="text-sm text-muted-foreground mt-0.5 capitalize">
                {target?.target_type?.replace('_', ' ')} · Cadence: Manual
              </p>
            </>
          )}
        </div>
      </div>

      {/* New-vs-Fixed timeline */}
      <Card className="glass-card overflow-hidden">
        <CardHeader className="pb-2">
          <div className="flex items-center gap-2">
            <TrendingUp className="h-4 w-4 text-muted-foreground" />
            <CardTitle className="text-sm font-medium">New vs Fixed</CardTitle>
            {diff && (diff.new.length > 0 || diff.fixed.length > 0) && (
              <div className="ml-auto flex items-center gap-2 text-xs">
                {diff.new.length > 0 && (
                  <span className="text-red-400">+{diff.new.length} new</span>
                )}
                {diff.fixed.length > 0 && (
                  <span className="text-emerald-400">-{diff.fixed.length} fixed</span>
                )}
                <span className="text-muted-foreground">{diff.still_present_count} carried over</span>
              </div>
            )}
          </div>
        </CardHeader>
        <CardContent className="pt-2">
          {scansLoading ? (
            <Skeleton className="h-[180px] w-full" />
          ) : (
            <TrendChart
              labels={timeline.labels}
              series={timeline.series}
              emptyMessage="No scan history to chart yet"
            />
          )}
        </CardContent>
      </Card>

      {/* Scan history */}
      <Card className="glass-card overflow-hidden">
        <CardHeader className="pb-2">
          <div className="flex items-center gap-2">
            <History className="h-4 w-4 text-muted-foreground" />
            <CardTitle className="text-sm font-medium">Scan history</CardTitle>
          </div>
        </CardHeader>
        <CardContent className="p-0">
          <ScanHistoryTable scans={scans} isLoading={scansLoading} />
        </CardContent>
      </Card>

      {/* Findings for this target — with Prove-it action */}
      <Card className="glass-card overflow-hidden">
        <CardHeader className="pb-2">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <AlertTriangle className="h-4 w-4 text-muted-foreground" />
              <CardTitle className="text-sm font-medium">Findings</CardTitle>
              {findings?.data?.length ? (
                <span className="text-[10px] text-muted-foreground bg-muted/50 px-1.5 py-0.5 rounded-md">
                  {findings.data.length}
                </span>
              ) : null}
            </div>
            {targetValue && (
              <Link
                href={`/findings?target=${encodeURIComponent(targetValue)}`}
                className="text-xs text-muted-foreground hover:text-primary transition-colors flex items-center gap-1"
              >
                View all <ArrowRight className="h-3 w-3" />
              </Link>
            )}
          </div>
        </CardHeader>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-[100px]">Severity</TableHead>
                <TableHead>Title</TableHead>
                <TableHead className="w-[120px]">Status</TableHead>
                <TableHead className="w-[140px] text-right">Action</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {findingsLoading ? (
                Array.from({ length: 4 }).map((_, i) => (
                  <TableRow key={i}>
                    <TableCell><Skeleton className="h-6 w-16" /></TableCell>
                    <TableCell><Skeleton className="h-4 w-64" /></TableCell>
                    <TableCell><Skeleton className="h-5 w-20" /></TableCell>
                    <TableCell><Skeleton className="h-8 w-24 ml-auto" /></TableCell>
                  </TableRow>
                ))
              ) : findings?.data?.length ? (
                findings.data.map((finding) => {
                  const style = severityStyle(finding.severity);
                  const isProving = provingId === finding.id;
                  return (
                    <TableRow key={finding.id} className={cn(style.border, 'hover:bg-white/[0.02] transition-colors')}>
                      <TableCell>
                        <span className={cn('text-[10px] font-semibold uppercase px-2 py-1 rounded-md', style.badge)}>
                          {finding.severity}
                        </span>
                      </TableCell>
                      <TableCell>
                        <Link href={`/findings/detail?id=${finding.id}`} className="font-medium hover:underline">
                          {finding.title}
                        </Link>
                      </TableCell>
                      <TableCell>
                        <Badge variant="outline" className="text-[10px] capitalize text-muted-foreground border-border/50">
                          {finding.status.replace('_', ' ')}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-right">
                        <Button
                          size="sm"
                          variant="outline"
                          className="h-7 gap-1.5 text-xs"
                          disabled={isProving}
                          onClick={() => proveFinding(finding)}
                          title="Escalate this scanner hit to an on-demand LLM exploit"
                        >
                          {isProving ? (
                            <Loader2 className="h-3.5 w-3.5 animate-spin" />
                          ) : (
                            <Crosshair className="h-3.5 w-3.5" />
                          )}
                          Prove it
                        </Button>
                      </TableCell>
                    </TableRow>
                  );
                })
              ) : (
                <TableRow>
                  <TableCell colSpan={4} className="text-center py-8 text-muted-foreground text-sm">
                    No findings recorded for this target yet.
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}
