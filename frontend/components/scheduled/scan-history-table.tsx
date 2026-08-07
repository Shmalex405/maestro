'use client';

import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { Badge } from '@/components/ui/badge';
import { Skeleton } from '@/components/ui/skeleton';
import { cn } from '@/lib/utils';
import { SEVERITY_STYLES } from '@/lib/severity';
import type { Scan } from '@/lib/types';

// =============================================================================
// ScanHistoryTable — the drill-in scan-history grid (plan §3.2).
//
// Each GET /scans run: timestamp, scanner_set chips, per-severity frozen
// counts, duration, trigger_kind. Read-only. Reuses lib/severity.ts for the
// severity colors.
// =============================================================================

function fmtTime(iso: string | null | undefined): string {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '—';
  return `${d.toLocaleDateString()} ${d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}`;
}

function duration(start: string, end: string | null | undefined): string {
  if (!end) return '—';
  const ms = new Date(end).getTime() - new Date(start).getTime();
  if (!Number.isFinite(ms) || ms < 0) return '—';
  const secs = Math.round(ms / 1000);
  if (secs < 60) return `${secs}s`;
  const mins = Math.floor(secs / 60);
  const rem = secs % 60;
  return rem ? `${mins}m ${rem}s` : `${mins}m`;
}

function scannerChips(scannerSet: unknown): string[] {
  if (Array.isArray(scannerSet)) return scannerSet.map((s) => String(s));
  return [];
}

export function ScanHistoryTable({
  scans,
  isLoading,
}: {
  scans: Scan[] | undefined;
  isLoading: boolean;
}) {
  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead className="w-[180px]">Started</TableHead>
          <TableHead>Scanners</TableHead>
          <TableHead className="w-[170px]">Severity counts</TableHead>
          <TableHead className="w-[90px]">Duration</TableHead>
          <TableHead className="w-[100px]">Trigger</TableHead>
          <TableHead className="w-[100px]">Status</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {isLoading ? (
          Array.from({ length: 4 }).map((_, i) => (
            <TableRow key={i}>
              <TableCell><Skeleton className="h-4 w-32" /></TableCell>
              <TableCell><Skeleton className="h-5 w-40" /></TableCell>
              <TableCell><Skeleton className="h-4 w-32" /></TableCell>
              <TableCell><Skeleton className="h-4 w-12" /></TableCell>
              <TableCell><Skeleton className="h-4 w-16" /></TableCell>
              <TableCell><Skeleton className="h-5 w-16" /></TableCell>
            </TableRow>
          ))
        ) : scans && scans.length > 0 ? (
          scans.map((scan) => {
            const chips = scannerChips(scan.scanner_set);
            const counts: [keyof typeof SEVERITY_STYLES, number][] = [
              ['critical', scan.critical_count],
              ['high', scan.high_count],
              ['medium', scan.medium_count],
              ['low', scan.low_count],
              ['info', scan.info_count],
            ];
            return (
              <TableRow key={scan.id} className="hover:bg-white/[0.02] transition-colors">
                <TableCell className="text-xs text-muted-foreground tabular-nums">
                  {fmtTime(scan.started_at)}
                </TableCell>
                <TableCell>
                  <div className="flex flex-wrap gap-1">
                    {chips.length > 0 ? (
                      chips.slice(0, 6).map((c, i) => (
                        <Badge key={i} variant="outline" className="text-[10px] font-mono px-1.5 py-0">
                          {c}
                        </Badge>
                      ))
                    ) : (
                      <span className="text-xs text-muted-foreground/60">—</span>
                    )}
                    {chips.length > 6 && (
                      <Badge variant="outline" className="text-[10px] px-1.5 py-0 text-muted-foreground">
                        +{chips.length - 6}
                      </Badge>
                    )}
                  </div>
                </TableCell>
                <TableCell>
                  <div className="flex items-center gap-2">
                    {counts.map(([sev, n]) =>
                      n > 0 ? (
                        <span key={sev} className="flex items-center gap-1 text-xs">
                          <span className={cn('h-2 w-2 rounded-sm', SEVERITY_STYLES[sev].bg)} />
                          <span className="tabular-nums font-medium">{n}</span>
                        </span>
                      ) : null,
                    )}
                    {scan.total_count === 0 && <span className="text-xs text-muted-foreground/60">0</span>}
                  </div>
                </TableCell>
                <TableCell className="text-xs text-muted-foreground tabular-nums">
                  {duration(scan.started_at, scan.finished_at)}
                </TableCell>
                <TableCell>
                  <Badge variant="outline" className="text-[10px] capitalize text-muted-foreground border-border/50">
                    {scan.trigger_kind}
                  </Badge>
                </TableCell>
                <TableCell>
                  <Badge
                    variant="outline"
                    className={cn(
                      'text-[10px] px-2 py-0.5 border-0 font-medium capitalize',
                      scan.status === 'completed' && 'bg-emerald-500/10 text-emerald-400',
                      scan.status === 'running' && 'bg-primary/10 text-primary',
                      scan.status === 'failed' && 'bg-red-500/10 text-red-400',
                      !['completed', 'running', 'failed'].includes(scan.status) && 'bg-muted text-muted-foreground',
                    )}
                  >
                    {scan.status}
                  </Badge>
                </TableCell>
              </TableRow>
            );
          })
        ) : (
          <TableRow>
            <TableCell colSpan={6} className="text-center py-8 text-muted-foreground text-sm">
              No scans recorded for this target yet.
            </TableCell>
          </TableRow>
        )}
      </TableBody>
    </Table>
  );
}
