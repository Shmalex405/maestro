'use client';

// =============================================================================
// Scheduled DAST — shared presentational pieces.
//
// Extracted from the old single-page `app/scheduled/page.tsx` so the section's
// sub-pages (Overview, Scans, Vulnerabilities, Targets, Schedules, Reports,
// Settings) can each render the relevant piece while sharing one implementation.
//
// The headline change vs the old tabbed page: the Vulnerabilities view queries
// `scan_only: 'true'` (scan_id IS NOT NULL, migration 0035) so it shows ONLY
// findings produced by scheduled/deterministic DAST scans — never the normal
// LLM exploitation/validation findings.
// =============================================================================

import { useMemo, useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { toast } from 'sonner';
import {
  CalendarClock,
  Plus,
  Play,
  Trash2,
  Search,
  History,
  TrendingUp,
  TrendingDown,
  Minus,
  Globe,
  Cloud,
  Network,
  Server,
  FolderGit2,
  ShieldAlert,
  Settings2,
  Download,
  ChevronDown,
  ChevronRight,
  ArrowRight,
  X,
  Sparkles,
  RefreshCw,
  Check,
  User,
  Tag as TagIcon,
  MessageSquare,
  Clock,
  AlertTriangle,
  ShieldCheck,
} from 'lucide-react';
import { Checkbox } from '@/components/ui/checkbox';
import { createProveRun } from '@/lib/prove-finding';
import type { FindingComment } from '@/lib/types';
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
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { SearchableSelect } from '@/components/ui/searchable-select';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from '@/components/ui/dialog';
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetDescription,
} from '@/components/ui/sheet';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { Textarea } from '@/components/ui/textarea';
import { Sparkline } from '@/components/dashboard/sparkline';
import { SeverityDonut } from '@/components/viz/severity-donut';
import { ScanStats } from '@/components/scheduled/scan-stats';
import { api } from '@/lib/tauri-api';
import { cn } from '@/lib/utils';
import { severityStyle, SEVERITY_ORDER } from '@/lib/severity';
import type { Severity } from '@/lib/types';
import type {
  Target,
  Application,
  Scan,
  ScanDiff,
  ScanSchedule,
  Finding,
  ScanFindingDetail,
  ScanAuth,
  ScanScope,
} from '@/lib/types';

// =============================================================================
// Constants + helpers
// =============================================================================

export const CADENCES = ['hourly', 'daily', 'weekly', 'monthly'] as const;
export const cadenceLabel = (c: string) => c.charAt(0).toUpperCase() + c.slice(1);
// DAST only applies to reachable web/host targets (not repos / cloud accounts).
export const DAST_TARGET_TYPES = new Set(['web', 'host', 'cidr']);

export function relativeTime(iso: string | null | undefined): string {
  if (!iso) return '—';
  const t = new Date(iso).getTime();
  if (!Number.isFinite(t)) return '—';
  const s = Math.floor((Date.now() - t) / 1000);
  if (s < 60) return 'just now';
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  const d = Math.floor(s / 86400);
  if (d < 30) return `${d}d ago`;
  return `${Math.floor(d / 30)}mo ago`;
}

export function absTime(iso: string | null | undefined): string {
  if (!iso) return '—';
  const d = new Date(iso);
  if (!Number.isFinite(d.getTime())) return '—';
  return d.toLocaleString(undefined, {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

export function duration(start?: string | null, end?: string | null): string {
  if (!start || !end) return '—';
  const ms = new Date(end).getTime() - new Date(start).getTime();
  if (!Number.isFinite(ms) || ms < 0) return '—';
  const s = Math.floor(ms / 1000);
  if (s < 60) return `${s}s`;
  return `${Math.floor(s / 60)}m ${s % 60}s`;
}

export function TargetTypeIcon({ targetType, className }: { targetType: string; className?: string }) {
  switch (targetType) {
    case 'web':
      return <Globe className={className} />;
    case 'cloud_account':
      return <Cloud className={className} />;
    case 'cidr':
      return <Network className={className} />;
    case 'repo':
      return <FolderGit2 className={className} />;
    default:
      return <Server className={className} />;
  }
}

function statusBadge(status: string | undefined) {
  const s = status ?? 'No runs';
  const known = ['completed', 'running', 'failed'].includes(s);
  return (
    <Badge
      variant="outline"
      className={cn(
        'text-[10px] px-2 py-0.5 border-0 font-medium capitalize',
        s === 'completed' && 'bg-emerald-500/10 text-emerald-400',
        s === 'running' && 'bg-primary/10 text-primary',
        s === 'failed' && 'bg-red-500/10 text-red-400',
        !known && 'bg-muted text-muted-foreground',
      )}
    >
      {s}
    </Badge>
  );
}

/** Compact severity breakdown for a scan row. */
function SeverityCounts({ scan }: { scan: Scan }) {
  const buckets: [string, number, string][] = [
    ['C', scan.critical_count, 'text-red-400'],
    ['H', scan.high_count, 'text-orange-400'],
    ['M', scan.medium_count, 'text-yellow-400'],
    ['L', scan.low_count, 'text-sky-400'],
  ];
  if (scan.total_count === 0) return <span className="text-xs text-muted-foreground/60">clean</span>;
  return (
    <div className="flex items-center gap-2 text-xs tabular-nums">
      {buckets.map(([label, n, color]) =>
        n > 0 ? (
          <span key={label} className={cn('font-semibold', color)} title={`${n} ${label}`}>
            {n}
            {label}
          </span>
        ) : null,
      )}
    </div>
  );
}

function findingStatusBadge(status: string) {
  return (
    <Badge variant="outline" className="text-[10px] px-2 py-0.5 border-border/50 text-muted-foreground capitalize">
      {status.replace('_', ' ')}
    </Badge>
  );
}

/** Clean a finding's `source` into a short scanner label.
 *  Deterministic findings carry `sequential-pipeline/<tool>`. */
export function scannerLabel(source?: string | null): string {
  if (!source) return '—';
  const tail = source.includes('/') ? source.split('/').pop()! : source;
  return tail.replace(/_/g, ' ');
}

/** Trigger a browser download of a string payload. */
export function downloadString(filename: string, mime: string, content: string) {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

// =============================================================================
// Export button — CSV / JSON / Markdown download of DAST-only findings.
// =============================================================================

function csvCell(v: unknown): string {
  const s = v == null ? '' : String(v);
  // Quote when the value contains a comma, quote, or newline; escape quotes.
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

function buildExport(format: 'csv' | 'json' | 'markdown', rows: Finding[]): string {
  if (format === 'json') {
    return JSON.stringify(
      rows.map((f) => ({
        id: f.id,
        title: f.title,
        severity: f.severity,
        status: f.status,
        target: f.target,
        scanner: scannerLabel(f.source_tool ?? f.source),
        cve: f.cve ?? null,
        cwe: f.cwe ?? null,
        first_seen_at: f.first_seen_at ?? null,
        last_seen_at: f.last_seen_at ?? null,
        occurrence_count: f.occurrence_count ?? null,
        description: f.description ?? null,
      })),
      null,
      2,
    );
  }
  const cols = ['Severity', 'Title', 'Target', 'Scanner', 'CVE', 'Status'] as const;
  const get = (f: Finding) => [
    f.severity,
    f.title,
    f.target,
    scannerLabel(f.source_tool ?? f.source),
    f.cve ?? '',
    f.status,
  ];
  if (format === 'csv') {
    return [cols.join(','), ...rows.map((f) => get(f).map(csvCell).join(','))].join('\n');
  }
  // markdown
  const header = `| ${cols.join(' | ')} |`;
  const divider = `| ${cols.map(() => '---').join(' | ')} |`;
  const body = rows
    .map((f) => `| ${get(f).map((c) => String(c).replace(/\|/g, '\\|')).join(' | ')} |`)
    .join('\n');
  return `# Scheduled DAST vulnerabilities\n\n_${rows.length} findings · ${new Date().toISOString().slice(0, 10)}_\n\n${header}\n${divider}\n${body}\n`;
}

export function ExportFindingsButton() {
  const [busy, setBusy] = useState(false);

  async function run(format: 'csv' | 'json' | 'markdown') {
    setBusy(true);
    try {
      // Build client-side from the DAST-only findings (scan_only ⇒ scan_id IS
      // NOT NULL, migration 0035) so the export never bleeds in LLM findings.
      const page = await api.findings.list({ scan_only: 'true', limit: 1000 });
      const rows = page.data ?? [];
      if (rows.length === 0) {
        toast.message('No DAST findings to export yet.');
        return;
      }
      const payload = buildExport(format, rows);
      const ext = format === 'markdown' ? 'md' : format;
      const mime =
        format === 'json' ? 'application/json' : format === 'csv' ? 'text/csv' : 'text/markdown';
      const stamp = new Date().toISOString().slice(0, 10);
      downloadString(`dast-findings-${stamp}.${ext}`, mime, payload);
      toast.success(`Exported ${rows.length} DAST findings as ${format.toUpperCase()}.`);
    } catch (e) {
      toast.error(`Export failed: ${e instanceof Error ? e.message : String(e)}`);
    } finally {
      setBusy(false);
    }
  }

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="outline" size="sm" className="h-8 text-sm" disabled={busy}>
          <Download className="mr-1.5 h-3.5 w-3.5" />
          {busy ? 'Exporting…' : 'Export'}
          <ChevronDown className="ml-1 h-3.5 w-3.5 opacity-60" />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end">
        <DropdownMenuItem onClick={() => run('csv')}>CSV</DropdownMenuItem>
        <DropdownMenuItem onClick={() => run('json')}>JSON</DropdownMenuItem>
        <DropdownMenuItem onClick={() => run('markdown')}>Markdown</DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

// =============================================================================
// Scans — org-wide ran-scan history
// =============================================================================

export function ScansTab({
  targetById,
  onSelectScan,
  onConfigure,
}: {
  targetById: Map<string, Target>;
  onSelectScan: (scan: Scan) => void;
  onConfigure: (targetId: string) => void;
}) {
  const { data: scans, isLoading } = useQuery({
    queryKey: ['scans', 'all'],
    queryFn: () => api.scans.list({ limit: 200 }),
    // Live progress: poll while any scan is running, then stop.
    refetchInterval: (q) => {
      const d = q.state.data as Scan[] | undefined;
      return d?.some((s) => s.status === 'running') ? 4000 : false;
    },
  });

  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  const [typeFilter, setTypeFilter] = useState('all');

  const filtered = useMemo(() => {
    return (scans ?? []).filter((s) => {
      if (statusFilter !== 'all' && s.status !== statusFilter) return false;
      if (typeFilter !== 'all' && s.scan_type !== typeFilter) return false;
      if (search) {
        const label = targetById.get(s.target_id)?.canonical_value ?? s.target_id;
        if (!label.toLowerCase().includes(search.toLowerCase())) return false;
      }
      return true;
    });
  }, [scans, statusFilter, typeFilter, search, targetById]);

  if (isLoading) {
    return (
      <div className="p-4 space-y-3">
        {Array.from({ length: 4 }).map((_, i) => (
          <Skeleton key={i} className="h-12 w-full" />
        ))}
      </div>
    );
  }

  if ((scans?.length ?? 0) === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-16 text-center">
        <div className="mb-3 rounded-xl bg-muted/50 p-3">
          <History className="h-7 w-7 text-muted-foreground/50" />
        </div>
        <p className="text-sm font-medium text-muted-foreground">No scans yet</p>
        <p className="mt-1 text-xs text-muted-foreground/70 max-w-md">
          Run a DAST scan or schedule a target. Each run lands here with its findings and timestamp.
        </p>
      </div>
    );
  }

  return (
    <div>
      <div className="flex items-center gap-2 flex-wrap p-3 border-b border-border/40">
        <div className="relative">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
          <Input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Filter by target…"
            className="h-8 w-[240px] pl-8 text-sm"
          />
        </div>
        <Select value={statusFilter} onValueChange={setStatusFilter}>
          <SelectTrigger className="h-8 w-[130px] text-sm">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All status</SelectItem>
            <SelectItem value="completed">Completed</SelectItem>
            <SelectItem value="running">Running</SelectItem>
            <SelectItem value="failed">Failed</SelectItem>
          </SelectContent>
        </Select>
        <Select value={typeFilter} onValueChange={setTypeFilter}>
          <SelectTrigger className="h-8 w-[140px] text-sm">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All types</SelectItem>
            <SelectItem value="deterministic">Deterministic</SelectItem>
            <SelectItem value="dast">DAST</SelectItem>
            <SelectItem value="full">Full</SelectItem>
          </SelectContent>
        </Select>
        <div className="ml-auto flex items-center gap-2">
          <span className="text-xs text-muted-foreground">
            {filtered.length} of {scans?.length ?? 0} runs
          </span>
        </div>
      </div>

      <Table>
        <TableHeader>
          <TableRow>
            <TableHead className="w-[150px]">Started</TableHead>
            <TableHead>Target</TableHead>
            <TableHead className="w-[110px]">Type</TableHead>
            <TableHead className="w-[100px]">Trigger</TableHead>
            <TableHead className="w-[160px]">Findings</TableHead>
            <TableHead className="w-[90px]">Duration</TableHead>
            <TableHead className="w-[100px]">Status</TableHead>
            <TableHead className="w-[80px] text-right">Actions</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {filtered.map((s) => {
            const target = targetById.get(s.target_id);
            const label = target?.canonical_value ?? s.target_id;
            return (
              <TableRow
                key={s.id}
                className="cursor-pointer hover:bg-white/[0.02] transition-colors"
                onClick={() => onSelectScan(s)}
              >
                <TableCell className="text-xs text-muted-foreground tabular-nums" title={s.started_at}>
                  {absTime(s.started_at)}
                </TableCell>
                <TableCell>
                  <div className="flex items-center gap-2 min-w-0">
                    <TargetTypeIcon
                      targetType={target?.target_type ?? 'host'}
                      className="h-3.5 w-3.5 text-primary/70 shrink-0"
                    />
                    <span className="text-sm truncate max-w-[280px]">{label}</span>
                  </div>
                </TableCell>
                <TableCell>
                  <Badge variant="outline" className="text-[10px] capitalize border-border/50 text-muted-foreground">
                    {s.scan_type}
                  </Badge>
                </TableCell>
                <TableCell className="text-xs text-muted-foreground capitalize">{s.trigger_kind}</TableCell>
                <TableCell>
                  {s.status === 'running' ? (
                    <div className="w-[150px]">
                      <div className="h-1.5 w-full overflow-hidden rounded bg-white/10">
                        <div
                          className="h-1.5 rounded bg-primary transition-all"
                          style={{ width: `${s.progress_pct ?? 0}%` }}
                        />
                      </div>
                      <p className="mt-0.5 truncate text-[10px] text-muted-foreground" title={s.current_activity ?? s.phase ?? ''}>
                        {s.progress_pct ?? 0}% · {s.phase ?? 'running'}
                      </p>
                    </div>
                  ) : (
                    <SeverityCounts scan={s} />
                  )}
                </TableCell>
                <TableCell className="text-xs text-muted-foreground tabular-nums">
                  {s.status === 'running' ? '—' : duration(s.started_at, s.finished_at)}
                </TableCell>
                <TableCell>{statusBadge(s.status)}</TableCell>
                <TableCell>
                  <div className="flex items-center justify-end gap-1">
                    <Button
                      variant="ghost"
                      size="sm"
                      className="h-7 w-7 p-0 text-muted-foreground hover:text-primary"
                      onClick={(e) => {
                        e.stopPropagation();
                        onConfigure(s.target_id);
                      }}
                      title="Configure auth + scope for this target"
                    >
                      <Settings2 className="h-3.5 w-3.5" />
                    </Button>
                  </div>
                </TableCell>
              </TableRow>
            );
          })}
        </TableBody>
      </Table>
    </div>
  );
}

// =============================================================================
// Validation tier (migration 0036 — AI escalation bridge) + SLA helpers
// =============================================================================

export type VulnTier =
  | 'unproven'
  | 'ai_confirmed'
  | 'oracle_verified'
  | 'not_exploitable'
  | 'human_attested';

// `oracle_verified` sits between attested and AI-confirmed (migration 0049): a
// named oracle re-proved the finding N/N in code and it carries a replay capsule.
// `ai_confirmed` now means what it always literally meant — an agent claims the
// finding is exploitable and nothing has independently re-proved it.
export const TIER_META: Record<VulnTier, { label: string; cls: string }> = {
  human_attested: { label: 'Attested', cls: 'bg-emerald-500/15 text-emerald-400' },
  oracle_verified: { label: 'Oracle-verified', cls: 'bg-violet-500/15 text-violet-400' },
  ai_confirmed: { label: 'AI-claimed', cls: 'bg-red-500/15 text-red-400' },
  not_exploitable: { label: 'Not exploitable', cls: 'bg-muted text-muted-foreground' },
  unproven: { label: 'Unproven', cls: 'bg-amber-500/15 text-amber-400' },
};

export function tierOf(f: Finding): VulnTier {
  return (f.validation_tier as VulnTier) ?? 'unproven';
}

export function TierBadge({ tier }: { tier: VulnTier }) {
  const m = TIER_META[tier];
  return (
    <span className={cn('rounded px-1.5 py-0.5 text-[10px] font-semibold whitespace-nowrap', m.cls)}>
      {m.label}
    </span>
  );
}

export interface SlaDays {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}
export const DEFAULT_SLA: SlaDays = { critical: 7, high: 14, medium: 30, low: 90, info: 90 };

export function slaFromSettings(s?: {
  sla_critical_days?: number;
  sla_high_days?: number;
  sla_medium_days?: number;
  sla_low_days?: number;
}): SlaDays {
  return {
    critical: s?.sla_critical_days ?? DEFAULT_SLA.critical,
    high: s?.sla_high_days ?? DEFAULT_SLA.high,
    medium: s?.sla_medium_days ?? DEFAULT_SLA.medium,
    low: s?.sla_low_days ?? DEFAULT_SLA.low,
    info: s?.sla_low_days ?? DEFAULT_SLA.info,
  };
}

/** Days-open + SLA breach, derived from first_seen_at. Null when no first_seen. */
export function slaInfo(f: Finding, sla: SlaDays): { ageDays: number; slaDays: number; breached: boolean } | null {
  if (!f.first_seen_at) return null;
  const seen = new Date(f.first_seen_at).getTime();
  if (!Number.isFinite(seen)) return null;
  const ageDays = Math.max(0, Math.floor((Date.now() - seen) / 86_400_000));
  const key = (['critical', 'high', 'medium', 'low', 'info'] as const).includes(f.severity as Severity)
    ? (f.severity as keyof SlaDays)
    : 'info';
  const slaDays = sla[key];
  const open = !['remediated', 'accepted', 'false_positive'].includes(f.status);
  return { ageDays, slaDays, breached: open && ageDays > slaDays };
}

// =============================================================================
// Vulnerabilities — the VM workbench. DAST-only findings (scan_id IS NOT NULL),
// separate from the global LLM-assessment findings. Bulk triage + tier filter +
// SLA aging + per-finding detail drawer (status / assign / tags / comments /
// Prove / Retest / Attest).
// =============================================================================

const TIER_FILTERS: { value: string; label: string }[] = [
  { value: 'all', label: 'All tiers' },
  { value: 'unproven', label: 'Unproven (queue)' },
  { value: 'ai_confirmed', label: 'AI-claimed' },
  { value: 'oracle_verified', label: 'Oracle-verified' },
  { value: 'human_attested', label: 'Attested' },
  { value: 'not_exploitable', label: 'Not exploitable' },
];

export function VulnerabilitiesView() {
  const queryClient = useQueryClient();
  const { data, isLoading } = useQuery({
    queryKey: ['dast-vulns'],
    queryFn: () => api.findings.list({ scan_only: 'true', limit: 300 }),
  });
  const { data: settings } = useQuery({
    queryKey: ['dast-settings'],
    queryFn: () => api.dastSettings.get(),
  });
  const sla = useMemo(() => slaFromSettings(settings), [settings]);

  const [search, setSearch] = useState('');
  const [sevFilter, setSevFilter] = useState('all');
  const [statusFilter, setStatusFilter] = useState('all');
  const [tierFilter, setTierFilter] = useState('all');
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [detailId, setDetailId] = useState<string | null>(null);
  const [assignVal, setAssignVal] = useState('');

  const findings = useMemo(
    () =>
      [...(data?.data ?? [])].sort(
        (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity),
      ),
    [data],
  );

  const filtered = useMemo(
    () =>
      findings.filter((f) => {
        if (sevFilter !== 'all' && f.severity !== sevFilter) return false;
        if (statusFilter !== 'all' && f.status !== statusFilter) return false;
        if (tierFilter !== 'all' && tierOf(f) !== tierFilter) return false;
        if (search && !`${f.title} ${f.target} ${f.cve ?? ''}`.toLowerCase().includes(search.toLowerCase()))
          return false;
        return true;
      }),
    [findings, sevFilter, statusFilter, tierFilter, search],
  );

  const refresh = () => queryClient.invalidateQueries({ queryKey: ['dast-vulns'] });

  const bulk = useMutation({
    mutationFn: (body: Parameters<typeof api.findings.bulkUpdate>[0]) => api.findings.bulkUpdate(body),
    onSuccess: (r) => {
      toast.success(`Updated ${r.updated} ${r.updated === 1 ? 'finding' : 'findings'}.`);
      setSelected(new Set());
      setAssignVal('');
      refresh();
    },
    onError: (e) => toast.error(`Bulk update failed: ${e instanceof Error ? e.message : String(e)}`),
  });

  const proveSelected = useMutation({
    mutationFn: async (ids: string[]) => {
      const targets = findings.filter((f) => ids.includes(f.id) && tierOf(f) === 'unproven');
      let queued = 0;
      for (const f of targets) {
        await createProveRun({
          findingId: f.id,
          title: f.title,
          severity: f.severity,
          cve: f.cve,
          description: f.description,
          targetValue: f.target,
        });
        queued++;
      }
      return queued;
    },
    onSuccess: (n) => {
      toast.success(`Queued ${n} Prove run(s) — start them from Assessments.`);
      setSelected(new Set());
    },
    onError: (e) => toast.error(`Couldn't queue Prove runs: ${e instanceof Error ? e.message : String(e)}`),
  });

  const allVisibleSelected = filtered.length > 0 && filtered.every((f) => selected.has(f.id));
  const toggleAll = () =>
    setSelected((prev) => {
      if (allVisibleSelected) return new Set();
      return new Set(filtered.map((f) => f.id));
    });
  const toggleOne = (id: string) =>
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });

  if (isLoading) {
    return (
      <div className="p-4 space-y-3">
        {Array.from({ length: 5 }).map((_, i) => (
          <Skeleton key={i} className="h-10 w-full" />
        ))}
      </div>
    );
  }

  if (findings.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-16 text-center">
        <div className="mb-3 rounded-xl bg-muted/50 p-3">
          <ShieldAlert className="h-7 w-7 text-muted-foreground/50" />
        </div>
        <p className="text-sm font-medium text-muted-foreground">No DAST vulnerabilities yet</p>
        <p className="mt-1 text-xs text-muted-foreground/70 max-w-md">
          Vulnerabilities found by your scheduled / on-demand DAST scans appear here — kept separate
          from the LLM exploitation findings. Run a scan to populate.
        </p>
      </div>
    );
  }

  const selCount = selected.size;

  return (
    <div>
      {/* Filters */}
      <div className="flex items-center gap-2 flex-wrap p-3 border-b border-border/40">
        <div className="relative">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
          <Input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Filter vulnerabilities…" className="h-8 w-[220px] pl-8 text-sm" />
        </div>
        <Select value={sevFilter} onValueChange={setSevFilter}>
          <SelectTrigger className="h-8 w-[120px] text-sm"><SelectValue /></SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All severity</SelectItem>
            {SEVERITY_ORDER.map((s) => (
              <SelectItem key={s} value={s} className="capitalize">{s}</SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select value={tierFilter} onValueChange={setTierFilter}>
          <SelectTrigger className="h-8 w-[150px] text-sm"><SelectValue /></SelectTrigger>
          <SelectContent>
            {TIER_FILTERS.map((t) => (
              <SelectItem key={t.value} value={t.value}>{t.label}</SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select value={statusFilter} onValueChange={setStatusFilter}>
          <SelectTrigger className="h-8 w-[120px] text-sm"><SelectValue /></SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All status</SelectItem>
            <SelectItem value="open">Open</SelectItem>
            <SelectItem value="in_progress">In progress</SelectItem>
            <SelectItem value="remediated">Remediated</SelectItem>
            <SelectItem value="accepted">Accepted</SelectItem>
            <SelectItem value="false_positive">False positive</SelectItem>
          </SelectContent>
        </Select>
        <div className="ml-auto flex items-center gap-2">
          <ExportFindingsButton />
          <span className="text-xs text-muted-foreground">
            {filtered.length} of {findings.length} vulnerabilities
          </span>
        </div>
      </div>

      {/* Bulk action bar */}
      {selCount > 0 && (
        <div className="flex items-center gap-2 flex-wrap border-b border-border/40 bg-primary/5 px-3 py-2">
          <span className="text-xs font-medium text-primary">{selCount} selected</span>
          <Select onValueChange={(status) => bulk.mutate({ ids: Array.from(selected), status })}>
            <SelectTrigger className="h-7 w-[140px] text-xs"><SelectValue placeholder="Set status…" /></SelectTrigger>
            <SelectContent>
              <SelectItem value="open">Open</SelectItem>
              <SelectItem value="in_progress">In progress</SelectItem>
              <SelectItem value="remediated">Remediated</SelectItem>
              <SelectItem value="accepted">Accepted</SelectItem>
              <SelectItem value="false_positive">False positive</SelectItem>
            </SelectContent>
          </Select>
          <div className="flex items-center gap-1">
            <Input
              value={assignVal}
              onChange={(e) => setAssignVal(e.target.value)}
              placeholder="Assign to…"
              className="h-7 w-[150px] text-xs"
            />
            <Button
              variant="outline"
              size="sm"
              className="h-7 text-xs"
              disabled={!assignVal.trim() || bulk.isPending}
              onClick={() => bulk.mutate({ ids: Array.from(selected), assigned_to: assignVal.trim() })}
            >
              Assign
            </Button>
          </div>
          <Button
            variant="outline"
            size="sm"
            className="h-7 text-xs"
            disabled={proveSelected.isPending}
            onClick={() => proveSelected.mutate(Array.from(selected))}
          >
            <Sparkles className="mr-1 h-3.5 w-3.5" /> Prove selected
          </Button>
          <Button variant="ghost" size="sm" className="h-7 text-xs text-muted-foreground" onClick={() => setSelected(new Set())}>
            Clear
          </Button>
        </div>
      )}

      <Table>
        <TableHeader>
          <TableRow>
            <TableHead className="w-[36px]">
              <Checkbox checked={allVisibleSelected} onCheckedChange={toggleAll} aria-label="Select all" />
            </TableHead>
            <TableHead className="w-[90px]">Severity</TableHead>
            <TableHead>Vulnerability</TableHead>
            <TableHead className="w-[170px]">Target</TableHead>
            <TableHead className="w-[120px]">Tier</TableHead>
            <TableHead className="w-[110px]">Assignee</TableHead>
            <TableHead className="w-[100px]">SLA</TableHead>
            <TableHead className="w-[100px]">Status</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {filtered.map((f) => {
            const sev = severityStyle(f.severity);
            const s = slaInfo(f, sla);
            return (
              <TableRow
                key={f.id}
                className="cursor-pointer hover:bg-white/[0.02] transition-colors"
                onClick={() => setDetailId(f.id)}
              >
                <TableCell onClick={(e) => e.stopPropagation()}>
                  <Checkbox checked={selected.has(f.id)} onCheckedChange={() => toggleOne(f.id)} aria-label="Select row" />
                </TableCell>
                <TableCell>
                  <span className={cn('text-[10px] font-semibold uppercase px-1.5 py-0.5 rounded', sev.badge)}>
                    {sev.label}
                  </span>
                </TableCell>
                <TableCell className="text-sm truncate max-w-[320px]" title={f.title}>
                  {f.title}
                  <span className="ml-1.5 text-[10px] text-muted-foreground capitalize">
                    {scannerLabel(f.source_tool ?? f.source)}
                  </span>
                </TableCell>
                <TableCell className="text-xs text-muted-foreground truncate max-w-[170px]" title={f.target}>
                  {f.target}
                </TableCell>
                <TableCell><TierBadge tier={tierOf(f)} /></TableCell>
                <TableCell className="text-xs text-muted-foreground truncate max-w-[110px]" title={f.assigned_to ?? ''}>
                  {f.assigned_to || <span className="text-muted-foreground/50">—</span>}
                </TableCell>
                <TableCell>
                  {s ? (
                    <span
                      className={cn('text-xs tabular-nums', s.breached ? 'font-semibold text-red-400' : 'text-muted-foreground')}
                      title={`Open ${s.ageDays}d · SLA ${s.slaDays}d`}
                    >
                      {s.breached && <AlertTriangle className="mr-0.5 inline h-3 w-3" />}
                      {s.ageDays}d/{s.slaDays}d
                    </span>
                  ) : (
                    <span className="text-xs text-muted-foreground/50">—</span>
                  )}
                </TableCell>
                <TableCell>{findingStatusBadge(f.status)}</TableCell>
              </TableRow>
            );
          })}
        </TableBody>
      </Table>

      <VulnDetailSheet
        findingId={detailId}
        open={!!detailId}
        onOpenChange={(v) => { if (!v) setDetailId(null); }}
      />
    </div>
  );
}

// =============================================================================
// Vulnerability detail drawer — triage one finding: status / assignee / tags /
// comments / history + actions (Prove it · Retest · Attest). Fetches the finding
// by id so edits stay live.
// =============================================================================

function VulnDetailSheet({
  findingId,
  open,
  onOpenChange,
}: {
  findingId: string | null;
  open: boolean;
  onOpenChange: (v: boolean) => void;
}) {
  const queryClient = useQueryClient();
  const router = useRouter();
  const [newTag, setNewTag] = useState('');
  const [assignDraft, setAssignDraft] = useState('');
  const [comment, setComment] = useState('');

  const { data: f, isLoading } = useQuery({
    queryKey: ['finding', findingId],
    queryFn: () => api.findings.get(findingId!),
    enabled: open && !!findingId,
  });
  const { data: comments } = useQuery({
    queryKey: ['finding-comments', findingId],
    queryFn: () => api.findings.comments.list(findingId!),
    enabled: open && !!findingId,
  });

  const invalidate = () => {
    queryClient.invalidateQueries({ queryKey: ['finding', findingId] });
    queryClient.invalidateQueries({ queryKey: ['dast-vulns'] });
  };

  const update = useMutation({
    mutationFn: (patch: Partial<Finding> & { attest?: boolean }) => api.findings.update(findingId!, patch),
    onSuccess: () => { invalidate(); },
    onError: (e) => toast.error(`Update failed: ${e instanceof Error ? e.message : String(e)}`),
  });

  const addComment = useMutation({
    mutationFn: (body: string) => api.findings.comments.create(findingId!, body),
    onSuccess: () => {
      setComment('');
      queryClient.invalidateQueries({ queryKey: ['finding-comments', findingId] });
    },
    onError: (e) => toast.error(`Couldn't add comment: ${e instanceof Error ? e.message : String(e)}`),
  });

  const prove = useMutation({
    mutationFn: async () => {
      if (!f) throw new Error('no finding');
      return createProveRun({
        findingId: f.id,
        title: f.title,
        severity: f.severity,
        cve: f.cve,
        description: f.description,
        targetValue: f.target,
      });
    },
    onSuccess: (id) => {
      toast.success('Prove run created — opening Assessments to start it.');
      router.push(`/assessments?id=${id}`);
    },
    onError: (e) => toast.error(`Couldn't create Prove run: ${e instanceof Error ? e.message : String(e)}`),
  });

  const retest = useMutation({
    mutationFn: async () => {
      if (!f) throw new Error('no finding');
      return api.agents.runOrchestrator({ mode: 'sequential', targets: [f.target] });
    },
    onSuccess: () => {
      toast.success('Retest scan started — results update this finding when it completes.');
      setTimeout(() => queryClient.invalidateQueries({ queryKey: ['scans'] }), 1500);
    },
    onError: (e) => toast.error(`Couldn't start retest: ${e instanceof Error ? e.message : String(e)}`),
  });

  const tags = f?.tags ?? [];

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent className="w-full sm:max-w-[680px] overflow-y-auto">
        {isLoading || !f ? (
          <div className="space-y-3 py-4">
            {Array.from({ length: 6 }).map((_, i) => <Skeleton key={i} className="h-10 w-full" />)}
          </div>
        ) : (
          <>
            <SheetHeader>
              <div className="flex items-center gap-2">
                <span className={cn('text-[10px] font-semibold uppercase px-1.5 py-0.5 rounded', severityStyle(f.severity).badge)}>
                  {severityStyle(f.severity).label}
                </span>
                <TierBadge tier={tierOf(f)} />
                {f.remediated_at && (
                  <span className="rounded bg-emerald-500/15 px-1.5 py-0.5 text-[10px] font-semibold text-emerald-400">✓ Fixed</span>
                )}
              </div>
              <SheetTitle className="text-base leading-snug">{f.title}</SheetTitle>
              <SheetDescription className="break-all">{f.target}</SheetDescription>
            </SheetHeader>

            {/* Actions */}
            <div className="mt-4 flex flex-wrap gap-2">
              <Button size="sm" className="h-8" disabled={prove.isPending} onClick={() => prove.mutate()}>
                <Sparkles className="mr-1.5 h-3.5 w-3.5" /> Prove it
              </Button>
              <Button size="sm" variant="outline" className="h-8" disabled={retest.isPending} onClick={() => retest.mutate()}>
                <RefreshCw className="mr-1.5 h-3.5 w-3.5" /> Retest
              </Button>
              <Button
                size="sm"
                variant="outline"
                className="h-8"
                disabled={update.isPending}
                onClick={() => update.mutate({ attest: !f.attested_at })}
              >
                {f.attested_at ? <Check className="mr-1.5 h-3.5 w-3.5 text-emerald-400" /> : <ShieldCheck className="mr-1.5 h-3.5 w-3.5" />}
                {f.attested_at ? 'Attested' : 'Attest'}
              </Button>
            </div>

            {/* Triage row: status + assignee */}
            <div className="mt-4 grid grid-cols-2 gap-3">
              <div className="space-y-1.5">
                <label className="text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">Status</label>
                <Select value={f.status} onValueChange={(status) => update.mutate({ status: status as Finding['status'] })}>
                  <SelectTrigger className="h-8 text-sm"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="open">Open</SelectItem>
                    <SelectItem value="in_progress">In progress</SelectItem>
                    <SelectItem value="remediated">Remediated</SelectItem>
                    <SelectItem value="accepted">Accepted</SelectItem>
                    <SelectItem value="false_positive">False positive</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-1.5">
                <label className="text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">Assignee</label>
                <div className="flex items-center gap-1">
                  <Input
                    value={assignDraft || f.assigned_to || ''}
                    onChange={(e) => setAssignDraft(e.target.value)}
                    placeholder="unassigned"
                    className="h-8 text-sm"
                  />
                  <Button
                    size="sm"
                    variant="outline"
                    className="h-8 px-2"
                    disabled={update.isPending}
                    onClick={() => update.mutate({ assigned_to: (assignDraft || f.assigned_to || '').trim() })}
                  >
                    <User className="h-3.5 w-3.5" />
                  </Button>
                </div>
              </div>
            </div>

            {/* Tags */}
            <div className="mt-4 space-y-1.5">
              <label className="text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">Tags</label>
              <div className="flex flex-wrap items-center gap-1.5">
                {tags.map((t) => (
                  <span key={t} className="flex items-center gap-1 rounded bg-white/5 px-1.5 py-0.5 text-xs">
                    <TagIcon className="h-3 w-3 text-muted-foreground" />
                    {t}
                    <button
                      onClick={() => update.mutate({ tags: tags.filter((x) => x !== t) })}
                      className="text-muted-foreground hover:text-red-400"
                    >
                      <X className="h-3 w-3" />
                    </button>
                  </span>
                ))}
                <Input
                  value={newTag}
                  onChange={(e) => setNewTag(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' && newTag.trim()) {
                      update.mutate({ tags: [...new Set([...tags, newTag.trim()])] });
                      setNewTag('');
                    }
                  }}
                  placeholder="add tag…"
                  className="h-7 w-[120px] text-xs"
                />
              </div>
            </div>

            {/* Evidence */}
            {(f.description?.trim() || f.evidence?.trim()) && (
              <div className="mt-5 space-y-3">
                {f.description?.trim() && (
                  <div>
                    <p className="mb-1 text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">Description</p>
                    <p className="whitespace-pre-wrap text-xs text-muted-foreground/90">{f.description}</p>
                  </div>
                )}
                {f.evidence?.trim() && (
                  <div>
                    <p className="mb-1 text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">Evidence</p>
                    <pre className="max-h-[320px] overflow-auto rounded-md bg-black/40 p-2.5 font-mono text-[11px] leading-relaxed text-muted-foreground/90">
                      {f.evidence}
                    </pre>
                  </div>
                )}
              </div>
            )}

            {/* History */}
            <div className="mt-5 rounded-lg border border-border/40 p-3">
              <p className="mb-2 flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">
                <Clock className="h-3 w-3" /> History
              </p>
              <div className="grid grid-cols-2 gap-y-1 text-xs text-muted-foreground">
                <span>First seen</span><span className="text-right text-foreground">{absTime(f.first_seen_at)}</span>
                <span>Last seen</span><span className="text-right text-foreground">{absTime(f.last_seen_at)}</span>
                <span>Occurrences</span><span className="text-right text-foreground">{f.occurrence_count ?? 1}</span>
                {f.cve && (<><span>CVE</span><span className="text-right font-mono text-foreground">{f.cve}</span></>)}
                {f.prior_exploitable && (<><span>Was</span><span className="text-right text-foreground capitalize">{f.prior_exploitable}</span></>)}
              </div>
            </div>

            {/* Comments */}
            <div className="mt-5">
              <p className="mb-2 flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">
                <MessageSquare className="h-3 w-3" /> Comments
              </p>
              <div className="space-y-2">
                {(comments ?? []).length === 0 && (
                  <p className="text-xs text-muted-foreground/60">No comments yet.</p>
                )}
                {(comments ?? []).map((c: FindingComment) => (
                  <div key={c.id} className="rounded-md bg-white/[0.02] p-2">
                    <div className="flex items-center justify-between text-[10px] text-muted-foreground">
                      <span className="font-medium text-foreground/80">{c.author ?? 'unknown'}</span>
                      <span>{relativeTime(c.created_at)}</span>
                    </div>
                    <p className="mt-0.5 whitespace-pre-wrap text-xs text-muted-foreground/90">{c.body}</p>
                  </div>
                ))}
              </div>
              <div className="mt-2 flex items-start gap-2">
                <Textarea
                  value={comment}
                  onChange={(e) => setComment(e.target.value)}
                  placeholder="Add a comment…"
                  className="min-h-[60px] text-sm"
                />
                <Button
                  size="sm"
                  className="h-8"
                  disabled={!comment.trim() || addComment.isPending}
                  onClick={() => addComment.mutate(comment.trim())}
                >
                  Post
                </Button>
              </div>
            </div>
          </>
        )}
      </SheetContent>
    </Sheet>
  );
}

// =============================================================================
// Schedules
// =============================================================================

function ScheduleRow({
  schedule,
  target,
  appName,
  onCadence,
  onRemove,
  onRunNow,
  onConfigure,
  onEditWindow,
}: {
  schedule: ScanSchedule;
  target?: Target;
  /** When the schedule is application-scoped (no target_id), the app's name. */
  appName?: string;
  onCadence: (cadence: string) => void;
  onRemove: () => void;
  onRunNow: () => void;
  onConfigure: () => void;
  onEditWindow: () => void;
}) {
  const tid = schedule.target_id ?? undefined;
  const isApp = !tid; // application-scoped schedule (fan-out)
  const { data: scans, isLoading } = useQuery({
    queryKey: ['scans', tid, 12],
    queryFn: () => api.scans.list({ target_id: tid, limit: 12 }),
    enabled: !!tid,
  });
  const { data: diff } = useQuery<ScanDiff>({
    queryKey: ['scan-diff', tid],
    queryFn: () => api.scans.diff({ target_id: tid ?? '' }),
    enabled: !!tid,
  });

  const latest: Scan | undefined = scans?.[0];
  const trend = (scans ?? []).map((s) => s.total_count).reverse();
  const critHigh = latest ? latest.critical_count + latest.high_count : 0;
  const newCount = diff?.new.length ?? 0;
  const fixedCount = diff?.fixed.length ?? 0;
  const label = target?.canonical_value ?? appName ?? schedule.target_id ?? 'Application scan';
  const detailHref = tid ? `/scheduled/detail?id=${tid}` : '/scheduled/applications';

  return (
    <TableRow className="hover:bg-white/[0.02] transition-colors">
      <TableCell>
        <Link href={detailHref} className="flex items-center gap-2.5 group">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-primary/8 shrink-0">
            <TargetTypeIcon targetType={isApp ? 'application' : target?.target_type ?? 'host'} className="h-4 w-4 text-primary/80" />
          </div>
          <div className="min-w-0">
            <p className="text-sm font-medium truncate group-hover:text-primary transition-colors max-w-[260px]">
              {label}
            </p>
            <p className="text-[10px] text-muted-foreground capitalize">
              {isApp ? 'application · fan-out' : (target?.target_type ?? 'host').replace('_', ' ')}
              {schedule.auth_mode === 'unauthed' ? ' · unauthed' : ''}
            </p>
          </div>
        </Link>
      </TableCell>
      <TableCell>
        <Select value={schedule.cadence} onValueChange={onCadence}>
          <SelectTrigger className="h-7 w-[108px] text-xs">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {CADENCES.map((c) => (
              <SelectItem key={c} value={c} className="text-xs">
                {cadenceLabel(c)}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </TableCell>
      <TableCell className="text-xs text-muted-foreground tabular-nums">
        {isLoading ? <Skeleton className="h-4 w-16" /> : relativeTime(latest?.finished_at ?? latest?.started_at)}
      </TableCell>
      <TableCell className="text-xs text-muted-foreground tabular-nums">{relativeTime(schedule.next_run_at)}</TableCell>
      <TableCell className="w-[120px]">
        {trend.length >= 2 ? (
          <Sparkline data={trend} width={100} height={22} className="w-[100px] h-[22px]" />
        ) : (
          <span className="text-xs text-muted-foreground/60">—</span>
        )}
      </TableCell>
      <TableCell>
        {latest ? (
          <span className={cn('text-sm font-semibold tabular-nums', critHigh > 0 ? 'text-orange-400' : 'text-muted-foreground/60')}>
            {critHigh}
          </span>
        ) : (
          <span className="text-xs text-muted-foreground/60">—</span>
        )}
      </TableCell>
      <TableCell>
        <div className="flex items-center gap-2 text-xs">
          {newCount > 0 && (
            <span className="flex items-center gap-0.5 text-red-400" title={`${newCount} new`}>
              <TrendingUp className="h-3 w-3" />+{newCount}
            </span>
          )}
          {fixedCount > 0 && (
            <span className="flex items-center gap-0.5 text-emerald-400" title={`${fixedCount} fixed`}>
              <TrendingDown className="h-3 w-3" />-{fixedCount}
            </span>
          )}
          {newCount === 0 && fixedCount === 0 && (
            <span className="flex items-center text-muted-foreground/60">
              <Minus className="h-3 w-3" />
            </span>
          )}
        </div>
      </TableCell>
      <TableCell>
        <div className="flex items-center justify-end gap-1">
          <Button variant="ghost" size="sm" className="h-7 px-2 text-muted-foreground hover:text-primary" onClick={onRunNow} title="Run a DAST scan now">
            <Play className="h-3.5 w-3.5" />
          </Button>
          <Button
            variant="ghost"
            size="sm"
            className={cn('h-7 px-2 hover:text-primary', schedule.window_start ? 'text-primary' : 'text-muted-foreground')}
            onClick={onEditWindow}
            title={schedule.window_start ? `Blackout window ${String(schedule.window_start).slice(0, 5)}–${String(schedule.window_end).slice(0, 5)}` : 'Set blackout window'}
          >
            <Clock className="h-3.5 w-3.5" />
          </Button>
          <Button variant="ghost" size="sm" className="h-7 px-2 text-muted-foreground hover:text-primary" onClick={onConfigure} title="Configure auth + scope">
            <Settings2 className="h-3.5 w-3.5" />
          </Button>
          <Button variant="ghost" size="sm" className="h-7 px-2 text-muted-foreground hover:text-red-400" onClick={onRemove} title="Unschedule">
            <Trash2 className="h-3.5 w-3.5" />
          </Button>
        </div>
      </TableCell>
    </TableRow>
  );
}

export function SchedulesTab({
  schedules,
  isLoading,
  targetById,
  onUpsert,
  onRemove,
  onRunNow,
  onAdd,
  onConfigure,
}: {
  schedules: ScanSchedule[] | undefined;
  isLoading: boolean;
  targetById: Map<string, Target>;
  // Schedule-aware (a schedule may be target- or application-scoped).
  onUpsert: (schedule: ScanSchedule, cadence: string) => void;
  onRemove: (id: string) => void;
  onRunNow: (schedule: ScanSchedule) => void;
  onAdd: () => void;
  onConfigure: (schedule: ScanSchedule) => void;
}) {
  const [search, setSearch] = useState('');
  const [cadenceFilter, setCadenceFilter] = useState('all');
  const [windowSched, setWindowSched] = useState<ScanSchedule | null>(null);
  const { data: applications } = useQuery({
    queryKey: ['applications'],
    queryFn: () => api.applications.list(),
  });
  const appById = useMemo(
    () => new Map((applications ?? []).map((a) => [a.id, a.name])),
    [applications],
  );
  const labelFor = (s: ScanSchedule): string =>
    (s.target_id ? targetById.get(s.target_id)?.canonical_value : undefined) ??
    (s.application_id ? appById.get(s.application_id) : undefined) ??
    s.target_id ??
    'Application scan';

  const filtered = useMemo(() => {
    return (schedules ?? []).filter((s) => {
      if (cadenceFilter !== 'all' && s.cadence !== cadenceFilter) return false;
      if (search && !labelFor(s).toLowerCase().includes(search.toLowerCase())) return false;
      return true;
    });
    // labelFor depends on targetById/appById; included transitively.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [schedules, cadenceFilter, search, targetById, appById]);

  if (isLoading) {
    return (
      <div className="p-4 space-y-3">
        {Array.from({ length: 3 }).map((_, i) => (
          <Skeleton key={i} className="h-12 w-full" />
        ))}
      </div>
    );
  }

  if ((schedules?.length ?? 0) === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-16 text-center">
        <div className="mb-3 rounded-xl bg-muted/50 p-3">
          <CalendarClock className="h-7 w-7 text-muted-foreground/50" />
        </div>
        <p className="text-sm font-medium text-muted-foreground">Nothing scheduled yet</p>
        <p className="mt-1 text-xs text-muted-foreground/70 max-w-md">
          Schedule a target to run cheap, deterministic DAST on a recurring cadence. Findings trend
          over time; prove any one on-demand.
        </p>
        <Button className="mt-4" onClick={onAdd}>
          <Plus className="mr-1.5 h-4 w-4" /> Schedule your first target
        </Button>
      </div>
    );
  }

  return (
    <div>
      <div className="flex items-center gap-2 flex-wrap p-3 border-b border-border/40">
        <div className="relative">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
          <Input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Filter targets…" className="h-8 w-[240px] pl-8 text-sm" />
        </div>
        <Select value={cadenceFilter} onValueChange={setCadenceFilter}>
          <SelectTrigger className="h-8 w-[140px] text-sm">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All cadences</SelectItem>
            {CADENCES.map((c) => (
              <SelectItem key={c} value={c}>
                {cadenceLabel(c)}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <span className="text-xs text-muted-foreground ml-auto">
          {filtered.length} of {schedules?.length ?? 0} scheduled
        </span>
      </div>

      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Target</TableHead>
            <TableHead className="w-[120px]">Cadence</TableHead>
            <TableHead className="w-[100px]">Last run</TableHead>
            <TableHead className="w-[100px]">Next run</TableHead>
            <TableHead className="w-[120px]">Trend</TableHead>
            <TableHead className="w-[90px]">Crit/high</TableHead>
            <TableHead className="w-[110px]">Δ since last</TableHead>
            <TableHead className="w-[90px] text-right">Actions</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {filtered.map((s) => (
            <ScheduleRow
              key={s.id}
              schedule={s}
              target={s.target_id ? targetById.get(s.target_id) : undefined}
              appName={s.application_id ? appById.get(s.application_id) : undefined}
              onCadence={(cadence) => onUpsert(s, cadence)}
              onRemove={() => onRemove(s.id)}
              onRunNow={() => onRunNow(s)}
              onConfigure={() => onConfigure(s)}
              onEditWindow={() => setWindowSched(s)}
            />
          ))}
        </TableBody>
      </Table>

      <ScheduleWindowDialog
        schedule={windowSched}
        open={!!windowSched}
        onOpenChange={(v) => { if (!v) setWindowSched(null); }}
      />
    </div>
  );
}

// Blackout-window editor for a schedule (WS4). Saves window_start/end + timezone
// via the schedule upsert; the due-query + external runner both honor it.
function ScheduleWindowDialog({
  schedule,
  open,
  onOpenChange,
}: {
  schedule: ScanSchedule | null;
  open: boolean;
  onOpenChange: (v: boolean) => void;
}) {
  const queryClient = useQueryClient();
  const [start, setStart] = useState('');
  const [end, setEnd] = useState('');
  const [tz, setTz] = useState('');
  const [hydratedFor, setHydratedFor] = useState<string | null | undefined>(undefined);
  if (open && schedule && hydratedFor !== schedule.id) {
    setStart((schedule.window_start ?? '').slice(0, 5));
    setEnd((schedule.window_end ?? '').slice(0, 5));
    setTz(schedule.timezone ?? Intl.DateTimeFormat().resolvedOptions().timeZone);
    setHydratedFor(schedule.id);
  }
  if (!open && hydratedFor !== undefined) setHydratedFor(undefined);

  const save = useMutation({
    mutationFn: () =>
      api.scanSchedules.upsert({
        // Target- or application-scoped (exactly one), matching the schedule.
        ...(schedule!.application_id
          ? { application_id: schedule!.application_id }
          : { target_id: schedule!.target_id ?? undefined }),
        auth_mode: schedule!.auth_mode,
        cadence: schedule!.cadence,
        window_start: start || undefined,
        window_end: end || undefined,
        timezone: tz || undefined,
      }),
    onSuccess: () => {
      toast.success('Blackout window saved.');
      queryClient.invalidateQueries({ queryKey: ['scan-schedules'] });
      onOpenChange(false);
    },
    onError: (e) => toast.error(`Couldn't save window: ${e instanceof Error ? e.message : String(e)}`),
  });

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-[420px]">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Clock className="h-4 w-4 text-primary/70" /> Blackout window
          </DialogTitle>
          <DialogDescription>
            Only run between these local times. Leave blank to run anytime.
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-3 py-2">
          <div className="grid grid-cols-2 gap-2">
            <div className="space-y-1.5">
              <label className="text-xs font-medium text-muted-foreground">From</label>
              <Input type="time" value={start} onChange={(e) => setStart(e.target.value)} className="h-8 text-sm" />
            </div>
            <div className="space-y-1.5">
              <label className="text-xs font-medium text-muted-foreground">To</label>
              <Input type="time" value={end} onChange={(e) => setEnd(e.target.value)} className="h-8 text-sm" />
            </div>
          </div>
          <div className="space-y-1.5">
            <label className="text-xs font-medium text-muted-foreground">Timezone (IANA)</label>
            <Input value={tz} onChange={(e) => setTz(e.target.value)} placeholder="America/New_York" className="h-8 text-sm font-mono" />
          </div>
        </div>
        <DialogFooter>
          <Button variant="ghost" onClick={() => onOpenChange(false)}>Cancel</Button>
          <Button disabled={save.isPending} onClick={() => save.mutate()}>
            {save.isPending ? 'Saving…' : 'Save window'}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// =============================================================================
// Targets — per-target DAST posture (all DAST-eligible targets, scheduled or not)
// =============================================================================

function TargetRow({
  target,
  scheduled,
  apps,
  onAssign,
  onRunNow,
  onConfigure,
}: {
  target: Target;
  scheduled: boolean;
  apps: Application[];
  onAssign: (targetId: string, applicationId: string) => void;
  onRunNow: () => void;
  onConfigure: () => void;
}) {
  const { data: scans, isLoading } = useQuery({
    queryKey: ['scans', target.id, 12],
    queryFn: () => api.scans.list({ target_id: target.id, limit: 12 }),
  });
  const latest = scans?.[0];
  const trend = (scans ?? []).map((s) => s.total_count).reverse();
  const critHigh = latest ? latest.critical_count + latest.high_count : 0;

  return (
    <TableRow className="hover:bg-white/[0.02] transition-colors">
      <TableCell>
        <Link href={`/scheduled/detail?id=${target.id}`} className="flex items-center gap-2.5 group">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-primary/8 shrink-0">
            <TargetTypeIcon targetType={target.target_type} className="h-4 w-4 text-primary/80" />
          </div>
          <div className="min-w-0">
            <p className="text-sm font-medium truncate group-hover:text-primary transition-colors max-w-[280px]">
              {target.canonical_value}
            </p>
            <p className="text-[10px] text-muted-foreground capitalize">{target.target_type.replace('_', ' ')}</p>
          </div>
        </Link>
      </TableCell>
      <TableCell>
        <Select
          value={target.application_id ?? 'none'}
          onValueChange={(v) => onAssign(target.id, v === 'none' ? '' : v)}
        >
          <SelectTrigger className="h-7 w-[150px] text-xs"><SelectValue placeholder="Unassigned" /></SelectTrigger>
          <SelectContent>
            <SelectItem value="none">Unassigned</SelectItem>
            {apps.map((a) => (
              <SelectItem key={a.id} value={a.id}>{a.name}</SelectItem>
            ))}
          </SelectContent>
        </Select>
      </TableCell>
      <TableCell>
        {scheduled ? (
          <Badge variant="outline" className="text-[10px] border-0 bg-primary/10 text-primary">scheduled</Badge>
        ) : (
          <span className="text-xs text-muted-foreground/60">on-demand</span>
        )}
      </TableCell>
      <TableCell className="text-xs text-muted-foreground tabular-nums">
        {isLoading ? <Skeleton className="h-4 w-16" /> : relativeTime(latest?.finished_at ?? latest?.started_at)}
      </TableCell>
      <TableCell className="w-[120px]">
        {trend.length >= 2 ? (
          <Sparkline data={trend} width={100} height={22} className="w-[100px] h-[22px]" />
        ) : (
          <span className="text-xs text-muted-foreground/60">—</span>
        )}
      </TableCell>
      <TableCell>
        {latest ? (
          <span className={cn('text-sm font-semibold tabular-nums', critHigh > 0 ? 'text-orange-400' : 'text-muted-foreground/60')}>
            {critHigh}
          </span>
        ) : (
          <span className="text-xs text-muted-foreground/60">—</span>
        )}
      </TableCell>
      <TableCell>
        <div className="flex items-center justify-end gap-1">
          <Button variant="ghost" size="sm" className="h-7 px-2 text-muted-foreground hover:text-primary" onClick={onRunNow} title="Run a DAST scan now">
            <Play className="h-3.5 w-3.5" />
          </Button>
          <Button variant="ghost" size="sm" className="h-7 px-2 text-muted-foreground hover:text-primary" onClick={onConfigure} title="Configure auth + scope">
            <Settings2 className="h-3.5 w-3.5" />
          </Button>
        </div>
      </TableCell>
    </TableRow>
  );
}

export function TargetsTab({
  targets,
  scheduledIds,
  onRunNow,
  onConfigure,
  onAdd,
}: {
  targets: Target[];
  scheduledIds: Set<string>;
  onRunNow: (target_id: string) => void;
  onConfigure: (target_id: string) => void;
  onAdd: () => void;
}) {
  const queryClient = useQueryClient();
  const [search, setSearch] = useState('');
  const { data: apps } = useQuery({
    queryKey: ['applications'],
    queryFn: () => api.applications.list(),
  });
  const assign = useMutation({
    mutationFn: ({ targetId, applicationId }: { targetId: string; applicationId: string }) =>
      api.targets.update(targetId, { application_id: applicationId }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['targets'] });
      queryClient.invalidateQueries({ queryKey: ['applications'] });
    },
    onError: (e) => toast.error(`Couldn't assign application: ${e instanceof Error ? e.message : String(e)}`),
  });
  const dastTargets = useMemo(
    () => targets.filter((t) => DAST_TARGET_TYPES.has(t.target_type)),
    [targets],
  );
  const filtered = useMemo(
    () => dastTargets.filter((t) => !search || t.canonical_value.toLowerCase().includes(search.toLowerCase())),
    [dastTargets, search],
  );

  if (dastTargets.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-16 text-center">
        <div className="mb-3 rounded-xl bg-muted/50 p-3">
          <Globe className="h-7 w-7 text-muted-foreground/50" />
        </div>
        <p className="text-sm font-medium text-muted-foreground">No DAST-eligible targets</p>
        <p className="mt-1 text-xs text-muted-foreground/70 max-w-md">
          DAST runs against reachable web / host targets. Add one in Config → Scope, then schedule
          or scan it here.
        </p>
        <Button className="mt-4" onClick={onAdd}>
          <CalendarClock className="mr-1.5 h-4 w-4" /> Schedule a target
        </Button>
      </div>
    );
  }

  return (
    <div>
      <div className="flex items-center gap-2 flex-wrap p-3 border-b border-border/40">
        <div className="relative">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
          <Input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Filter targets…" className="h-8 w-[240px] pl-8 text-sm" />
        </div>
        <span className="text-xs text-muted-foreground ml-auto">
          {filtered.length} of {dastTargets.length} targets
        </span>
      </div>
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Target</TableHead>
            <TableHead className="w-[160px]">Application</TableHead>
            <TableHead className="w-[110px]">Status</TableHead>
            <TableHead className="w-[100px]">Last run</TableHead>
            <TableHead className="w-[120px]">Trend</TableHead>
            <TableHead className="w-[90px]">Crit/high</TableHead>
            <TableHead className="w-[90px] text-right">Actions</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {filtered.map((t) => (
            <TargetRow
              key={t.id}
              target={t}
              scheduled={scheduledIds.has(t.id)}
              apps={apps ?? []}
              onAssign={(targetId, applicationId) => assign.mutate({ targetId, applicationId })}
              onRunNow={() => onRunNow(t.id)}
              onConfigure={() => onConfigure(t.id)}
            />
          ))}
        </TableBody>
      </Table>
    </div>
  );
}

// =============================================================================
// Per-scan run detail — a Sheet showing every finding that run produced.
// =============================================================================

function RunFindingRow({ f }: { f: ScanFindingDetail }) {
  const [open, setOpen] = useState(false);
  const sev = severityStyle(f.severity);
  const hasDetail = Boolean(f.description?.trim() || f.evidence?.trim());

  return (
    <div className="rounded-lg border border-border/40 bg-white/[0.01]">
      <button
        type="button"
        onClick={() => hasDetail && setOpen((v) => !v)}
        className={cn(
          'flex w-full items-start gap-2.5 p-3 text-left',
          hasDetail && 'hover:bg-white/[0.02] transition-colors',
        )}
      >
        {hasDetail ? (
          open ? (
            <ChevronDown className="mt-0.5 h-3.5 w-3.5 shrink-0 text-muted-foreground" />
          ) : (
            <ChevronRight className="mt-0.5 h-3.5 w-3.5 shrink-0 text-muted-foreground" />
          )
        ) : (
          <span className="mt-0.5 h-3.5 w-3.5 shrink-0" />
        )}
        <span
          className={cn('text-[10px] font-semibold uppercase px-1.5 py-0.5 rounded shrink-0', sev.badge)}
        >
          {sev.label}
        </span>
        <div className="min-w-0 flex-1">
          <p className="text-sm font-medium leading-snug">{f.title}</p>
          <div className="mt-0.5 flex items-center gap-2 text-[11px] text-muted-foreground">
            {f.cve && <span className="font-mono">{f.cve}</span>}
            <span className="capitalize">{f.status.replace('_', ' ')}</span>
          </div>
        </div>
      </button>
      {open && hasDetail && (
        <div className="space-y-3 border-t border-border/40 px-3 py-3">
          {f.description?.trim() && (
            <div>
              <p className="mb-1 text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">
                Description
              </p>
              <p className="whitespace-pre-wrap text-xs text-muted-foreground/90">{f.description}</p>
            </div>
          )}
          {f.evidence?.trim() && (
            <div>
              <p className="mb-1 text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">
                Evidence
              </p>
              <pre className="max-h-[320px] overflow-auto rounded-md bg-black/40 p-2.5 font-mono text-[11px] leading-relaxed text-muted-foreground/90">
                {f.evidence}
              </pre>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export function ScanRunSheet({
  scan,
  targetLabel,
  open,
  onOpenChange,
}: {
  scan: Scan | null;
  targetLabel: string;
  open: boolean;
  onOpenChange: (v: boolean) => void;
}) {
  const { data: findings, isLoading } = useQuery({
    queryKey: ['scan-findings', scan?.id],
    queryFn: () => api.scans.findings(scan!.id),
    enabled: open && !!scan,
  });

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent className="w-full sm:max-w-[760px] overflow-y-auto">
        <SheetHeader>
          <SheetTitle className="flex items-center gap-2 truncate">
            <History className="h-4 w-4 text-primary/70 shrink-0" />
            <span className="truncate">{targetLabel}</span>
          </SheetTitle>
          <SheetDescription>
            Run started {scan ? absTime(scan.started_at) : '—'}
            {scan?.finished_at ? ` · ${duration(scan.started_at, scan.finished_at)}` : ''}
          </SheetDescription>
        </SheetHeader>

        {/* Statistics — attacks executed, per-tool breakdown, severity, metrics */}
        {scan && scan.status !== 'running' && (
          <div className="mt-4">
            <ScanStats scan={scan} />
          </div>
        )}

        <div className="mt-5 mb-2 flex items-center gap-2">
          <ShieldAlert className="h-4 w-4 text-muted-foreground" />
          <h3 className="text-sm font-semibold">Findings</h3>
          {!isLoading && (findings?.length ?? 0) > 0 && (
            <span className="rounded-md bg-muted/50 px-1.5 py-0.5 text-[10px] text-muted-foreground">
              {findings?.length}
            </span>
          )}
        </div>

        <div className="mt-1 space-y-2">
          {isLoading ? (
            Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-14 w-full" />)
          ) : (findings?.length ?? 0) === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 text-center">
              <div className="mb-3 rounded-xl bg-muted/50 p-3">
                <ShieldAlert className="h-7 w-7 text-muted-foreground/50" />
              </div>
              <p className="text-sm font-medium text-muted-foreground">No findings in this run</p>
              <p className="mt-1 text-xs text-muted-foreground/70 max-w-xs">
                This scan completed without confirming any findings.
              </p>
            </div>
          ) : (
            (findings ?? []).map((f) => <RunFindingRow key={f.id} f={f} />)
          )}
        </div>
      </SheetContent>
    </Sheet>
  );
}

// =============================================================================
// Per-target scan config — auth + scope for the deterministic DAST run.
// =============================================================================

const AUTH_TYPES: { value: ScanAuth['type']; label: string }[] = [
  { value: 'none', label: 'None' },
  { value: 'header', label: 'Header' },
  { value: 'basic', label: 'Basic' },
  { value: 'bearer', label: 'Bearer' },
  { value: 'form', label: 'Form login' },
];

function linesToArray(s: string): string[] {
  return s
    .split('\n')
    .map((l) => l.trim())
    .filter(Boolean);
}

export function ScanConfigDialog({
  targetId,
  targetLabel,
  open,
  onOpenChange,
}: {
  targetId: string | null;
  targetLabel: string;
  open: boolean;
  onOpenChange: (v: boolean) => void;
}) {
  const queryClient = useQueryClient();
  const { data: config, isLoading } = useQuery({
    queryKey: ['scan-config', targetId],
    queryFn: () => api.scanConfigs.get({ target_id: targetId! }),
    enabled: open && !!targetId,
  });

  // Local editable state, hydrated from the loaded config.
  const [authType, setAuthType] = useState<ScanAuth['type']>('none');
  const [headerRows, setHeaderRows] = useState<{ key: string; value: string }[]>([{ key: '', value: '' }]);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [token, setToken] = useState('');
  const [loginUrl, setLoginUrl] = useState('');
  const [usernameField, setUsernameField] = useState('');
  const [passwordField, setPasswordField] = useState('');
  const [include, setInclude] = useState('');
  const [exclude, setExclude] = useState('');
  const [openapiUrl, setOpenapiUrl] = useState('');
  // WS7 session keep-alive / recorded login (runner-enforced).
  const [keepAliveUrl, setKeepAliveUrl] = useState('');
  const [sessionCheck, setSessionCheck] = useState('');
  const [loginSequence, setLoginSequence] = useState('');

  // Hydrate the form whenever a fresh config loads for this target.
  const [hydratedFor, setHydratedFor] = useState<string | null>(null);
  if (open && config && hydratedFor !== targetId) {
    const a = (config.auth ?? {}) as ScanAuth;
    const s = (config.scope ?? {}) as ScanScope;
    setAuthType(a.type ?? 'none');
    const hdrs = a.headers ?? {};
    const rows = Object.entries(hdrs).map(([key, value]) => ({ key, value: String(value) }));
    setHeaderRows(rows.length ? rows : [{ key: '', value: '' }]);
    setUsername(a.username ?? '');
    setPassword(a.password ?? '');
    setToken(a.token ?? '');
    setLoginUrl(a.login_url ?? '');
    setUsernameField(a.username_field ?? '');
    setPasswordField(a.password_field ?? '');
    setKeepAliveUrl(a.keep_alive_url ?? '');
    setSessionCheck(a.session_check ?? '');
    setLoginSequence(a.login_sequence ?? '');
    setInclude((s.include ?? []).join('\n'));
    setExclude((s.exclude ?? []).join('\n'));
    setOpenapiUrl(s.openapi_url ?? '');
    setHydratedFor(targetId);
  }
  // Reset the hydration guard when the dialog closes so it re-hydrates next open.
  if (!open && hydratedFor !== null) {
    setHydratedFor(null);
  }

  const save = useMutation({
    mutationFn: () => {
      const auth: ScanAuth = { type: authType };
      if (authType === 'header') {
        const headers: Record<string, string> = {};
        for (const r of headerRows) {
          if (r.key.trim()) headers[r.key.trim()] = r.value;
        }
        auth.headers = headers;
      } else if (authType === 'basic') {
        auth.username = username;
        auth.password = password;
      } else if (authType === 'bearer') {
        auth.token = token;
      } else if (authType === 'form') {
        auth.login_url = loginUrl;
        auth.username = username;
        auth.password = password;
        auth.username_field = usernameField;
        auth.password_field = passwordField;
      }
      // Session keep-alive / recorded login (WS7) apply to authed scans.
      if (authType !== 'none') {
        if (keepAliveUrl.trim()) auth.keep_alive_url = keepAliveUrl.trim();
        if (sessionCheck.trim()) auth.session_check = sessionCheck.trim();
        if (loginSequence.trim()) auth.login_sequence = loginSequence.trim();
      }
      const scope: ScanScope = {
        include: linesToArray(include),
        exclude: linesToArray(exclude),
        ...(openapiUrl.trim() ? { openapi_url: openapiUrl.trim() } : {}),
      };
      return api.scanConfigs.upsert({ target_id: targetId!, auth, scope });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scan-config', targetId] });
      toast.success('Scan config saved.');
      onOpenChange(false);
    },
    onError: (e) => toast.error(`Couldn't save config: ${e instanceof Error ? e.message : String(e)}`),
  });

  function setHeaderRow(i: number, patch: Partial<{ key: string; value: string }>) {
    setHeaderRows((rows) => rows.map((r, idx) => (idx === i ? { ...r, ...patch } : r)));
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-[560px] max-h-[85vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Settings2 className="h-4 w-4 text-primary/70" /> Scan config
          </DialogTitle>
          <DialogDescription className="truncate">
            Auth + scope for the DAST run on <span className="font-medium">{targetLabel}</span>.
          </DialogDescription>
        </DialogHeader>

        {isLoading ? (
          <div className="space-y-3 py-2">
            {Array.from({ length: 4 }).map((_, i) => (
              <Skeleton key={i} className="h-9 w-full" />
            ))}
          </div>
        ) : (
          <div className="space-y-5 py-2">
            {/* Auth */}
            <div className="space-y-3">
              <div className="space-y-1.5">
                <label className="text-xs font-medium text-muted-foreground">Authentication</label>
                <Select value={authType} onValueChange={(v) => setAuthType(v as ScanAuth['type'])}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {AUTH_TYPES.map((t) => (
                      <SelectItem key={t.value} value={t.value}>
                        {t.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>

              {authType === 'header' && (
                <div className="space-y-2">
                  <label className="text-xs font-medium text-muted-foreground">Request headers</label>
                  {headerRows.map((r, i) => (
                    <div key={i} className="flex items-center gap-2">
                      <Input
                        value={r.key}
                        onChange={(e) => setHeaderRow(i, { key: e.target.value })}
                        placeholder="Header name"
                        className="h-8 text-sm"
                      />
                      <Input
                        value={r.value}
                        onChange={(e) => setHeaderRow(i, { value: e.target.value })}
                        placeholder="Value"
                        className="h-8 text-sm"
                      />
                      <Button
                        variant="ghost"
                        size="sm"
                        className="h-8 w-8 p-0 text-muted-foreground hover:text-red-400 shrink-0"
                        onClick={() =>
                          setHeaderRows((rows) =>
                            rows.length > 1 ? rows.filter((_, idx) => idx !== i) : rows,
                          )
                        }
                        title="Remove header"
                      >
                        <X className="h-3.5 w-3.5" />
                      </Button>
                    </div>
                  ))}
                  <Button
                    variant="ghost"
                    size="sm"
                    className="h-7 text-xs text-muted-foreground"
                    onClick={() => setHeaderRows((rows) => [...rows, { key: '', value: '' }])}
                  >
                    <Plus className="mr-1 h-3 w-3" /> Add header
                  </Button>
                </div>
              )}

              {authType === 'basic' && (
                <div className="grid grid-cols-2 gap-2">
                  <div className="space-y-1.5">
                    <label className="text-xs font-medium text-muted-foreground">Username</label>
                    <Input value={username} onChange={(e) => setUsername(e.target.value)} className="h-8 text-sm" />
                  </div>
                  <div className="space-y-1.5">
                    <label className="text-xs font-medium text-muted-foreground">Password</label>
                    <Input value={password} onChange={(e) => setPassword(e.target.value)} className="h-8 text-sm" />
                  </div>
                </div>
              )}

              {authType === 'bearer' && (
                <div className="space-y-1.5">
                  <label className="text-xs font-medium text-muted-foreground">Token</label>
                  <Input
                    value={token}
                    onChange={(e) => setToken(e.target.value)}
                    placeholder="Bearer token"
                    className="h-8 text-sm font-mono"
                  />
                </div>
              )}

              {authType === 'form' && (
                <div className="space-y-2">
                  <div className="space-y-1.5">
                    <label className="text-xs font-medium text-muted-foreground">Login URL</label>
                    <Input
                      value={loginUrl}
                      onChange={(e) => setLoginUrl(e.target.value)}
                      placeholder="https://app.example.com/login"
                      className="h-8 text-sm"
                    />
                  </div>
                  <div className="grid grid-cols-2 gap-2">
                    <div className="space-y-1.5">
                      <label className="text-xs font-medium text-muted-foreground">Username</label>
                      <Input value={username} onChange={(e) => setUsername(e.target.value)} className="h-8 text-sm" />
                    </div>
                    <div className="space-y-1.5">
                      <label className="text-xs font-medium text-muted-foreground">Password</label>
                      <Input value={password} onChange={(e) => setPassword(e.target.value)} className="h-8 text-sm" />
                    </div>
                    <div className="space-y-1.5">
                      <label className="text-xs font-medium text-muted-foreground">Username field</label>
                      <Input
                        value={usernameField}
                        onChange={(e) => setUsernameField(e.target.value)}
                        placeholder="email"
                        className="h-8 text-sm"
                      />
                    </div>
                    <div className="space-y-1.5">
                      <label className="text-xs font-medium text-muted-foreground">Password field</label>
                      <Input
                        value={passwordField}
                        onChange={(e) => setPasswordField(e.target.value)}
                        placeholder="password"
                        className="h-8 text-sm"
                      />
                    </div>
                  </div>
                </div>
              )}

              {/* Session keep-alive / recorded login (WS7) — runner-enforced. */}
              {authType !== 'none' && (
                <div className="space-y-2 rounded-md border border-dashed border-border/50 p-2.5">
                  <p className="text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">
                    Session keep-alive (runner-enforced)
                  </p>
                  <div className="grid grid-cols-2 gap-2">
                    <div className="space-y-1.5">
                      <label className="text-xs text-muted-foreground/80">Keep-alive URL</label>
                      <Input value={keepAliveUrl} onChange={(e) => setKeepAliveUrl(e.target.value)} placeholder="/api/me" className="h-8 text-sm" />
                    </div>
                    <div className="space-y-1.5">
                      <label className="text-xs text-muted-foreground/80">Logged-in indicator</label>
                      <Input value={sessionCheck} onChange={(e) => setSessionCheck(e.target.value)} placeholder='"email":' className="h-8 text-sm" />
                    </div>
                  </div>
                  <div className="space-y-1.5">
                    <label className="text-xs text-muted-foreground/80">Recorded login steps (JSON, optional)</label>
                    <Textarea value={loginSequence} onChange={(e) => setLoginSequence(e.target.value)} placeholder='[{"click":"#login"},{"fill":["#user","alice"]}]' className="min-h-[52px] text-xs font-mono" />
                  </div>
                  <p className="text-[10px] text-muted-foreground/60">
                    Stored now; executed by the in-container runner (enforcement pending).
                  </p>
                </div>
              )}
            </div>

            {/* Scope */}
            <div className="space-y-3 border-t border-border/40 pt-4">
              <p className="text-xs font-medium text-muted-foreground">Scope (one glob per line)</p>
              <div className="space-y-1.5">
                <label className="text-xs text-muted-foreground/80">OpenAPI / Swagger URL</label>
                <Input
                  value={openapiUrl}
                  onChange={(e) => setOpenapiUrl(e.target.value)}
                  placeholder="https://app.example.com/openapi.json"
                  className="h-8 text-sm font-mono"
                />
              </div>
              <div className="space-y-1.5">
                <label className="text-xs text-muted-foreground/80">Include patterns</label>
                <Textarea
                  value={include}
                  onChange={(e) => setInclude(e.target.value)}
                  placeholder={'https://app.example.com/*\n/api/*'}
                  className="min-h-[72px] text-sm font-mono"
                />
              </div>
              <div className="space-y-1.5">
                <label className="text-xs text-muted-foreground/80">Exclude patterns</label>
                <Textarea
                  value={exclude}
                  onChange={(e) => setExclude(e.target.value)}
                  placeholder={'*/logout\n*/admin/delete*'}
                  className="min-h-[72px] text-sm font-mono"
                />
              </div>
            </div>
          </div>
        )}

        <DialogFooter>
          <Button variant="ghost" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button disabled={!targetId || isLoading || save.isPending} onClick={() => save.mutate()}>
            {save.isPending ? 'Saving…' : 'Save config'}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// =============================================================================
// Pick-a-target dialog (schedule / run now)
// =============================================================================

/** Create a brand-new DAST target (web URL or host). Tagged source='dast' by the
 *  caller so it stays on the Scheduled DAST Targets page. */
export function NewTargetDialog({
  open,
  onOpenChange,
  onConfirm,
  busy,
}: {
  open: boolean;
  onOpenChange: (v: boolean) => void;
  onConfirm: (rawValue: string, targetType: string) => void;
  busy: boolean;
}) {
  const [value, setValue] = useState('');
  const [type, setType] = useState('web');
  const submit = () => {
    const v = value.trim();
    if (v) onConfirm(v, type);
  };
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-[480px]">
        <DialogHeader>
          <DialogTitle>New target</DialogTitle>
          <DialogDescription>
            Add a web URL or host to scan. Targets you create here are managed on this page —
            separate from the AI-assessment scope.
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-4 py-2">
          <div className="space-y-1.5">
            <label className="text-xs font-medium text-muted-foreground">Target</label>
            <Input
              value={value}
              onChange={(e) => setValue(e.target.value)}
              placeholder="https://api.example.com  or  host.example.com"
              onKeyDown={(e) => {
                if (e.key === 'Enter') submit();
              }}
              autoFocus
            />
          </div>
          <div className="space-y-1.5">
            <label className="text-xs font-medium text-muted-foreground">Type</label>
            <Select value={type} onValueChange={setType}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="web">Web (URL)</SelectItem>
                <SelectItem value="host">Host</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </div>
        <DialogFooter>
          <Button variant="ghost" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button disabled={!value.trim() || busy} onClick={submit}>
            {busy ? 'Adding…' : 'Add target'}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export function PickTargetDialog({
  open,
  onOpenChange,
  title,
  description,
  cta,
  options,
  withCadence,
  withAuthMode,
  policies,
  onConfirm,
  busy,
}: {
  open: boolean;
  onOpenChange: (v: boolean) => void;
  title: string;
  description: string;
  cta: string;
  /** value may encode an app ("app:<id>") or a target ("target:<id>"); hint marks the kind. */
  options: { value: string; label: string; hint?: string }[];
  withCadence: boolean;
  /** Show an Authenticated / Unauthenticated toggle (DAST auth_mode). */
  withAuthMode?: boolean;
  /** When provided, shows a scan-policy picker; '' = full assessment. */
  policies?: { value: string; label: string }[];
  onConfirm: (selection: string, cadence: string, policyId: string, authMode: string) => void;
  busy: boolean;
}) {
  const [targetId, setTargetId] = useState('');
  const [cadence, setCadence] = useState('daily');
  const [policyId, setPolicyId] = useState('');
  const [authMode, setAuthMode] = useState('authed');

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-[480px]">
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          <DialogDescription>{description}</DialogDescription>
        </DialogHeader>
        <div className="space-y-4 py-2">
          <div className="space-y-1.5">
            <label className="text-xs font-medium text-muted-foreground">Application or target</label>
            <SearchableSelect
              options={options}
              value={targetId}
              onChange={setTargetId}
              placeholder={options.length ? 'Select an application or target…' : 'No eligible targets'}
            />
          </div>
          {withAuthMode && (
            <div className="space-y-1.5">
              <label className="text-xs font-medium text-muted-foreground">Authentication</label>
              <div className="flex gap-1 rounded-md border border-border p-0.5">
                {(['authed', 'unauthed'] as const).map((m) => (
                  <button
                    key={m}
                    type="button"
                    onClick={() => setAuthMode(m)}
                    className={cn(
                      'flex-1 rounded px-2 py-1 text-xs transition-colors',
                      authMode === m
                        ? 'bg-primary text-primary-foreground'
                        : 'text-muted-foreground hover:text-foreground',
                    )}
                  >
                    {m === 'authed' ? 'Authenticated' : 'Unauthenticated'}
                  </button>
                ))}
              </div>
              <p className="text-[11px] text-muted-foreground">
                {authMode === 'authed'
                  ? "Uses the target's configured auth — the deeper, logged-in surface."
                  : 'Anonymous — what an unauthenticated attacker sees.'}
              </p>
            </div>
          )}
          {policies && (
            <div className="space-y-1.5">
              <label className="text-xs font-medium text-muted-foreground">Scan policy</label>
              <Select value={policyId || 'all'} onValueChange={(v) => setPolicyId(v === 'all' ? '' : v)}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">Full assessment (all attacks)</SelectItem>
                  {policies.map((p) => (
                    <SelectItem key={p.value} value={p.value}>{p.label}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          )}
          {withCadence && (
            <div className="space-y-1.5">
              <label className="text-xs font-medium text-muted-foreground">Cadence</label>
              <Select value={cadence} onValueChange={setCadence}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {CADENCES.map((c) => (
                    <SelectItem key={c} value={c}>
                      {cadenceLabel(c)}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          )}
        </div>
        <DialogFooter>
          <Button variant="ghost" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button disabled={!targetId || busy} onClick={() => onConfirm(targetId, cadence, policyId, authMode)}>
            {busy ? 'Working…' : cta}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// =============================================================================
// Overview — KPIs + DAST severity distribution (scan_only).
// =============================================================================

function KpiCard({
  label,
  value,
  accent,
  hint,
  href,
}: {
  label: string;
  value: string | number;
  accent?: string;
  hint?: string;
  href?: string;
}) {
  const inner = (
    <div className={cn('rounded-lg bg-white/[0.015] px-4 py-3', href && 'transition-colors hover:bg-white/[0.03]')}>
      <p className="text-[10px] font-medium uppercase tracking-wider text-muted-foreground">{label}</p>
      <p className={cn('mt-1 text-2xl font-bold tabular-nums leading-none', accent ?? 'text-foreground')}>{value}</p>
      {hint && <p className="mt-1 text-[11px] text-muted-foreground/70">{hint}</p>}
    </div>
  );
  return href ? <Link href={href}>{inner}</Link> : inner;
}

export function DastOverview() {
  const { data: scans } = useQuery({
    queryKey: ['scans', 'all'],
    queryFn: () => api.scans.list({ limit: 200 }),
  });
  const { data: schedules } = useQuery({
    queryKey: ['scan-schedules'],
    queryFn: () => api.scanSchedules.list(),
  });
  const { data: vulnsPage } = useQuery({
    queryKey: ['dast-vulns'],
    queryFn: () => api.findings.list({ scan_only: 'true', limit: 300 }),
  });

  const findings = useMemo(() => vulnsPage?.data ?? [], [vulnsPage]);

  const counts = useMemo(() => {
    const c: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const f of findings) {
      const k = (f.severity as Severity) in c ? (f.severity as Severity) : 'info';
      c[k] += 1;
    }
    return c;
  }, [findings]);

  const scanList = scans ?? [];
  const lastScan = scanList[0];
  const running = scanList.filter((s) => s.status === 'running').length;
  const critHigh = counts.critical + counts.high;
  const hasData = findings.length > 0 || scanList.length > 0;

  return (
    <div className="glass-card rounded-xl p-4">
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-[1fr_auto]">
        {/* KPI grid */}
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          <KpiCard
            label="Total runs"
            value={scanList.length}
            hint={running > 0 ? `${running} running now` : lastScan ? `last ${relativeTime(lastScan.finished_at ?? lastScan.started_at)}` : 'no runs yet'}
            accent="text-primary"
            href="/scheduled/scans"
          />
          <KpiCard label="Scheduled targets" value={schedules?.length ?? 0} hint="recurring DAST" href="/scheduled/schedules" />
          <KpiCard
            label="Open crit + high"
            value={critHigh}
            accent={critHigh > 0 ? 'text-orange-400' : 'text-muted-foreground/50'}
            hint="across DAST findings"
            href="/scheduled/vulnerabilities"
          />
          <KpiCard label="Vulnerabilities" value={findings.length} hint="DAST only" href="/scheduled/vulnerabilities" />
        </div>

        {/* Severity donut */}
        <div className="flex items-center justify-center rounded-lg bg-white/[0.015] px-4 py-2 lg:min-w-[300px]">
          {hasData && findings.length > 0 ? (
            <SeverityDonut counts={counts} size={120} thickness={18} centerLabel="vulns" />
          ) : (
            <span className="py-6 text-center text-xs text-muted-foreground/70">
              Run a scan to populate the severity breakdown.
            </span>
          )}
        </div>
      </div>
    </div>
  );
}

/** Recent-scans mini list for the Overview page. */
export function RecentScans({ targetById, onSelectScan }: { targetById: Map<string, Target>; onSelectScan: (s: Scan) => void }) {
  const { data: scans, isLoading } = useQuery({
    queryKey: ['scans', 'all'],
    queryFn: () => api.scans.list({ limit: 200 }),
  });
  const recent = (scans ?? []).slice(0, 6);

  return (
    <div className="glass-card rounded-xl">
      <div className="flex items-center justify-between border-b border-border/40 px-4 py-3">
        <h3 className="flex items-center gap-2 text-sm font-semibold">
          <History className="h-4 w-4 text-primary/70" /> Recent scans
        </h3>
        <Link href="/scheduled/scans" className="flex items-center gap-1 text-xs text-muted-foreground hover:text-primary">
          View all <ArrowRight className="h-3 w-3" />
        </Link>
      </div>
      <div className="p-2">
        {isLoading ? (
          <div className="space-y-2 p-2">
            {Array.from({ length: 3 }).map((_, i) => <Skeleton key={i} className="h-10 w-full" />)}
          </div>
        ) : recent.length === 0 ? (
          <p className="px-2 py-8 text-center text-xs text-muted-foreground/70">No scans yet.</p>
        ) : (
          recent.map((s) => {
            const label = targetById.get(s.target_id)?.canonical_value ?? s.target_id;
            return (
              <button
                key={s.id}
                onClick={() => onSelectScan(s)}
                className="flex w-full items-center gap-3 rounded-lg px-2 py-2 text-left transition-colors hover:bg-white/[0.02]"
              >
                <TargetTypeIcon targetType={targetById.get(s.target_id)?.target_type ?? 'host'} className="h-3.5 w-3.5 shrink-0 text-primary/70" />
                <span className="flex-1 truncate text-sm">{label}</span>
                <SeverityCounts scan={s} />
                <span className="w-[70px] shrink-0 text-right text-[11px] text-muted-foreground tabular-nums">
                  {relativeTime(s.finished_at ?? s.started_at)}
                </span>
              </button>
            );
          })
        )}
      </div>
    </div>
  );
}
