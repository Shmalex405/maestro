'use client';

import { useMemo } from 'react';
import { Crosshair, Clock, ListChecks, Wrench, Info, History, ShieldAlert } from 'lucide-react';
import { SeverityDonut } from '@/components/viz/severity-donut';
import { cn } from '@/lib/utils';
import { SEVERITY_STYLES } from '@/lib/severity';
import type { Scan, Severity } from '@/lib/types';

// =============================================================================
// ScanStats — the per-scan Statistics block (Scheduled DAST → Scans drill-in).
//
// The headline is "attacks executed": the real number of HTTP requests the run
// fired at the target (the *bill*), not the 234-technique catalog (the *menu*).
// This is the apples-to-apples figure vs other DAST tools that report "N
// attacks per scan". Backed by migration 0045 (scans.attacks_executed +
// attacks_by_tool); the deterministic pipeline measures the count per tool and
// flags any contribution that's a calibrated estimate rather than measured.
//
// Hand-rolled SVG/Tailwind viz — no charting dep (matches TrendChart /
// SeverityDonut house style).
// =============================================================================

/** Prettify an MCP tool name for display: run_nuclei → "Nuclei". */
function toolLabel(tool: string): string {
  const cleaned = tool.replace(/^(run|test|scan|fuzz)_/, '').replace(/_/g, ' ');
  return cleaned.charAt(0).toUpperCase() + cleaned.slice(1);
}

function fmt(n: number): string {
  return n.toLocaleString();
}

/** Whole-scan duration as a compact human string. */
function durationStr(start?: string, end?: string | null): string {
  if (!start || !end) return '—';
  const ms = new Date(end).getTime() - new Date(start).getTime();
  if (!Number.isFinite(ms) || ms < 0) return '—';
  const s = Math.round(ms / 1000);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  const rem = s % 60;
  if (m < 60) return rem ? `${m}m ${rem}s` : `${m}m`;
  const h = Math.floor(m / 60);
  return `${h}h ${m % 60}m`;
}

interface ToolBar {
  tool: string;
  count: number;
  estimated: boolean;
}

function StatTile({
  icon: Icon,
  label,
  value,
  sub,
}: {
  icon: typeof Clock;
  label: string;
  value: string;
  sub?: string;
}) {
  return (
    <div className="rounded-lg border border-border/40 bg-white/[0.01] px-3 py-2.5">
      <div className="flex items-center gap-1.5 text-[10px] font-medium uppercase tracking-wide text-muted-foreground/70">
        <Icon className="h-3 w-3" />
        {label}
      </div>
      <div className="mt-1 text-lg font-semibold tabular-nums leading-none">{value}</div>
      {sub ? <div className="mt-1 text-[11px] text-muted-foreground">{sub}</div> : null}
    </div>
  );
}

// =============================================================================
// ScansOverview — aggregate KPI header for the org-wide Scans list. Summarizes
// the whole run history: total runs, cumulative attacks executed, findings, and
// average run duration. Computed client-side from the same scans the table
// renders (no extra fetch — shares the react-query cache).
// =============================================================================

function OverviewCard({
  icon: Icon,
  label,
  value,
  sub,
  accent,
}: {
  icon: typeof Clock;
  label: string;
  value: string;
  sub?: string;
  accent?: boolean;
}) {
  return (
    <div
      className={cn(
        'rounded-xl border px-4 py-3',
        accent
          ? 'border-primary/20 bg-gradient-to-br from-primary/[0.07] to-transparent'
          : 'border-border/40 bg-white/[0.01]',
      )}
    >
      <div className="flex items-center gap-1.5 text-[10px] font-medium uppercase tracking-wide text-muted-foreground/70">
        <Icon className={cn('h-3 w-3', accent && 'text-primary/80')} />
        {label}
      </div>
      <div className="mt-1.5 text-2xl font-bold tabular-nums leading-none">{value}</div>
      {sub ? <div className="mt-1 text-[11px] text-muted-foreground">{sub}</div> : null}
    </div>
  );
}

export function ScansOverview({ scans }: { scans: Scan[] }) {
  const stats = useMemo(() => {
    const completed = scans.filter((s) => s.status === 'completed');
    const totalAttacks = scans.reduce((a, s) => a + (s.attacks_executed ?? 0), 0);
    const anyEstimated = scans.some((s) => s.attacks_estimated);
    const totalFindings = scans.reduce((a, s) => a + (s.total_count ?? 0), 0);
    const durations = completed
      .map((s) =>
        s.finished_at ? new Date(s.finished_at).getTime() - new Date(s.started_at).getTime() : null,
      )
      .filter((d): d is number => d != null && d >= 0);
    const avgMs = durations.length ? durations.reduce((a, b) => a + b, 0) / durations.length : 0;
    const running = scans.filter((s) => s.status === 'running').length;
    return { runs: scans.length, completed: completed.length, running, totalAttacks, anyEstimated, totalFindings, avgMs };
  }, [scans]);

  if (scans.length === 0) return null;

  const avgStr =
    stats.avgMs > 0
      ? stats.avgMs < 60000
        ? `${Math.round(stats.avgMs / 1000)}s`
        : `${Math.round(stats.avgMs / 60000)}m`
      : '—';

  return (
    <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
      <OverviewCard
        icon={History}
        label="Scan runs"
        value={fmt(stats.runs)}
        sub={stats.running > 0 ? `${stats.running} running` : `${fmt(stats.completed)} completed`}
      />
      <OverviewCard
        icon={Crosshair}
        label="Attacks executed"
        value={fmt(stats.totalAttacks)}
        sub={stats.anyEstimated ? 'requests fired (partly est.)' : 'requests fired'}
        accent
      />
      <OverviewCard icon={ShieldAlert} label="Findings" value={fmt(stats.totalFindings)} sub="across all runs" />
      <OverviewCard icon={Clock} label="Avg duration" value={avgStr} sub="per completed run" />
    </div>
  );
}

export function ScanStats({ scan }: { scan: Scan }) {
  const attacks = scan.attacks_executed ?? 0;
  const estimated = scan.attacks_estimated ?? false;

  const bars = useMemo<ToolBar[]>(() => {
    const byTool = scan.attacks_by_tool ?? {};
    return Object.entries(byTool)
      .map(([tool, v]) => ({ tool, count: v?.count ?? 0, estimated: !!v?.estimated }))
      .filter((b) => b.count > 0)
      .sort((a, b) => b.count - a.count);
  }, [scan.attacks_by_tool]);

  const maxBar = bars.length ? bars[0].count : 0;

  const sevCounts = useMemo<Record<Severity, number>>(
    () => ({
      critical: scan.critical_count ?? 0,
      high: scan.high_count ?? 0,
      medium: scan.medium_count ?? 0,
      low: scan.low_count ?? 0,
      info: scan.info_count ?? 0,
    }),
    [scan],
  );

  const toolCount = bars.length;
  const testsLabel =
    (scan.tests_total ?? 0) > 0 ? `${scan.tests_done ?? 0} / ${scan.tests_total}` : '—';

  return (
    <div className="space-y-4">
      {/* Hero: attacks executed */}
      <div className="rounded-xl border border-primary/20 bg-gradient-to-br from-primary/[0.07] to-transparent px-4 py-4">
        <div className="flex items-center gap-1.5 text-[11px] font-medium uppercase tracking-wide text-primary/80">
          <Crosshair className="h-3.5 w-3.5" />
          Attacks executed
        </div>
        <div className="mt-1 flex items-baseline gap-2">
          <span className="text-3xl font-bold tabular-nums leading-none">{fmt(attacks)}</span>
          <span className="text-sm text-muted-foreground">requests fired</span>
          {estimated && (
            <span
              className="ml-1 rounded bg-amber-500/15 px-1.5 py-0.5 text-[10px] font-semibold text-amber-400"
              title="Some contributing tools don't expose a measured request total; their count is a calibrated estimate."
            >
              partly est.
            </span>
          )}
        </div>
        <p className="mt-1.5 text-[11px] leading-snug text-muted-foreground">
          The real runtime volume — each technique fans out into many requests as it sweeps
          discovered parameters and payloads.
        </p>
      </div>

      {/* Key metrics */}
      <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
        <StatTile icon={Clock} label="Duration" value={durationStr(scan.started_at, scan.finished_at)} />
        <StatTile icon={ListChecks} label="Tests run" value={testsLabel} />
        <StatTile icon={Wrench} label="Tools" value={toolCount ? fmt(toolCount) : '—'} />
        <StatTile icon={Info} label="Findings" value={fmt(scan.total_count ?? 0)} />
      </div>

      {/* Per-tool breakdown + severity donut */}
      <div className="grid gap-4 lg:grid-cols-[1fr_auto]">
        <div className="rounded-lg border border-border/40 bg-white/[0.01] p-3">
          <div className="mb-2.5 flex items-center justify-between">
            <span className="text-xs font-medium text-muted-foreground">Attacks by tool</span>
            {estimated && (
              <span className="text-[10px] text-muted-foreground/60">✳ estimated</span>
            )}
          </div>
          {bars.length === 0 ? (
            <p className="py-4 text-center text-xs text-muted-foreground/60">
              No request counts recorded for this run.
            </p>
          ) : (
            <div className="space-y-2">
              {bars.map((b) => (
                <div key={b.tool}>
                  <div className="mb-0.5 flex items-center justify-between text-[11px]">
                    <span className="truncate text-foreground/90">
                      {toolLabel(b.tool)}
                      {b.estimated && <span className="text-muted-foreground/50"> ✳</span>}
                    </span>
                    <span className="tabular-nums text-muted-foreground">{fmt(b.count)}</span>
                  </div>
                  <div className="h-1.5 w-full overflow-hidden rounded bg-white/[0.04]">
                    <div
                      className={cn('h-1.5 rounded', b.estimated ? 'bg-amber-500/60' : 'bg-primary')}
                      style={{ width: `${maxBar > 0 ? Math.max(2, (b.count / maxBar) * 100) : 0}%` }}
                    />
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Severity distribution */}
        <div className="flex flex-col items-center justify-center rounded-lg border border-border/40 bg-white/[0.01] p-3">
          <span className="mb-2 self-start text-xs font-medium text-muted-foreground">Findings by severity</span>
          {(scan.total_count ?? 0) > 0 ? (
            <SeverityDonut counts={sevCounts} size={132} centerLabel="findings" />
          ) : (
            <div className="flex h-[132px] w-[132px] items-center justify-center text-center text-xs text-muted-foreground/60">
              Clean run — no findings
            </div>
          )}
          <div className="mt-2 flex flex-wrap justify-center gap-x-3 gap-y-1 text-[10px] tabular-nums">
            {(['critical', 'high', 'medium', 'low', 'info'] as const).map((s) =>
              sevCounts[s] > 0 ? (
                <span key={s} className="flex items-center gap-1">
                  <span
                    className="inline-block h-2 w-2 rounded-full"
                    style={{ backgroundColor: SEVERITY_STYLES[s].hex }}
                  />
                  <span className="text-muted-foreground">
                    {sevCounts[s]} {SEVERITY_STYLES[s].label}
                  </span>
                </span>
              ) : null,
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
