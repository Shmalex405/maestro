'use client';

import { useMemo, useState } from 'react';
import {
  ChevronDown,
  CheckCircle2,
  MinusCircle,
  ShieldAlert,
  SlashSquare,
  SkipForward,
  Telescope,
} from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { cn } from '@/lib/utils';
import type { Assessment, ExecutionTestResult } from '@/lib/types';
import { computeCoverage, type CategoryCoverage } from '@/lib/test-matrix-manifest';
import { TestCoverageMatrix } from './test-coverage-matrix';

interface CoverageBreakdownProps {
  testResults: ExecutionTestResult[];
  assessment: Assessment | null;
  /** From overview.provenance.test_results — 'absent' renders a placeholder. */
  provenance?: 'db' | 'derived' | 'absent';
}

/**
 * The "what ran / what didn't / what was excluded" disclosure. Collapsed, it
 * shows a one-line summary + a stacked bar. Expanded, it accounts for every
 * test bucket — executed, not-applicable, blocked, deliberately EXCLUDED by
 * scope (e.g. 29 cloud tests skipped because no cloud account was in scope),
 * and skipped — then a per-category table and the full per-test matrix.
 */
export function CoverageBreakdown({ testResults, assessment, provenance }: CoverageBreakdownProps) {
  const [open, setOpen] = useState(false);
  const coverage = useMemo(
    () => computeCoverage(testResults, assessment),
    [testResults, assessment],
  );

  const captured = provenance !== 'absent' && coverage.hasData;
  const t = coverage.totals;

  const header = (
    <CardHeader className="pb-3">
      <CardTitle className="text-base flex items-center gap-2">
        <Telescope className="h-4 w-4" />
        Coverage
        {captured && (
          <span className="text-xs font-normal text-muted-foreground">
            · {t.recordedTotal} ran · {t.excludedByScope} excluded
          </span>
        )}
      </CardTitle>
    </CardHeader>
  );

  // No per-test data promoted for this run → labeled placeholder, no caret.
  if (!captured) {
    return (
      <Card>
        {header}
        <CardContent>
          <div className="rounded-lg border border-dashed border-border p-4 text-sm text-muted-foreground">
            Per-test coverage was not captured for this run. The breakdown of what
            ran, what was blocked, and what was excluded by scope appears here once
            an assessment records and promotes its per-test results.
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="w-full text-left"
        aria-expanded={open}
      >
        <CardHeader className="pb-3">
          <CardTitle className="text-base flex items-center gap-2">
            <Telescope className="h-4 w-4" />
            Coverage
            <span className="text-xs font-normal text-muted-foreground">
              · {summaryLine(coverage)}
            </span>
            <ChevronDown
              className={cn(
                'ml-auto h-4 w-4 text-muted-foreground transition-transform',
                open && 'rotate-180',
              )}
            />
          </CardTitle>
          {/* Stacked bar — always visible, even collapsed. */}
          <CoverageBar coverage={coverage} />
        </CardHeader>
      </button>

      {open && (
        <CardContent className="space-y-5">
          {/* Bucket chips */}
          <div className="flex flex-wrap gap-2">
            <BucketChip icon={<CheckCircle2 className="h-3.5 w-3.5" />} label="Ran" value={t.ran} tone="green" />
            <BucketChip icon={<MinusCircle className="h-3.5 w-3.5" />} label="Not applicable" value={t.n_a} tone="muted" />
            <BucketChip icon={<ShieldAlert className="h-3.5 w-3.5" />} label="Blocked" value={t.blocked} tone="amber" />
            <BucketChip icon={<SlashSquare className="h-3.5 w-3.5" />} label="Excluded (scope)" value={t.excludedByScope} tone="slate" />
            {t.skipped > 0 && (
              <BucketChip icon={<SkipForward className="h-3.5 w-3.5" />} label="Skipped" value={t.skipped} tone="muted" />
            )}
          </div>

          {/* Excluded-by-scope callout — the headline of "what didn't run, and why". */}
          {coverage.excludedCategories.length > 0 && (
            <div className="rounded-lg border border-border bg-muted/30 p-3">
              <div className="mb-2 flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                <SlashSquare className="h-3.5 w-3.5" />
                Excluded — not in scope
              </div>
              <ul className="space-y-1.5">
                {coverage.excludedCategories.map((c) => (
                  <li key={c.key} className="flex items-start gap-2 text-sm">
                    <span className="mt-0.5 inline-flex h-5 min-w-[2.5rem] items-center justify-center rounded-md border border-border bg-background px-1 text-[11px] font-medium tabular-nums text-muted-foreground">
                      {c.matrixCount}
                    </span>
                    <span>
                      <span className="font-medium">{c.label}</span>
                      <span className="text-muted-foreground"> — {c.excludedReason}</span>
                    </span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* Per-category table */}
          <div className="overflow-hidden rounded-lg border border-border">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border bg-muted/30 text-[11px] uppercase tracking-wider text-muted-foreground">
                  <th className="px-3 py-2 text-left font-medium">Category</th>
                  <th className="px-2 py-2 text-right font-medium">Tests</th>
                  <th className="px-2 py-2 text-right font-medium">Ran</th>
                  <th className="px-2 py-2 text-right font-medium">N/A</th>
                  <th className="px-2 py-2 text-right font-medium">Blocked</th>
                  <th className="px-3 py-2 text-right font-medium">Status</th>
                </tr>
              </thead>
              <tbody>
                {coverage.categories.map((c) => (
                  <CategoryRow key={c.key} c={c} />
                ))}
              </tbody>
            </table>
          </div>

          {/* Full per-test matrix, nested under the disclosure. */}
          <TestCoverageMatrix testResults={testResults} provenance={provenance} />
        </CardContent>
      )}
    </Card>
  );
}

function summaryLine(coverage: ReturnType<typeof computeCoverage>): string {
  const t = coverage.totals;
  const parts = [`${t.ran} ran`];
  if (t.blocked > 0) parts.push(`${t.blocked} blocked`);
  if (t.excludedByScope > 0) parts.push(`${t.excludedByScope} excluded`);
  return parts.join(' · ');
}

function CoverageBar({ coverage }: { coverage: ReturnType<typeof computeCoverage> }) {
  const t = coverage.totals;
  const denom = t.ran + t.n_a + t.blocked + t.skipped + t.excludedByScope || 1;
  const seg = (n: number) => `${(n / denom) * 100}%`;
  return (
    <div className="mt-2 flex h-2 w-full overflow-hidden rounded-full bg-muted">
      <div className="bg-green-500/70" style={{ width: seg(t.ran) }} title={`${t.ran} ran`} />
      <div className="bg-muted-foreground/30" style={{ width: seg(t.n_a) }} title={`${t.n_a} N/A`} />
      <div className="bg-amber-500/70" style={{ width: seg(t.blocked) }} title={`${t.blocked} blocked`} />
      <div className="bg-slate-400/40 dark:bg-slate-500/40" style={{ width: seg(t.excludedByScope) }} title={`${t.excludedByScope} excluded by scope`} />
    </div>
  );
}

function BucketChip({
  icon,
  label,
  value,
  tone,
}: {
  icon: React.ReactNode;
  label: string;
  value: number;
  tone: 'green' | 'amber' | 'slate' | 'muted';
}) {
  const tones: Record<string, string> = {
    green: 'text-green-600 dark:text-green-400 border-green-500/30 bg-green-500/10',
    amber: 'text-amber-600 dark:text-amber-400 border-amber-500/30 bg-amber-500/10',
    slate: 'text-slate-600 dark:text-slate-300 border-slate-400/30 bg-slate-400/10',
    muted: 'text-muted-foreground border-border bg-muted/40',
  };
  return (
    <div className={cn('inline-flex items-center gap-1.5 rounded-lg border px-2.5 py-1', tones[tone])}>
      {icon}
      <span className="text-xs font-medium">{label}</span>
      <span className="text-sm font-semibold tabular-nums">{value}</span>
    </div>
  );
}

function CategoryRow({ c }: { c: CategoryCoverage }) {
  let status: { label: string; cls: string };
  if (c.excluded) status = { label: 'Excluded', cls: 'text-slate-500 dark:text-slate-400' };
  else if (!c.assessed) status = { label: 'Not run', cls: 'text-muted-foreground' };
  else if (c.blocked > 0) status = { label: 'Partial', cls: 'text-amber-600 dark:text-amber-400' };
  else status = { label: 'Assessed', cls: 'text-green-600 dark:text-green-400' };

  return (
    <tr className={cn('border-b border-border last:border-0', c.excluded && 'opacity-60')}>
      <td className="px-3 py-2 font-medium">{c.label}</td>
      <td className="px-2 py-2 text-right tabular-nums text-muted-foreground">{c.matrixCount}</td>
      <td className="px-2 py-2 text-right tabular-nums">{c.assessed ? c.ran : '—'}</td>
      <td className="px-2 py-2 text-right tabular-nums">{c.assessed ? c.n_a : '—'}</td>
      <td className="px-2 py-2 text-right tabular-nums">{c.assessed ? c.blocked : '—'}</td>
      <td className={cn('px-3 py-2 text-right text-xs font-medium', status.cls)}>{status.label}</td>
    </tr>
  );
}
