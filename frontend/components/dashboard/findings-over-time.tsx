'use client';

import { useMemo, useState } from 'react';
import Link from 'next/link';
import { ArrowRight, TrendingUp, Activity, Filter } from 'lucide-react';
import { Skeleton } from '@/components/ui/skeleton';
import { Button } from '@/components/ui/button';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import {
  useFindingsTrend,
  type TrendBucket,
  type TrendCategoryFilter,
} from '@/hooks/use-findings-trend';
import { cn } from '@/lib/utils';
import type { Severity } from '@/lib/types';

// Visual order: stack from highest severity on bottom to info on top so the
// most important band reads first along the axis.
const STACK_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

// Bars use opaque fills (vs the translucent area-chart fills the old
// implementation used) so each segment reads as a clear block at small
// per-day widths. The dot colors match the chart fills so the legend
// still maps obviously.
const SEVERITY_STYLE: Record<Severity, { fill: string; dot: string; label: string }> = {
  critical: { fill: 'fill-red-500',    dot: 'bg-red-500',    label: 'Critical' },
  high:     { fill: 'fill-orange-500', dot: 'bg-orange-500', label: 'High' },
  medium:   { fill: 'fill-yellow-500', dot: 'bg-yellow-500', label: 'Medium' },
  low:      { fill: 'fill-blue-500',   dot: 'bg-blue-500',   label: 'Low' },
  info:     { fill: 'fill-slate-500',  dot: 'bg-slate-500',  label: 'Info' },
};

const RANGE_PRESETS: { days: number; label: string }[] = [
  { days: 7,  label: '7d' },
  { days: 30, label: '30d' },
  { days: 90, label: '90d' },
];

const CATEGORY_OPTIONS: { value: TrendCategoryFilter; label: string }[] = [
  { value: 'all',            label: 'All categories' },
  { value: 'web_app',        label: 'Web / API' },
  { value: 'code_security',  label: 'Code security' },
  { value: 'cloud',          label: 'Cloud' },
  { value: 'infrastructure', label: 'Infrastructure' },
  { value: 'identity',       label: 'Identity / IDP' },
  { value: 'ai',             label: 'AI / LLM' },
];

interface BarSegment {
  severity: Severity;
  x: number;
  y: number;
  width: number;
  height: number;
  bucketIndex: number;
  count: number;
}

/** Build the stacked-bar geometry. Each bucket becomes one vertical
 *  column made of up-to-five rectangles (one per visible severity),
 *  stacked critical → info from the baseline up. Hidden severities
 *  contribute zero so toggling them in the legend shrinks the
 *  columns instead of leaving gaps. */
function buildBars(
  buckets: TrendBucket[],
  hidden: Set<Severity>,
  width: number,
  innerLeft: number,
  innerRight: number,
  height: number,
  padTop: number,
  padBottom: number,
): { segments: BarSegment[]; yMax: number; barWidth: number; stepX: number } {
  const n = buckets.length;
  if (n === 0) return { segments: [], yMax: 0, barWidth: 0, stepX: 0 };

  // Per-bucket total → determines yMax for shared y-scale.
  const totals = buckets.map((b) =>
    STACK_ORDER.reduce(
      (acc, sev) => acc + (hidden.has(sev) ? 0 : (b[sev] as number)),
      0,
    ),
  );
  const yMax = Math.max(...totals, 1);

  const innerW = innerRight - innerLeft;
  // For n bars, divide the inner width into n equal columns and
  // place each bar in the middle 70% of its column.
  const stepX = n > 0 ? innerW / n : 0;
  const barWidth = Math.max(2, stepX * 0.7);
  const innerH = height - padTop - padBottom;
  const baseline = padTop + innerH;
  const yFor = (v: number) => (v / yMax) * innerH;

  const segments: BarSegment[] = [];
  for (let i = 0; i < n; i++) {
    const colCenter = innerLeft + i * stepX + stepX / 2;
    const x = colCenter - barWidth / 2;
    let cumHeight = 0;
    for (const sev of STACK_ORDER) {
      if (hidden.has(sev)) continue;
      const count = buckets[i][sev] as number;
      if (count <= 0) continue;
      const segH = yFor(count);
      cumHeight += segH;
      segments.push({
        severity: sev,
        x,
        y: baseline - cumHeight,
        width: barWidth,
        height: segH,
        bucketIndex: i,
        count,
      });
    }
  }

  return { segments, yMax, barWidth, stepX };
}

// Pick ~6 evenly-spaced indices (including first and last) regardless of
// window length. 7d gets 7 ticks, 30d gets 6, 90d gets 6.
function pickTickIndices(n: number, target = 6): number[] {
  if (n <= target) return Array.from({ length: n }, (_, i) => i);
  const step = (n - 1) / (target - 1);
  const out = new Set<number>();
  for (let i = 0; i < target; i++) {
    out.add(Math.round(i * step));
  }
  return Array.from(out).sort((a, b) => a - b);
}

function formatTick(iso: string): string {
  return new Date(iso).toLocaleDateString(undefined, {
    month: 'short',
    day: 'numeric',
  });
}

export function FindingsOverTime({
  initialDays = 30,
  className,
  category,
}: {
  initialDays?: number;
  className?: string;
  /** When set, locks the trend to this category (surface pages show only their
   *  own findings over time) and hides the category picker. Omit for the
   *  overall view. */
  category?: TrendCategoryFilter;
}) {
  const [days, setDays] = useState(initialDays);
  const [hiddenSeverities, setHiddenSeverities] = useState<Set<Severity>>(new Set());
  const [categoryFilter, setCategoryFilter] = useState<TrendCategoryFilter>('all');
  // A locked `category` (surface context) wins over the in-widget picker.
  const effectiveCategory = category ?? categoryFilter;

  const { data, isLoading } = useFindingsTrend(days, effectiveCategory);

  const buckets = data?.buckets ?? [];

  // Totals respect the severity-visibility filter, so the "in window" counter
  // and per-series chips match what's actually rendered.
  const visibleTotals = useMemo(() => {
    const perSev: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    let total = 0;
    for (const b of buckets) {
      for (const sev of STACK_ORDER) {
        const n = b[sev] as number;
        perSev[sev] += n;
        if (!hiddenSeverities.has(sev)) total += n;
      }
    }
    return { perSev, total };
  }, [buckets, hiddenSeverities]);

  const width = 600;
  const height = 170;
  const padTop = 10;
  const padBottom = 22;
  // Inset left/right so axis labels don't touch the SVG edges.
  const innerLeft = 24;
  const innerRight = width - 10;

  const { segments, yMax, stepX } = buildBars(
    buckets,
    hiddenSeverities,
    width,
    innerLeft,
    innerRight,
    height,
    padTop,
    padBottom,
  );

  const tickIndices = pickTickIndices(buckets.length, days <= 7 ? 7 : 6);

  const toggleSeverity = (sev: Severity) => {
    setHiddenSeverities((prev) => {
      const next = new Set(prev);
      if (next.has(sev)) next.delete(sev);
      else next.add(sev);
      return next;
    });
  };

  return (
    <div className={cn('glass-card rounded-xl overflow-hidden', className)}>
      {/* Header */}
      <div className="px-4 py-3 border-b border-border/50 flex items-center justify-between gap-3 flex-wrap">
        <div className="flex items-center gap-2">
          <TrendingUp className="h-4 w-4 text-muted-foreground" />
          <span className="text-sm font-medium">Findings over time</span>
          <span className="text-[10px] text-muted-foreground bg-muted/50 px-1.5 py-0.5 rounded-md">
            last {days}d
          </span>
        </div>

        <div className="flex items-center gap-2 flex-wrap">
          {/* Category filter — hidden when a surface locks the category. */}
          {!category && (
            <div className="flex items-center gap-1.5">
              <Filter className="h-3.5 w-3.5 text-muted-foreground" />
              <Select value={categoryFilter} onValueChange={(v) => setCategoryFilter(v as TrendCategoryFilter)}>
                <SelectTrigger size="sm" className="h-7 text-xs min-w-[150px]">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {CATEGORY_OPTIONS.map((opt) => (
                    <SelectItem key={opt.value} value={opt.value} className="text-xs">
                      {opt.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          )}

          {/* Range presets */}
          <div className="inline-flex rounded-md border border-border/50 overflow-hidden">
            {RANGE_PRESETS.map((p, i) => (
              <Button
                key={p.days}
                variant={days === p.days ? 'default' : 'ghost'}
                size="sm"
                onClick={() => setDays(p.days)}
                className={cn(
                  'h-7 rounded-none text-xs px-2.5',
                  i > 0 && 'border-l border-border/50',
                )}
              >
                {p.label}
              </Button>
            ))}
          </div>

          <Link
            href="/findings"
            className="text-xs text-muted-foreground hover:text-primary transition-colors flex items-center gap-1"
          >
            View all <ArrowRight className="h-3 w-3" />
          </Link>
        </div>
      </div>

      <div className="p-4">
        {isLoading ? (
          <Skeleton className="h-[170px] w-full" />
        ) : visibleTotals.total === 0 ? (
          <div className="flex flex-col items-center justify-center py-10 text-center">
            <div className="mb-3 rounded-xl bg-muted/50 p-3">
              <Activity className="h-6 w-6 text-muted-foreground/50" />
            </div>
            <p className="text-sm font-medium text-muted-foreground">
              No scan activity in the last {days} days
            </p>
            <p className="mt-0.5 text-xs text-muted-foreground/70">
              {hiddenSeverities.size > 0
                ? 'Try un-hiding severities or widening the date range'
                : !category && categoryFilter !== 'all'
                ? 'Try a different category or widening the date range'
                : 'Findings observed by a recent scan will appear here'}
            </p>
          </div>
        ) : (
          <>
            {/* Chart paths render in SVG (vectors are meant to stretch),
                but axis labels are HTML positioned by % left so they keep
                their natural typographic proportions instead of getting
                horizontally squished by `preserveAspectRatio="none"`. */}
            <div className="relative w-full h-[170px]">
              <svg
                viewBox={`0 0 ${width} ${height}`}
                preserveAspectRatio="none"
                className="absolute inset-0 w-full h-full block"
                aria-label="Findings over time stacked area chart"
              >
                {/* Top gridline (dashed) */}
                <line
                  x1={innerLeft}
                  y1={padTop}
                  x2={innerRight}
                  y2={padTop}
                  className="stroke-border/40"
                  strokeWidth={1}
                  strokeDasharray="2 3"
                  vectorEffect="non-scaling-stroke"
                />
                {/* Baseline */}
                <line
                  x1={innerLeft}
                  y1={height - padBottom}
                  x2={innerRight}
                  y2={height - padBottom}
                  className="stroke-border/60"
                  strokeWidth={1}
                  vectorEffect="non-scaling-stroke"
                />

                {/* X-axis tick marks — at the center of each labelled
                    column so the dates align with their bars. */}
                {tickIndices.map((idx) => {
                  const x = innerLeft + idx * stepX + stepX / 2;
                  return (
                    <line
                      key={`tick-${idx}`}
                      x1={x}
                      y1={height - padBottom}
                      x2={x}
                      y2={height - padBottom + 3}
                      className="stroke-border/60"
                      strokeWidth={1}
                      vectorEffect="non-scaling-stroke"
                    />
                  );
                })}

                {/* Stacked bars */}
                {segments.map((seg, i) => {
                  const style = SEVERITY_STYLE[seg.severity];
                  return (
                    <rect
                      key={`bar-${i}`}
                      x={seg.x}
                      y={seg.y}
                      width={seg.width}
                      height={seg.height}
                      rx={0.5}
                      className={cn(style.fill, 'stroke-none')}
                    >
                      <title>{`${formatTick(buckets[seg.bucketIndex].iso)} — ${style.label}: ${seg.count}`}</title>
                    </rect>
                  );
                })}
              </svg>

              {/* HTML overlay: y-axis labels. Positioned by % of the
                  same coordinate system the SVG uses. */}
              <div
                className="absolute text-[10px] text-muted-foreground/80 tabular-nums"
                style={{
                  left: `${((innerLeft - 4) / width) * 100}%`,
                  top: padTop - 6,
                  transform: 'translateX(-100%)',
                }}
              >
                {yMax}
              </div>
              <div
                className="absolute text-[10px] text-muted-foreground/80 tabular-nums"
                style={{
                  left: `${((innerLeft - 4) / width) * 100}%`,
                  top: height - padBottom - 6,
                  transform: 'translateX(-100%)',
                }}
              >
                0
              </div>

              {/* HTML overlay: x-axis date labels. Anchored to the
                  center of each bar's column so dates sit under their
                  bars regardless of container width. */}
              {tickIndices.map((idx) => {
                const b = buckets[idx];
                if (!b) return null;
                const x = innerLeft + idx * stepX + stepX / 2;
                const isFirst = idx === 0;
                const isLast = idx === buckets.length - 1;
                const align = isFirst ? '0%' : isLast ? '-100%' : '-50%';
                return (
                  <div
                    key={`label-${idx}`}
                    className="absolute text-[10px] text-muted-foreground/80 whitespace-nowrap tracking-tight"
                    style={{
                      left: `${(x / width) * 100}%`,
                      top: height - padBottom + 6,
                      transform: `translateX(${align})`,
                    }}
                  >
                    {formatTick(b.iso)}
                  </div>
                );
              })}
            </div>

            {/* Legend — click to toggle visibility */}
            <div className="mt-3 flex flex-wrap items-center gap-x-3 gap-y-1.5">
              {STACK_ORDER.map((sev) => {
                const style = SEVERITY_STYLE[sev];
                const hidden = hiddenSeverities.has(sev);
                const total = visibleTotals.perSev[sev];
                return (
                  <button
                    key={sev}
                    type="button"
                    onClick={() => toggleSeverity(sev)}
                    className={cn(
                      'flex items-center gap-1.5 rounded-md px-1.5 py-0.5 transition-opacity hover:bg-white/[0.04]',
                      hidden && 'opacity-40',
                    )}
                    title={hidden ? `Show ${style.label}` : `Hide ${style.label}`}
                  >
                    <span className={cn('h-2 w-2 rounded-sm', style.dot, hidden && 'opacity-50')} />
                    <span className="text-[11px] text-muted-foreground">{style.label}</span>
                    <span className="text-[11px] font-medium tabular-nums">{total}</span>
                  </button>
                );
              })}
              <div className="ml-auto text-[11px] text-muted-foreground">
                <span className="font-medium text-foreground tabular-nums">{visibleTotals.total}</span>{' '}
                in window
              </div>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
