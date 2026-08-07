'use client';

import { useMemo } from 'react';
import { cn } from '@/lib/utils';

// =============================================================================
// TrendChart (W2) — generic signed multi-series bar/area trend.
//
// Generalizes the hand-rolled inline-SVG pattern from FindingsOverTime so it
// can render BOTH positive-only stacks (the original findings-over-time use)
// AND signed series — e.g. new findings up (+), fixed findings down (-) around
// a zero baseline. No charting dep; same preserveAspectRatio="none" + HTML
// axis-overlay idiom as the original.
//
// FindingsOverTime is left intact and still compiles (the rebuilt Coverage
// Dashboard now uses this generic TrendChart instead); this is the generic
// primitive the new-vs-fixed widget uses.
// =============================================================================

export interface TrendSeries {
  key: string;
  label: string;
  /** Per-bucket values, same length as `buckets`. */
  values: number[];
  /** Solid color (hex) for the bar fill. */
  color: string;
  /** When true, values render BELOW the zero baseline (drawn as their abs
   *  value going down). Use for "fixed" / removed counts. */
  signed?: boolean;
}

export interface TrendChartProps {
  /** X-axis bucket labels (already formatted, e.g. "Jun 3"). */
  labels: string[];
  series: TrendSeries[];
  className?: string;
  height?: number;
  /** Tick count target for the x-axis. */
  tickTarget?: number;
  emptyMessage?: string;
}

function pickTickIndices(n: number, target: number): number[] {
  if (n <= target) return Array.from({ length: n }, (_, i) => i);
  const step = (n - 1) / (target - 1);
  const out = new Set<number>();
  for (let i = 0; i < target; i++) out.add(Math.round(i * step));
  return Array.from(out).sort((a, b) => a - b);
}

export function TrendChart({
  labels,
  series,
  className,
  height = 180,
  tickTarget = 6,
  emptyMessage = 'No data in this window',
}: TrendChartProps) {
  const width = 600;
  const padTop = 12;
  const padBottom = 24;
  const innerLeft = 28;
  const innerRight = width - 10;

  const n = labels.length;

  // Split series into "up" (positive baseline) and "down" (below baseline).
  const upSeries = series.filter((s) => !s.signed);
  const downSeries = series.filter((s) => s.signed);

  const { maxUp, maxDown } = useMemo(() => {
    let up = 0;
    let down = 0;
    for (let i = 0; i < n; i++) {
      const upSum = upSeries.reduce((acc, s) => acc + Math.max(0, s.values[i] ?? 0), 0);
      const downSum = downSeries.reduce((acc, s) => acc + Math.abs(s.values[i] ?? 0), 0);
      up = Math.max(up, upSum);
      down = Math.max(down, downSum);
    }
    return { maxUp: Math.max(up, 1), maxDown: Math.max(down, 0) };
  }, [n, upSeries, downSeries]);

  const hasAnyData = useMemo(
    () => series.some((s) => s.values.some((v) => v !== 0)),
    [series],
  );

  const innerH = height - padTop - padBottom;
  // Split the vertical space proportionally when there's a "down" half.
  const downSpan = maxDown > 0 ? innerH * (maxDown / (maxUp + maxDown)) : 0;
  const upSpan = innerH - downSpan;
  const baselineY = padTop + upSpan;

  const innerW = innerRight - innerLeft;
  const stepX = n > 0 ? innerW / n : 0;
  const barWidth = Math.max(2, stepX * 0.62);

  const tickIndices = pickTickIndices(n, n <= 7 ? 7 : tickTarget);

  if (!hasAnyData) {
    return (
      <div className={cn('flex flex-col items-center justify-center text-center', className)} style={{ height }}>
        <p className="text-sm text-muted-foreground">{emptyMessage}</p>
      </div>
    );
  }

  return (
    <div className={cn('relative w-full', className)} style={{ height }}>
      <svg
        viewBox={`0 0 ${width} ${height}`}
        preserveAspectRatio="none"
        className="absolute inset-0 w-full h-full block"
        aria-label="Trend chart"
      >
        {/* Top gridline */}
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
        {/* Zero baseline */}
        <line
          x1={innerLeft}
          y1={baselineY}
          x2={innerRight}
          y2={baselineY}
          className="stroke-border/70"
          strokeWidth={1}
          vectorEffect="non-scaling-stroke"
        />

        {Array.from({ length: n }).map((_, i) => {
          const colCenter = innerLeft + i * stepX + stepX / 2;
          const x = colCenter - barWidth / 2;

          // Up stack
          let cumUp = 0;
          const upRects = upSeries.map((s) => {
            const v = Math.max(0, s.values[i] ?? 0);
            if (v <= 0) return null;
            const h = (v / maxUp) * upSpan;
            cumUp += h;
            const rect = (
              <rect
                key={`${s.key}-up-${i}`}
                x={x}
                y={baselineY - cumUp}
                width={barWidth}
                height={h}
                rx={0.5}
                fill={s.color}
              >
                <title>{`${labels[i]} — ${s.label}: ${v}`}</title>
              </rect>
            );
            return rect;
          });

          // Down stack
          let cumDown = 0;
          const downRects = downSeries.map((s) => {
            const v = Math.abs(s.values[i] ?? 0);
            if (v <= 0 || downSpan <= 0 || maxDown <= 0) return null;
            const h = (v / maxDown) * downSpan;
            const yTop = baselineY + cumDown;
            cumDown += h;
            return (
              <rect
                key={`${s.key}-down-${i}`}
                x={x}
                y={yTop}
                width={barWidth}
                height={h}
                rx={0.5}
                fill={s.color}
                opacity={0.85}
              >
                <title>{`${labels[i]} — ${s.label}: ${v}`}</title>
              </rect>
            );
          });

          return (
            <g key={`col-${i}`}>
              {upRects}
              {downRects}
            </g>
          );
        })}
      </svg>

      {/* y-axis labels */}
      <div
        className="absolute text-[10px] text-muted-foreground/80 tabular-nums"
        style={{ left: `${((innerLeft - 4) / width) * 100}%`, top: padTop - 6, transform: 'translateX(-100%)' }}
      >
        {maxUp}
      </div>
      {maxDown > 0 && (
        <div
          className="absolute text-[10px] text-muted-foreground/80 tabular-nums"
          style={{ left: `${((innerLeft - 4) / width) * 100}%`, top: height - padBottom - 6, transform: 'translateX(-100%)' }}
        >
          -{maxDown}
        </div>
      )}

      {/* x-axis tick labels */}
      {tickIndices.map((idx) => {
        const label = labels[idx];
        if (label == null) return null;
        const x = innerLeft + idx * stepX + stepX / 2;
        const isFirst = idx === 0;
        const isLast = idx === n - 1;
        const align = isFirst ? '0%' : isLast ? '-100%' : '-50%';
        return (
          <div
            key={`xlabel-${idx}`}
            className="absolute text-[10px] text-muted-foreground/80 whitespace-nowrap tracking-tight"
            style={{ left: `${(x / width) * 100}%`, top: height - padBottom + 6, transform: `translateX(${align})` }}
          >
            {label}
          </div>
        );
      })}
    </div>
  );
}
