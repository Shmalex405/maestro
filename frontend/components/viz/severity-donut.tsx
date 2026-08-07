'use client';

import { useMemo } from 'react';
import { cn } from '@/lib/utils';
import { SEVERITY_ORDER, SEVERITY_STYLES } from '@/lib/severity';
import type { Severity } from '@/lib/types';

// =============================================================================
// SeverityDonut (W1) — hand-rolled SVG arc donut, no charting dep.
//
// Renders open findings by severity as a ring with a center total. Arc order
// follows SEVERITY_ORDER (critical first). Hovering a segment shows the count
// via a native <title>. Colors come from lib/severity.ts (hex, since SVG
// stroke can't use Tailwind classes reliably across the arc geometry).
// =============================================================================

interface SeverityDonutProps {
  counts: Record<Severity, number>;
  size?: number;
  thickness?: number;
  className?: string;
  /** Optional label rendered under the center total (e.g. "open"). */
  centerLabel?: string;
}

interface Arc {
  severity: Severity;
  path: string;
  count: number;
}

/** Polar → cartesian on a circle of radius r centered at (cx, cy). Angle in
 *  degrees, measured clockwise from 12 o'clock. */
function polar(cx: number, cy: number, r: number, angleDeg: number): [number, number] {
  const a = ((angleDeg - 90) * Math.PI) / 180;
  return [cx + r * Math.cos(a), cy + r * Math.sin(a)];
}

/** SVG arc path for the slice [startAngle, endAngle] on the ring. */
function arcPath(
  cx: number,
  cy: number,
  rOuter: number,
  rInner: number,
  startAngle: number,
  endAngle: number,
): string {
  const [sxO, syO] = polar(cx, cy, rOuter, endAngle);
  const [exO, eyO] = polar(cx, cy, rOuter, startAngle);
  const [sxI, syI] = polar(cx, cy, rInner, startAngle);
  const [exI, eyI] = polar(cx, cy, rInner, endAngle);
  const largeArc = endAngle - startAngle > 180 ? 1 : 0;
  return [
    `M ${sxO} ${syO}`,
    `A ${rOuter} ${rOuter} 0 ${largeArc} 0 ${exO} ${eyO}`,
    `L ${sxI} ${syI}`,
    `A ${rInner} ${rInner} 0 ${largeArc} 1 ${exI} ${eyI}`,
    'Z',
  ].join(' ');
}

export function SeverityDonut({
  counts,
  size = 160,
  thickness = 22,
  className,
  centerLabel = 'open',
}: SeverityDonutProps) {
  const total = useMemo(
    () => SEVERITY_ORDER.reduce((acc, s) => acc + (counts[s] || 0), 0),
    [counts],
  );

  const cx = size / 2;
  const cy = size / 2;
  const rOuter = size / 2 - 1;
  const rInner = rOuter - thickness;

  const arcs = useMemo<Arc[]>(() => {
    if (total === 0) return [];
    const out: Arc[] = [];
    let angle = 0;
    // Small gap (deg) between slices for a crisp segmented look — only when
    // there's more than one non-zero severity.
    const nonZero = SEVERITY_ORDER.filter((s) => (counts[s] || 0) > 0);
    const gap = nonZero.length > 1 ? 2 : 0;
    for (const sev of SEVERITY_ORDER) {
      const count = counts[sev] || 0;
      if (count <= 0) continue;
      const sweep = (count / total) * 360;
      const start = angle + gap / 2;
      const end = angle + sweep - gap / 2;
      if (end > start) {
        out.push({
          severity: sev,
          path: arcPath(cx, cy, rOuter, rInner, start, end),
          count,
        });
      }
      angle += sweep;
    }
    return out;
  }, [counts, total, cx, cy, rOuter, rInner]);

  return (
    <div className={cn('flex items-center gap-5', className)}>
      <div className="relative shrink-0" style={{ width: size, height: size }}>
        <svg viewBox={`0 0 ${size} ${size}`} className="w-full h-full" aria-label="Severity distribution donut">
          {/* Track ring (background) — visible even when total is 0 so the
              widget never looks broken. */}
          <circle
            cx={cx}
            cy={cy}
            r={(rOuter + rInner) / 2}
            fill="none"
            className="stroke-muted/40"
            strokeWidth={thickness}
          />
          {arcs.map((arc) => (
            <path key={arc.severity} d={arc.path} fill={SEVERITY_STYLES[arc.severity].hex}>
              <title>{`${SEVERITY_STYLES[arc.severity].label}: ${arc.count}`}</title>
            </path>
          ))}
        </svg>
        {/* Center total */}
        <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
          <span className="text-3xl font-bold tabular-nums tracking-tight">{total}</span>
          {centerLabel && (
            <span className="text-[10px] uppercase tracking-wider text-muted-foreground">{centerLabel}</span>
          )}
        </div>
      </div>

      {/* Legend */}
      <div className="flex flex-col gap-1.5 min-w-[120px]">
        {SEVERITY_ORDER.map((sev) => {
          const style = SEVERITY_STYLES[sev];
          const count = counts[sev] || 0;
          const pct = total > 0 ? Math.round((count / total) * 100) : 0;
          return (
            <div key={sev} className="flex items-center gap-2 text-xs">
              <span className={cn('h-2.5 w-2.5 rounded-sm shrink-0', style.bg)} />
              <span className="text-muted-foreground">{style.label}</span>
              <span className="ml-auto font-medium tabular-nums">{count}</span>
              <span className="w-9 text-right text-[10px] text-muted-foreground/70 tabular-nums">
                {pct}%
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
