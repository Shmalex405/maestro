'use client';

import { cn } from '@/lib/utils';

interface SparklineProps {
  data: number[];
  /** Tailwind stroke color class (e.g. 'stroke-red-400'). */
  stroke?: string;
  /** Tailwind fill color class for the area below the line. */
  fill?: string;
  width?: number;
  height?: number;
  className?: string;
  /** Show a dot on the last point. */
  showLastDot?: boolean;
}

/**
 * Lightweight inline-SVG sparkline. No external dep. Pads a flat baseline
 * when the series is empty or all zeros so the tile doesn't look broken.
 */
export function Sparkline({
  data,
  stroke = 'stroke-primary',
  fill = 'fill-primary/15',
  width = 80,
  height = 20,
  className,
  showLastDot = true,
}: SparklineProps) {
  const n = data.length;
  if (n < 2) {
    return (
      <svg
        viewBox={`0 0 ${width} ${height}`}
        className={cn('overflow-visible', className)}
        aria-hidden
      >
        <line
          x1={0}
          y1={height - 1}
          x2={width}
          y2={height - 1}
          className={cn(stroke, 'opacity-30')}
          strokeWidth={1}
        />
      </svg>
    );
  }

  const max = Math.max(...data, 1);
  const stepX = width / (n - 1);
  const yFor = (v: number) =>
    height - 1 - (v / max) * (height - 2);

  const points = data.map((v, i) => [i * stepX, yFor(v)] as const);
  const linePath = points
    .map(([x, y], i) => `${i === 0 ? 'M' : 'L'}${x.toFixed(2)},${y.toFixed(2)}`)
    .join(' ');
  const areaPath =
    `M0,${height} ` +
    points.map(([x, y]) => `L${x.toFixed(2)},${y.toFixed(2)}`).join(' ') +
    ` L${width},${height} Z`;

  const [lastX, lastY] = points[points.length - 1];

  return (
    <svg
      viewBox={`0 0 ${width} ${height}`}
      preserveAspectRatio="none"
      className={cn('overflow-visible', className)}
      aria-hidden
    >
      <path d={areaPath} className={cn(fill, 'stroke-none')} />
      <path
        d={linePath}
        className={cn(stroke, 'fill-none')}
        strokeWidth={1.25}
        strokeLinecap="round"
        strokeLinejoin="round"
        vectorEffect="non-scaling-stroke"
      />
      {showLastDot && (
        <circle cx={lastX} cy={lastY} r={1.6} className={cn(stroke, 'fill-current')} />
      )}
    </svg>
  );
}
