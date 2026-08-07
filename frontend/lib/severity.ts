// =============================================================================
// SEVERITY — single source of truth for severity color / label / order.
//
// This map was duplicated across app/page.tsx, app/findings/page.tsx,
// components/dashboard/findings-over-time.tsx, and
// components/dashboard/exploited-vulnerabilities.tsx. Each new viz primitive
// (donut, trend chart, coverage heatmap) needs the same colors and ordering,
// so the canonical definitions live here. New components should import from
// this module rather than re-declaring inline configs.
//
// The Tailwind class strings here are the literal classes the existing
// components used, so swapping a component over to this module is a drop-in
// replacement (no visual change).
// =============================================================================

import type { Severity } from './types';

/**
 * Canonical render order: highest severity first. Use for legends, stacked
 * bars (render critical at the bottom), donut arc order, and sort tie-breaks.
 */
export const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

/**
 * Numeric rank for sorting (critical highest). Mirrors the SEVERITY_RANK that
 * findings/page.tsx declared inline.
 */
export const SEVERITY_RANK: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

export interface SeverityStyle {
  /** Human label, title-cased. */
  label: string;
  /** Solid background class (e.g. for bars / chips). */
  bg: string;
  /** Lighter solid background class (dot / accent). */
  dot: string;
  /** Foreground text color. */
  text: string;
  /** SVG fill class (opaque). */
  fill: string;
  /** SVG fill class (translucent area). */
  fillSoft: string;
  /** SVG stroke class. */
  stroke: string;
  /** The dense glass-card badge utility class. */
  badge: string;
  /** The severity-border-* utility class. */
  border: string;
  /** The glow-* utility class (empty for info). */
  glow: string;
  /** Raw hex used for inline SVG attributes where a Tailwind class can't reach
   *  (gradients, stop-color). Matches the Tailwind-500 shade of the family. */
  hex: string;
}

export const SEVERITY_STYLES: Record<Severity, SeverityStyle> = {
  critical: {
    label: 'Critical',
    bg: 'bg-red-500',
    dot: 'bg-red-400',
    text: 'text-red-400',
    fill: 'fill-red-500',
    fillSoft: 'fill-red-500/20',
    stroke: 'stroke-red-400',
    badge: 'badge-critical',
    border: 'severity-border-critical',
    glow: 'glow-critical',
    hex: '#ef4444',
  },
  high: {
    label: 'High',
    bg: 'bg-orange-500',
    dot: 'bg-orange-400',
    text: 'text-orange-400',
    fill: 'fill-orange-500',
    fillSoft: 'fill-orange-500/20',
    stroke: 'stroke-orange-400',
    badge: 'badge-high',
    border: 'severity-border-high',
    glow: 'glow-high',
    hex: '#f97316',
  },
  medium: {
    label: 'Medium',
    bg: 'bg-yellow-500',
    dot: 'bg-yellow-400',
    text: 'text-yellow-400',
    fill: 'fill-yellow-500',
    fillSoft: 'fill-yellow-500/20',
    stroke: 'stroke-yellow-400',
    badge: 'badge-medium',
    border: 'severity-border-medium',
    glow: 'glow-medium',
    hex: '#eab308',
  },
  low: {
    label: 'Low',
    bg: 'bg-blue-500',
    dot: 'bg-blue-400',
    text: 'text-blue-400',
    fill: 'fill-blue-500',
    fillSoft: 'fill-blue-500/20',
    stroke: 'stroke-blue-400',
    badge: 'badge-low',
    border: 'severity-border-low',
    glow: 'glow-low',
    hex: '#3b82f6',
  },
  info: {
    label: 'Info',
    bg: 'bg-slate-500',
    dot: 'bg-slate-400',
    text: 'text-slate-400',
    fill: 'fill-slate-500',
    fillSoft: 'fill-slate-500/20',
    stroke: 'stroke-slate-400',
    badge: 'badge-info',
    border: 'severity-border-info',
    glow: '',
    hex: '#64748b',
  },
};

/** Lookup helper that tolerates an unknown / missing severity string by
 *  falling back to `info` (the neutral bucket). */
export function severityStyle(sev: string | null | undefined): SeverityStyle {
  if (sev && sev in SEVERITY_STYLES) {
    return SEVERITY_STYLES[sev as Severity];
  }
  return SEVERITY_STYLES.info;
}

/** Title-cased label for a severity string. */
export function severityLabel(sev: string | null | undefined): string {
  return severityStyle(sev).label;
}
