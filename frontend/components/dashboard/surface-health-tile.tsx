'use client';

import { cn } from '@/lib/utils';
import type { LucideIcon } from 'lucide-react';

// =============================================================================
// SurfaceHealthTile — one compact "surface health" card in the strip at the top
// of the Coverage Dashboard. Headlines the surface's full finding count (full
// scope) with the critical+high count as a secondary danger signal, plus a
// last-scan recency dot. Clicking sets the FilterBar surface lens (handled by
// parent).
// =============================================================================

export interface SurfaceHealthTileProps {
  label: string;
  icon: LucideIcon;
  /** critical + high findings on this surface (secondary danger signal). */
  critHigh: number;
  /** total findings on this surface — the headline number (full scope). */
  total: number;
  /** ISO string of the most recent scan/assessment on this surface, if any. */
  lastActivity?: string | null;
  active?: boolean;
  onClick?: () => void;
  /** When false, the surface has no data yet (e.g. Identity). Renders muted. */
  enabled?: boolean;
}

function recency(iso: string | null | undefined): { label: string; dot: string } {
  if (!iso) return { label: 'No activity', dot: 'bg-muted-foreground/40' };
  const t = new Date(iso).getTime();
  if (!Number.isFinite(t)) return { label: 'No activity', dot: 'bg-muted-foreground/40' };
  const days = Math.floor((Date.now() - t) / 86_400_000);
  if (days <= 1) return { label: 'Active today', dot: 'bg-emerald-400' };
  if (days <= 7) return { label: `${days}d ago`, dot: 'bg-emerald-400' };
  if (days <= 30) return { label: `${days}d ago`, dot: 'bg-amber-400' };
  return { label: `${days}d ago`, dot: 'bg-red-400' };
}

export function SurfaceHealthTile({
  label,
  icon: Icon,
  critHigh,
  total,
  lastActivity,
  active,
  onClick,
  enabled = true,
}: SurfaceHealthTileProps) {
  const r = recency(lastActivity);

  return (
    <button
      type="button"
      onClick={onClick}
      disabled={!enabled}
      className={cn(
        'glass-card rounded-xl p-4 text-left transition-all w-full',
        enabled ? 'hover-lift cursor-pointer' : 'opacity-50 cursor-default',
        active && 'ring-1 ring-primary/50',
        critHigh > 0 && enabled && 'glow-high',
      )}
    >
      <div className="flex items-center gap-2 mb-3">
        <div className="rounded-lg bg-primary/10 p-1.5">
          <Icon className="h-4 w-4 text-primary" />
        </div>
        <span className="text-sm font-medium">{label}</span>
        <span className="ml-auto flex items-center gap-1.5 text-[11px] text-muted-foreground">
          <span className={cn('h-1.5 w-1.5 rounded-full', r.dot)} />
          {r.label}
        </span>
      </div>

      {enabled ? (
        <div className="flex items-baseline gap-2">
          <span className={cn(
            'text-2xl font-bold tabular-nums',
            critHigh > 0 ? 'text-orange-400' : total > 0 ? 'text-foreground' : 'text-muted-foreground/60',
          )}>
            {total}
          </span>
          <span className="text-[11px] text-muted-foreground">findings</span>
          <span className="ml-auto text-[11px] text-muted-foreground tabular-nums">
            {critHigh} crit + high
          </span>
        </div>
      ) : (
        <div className="text-xs text-muted-foreground/70">Not yet available</div>
      )}
    </button>
  );
}
