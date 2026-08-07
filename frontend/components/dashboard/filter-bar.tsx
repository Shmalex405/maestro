'use client';

import { useQuery } from '@tanstack/react-query';
import { Layers, ShieldAlert, CircleDot, Target as TargetIcon, Clock } from 'lucide-react';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from '@/components/ui/popover';
import { Button } from '@/components/ui/button';
import { Checkbox } from '@/components/ui/checkbox';
import { cn } from '@/lib/utils';
import { api } from '@/lib/tauri-api';
import { SEVERITY_ORDER, SEVERITY_STYLES } from '@/lib/severity';
import { SURFACE_LABELS, SURFACE_ORDER } from '@/lib/surface';
import type { Severity } from '@/lib/types';
import {
  useDashboardFilterStore,
  type Surface,
  type StatusFilter,
  type TimeWindow,
  TIME_WINDOWS,
} from '@/lib/stores/dashboard-filter-store';

// =============================================================================
// FilterBar — the shared, sticky control surface that drives every Coverage
// Dashboard widget via the dashboard-filter-store. Surface / Severity / Status
// / Target / Time-window. All shadcn Select + Popover; dense + dark.
// =============================================================================

// Derived from the shared surface taxonomy (lib/surface.ts) so labels — e.g.
// "Cloud / Infra" — stay in lockstep with the surface tiles and never drift.
const SURFACE_OPTIONS: { value: Surface; label: string }[] = [
  { value: 'all', label: SURFACE_LABELS.all },
  ...SURFACE_ORDER.map((s) => ({ value: s, label: SURFACE_LABELS[s] })),
];

const STATUS_OPTIONS: { value: StatusFilter; label: string }[] = [
  { value: 'all', label: 'All statuses' },
  { value: 'open', label: 'Open' },
  { value: 'fixed', label: 'Fixed' },
  { value: 'suppressed', label: 'Suppressed' },
];

export function FilterBar({
  className,
  showSurface = true,
}: {
  className?: string;
  /** Surface pages set their surface from the route, so they hide this. */
  showSurface?: boolean;
}) {
  const surface = useDashboardFilterStore((s) => s.surface);
  const setSurface = useDashboardFilterStore((s) => s.setSurface);
  const severities = useDashboardFilterStore((s) => s.severities);
  const toggleSeverity = useDashboardFilterStore((s) => s.toggleSeverity);
  const setSeverities = useDashboardFilterStore((s) => s.setSeverities);
  const status = useDashboardFilterStore((s) => s.status);
  const setStatus = useDashboardFilterStore((s) => s.setStatus);
  const target = useDashboardFilterStore((s) => s.target);
  const setTarget = useDashboardFilterStore((s) => s.setTarget);
  const win = useDashboardFilterStore((s) => s.window);
  const setWindow = useDashboardFilterStore((s) => s.setWindow);

  const { data: targets } = useQuery({
    queryKey: ['targets'],
    queryFn: () => api.targets.list(),
  });

  // The targets table can hold more than one row per canonical value, and
  // findings are filtered by the target STRING (findings.target = ...), not the
  // target row id. So dedupe by canonical_value and use that as the option value
  // — this both removes the duplicate rows and makes the filter actually match.
  const targetOptions = Array.from(
    new Set((targets ?? []).map((t) => t.canonical_value).filter(Boolean)),
  ).sort();

  const severityLabel =
    severities.size === 0
      ? 'All severities'
      : SEVERITY_ORDER.filter((s) => severities.has(s))
          .map((s) => SEVERITY_STYLES[s].label)
          .join(', ');

  return (
    <div className={cn('flex items-center gap-2 flex-wrap', className)}>
      {/* Surface — hidden on the dedicated per-surface pages (the sidebar has a
          separate page per surface, so the dropdown is redundant there). */}
      {showSurface && (
        <Select value={surface} onValueChange={(v) => setSurface(v as Surface)}>
          <SelectTrigger size="sm" className="h-8 text-xs min-w-[140px]">
            <Layers className="h-3.5 w-3.5 text-muted-foreground" />
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {SURFACE_OPTIONS.map((o) => (
              <SelectItem key={o.value} value={o.value} className="text-xs">
                {o.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      )}

      {/* Severity (multi-select popover) */}
      <Popover>
        <PopoverTrigger asChild>
          <Button variant="outline" size="sm" className="h-8 text-xs gap-1.5 min-w-[140px] justify-start font-normal">
            <ShieldAlert className="h-3.5 w-3.5 text-muted-foreground" />
            <span className="truncate max-w-[160px]">{severityLabel}</span>
          </Button>
        </PopoverTrigger>
        <PopoverContent align="start" className="w-48 p-2">
          <div className="space-y-1">
            {SEVERITY_ORDER.map((sev: Severity) => {
              const style = SEVERITY_STYLES[sev];
              const checked = severities.has(sev);
              return (
                <button
                  key={sev}
                  type="button"
                  onClick={() => toggleSeverity(sev)}
                  className="flex w-full items-center gap-2 rounded-md px-1.5 py-1 text-xs hover:bg-white/[0.04]"
                >
                  <Checkbox checked={checked} className="pointer-events-none" />
                  <span className={cn('h-2.5 w-2.5 rounded-sm', style.bg)} />
                  <span>{style.label}</span>
                </button>
              );
            })}
            {severities.size > 0 && (
              <button
                type="button"
                onClick={() => setSeverities(new Set())}
                className="w-full pt-1 text-left text-[11px] text-muted-foreground hover:text-foreground"
              >
                Clear
              </button>
            )}
          </div>
        </PopoverContent>
      </Popover>

      {/* Status */}
      <Select value={status} onValueChange={(v) => setStatus(v as StatusFilter)}>
        <SelectTrigger size="sm" className="h-8 text-xs min-w-[130px]">
          <CircleDot className="h-3.5 w-3.5 text-muted-foreground" />
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          {STATUS_OPTIONS.map((o) => (
            <SelectItem key={o.value} value={o.value} className="text-xs">
              {o.label}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>

      {/* Target */}
      <Select value={target || '__all__'} onValueChange={(v) => setTarget(v === '__all__' ? '' : v)}>
        <SelectTrigger size="sm" className="h-8 text-xs min-w-[160px] max-w-[240px]">
          <TargetIcon className="h-3.5 w-3.5 text-muted-foreground" />
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="__all__" className="text-xs">All targets</SelectItem>
          {targetOptions.map((cv) => (
            <SelectItem key={cv} value={cv} className="text-xs">
              <span className="truncate max-w-[200px]">{cv}</span>
            </SelectItem>
          ))}
        </SelectContent>
      </Select>

      {/* Time window */}
      <div className="inline-flex items-center gap-1.5">
        <Clock className="h-3.5 w-3.5 text-muted-foreground" />
        <div className="inline-flex rounded-md border border-border/50 overflow-hidden">
          {TIME_WINDOWS.map((w: TimeWindow, i) => (
            <button
              key={w}
              type="button"
              onClick={() => setWindow(w)}
              className={cn(
                'h-8 px-2.5 text-xs font-medium transition-colors',
                i > 0 && 'border-l border-border/50',
                win === w
                  ? 'bg-primary text-primary-foreground'
                  : 'text-muted-foreground hover:bg-white/[0.04] hover:text-foreground',
              )}
            >
              {w}d
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}
