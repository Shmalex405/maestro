'use client';

import { Table2, TrendingUp, LayoutGrid } from 'lucide-react';
import { cn } from '@/lib/utils';

// =============================================================================
// ViewToggle — segmented Table ⇄ Board ⇄ Trend control for the Coverage
// Dashboard. Board is the status-kanban triage view (board-view.tsx). Uses the
// same inline-flex bordered-segment idiom as the RANGE_PRESETS toggle in
// FindingsOverTime so it reads as part of the same control family.
// =============================================================================

export type DashboardView = 'table' | 'board' | 'trend';

const VIEWS: { value: DashboardView; label: string; icon: typeof Table2 }[] = [
  { value: 'table', label: 'Table', icon: Table2 },
  { value: 'board', label: 'Board', icon: LayoutGrid },
  { value: 'trend', label: 'Trend', icon: TrendingUp },
];

export function ViewToggle({
  value,
  onChange,
  className,
}: {
  value: DashboardView;
  onChange: (v: DashboardView) => void;
  className?: string;
}) {
  return (
    <div className={cn('inline-flex rounded-md border border-border/50 overflow-hidden', className)}>
      {VIEWS.map((v, i) => {
        const Icon = v.icon;
        const active = value === v.value;
        return (
          <button
            key={v.value}
            type="button"
            onClick={() => onChange(v.value)}
            className={cn(
              'inline-flex items-center gap-1.5 h-7 px-2.5 text-xs font-medium transition-colors',
              i > 0 && 'border-l border-border/50',
              active
                ? 'bg-primary text-primary-foreground'
                : 'text-muted-foreground hover:bg-white/[0.04] hover:text-foreground',
            )}
          >
            <Icon className="h-3.5 w-3.5" />
            {v.label}
          </button>
        );
      })}
    </div>
  );
}
