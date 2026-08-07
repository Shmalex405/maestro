import { create } from 'zustand';
import type { Severity } from '@/lib/types';

// =============================================================================
// DASHBOARD FILTER STORE
//
// Single source of truth for the Coverage Dashboard's FilterBar selections.
// Every dashboard widget (donut, trend, surface strip, rails) reads from this
// store so the bar drives them all. Mirrors the lightweight Zustand pattern in
// terminal-store.ts.
//
// Surface is a LENS over `source` + `target.target_type` (the findings/page.tsx
// categoryTabs precedent), never a separate data silo. Time window is in days.
//
// URL sync: the dashboard page reads ?surface=&severity=&status=&target=&window=
// on mount (hydrateFromParams) and pushes changes back via toQuery() so a
// filtered dashboard is shareable and "View all" deep-links can carry the filter
// straight into /findings.
// =============================================================================

export type Surface = 'all' | 'web' | 'cloud' | 'identity' | 'code' | 'ai';
export type StatusFilter = 'all' | 'open' | 'fixed' | 'suppressed';
// Cross-cutting exploitation lens (mirrors the Findings page's Exploited pills):
// 'any' = exploitable in (true, potentially), 'fully' = 'true', 'partial' =
// 'potentially'. 'all' = no exploitation filter.
export type ExploitedFilter = 'all' | 'any' | 'fully' | 'partial';

export const TIME_WINDOWS = [7, 30, 90] as const;
export type TimeWindow = (typeof TIME_WINDOWS)[number];

export interface DashboardFilterState {
  surface: Surface;
  /** Multi-select; empty set = all severities. */
  severities: Set<Severity>;
  status: StatusFilter;
  /** Cross-cutting exploitation lens — narrows to fully/partially exploited. */
  exploited: ExploitedFilter;
  /** Canonical target_id from GET /targets, or '' for all targets. */
  target: string;
  window: TimeWindow;

  setSurface: (s: Surface) => void;
  toggleSeverity: (s: Severity) => void;
  setSeverities: (s: Set<Severity>) => void;
  setStatus: (s: StatusFilter) => void;
  /** Set the exploited lens; passing the active value clears it (toggle). */
  setExploited: (e: ExploitedFilter) => void;
  setTarget: (id: string) => void;
  setWindow: (w: TimeWindow) => void;
  reset: () => void;

  hydrateFromParams: (params: URLSearchParams) => void;
  toQuery: () => string;
}

const SURFACES: Surface[] = ['all', 'web', 'cloud', 'identity', 'code', 'ai'];
const STATUSES: StatusFilter[] = ['all', 'open', 'fixed', 'suppressed'];
const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

const DEFAULTS = {
  surface: 'all' as Surface,
  severities: new Set<Severity>(),
  status: 'all' as StatusFilter,
  exploited: 'all' as ExploitedFilter,
  target: '',
  window: 30 as TimeWindow,
};

export const useDashboardFilterStore = create<DashboardFilterState>((set, get) => ({
  ...DEFAULTS,

  setSurface: (surface) => set({ surface }),
  toggleSeverity: (sev) =>
    set((state) => {
      const next = new Set(state.severities);
      if (next.has(sev)) next.delete(sev);
      else next.add(sev);
      return { severities: next };
    }),
  setSeverities: (severities) => set({ severities: new Set(severities) }),
  setStatus: (status) => set({ status }),
  setExploited: (exploited) =>
    set((state) => ({ exploited: state.exploited === exploited ? 'all' : exploited })),
  setTarget: (target) => set({ target }),
  setWindow: (window) => set({ window }),
  reset: () => set({ ...DEFAULTS, severities: new Set() }),

  hydrateFromParams: (params) => {
    const next: Partial<DashboardFilterState> = {};

    const surface = params.get('surface');
    if (surface && SURFACES.includes(surface as Surface)) {
      next.surface = surface as Surface;
    }

    const sevParam = params.get('severity');
    if (sevParam) {
      const parsed = sevParam
        .split(',')
        .map((s) => s.trim())
        .filter((s): s is Severity => SEVERITIES.includes(s as Severity));
      next.severities = new Set(parsed);
    }

    const status = params.get('status');
    if (status && STATUSES.includes(status as StatusFilter)) {
      next.status = status as StatusFilter;
    }

    const target = params.get('target');
    if (target) next.target = target;

    const win = Number(params.get('window'));
    if (TIME_WINDOWS.includes(win as TimeWindow)) {
      next.window = win as TimeWindow;
    }

    if (Object.keys(next).length > 0) set(next);
  },

  toQuery: () => {
    const { surface, severities, status, target, window } = get();
    const params = new URLSearchParams();
    if (surface !== 'all') params.set('surface', surface);
    if (severities.size > 0) {
      params.set('severity', SEVERITIES.filter((s) => severities.has(s)).join(','));
    }
    if (status !== 'all') params.set('status', status);
    if (target) params.set('target', target);
    if (window !== 30) params.set('window', String(window));
    const qs = params.toString();
    return qs ? `?${qs}` : '';
  },
}));
