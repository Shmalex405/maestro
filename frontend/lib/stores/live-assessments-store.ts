import { create } from 'zustand';

export type LiveSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface LiveSeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface LiveAssessment {
  id: string;
  name: string;
  startedAt: number;
  collapsed: boolean;
  counts: LiveSeverityCounts;
  status: 'running' | 'completed' | 'failed' | 'idle';
}

interface LiveAssessmentsStore {
  /** Keyed by assessment id. Map so iteration order is insertion-stable. */
  byId: Map<string, LiveAssessment>;
  /** Master collapse for the whole popup. When true the stack of cards
   *  is hidden behind the header pill (still mounted, still polling). */
  masterCollapsed: boolean;

  register: (id: string, name: string) => void;
  setName: (id: string, name: string) => void;
  setCounts: (id: string, counts: LiveSeverityCounts) => void;
  setStatus: (id: string, status: LiveAssessment['status']) => void;
  setCollapsed: (id: string, collapsed: boolean) => void;
  unregister: (id: string) => void;
  setMasterCollapsed: (collapsed: boolean) => void;
  dismissCompleted: () => void;
}

const emptyCounts = (): LiveSeverityCounts => ({
  critical: 0,
  high: 0,
  medium: 0,
  low: 0,
  info: 0,
});

export const useLiveAssessmentsStore = create<LiveAssessmentsStore>((set) => ({
  byId: new Map(),
  masterCollapsed: false,

  register: (id, name) =>
    set((state) => {
      // Already tracked — just refresh the name in case it was renamed.
      const existing = state.byId.get(id);
      if (existing) {
        if (existing.name === name) return state;
        const next = new Map(state.byId);
        next.set(id, { ...existing, name });
        return { ...state, byId: next };
      }
      const next = new Map(state.byId);
      next.set(id, {
        id,
        name,
        startedAt: Date.now(),
        collapsed: false,
        counts: emptyCounts(),
        status: 'running',
      });
      return { ...state, byId: next };
    }),

  setName: (id, name) =>
    set((state) => {
      const existing = state.byId.get(id);
      if (!existing || existing.name === name) return state;
      const next = new Map(state.byId);
      next.set(id, { ...existing, name });
      return { ...state, byId: next };
    }),

  setCounts: (id, counts) =>
    set((state) => {
      const existing = state.byId.get(id);
      if (!existing) return state;
      // Skip the update when counts haven't changed — prevents needless
      // re-renders on every parser tick when nothing new was found.
      if (
        existing.counts.critical === counts.critical &&
        existing.counts.high === counts.high &&
        existing.counts.medium === counts.medium &&
        existing.counts.low === counts.low &&
        existing.counts.info === counts.info
      ) {
        return state;
      }
      const next = new Map(state.byId);
      next.set(id, { ...existing, counts });
      return { ...state, byId: next };
    }),

  setStatus: (id, status) =>
    set((state) => {
      const existing = state.byId.get(id);
      if (!existing || existing.status === status) return state;
      const next = new Map(state.byId);
      next.set(id, { ...existing, status });
      return { ...state, byId: next };
    }),

  setCollapsed: (id, collapsed) =>
    set((state) => {
      const existing = state.byId.get(id);
      if (!existing || existing.collapsed === collapsed) return state;
      const next = new Map(state.byId);
      next.set(id, { ...existing, collapsed });
      return { ...state, byId: next };
    }),

  unregister: (id) =>
    set((state) => {
      if (!state.byId.has(id)) return state;
      const next = new Map(state.byId);
      next.delete(id);
      return { ...state, byId: next };
    }),

  setMasterCollapsed: (masterCollapsed) =>
    set((state) =>
      state.masterCollapsed === masterCollapsed ? state : { ...state, masterCollapsed },
    ),

  // Drop every card whose status is no longer 'running'. Called from the
  // popup's "Dismiss completed" action and on the auto-dismiss timer.
  dismissCompleted: () =>
    set((state) => {
      const next = new Map(state.byId);
      let changed = false;
      for (const [id, entry] of state.byId) {
        if (entry.status !== 'running') {
          next.delete(id);
          changed = true;
        }
      }
      return changed ? { ...state, byId: next } : state;
    }),
}));

// Note: selectors that derive arrays / sums are deliberately NOT exported
// from this file. A Zustand selector that returns a freshly-allocated
// Array.from(byId.values()) every render trips React 18's
// useSyncExternalStore "getSnapshot should be cached" detector and can
// stall the entire React tree (manifested as sidebar nav going
// "not clickable" — see Desktop E2E on v1.0.14). Consumers subscribe
// to `byId` directly and derive arrays via useMemo on the component
// side, where the memo dep on the Map reference is stable.
