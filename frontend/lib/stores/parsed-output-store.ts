import { create } from 'zustand';
import type { ParsedBlock } from '@/lib/terminal-parser';

interface ParsedOutputState {
  /** Map of sessionKey → ParsedBlock[] */
  sessions: Map<string, ParsedBlock[]>;

  /** Add a new block to a session */
  addBlock: (sessionKey: string, block: ParsedBlock) => void;

  /** Update an existing block's content (for streaming updates) */
  updateBlock: (sessionKey: string, blockId: string, content: string) => void;

  /** Get blocks for a session */
  getBlocks: (sessionKey: string) => ParsedBlock[];

  /** Clear blocks for a session */
  clearSession: (sessionKey: string) => void;

  /** Clear all sessions */
  clearAll: () => void;

  /** Get total finding count for a session */
  getFindingCount: (sessionKey: string) => number;

  /** Get findings by severity for a session */
  getFindingsBySeverity: (sessionKey: string) => Record<string, number>;
}

// --- Backpressure: coalesce high-frequency block appends --------------------
// Heavy scan output (nmap -p-, nuclei, nikto) emits 100+ parsed blocks/sec.
// Committing each one synchronously — new Map + new array + Zustand notify →
// React re-render of every subscriber (header counts, badges, sidebar) — backs
// up the render queue and freezes the UI (issue #19, the parser→store→React
// path, distinct from the Rust docker-poll freeze fixed in A1/A2/A3).
//
// Instead we buffer incoming blocks and flush them in a SINGLE store update on
// the next animation frame: N appends/frame collapse into one Map copy and one
// notify, capping store churn at ≤60 updates/sec regardless of output rate.
// Blocks arriving during a flush queue for the following frame. Reads stay on
// committed state — React reads happen inside renders, which only fire after a
// flush, so subscribers always converge within a frame.
const pendingBlocks = new Map<string, ParsedBlock[]>();
let flushScheduled = false;

function flushPending() {
  flushScheduled = false;
  if (pendingBlocks.size === 0) return;
  useParsedOutputStore.setState((state) => {
    const newSessions = new Map(state.sessions);
    for (const [sessionKey, blocks] of pendingBlocks) {
      const existing = newSessions.get(sessionKey) || [];
      newSessions.set(sessionKey, existing.concat(blocks));
    }
    return { sessions: newSessions };
  });
  pendingBlocks.clear();
}

function scheduleFlush() {
  if (flushScheduled) return;
  flushScheduled = true;
  if (typeof requestAnimationFrame === 'function') {
    requestAnimationFrame(flushPending);
  } else {
    setTimeout(flushPending, 16);
  }
}

export const useParsedOutputStore = create<ParsedOutputState>((set, get) => ({
  sessions: new Map(),

  addBlock: (sessionKey, block) => {
    // Enqueue; the rAF-batched flush commits all pending blocks in one update.
    const queued = pendingBlocks.get(sessionKey);
    if (queued) {
      queued.push(block);
    } else {
      pendingBlocks.set(sessionKey, [block]);
    }
    scheduleFlush();
  },

  updateBlock: (sessionKey, blockId, content) =>
    set((state) => {
      const newSessions = new Map(state.sessions);
      const blocks = newSessions.get(sessionKey);
      if (!blocks) return state;

      const updated = blocks.map((b) =>
        b.id === blockId ? { ...b, content } : b
      );
      newSessions.set(sessionKey, updated);
      return { sessions: newSessions };
    }),

  getBlocks: (sessionKey) => get().sessions.get(sessionKey) || [],

  clearSession: (sessionKey) => {
    // Drop any not-yet-flushed blocks so a clear can't be undone by a late flush.
    pendingBlocks.delete(sessionKey);
    set((state) => {
      const newSessions = new Map(state.sessions);
      newSessions.delete(sessionKey);
      return { sessions: newSessions };
    });
  },

  clearAll: () => {
    pendingBlocks.clear();
    set({ sessions: new Map() });
  },

  getFindingCount: (sessionKey) => {
    const blocks = get().sessions.get(sessionKey) || [];
    return blocks.filter((b) => b.type === 'finding_detected').length;
  },

  getFindingsBySeverity: (sessionKey) => {
    const blocks = get().sessions.get(sessionKey) || [];
    const findings = blocks.filter((b) => b.type === 'finding_detected');
    const counts: Record<string, number> = {};
    for (const f of findings) {
      const severity = (f.metadata as { severity?: string })?.severity || 'info';
      counts[severity] = (counts[severity] || 0) + 1;
    }
    return counts;
  },
}));
