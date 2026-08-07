import { create } from 'zustand';
import type { Terminal } from '@xterm/xterm';

export interface TerminalSessionState {
  sessionId: string;
  assessmentId?: string;
  terminal?: Terminal;
  ptyProcess?: unknown; // tauri-pty PtyProcess
  status: 'spawning' | 'running' | 'exited' | 'error' | 'detached';
  exitCode?: number;
  errorMessage?: string;
  tmuxSessionName?: string; // e.g. "assess-abc123"
}

interface TerminalStore {
  sessions: Map<string, TerminalSessionState>;
  activeSessionKey: string | null;

  setSession: (key: string, session: TerminalSessionState) => void;
  getSession: (key: string) => TerminalSessionState | undefined;
  removeSession: (key: string) => void;
  setActiveSessionKey: (key: string | null) => void;
  updateSessionStatus: (key: string, status: TerminalSessionState['status'], exitCode?: number, errorMessage?: string) => void;
  clearAll: () => void;
}

export const useTerminalStore = create<TerminalStore>((set, get) => ({
  sessions: new Map(),
  activeSessionKey: null,

  setSession: (key, session) =>
    set((state) => {
      const newSessions = new Map(state.sessions);
      newSessions.set(key, session);
      return { sessions: newSessions };
    }),

  getSession: (key) => get().sessions.get(key),

  removeSession: (key) =>
    set((state) => {
      const newSessions = new Map(state.sessions);
      const session = newSessions.get(key);
      if (session?.terminal) {
        session.terminal.dispose();
      }
      newSessions.delete(key);
      return {
        sessions: newSessions,
        activeSessionKey: state.activeSessionKey === key ? null : state.activeSessionKey,
      };
    }),

  setActiveSessionKey: (key) => set({ activeSessionKey: key }),

  updateSessionStatus: (key, status, exitCode, errorMessage) =>
    set((state) => {
      const newSessions = new Map(state.sessions);
      const session = newSessions.get(key);
      if (session) {
        newSessions.set(key, { ...session, status, exitCode, errorMessage });
      }
      return { sessions: newSessions };
    }),

  clearAll: () =>
    set((state) => {
      state.sessions.forEach((session) => {
        if (session.terminal) {
          session.terminal.dispose();
        }
      });
      return { sessions: new Map(), activeSessionKey: null };
    }),
}));
