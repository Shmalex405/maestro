import { useCallback, useRef } from 'react';
import { api } from '@/lib/tauri-api';
import { useTerminalStore } from '@/lib/stores/terminal-store';
import type { TerminalSessionState } from '@/lib/stores/terminal-store';

export interface SpawnOptions {
  assessmentId?: string;
  assessmentType?: string;
  targets?: string[];
  initialPrompt?: string;
}

export function useTerminalSession() {
  const { setSession, removeSession, updateSessionStatus, getSession } = useTerminalStore();
  const cleanupRefs = useRef<Map<string, () => void>>(new Map());

  const spawnSession = useCallback(
    async (key: string, options: SpawnOptions = {}) => {
      try {
        // Call backend to register session and check claude availability
        const result = await api.terminal.spawn({
          assessment_id: options.assessmentId,
          assessment_type: options.assessmentType,
          targets: options.targets,
          initial_prompt: options.initialPrompt,
        });

        const sessionState: TerminalSessionState = {
          sessionId: result.session_id,
          assessmentId: options.assessmentId,
          status: result.claude_available ? 'spawning' : 'error',
          errorMessage: result.claude_available
            ? undefined
            : 'No CLI found. Install maestro (npm link in cli/) or Claude Code CLI.',
        };

        setSession(key, sessionState);

        return {
          sessionId: result.session_id,
          claudeAvailable: result.claude_available,
          workingDir: result.working_dir,
          workingDirContainer: result.working_dir_container,
          cliCommand: result.cli_command || 'claude',
        };
      } catch (err) {
        const errorMessage = err instanceof Error ? err.message : String(err);
        setSession(key, {
          sessionId: '',
          assessmentId: options.assessmentId,
          status: 'error',
          errorMessage,
        });
        return null;
      }
    },
    [setSession]
  );

  const killSession = useCallback(
    async (key: string) => {
      const session = getSession(key);
      if (!session) return;

      // Run cleanup function if exists
      const cleanup = cleanupRefs.current.get(key);
      if (cleanup) {
        cleanup();
        cleanupRefs.current.delete(key);
      }

      // Notify backend
      if (session.sessionId) {
        try {
          await api.terminal.end(session.sessionId, undefined);
        } catch {
          // Ignore errors when ending session
        }
      }

      removeSession(key);
    },
    [getSession, removeSession]
  );

  const restartSession = useCallback(
    async (key: string, options: SpawnOptions = {}) => {
      await killSession(key);
      return spawnSession(key, options);
    },
    [killSession, spawnSession]
  );

  const linkToAssessment = useCallback(
    async (key: string, assessmentId: string) => {
      const session = getSession(key);
      if (session?.sessionId) {
        try {
          await api.terminal.linkToAssessment(session.sessionId, assessmentId);
        } catch {
          // Ignore
        }
      }
    },
    [getSession]
  );

  const registerCleanup = useCallback((key: string, cleanup: () => void) => {
    cleanupRefs.current.set(key, cleanup);
  }, []);

  return {
    spawnSession,
    killSession,
    restartSession,
    linkToAssessment,
    updateSessionStatus,
    registerCleanup,
  };
}
