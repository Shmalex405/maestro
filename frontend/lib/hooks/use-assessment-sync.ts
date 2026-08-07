import { useEffect } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { useTerminalStore } from '@/lib/stores/terminal-store';

/**
 * Polls assessment data every 3s while a terminal session is active,
 * so findings/status created by the CLI show up in the frontend quickly.
 */
export function useAssessmentSync(assessmentId: string | null) {
  const queryClient = useQueryClient();

  // Derive whether the terminal is actively running for this assessment
  const sessionKey = assessmentId || '__default__';
  const sessionStatus = useTerminalStore(
    (s) => s.sessions.get(sessionKey)?.status
  );
  const isActive = sessionStatus === 'running' || sessionStatus === 'spawning';

  useEffect(() => {
    if (!assessmentId || !isActive) return;

    const interval = setInterval(() => {
      queryClient.invalidateQueries({ queryKey: ['assessments'] });
    }, 3000);

    return () => clearInterval(interval);
  }, [assessmentId, isActive, queryClient]);
}
