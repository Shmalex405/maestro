'use client';

import { useEffect, useState } from 'react';
import { api } from '@/lib/tauri-api';

export type AssessmentLiveStatus = 'unknown' | 'live' | 'idle';

/**
 * Polls whether an assessment's tmux session is alive inside the Kali
 * container. "Live" means reopening the pane will reattach to a running
 * claude — vs "idle" where the user starts fresh.
 *
 * Polls every 10s and re-checks on window focus. Cheap (just a docker exec
 * with tmux has-session, exit-code only — no output to parse).
 */
export function useAssessmentLiveStatus(
  assessmentId: string | null | undefined,
): AssessmentLiveStatus {
  const [status, setStatus] = useState<AssessmentLiveStatus>('unknown');

  useEffect(() => {
    if (!assessmentId) {
      setStatus('unknown');
      return;
    }
    let cancelled = false;

    const check = async () => {
      try {
        const live = await api.terminal.checkAssessmentSessionLive(assessmentId);
        if (!cancelled) setStatus(live ? 'live' : 'idle');
      } catch {
        if (!cancelled) setStatus('unknown');
      }
    };

    check();
    const interval = setInterval(check, 10_000);

    const onFocus = () => check();
    window.addEventListener('focus', onFocus);

    return () => {
      cancelled = true;
      clearInterval(interval);
      window.removeEventListener('focus', onFocus);
    };
  }, [assessmentId]);

  return status;
}
