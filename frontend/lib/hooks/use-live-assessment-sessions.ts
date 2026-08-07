'use client';

import { useQuery } from '@tanstack/react-query';
import { api, isTauri } from '@/lib/tauri-api';
import { useEffect } from 'react';

/**
 * Returns a Set of assessment IDs whose tmux sessions are currently alive
 * inside the Kali container. Single docker exec covers the whole list, so
 * rendering N rows is the same cost as 1.
 *
 * React Query handles dedupe — multiple components calling this hook share
 * one underlying fetch.
 */
export function useLiveAssessmentSessions(): {
  liveIds: Set<string>;
  isLoading: boolean;
} {
  const { data, refetch, isLoading } = useQuery({
    queryKey: ['live-assessment-sessions'],
    queryFn: () => api.terminal.listLiveAssessmentSessions(),
    refetchInterval: 10_000,
    staleTime: 5_000,
    enabled: isTauri(),
  });

  // Refetch on window focus — users come back to the app expecting current state.
  useEffect(() => {
    if (!isTauri()) return;
    const onFocus = () => refetch();
    window.addEventListener('focus', onFocus);
    return () => window.removeEventListener('focus', onFocus);
  }, [refetch]);

  return {
    liveIds: new Set(data || []),
    isLoading,
  };
}
