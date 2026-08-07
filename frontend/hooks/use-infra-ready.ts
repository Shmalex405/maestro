'use client';

import { useState, useCallback, useRef } from 'react';
import { useInfraStore } from '@/lib/stores/infrastructure-store';
import { isWebMode } from '@/lib/deploy-mode';

export function useInfraReady() {
  const status = useInfraStore((s) => s.status);
  const healthy = useInfraStore((s) => s.healthy);
  const [showGate, setShowGate] = useState(false);
  const resolveRef = useRef<((ready: boolean) => void) | null>(null);

  const isReady = status === 'running' && healthy;

  const ensureReady = useCallback(async (): Promise<boolean> => {
    // Desktop mode always ready
    if (!isWebMode()) return true;
    // Already running and healthy
    if (isReady) return true;
    // Not provisioned — can't auto-start
    if (status === 'not_provisioned') return false;

    // Show the auto-start gate
    return new Promise<boolean>((resolve) => {
      resolveRef.current = resolve;
      setShowGate(true);
    });
  }, [status, isReady]);

  const handleComplete = useCallback(() => {
    setShowGate(false);
    resolveRef.current?.(true);
    resolveRef.current = null;
  }, []);

  const handleCancel = useCallback(() => {
    setShowGate(false);
    resolveRef.current?.(false);
    resolveRef.current = null;
  }, []);

  return { ensureReady, showGate, handleComplete, handleCancel, isReady };
}
