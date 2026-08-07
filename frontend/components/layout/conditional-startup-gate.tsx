'use client';

import { useEffect } from 'react';
import { isWebMode } from '@/lib/deploy-mode';
import { StartupGate } from './startup-gate';
import { useInfraStore } from '@/lib/stores/infrastructure-store';

function WebInfraProvider({ children }: { children: React.ReactNode }) {
  const checkStatus = useInfraStore((s) => s.checkStatus);

  // Check infrastructure status on mount (non-blocking)
  useEffect(() => {
    checkStatus();
  }, [checkStatus]);

  return <>{children}</>;
}

export function ConditionalStartupGate({ children }: { children: React.ReactNode }) {
  if (isWebMode()) {
    return <WebInfraProvider>{children}</WebInfraProvider>;
  }
  return <StartupGate>{children}</StartupGate>;
}
