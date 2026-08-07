'use client';

import { useEffect, useState } from 'react';
import { AlertTriangle, X } from 'lucide-react';
import { checkVersionCompatibility, type CompatibilityStatus } from '@/lib/version-check';

// Shown at the top of the app when the backend and desktop are out of sync.
// Non-blocking — lets the user keep working, but warns that some features
// may not work. Poll every 5 minutes so it clears itself after an upgrade.

const POLL_INTERVAL_MS = 5 * 60 * 1000;
const DISMISSED_KEY = 'maestro-version-banner-dismissed';

export function VersionBanner() {
  const [status, setStatus] = useState<CompatibilityStatus | null>(null);
  const [dismissed, setDismissed] = useState(false);

  useEffect(() => {
    setDismissed(sessionStorage.getItem(DISMISSED_KEY) === '1');
  }, []);

  useEffect(() => {
    let cancelled = false;

    async function run() {
      const result = await checkVersionCompatibility();
      if (!cancelled) setStatus(result);
    }

    run();
    const interval = setInterval(run, POLL_INTERVAL_MS);
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, []);

  if (!status || status.ok || dismissed) return null;
  if (status.reason === 'unreachable') return null; // Don't spam during auth/setup

  const severityClass =
    status.reason === 'backend_too_old'
      ? 'bg-amber-500/10 border-amber-500/40 text-amber-600 dark:text-amber-400'
      : 'bg-red-500/10 border-red-500/40 text-red-600 dark:text-red-400';

  return (
    <div className={`border-b ${severityClass}`}>
      <div className="mx-auto flex max-w-7xl items-start gap-3 px-4 py-2.5">
        <AlertTriangle className="h-4 w-4 mt-0.5 shrink-0" />
        <p className="text-sm flex-1">{status.message}</p>
        <button
          onClick={() => {
            sessionStorage.setItem(DISMISSED_KEY, '1');
            setDismissed(true);
          }}
          className="shrink-0 opacity-70 hover:opacity-100"
          aria-label="Dismiss"
        >
          <X className="h-4 w-4" />
        </button>
      </div>
    </div>
  );
}
