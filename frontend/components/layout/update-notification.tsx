'use client';

import { useEffect, useRef, useState } from 'react';
import { check, type Update } from '@tauri-apps/plugin-updater';
import { relaunch } from '@tauri-apps/plugin-process';
import { getCurrentWindow } from '@tauri-apps/api/window';
import { Download, RefreshCw, X } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { toast } from 'sonner';

// Poll the updater endpoint frequently so desktop clients stay aligned with
// backend deploys — if a backend release ships a version gate bump, the
// desktop should pick up the matching build within a few minutes, not an hour.
const POLL_INTERVAL_MS = 5 * 60 * 1000;

type InstallPhase = 'idle' | 'downloading' | 'installing';

export function UpdateNotification() {
  const [update, setUpdate] = useState<Update | null>(null);
  const [phase, setPhase] = useState<InstallPhase>('idle');
  const [deferred, setDeferred] = useState(false);
  const downloadedRef = useRef(false);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    // Only run inside the Tauri shell — Tauri APIs aren't available in a
    // plain browser dev preview. Guard so Next.js SSR / web builds don't
    // blow up importing these.
    if (typeof window === 'undefined' || !('__TAURI_INTERNALS__' in window)) {
      return;
    }

    let cancelled = false;

    const runCheck = async () => {
      try {
        const next = await check();
        if (cancelled) return;
        if (next && (!update || next.version !== update.version)) {
          setUpdate(next);
          setDeferred(false);
          downloadedRef.current = false;
        }
      } catch (err) {
        // Network errors, signing failures, etc. Keep quiet — the banner
        // just won't appear.
        console.warn('[updater] check failed', err);
      }
    };

    runCheck();
    pollRef.current = setInterval(runCheck, POLL_INTERVAL_MS);

    const unlistenPromise = getCurrentWindow().onCloseRequested(async (event) => {
      if (!deferred || !update) return;
      event.preventDefault();
      try {
        setPhase('installing');
        toast.loading('Installing update before close…', { id: 'update-close' });
        // download() is a no-op if we already staged bytes.
        if (!downloadedRef.current) {
          await update.download();
          downloadedRef.current = true;
        }
        await update.install();
      } catch (err) {
        console.error('[updater] install-on-close failed', err);
      } finally {
        toast.dismiss('update-close');
        await getCurrentWindow().destroy();
      }
    });

    return () => {
      cancelled = true;
      if (pollRef.current) clearInterval(pollRef.current);
      unlistenPromise.then((unlisten) => unlisten()).catch(() => {});
    };
    // deferred + update are read inside the close handler via closures; we
    // intentionally re-register when they change so the handler sees fresh
    // values.
  }, [update, deferred]);

  // Pre-download in the background so "Install & restart" is instant.
  useEffect(() => {
    if (!update || downloadedRef.current) return;
    let cancelled = false;
    (async () => {
      try {
        setPhase('downloading');
        await update.download();
        if (cancelled) return;
        downloadedRef.current = true;
        setPhase('idle');
      } catch (err) {
        console.warn('[updater] background download failed', err);
        if (!cancelled) setPhase('idle');
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [update]);

  if (!update) return null;

  const handleInstallNow = async () => {
    try {
      setPhase('installing');
      if (!downloadedRef.current) {
        await update.download();
        downloadedRef.current = true;
      }
      await update.install();
      await relaunch();
    } catch (err) {
      setPhase('idle');
      toast.error(
        `Update failed: ${err instanceof Error ? err.message : String(err)}`
      );
    }
  };

  const handleDeferToQuit = () => {
    setDeferred(true);
    toast.success(`Maestro ${update.version} will install when you quit.`);
  };

  if (deferred) return null;

  return (
    <div className="border-b border-primary/30 bg-primary/10 px-4 py-2.5 text-sm">
      <div className="mx-auto flex max-w-6xl items-center gap-3">
        <Download className="h-4 w-4 text-primary" />
        <span className="flex-1">
          <span className="font-medium">Maestro {update.version}</span> is
          available.
          {update.body && (
            <span className="text-muted-foreground ml-2">{update.body}</span>
          )}
        </span>
        <Button
          size="sm"
          onClick={handleInstallNow}
          disabled={phase === 'installing'}
        >
          {phase === 'installing' ? (
            <>
              <RefreshCw className="mr-1.5 h-3.5 w-3.5 animate-spin" />
              Installing…
            </>
          ) : (
            <>
              <RefreshCw className="mr-1.5 h-3.5 w-3.5" />
              Install &amp; restart
            </>
          )}
        </Button>
        <Button
          size="sm"
          variant="outline"
          onClick={handleDeferToQuit}
          disabled={phase === 'installing'}
        >
          Install on quit
        </Button>
        <button
          aria-label="Dismiss"
          onClick={() => setUpdate(null)}
          className="text-muted-foreground hover:text-foreground"
        >
          <X className="h-4 w-4" />
        </button>
      </div>
    </div>
  );
}
