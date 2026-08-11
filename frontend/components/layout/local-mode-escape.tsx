'use client';

// The startup escape hatch.
//
// Shown on the discovery and sign-in gates once they have actually failed. Both
// of those depend on a Groovy-hosted endpoint answering — /api/discover for
// discovery, the Cognito Hosted UI for browser sign-in — and when one is down
// the user is parked on a screen whose only action is to try again, in front of
// a product that does not need either. Scanners, the Kali container, the agents
// and the report pipeline all run locally; the account only decides where
// findings are STORED.
//
// Two deliberate constraints:
//
//   1. Only after a failure. Offered up front it reads as a mode picker and
//      invites a paying user to wander out of their team's data by accident.
//   2. Never automatic. Local mode shows an empty local SQLite DB, so an
//      install that silently switched itself would present as "all my findings
//      vanished" — the failure DEFAULT_MODE in deployment-mode.ts exists to
//      prevent. The copy below states the consequence and the way back before
//      the click, not after.

import { useState } from 'react';
import { Button } from '@/components/ui/button';
import { HardDrive, Loader2 } from 'lucide-react';

interface LocalModeEscapeProps {
  /** Switch to local mode and re-run startup. */
  onUseLocalMode: () => void | Promise<void>;
  /** What failed, so the copy can name it rather than gesturing at "an error". */
  context: 'discovery' | 'signin';
}

export function LocalModeEscape({ onUseLocalMode, context }: LocalModeEscapeProps) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  async function handleClick() {
    setBusy(true);
    setError('');
    try {
      await onUseLocalMode();
    } catch (e) {
      // Staying on this screen with the reason visible beats a dead button.
      setError(e instanceof Error ? e.message : String(e));
      setBusy(false);
    }
  }

  return (
    <div className="mt-6 border-t pt-5">
      <p className="text-sm font-medium">
        {context === 'discovery'
          ? "Can't reach the Maestro platform?"
          : "Can't sign in?"}
      </p>
      <p className="mt-1.5 text-sm text-muted-foreground">
        You can run Maestro entirely on this machine instead. Assessments,
        findings, reports and every scanner work exactly the same — the account
        only decides where findings are stored.
      </p>
      <p className="mt-2 text-sm text-muted-foreground">
        Findings already in your team&apos;s cloud workspace stay there and
        won&apos;t be visible locally. You can reconnect any time from{' '}
        <span className="font-medium text-foreground">Config → Data &amp; Sync</span>.
      </p>

      {error && (
        <p className="mt-3 text-sm text-destructive">
          Could not switch to local mode: {error}
        </p>
      )}

      <Button
        type="button"
        variant="outline"
        className="mt-4 w-full"
        onClick={handleClick}
        disabled={busy}
      >
        {busy ? (
          <>
            <Loader2 className="mr-2 h-4 w-4 animate-spin" />
            Switching…
          </>
        ) : (
          <>
            <HardDrive className="mr-2 h-4 w-4" />
            Continue without an account
          </>
        )}
      </Button>
    </div>
  );
}
