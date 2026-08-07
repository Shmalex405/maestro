'use client';

import { useEffect, useRef, useState } from 'react';
import { api } from '@/lib/tauri-api';
import { Button } from '@/components/ui/button';
import { Play, Loader2 } from 'lucide-react';
import '@xterm/xterm/css/xterm.css';

interface TranscriptViewProps {
  assessmentId: string;
  /** Whether the conversation can be turned back into a live session:
   *   'resumable' — Claude's .jsonl is still in the container → "Resume
   *                 session" reloads the full graph (history + tool calls).
   *   'lost'      — had a session but the file is gone (container rebuilt /
   *                 claude-home reset) → "Start fresh session"; prior context
   *                 is unrecoverable, shown clearly so an empty prompt is
   *                 never a surprise.
   *   'none'      — no stored session id (pre-v0.1.39 runs) → no button.
   *   'unknown'   — still checking → no button yet. */
  resumeContext?: 'unknown' | 'resumable' | 'lost' | 'none';
  /** Triggered by the Resume / Start-fresh button. Parent
   *  (assessment-terminal-view) flips assessment.status to 'running', which
   *  cascades through determineSessionMode → live PTY spawn. `fresh` is true
   *  for a start-fresh (drops the stale session id), false to resume. */
  onResume?: (fresh: boolean) => void | Promise<void>;
}

export function TranscriptView({ assessmentId, resumeContext = 'unknown', onResume }: TranscriptViewProps) {
  const terminalRef = useRef<HTMLDivElement>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const termRef = useRef<import('@xterm/xterm').Terminal | null>(null);

  useEffect(() => {
    let disposed = false;

    async function loadTranscript() {
      try {
        const sessions = await api.terminal.listForAssessment(assessmentId);
        const withTranscript = sessions.find(s => s.transcript);

        if (!withTranscript?.transcript || !terminalRef.current) {
          setError(withTranscript ? null : 'No transcript available for this assessment.');
          setLoading(false);
          return;
        }

        if (disposed) return;

        const [{ Terminal }, { FitAddon }] = await Promise.all([
          import('@xterm/xterm'),
          import('@xterm/addon-fit'),
        ]);

        if (disposed) return;

        const term = new Terminal({
          disableStdin: true,
          fontSize: 13,
          fontFamily: "'JetBrains Mono', 'Fira Code', 'Cascadia Code', 'Menlo', monospace",
          lineHeight: 1.2,
          theme: {
            background: '#0a0a0a',
            foreground: '#e4e4e7',
            cursor: '#0a0a0a', // hidden cursor
            cursorAccent: '#0a0a0a',
            selectionBackground: '#3f3f46',
            selectionForeground: '#fafafa',
            black: '#18181b',
            red: '#ef4444',
            green: '#22c55e',
            yellow: '#eab308',
            blue: '#3b82f6',
            magenta: '#a855f7',
            cyan: '#06b6d4',
            white: '#e4e4e7',
            brightBlack: '#52525b',
            brightRed: '#f87171',
            brightGreen: '#4ade80',
            brightYellow: '#facc15',
            brightBlue: '#60a5fa',
            brightMagenta: '#c084fc',
            brightCyan: '#22d3ee',
            brightWhite: '#fafafa',
          },
          allowTransparency: false,
          scrollback: 50000,
          convertEol: true,
          cursorBlink: false,
          cursorStyle: 'underline',
          cursorInactiveStyle: 'none',
        });

        const fitAddon = new FitAddon();
        term.loadAddon(fitAddon);
        term.open(terminalRef.current);

        try {
          fitAddon.fit();
        } catch { /* ignore fit errors */ }

        // Write the saved transcript (may contain ANSI codes for colored replay)
        term.write(withTranscript.transcript);
        termRef.current = term;

        // Handle resize
        const resizeObserver = new ResizeObserver(() => {
          try { fitAddon.fit(); } catch { /* ignore */ }
        });
        if (terminalRef.current) {
          resizeObserver.observe(terminalRef.current);
        }

        setLoading(false);

        // Return cleanup
        return () => {
          resizeObserver.disconnect();
          term.dispose();
        };
      } catch (err) {
        if (!disposed) {
          setError(`Failed to load transcript: ${err instanceof Error ? err.message : String(err)}`);
          setLoading(false);
        }
      }
    }

    const cleanupPromise = loadTranscript();

    return () => {
      disposed = true;
      cleanupPromise?.then(cleanup => cleanup?.());
      if (termRef.current) {
        termRef.current.dispose();
        termRef.current = null;
      }
    };
  }, [assessmentId]);

  const [resuming, setResuming] = useState(false);
  const fresh = resumeContext === 'lost';
  const handleResume = async () => {
    if (!onResume || resuming) return;
    setResuming(true);
    try {
      await onResume(fresh);
    } finally {
      setResuming(false);
    }
  };

  return (
    <div className="flex flex-col h-full">
      <div
        ref={terminalRef}
        className="flex-1 min-h-0"
        style={{ backgroundColor: '#0a0a0a', padding: '4px' }}
      />
      <div className="px-3 py-1.5 text-xs text-muted-foreground border-t bg-muted/30 flex items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          {loading ? (
            <span>Loading transcript...</span>
          ) : error ? (
            <span className="text-yellow-500">{error}</span>
          ) : fresh ? (
            <span className="text-yellow-500">
              Read-only transcript — prior conversation isn&apos;t recoverable (container was rebuilt)
            </span>
          ) : (
            <span>Read-only transcript</span>
          )}
        </div>
        {/* Resume affordance. Two shapes, driven by whether Claude's
            conversation file still exists in the container:
              • 'resumable' → "Resume session": flips status to running →
                terminal-view respawns `claude --resume <uuid>`, reloading
                ONLY this assessment's graph (isolated by UUID).
              • 'lost' → "Start fresh session": the file is gone, so we drop
                the stale id and spawn a brand-new session. Labeled clearly so
                a fresh prompt never looks like silently-lost work.
            'none'/'unknown' render nothing. */}
        {onResume && (resumeContext === 'resumable' || resumeContext === 'lost') && (
          <Button
            size="sm"
            variant={fresh ? 'outline' : 'default'}
            className="h-7 px-2 text-xs"
            onClick={handleResume}
            disabled={resuming}
            title={
              fresh
                ? "This assessment's saved conversation is no longer in the container (it was rebuilt, e.g. by a Kali image update), so it can't be reloaded. This starts a brand-new Claude session against the same assessment and findings."
                : "Continue this assessment's conversation. Claude reloads the full history (tool calls, findings, scratchpad) so you can ask follow-up questions or run more tools."
            }
          >
            {resuming ? (
              <Loader2 className="h-3 w-3 mr-1 animate-spin" />
            ) : (
              <Play className="h-3 w-3 mr-1" />
            )}
            {fresh ? 'Start fresh session' : 'Resume session'}
          </Button>
        )}
      </div>
    </div>
  );
}
