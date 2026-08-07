'use client';

import { useEffect, useRef, useCallback, useState } from 'react';
import { useTerminalStore } from '@/lib/stores/terminal-store';
import { useTerminalSession } from '@/lib/hooks/use-terminal-session';
import { api } from '@/lib/tauri-api';
import { isReadOnlyNow } from '@/lib/read-only';
import { autoTypedAssessmentIds } from './auto-typed-prompts';
import { TerminalStatusBar } from './terminal-status-bar';
import { TerminalError } from './terminal-error';
import { Button } from '@/components/ui/button';
import { Loader2, KeyRound } from 'lucide-react';
import type { Assessment } from '@/lib/types';
import '@xterm/xterm/css/xterm.css';

interface CodexTerminalViewProps {
  assessmentId?: string;
  assessment?: Assessment | null;
  onSessionStarted?: (sessionId: string) => void;
  onAssessmentStatusChanged?: () => void;
  /** Callback that receives raw PTY data alongside xterm.write — used by the terminal parser */
  onPtyData?: (data: string) => void;
  /** Resolved path to tmux binary (bundled sidecar or system). Null disables tmux. */
  tmuxPath?: string | null;
}

/**
 * Codex (GPT-5.5) terminal pane. Mirror of `terminal-view.tsx` for the
 * second brain. Same xterm + tauri-pty + tmux pattern; differences are:
 *
 *   - Spawns `codex` (OpenAI Codex CLI) instead of `claude`
 *   - tmux session prefix is `codex-assess-` so it doesn't collide with
 *     Claude's `assess-` sessions for the same assessment
 *   - Auth check polls `/root/.codex/auth.json` (Codex's credentials file)
 *   - The login flow uses Codex's device-code path (`codex login
 *     --device-auth`) rather than Claude's browser OAuth — Codex prints a
 *     URL + 8-digit code in the pane, the user authorizes in their host
 *     browser, the container's auth.json gets written
 *   - Before spawning, writes `~/.codex/config.toml` registering the
 *     kali-pentest MCP server (Codex's TOML equivalent of `.mcp.json`)
 *   - Reads `OPENAI_*` env vars instead of `ANTHROPIC_*`
 */
export function CodexTerminalView({
  assessmentId,
  assessment,
  onSessionStarted,
  onAssessmentStatusChanged,
  onPtyData,
  tmuxPath,
}: CodexTerminalViewProps) {
  const terminalRef = useRef<HTMLDivElement>(null);
  const sessionKey = assessmentId ? `codex-${assessmentId}` : '__codex_new__';
  const session = useTerminalStore((s) => s.sessions.get(sessionKey));
  const { spawnSession, killSession: _killSession, restartSession, registerCleanup, updateSessionStatus } =
    useTerminalSession();
  const [mounted, setMounted] = useState(false);
  const initRef = useRef(false);

  // Container-side codex auth state. Persisted at /root/.codex/auth.json
  // (bind-mounted from ~/.kali-mcp-pentest/codex-home/) so device-code
  // login is one-time per machine. When missing we render a CTA → spawn
  // `codex login --device-auth` to print the URL+code → poll the auth
  // file → auto-respawn with `exec codex` once detected.
  const [authPhase, setAuthPhase] = useState<'checking' | 'cta' | 'logging_in' | 'ready'>('checking');
  const authPollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // Track mounted state
  useEffect(() => {
    setMounted(true);
    return () => setMounted(false);
  }, []);

  // See terminal-view.tsx — same stale-session drop on mount. Codex
  // and Claude both keep tmux alive inside the container so a fresh
  // xterm just attaches; the only thing we lose by clearing the store
  // entry is the in-memory xterm widget reference (which was dead
  // anyway).
  useEffect(() => {
    if (!mounted) return;
    const existing = useTerminalStore.getState().sessions.get(sessionKey);
    if (!existing) return;
    const elem = existing.terminal?.element;
    const elemAlive = !!(elem && elem.isConnected);
    if (!elemAlive) {
      try {
        const pty = existing.ptyProcess as { kill?: () => unknown } | undefined;
        pty?.kill?.();
      } catch {
        // PTY may already be gone
      }
      useTerminalStore.getState().removeSession(sessionKey);
    }
  }, [mounted, sessionKey]);

  // Check container codex auth once mounted.
  useEffect(() => {
    if (!mounted) return;
    let cancelled = false;
    api.terminal.checkCodexAuthInContainer().then((authed) => {
      if (cancelled) return;
      setAuthPhase(authed ? 'ready' : 'cta');
    }).catch(() => {
      if (!cancelled) setAuthPhase('cta');
    });
    return () => { cancelled = true; };
  }, [mounted]);

  // Cleanup auth-completion poller if the user unmounts mid-login.
  useEffect(() => {
    return () => {
      if (authPollRef.current) {
        clearInterval(authPollRef.current);
        authPollRef.current = null;
      }
    };
  }, []);

  // Codex session-ID capture poller. Codex has no `--session-id` pin
  // equivalent to Claude's, so we discover the UUID it chose by watching
  // `~/.codex/sessions/` for the new file Codex writes after the user's
  // first prompt+response. Once captured, every future spawn for this
  // assessment uses `codex resume <id>` (see initTerminal above) for
  // exact per-assessment context isolation.
  //
  // Polls every 5s for up to 5 minutes. If no file appears (user closed
  // the pane before chatting), give up silently — there's nothing to
  // resume anyway. The `spawnTimeRef` cutoff filters out session files
  // from earlier assessments so multiple parallel codex sessions can't
  // cross-claim each other's UUIDs.
  const sessionCapturePollRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const spawnTimeRef = useRef<number>(0);
  useEffect(() => {
    // Only run when we're in a ready Codex session for an assessment that
    // doesn't yet have a captured session ID.
    if (authPhase !== 'ready' || !assessmentId || !assessment) {
      return;
    }
    const alreadyStored = (assessment.options as { codex_session_id?: string } | null | undefined)
      ?.codex_session_id;
    if (alreadyStored) {
      return; // Already have one — nothing to capture.
    }

    spawnTimeRef.current = Math.floor(Date.now() / 1000);
    const startedAt = Date.now();
    const TIMEOUT_MS = 5 * 60 * 1000; // give up after 5 minutes

    const poll = async () => {
      if (Date.now() - startedAt > TIMEOUT_MS) {
        if (sessionCapturePollRef.current) {
          clearInterval(sessionCapturePollRef.current);
          sessionCapturePollRef.current = null;
        }
        return;
      }
      try {
        const captured = await api.terminal.captureCodexSessionId(spawnTimeRef.current);
        if (captured) {
          // Persist via the same options-merge pattern Claude uses.
          const newOptions = {
            ...((assessment.options as Record<string, unknown> | null | undefined) || {}),
            codex_session_id: captured,
          };
          try {
            await api.assessments.updateOptions(assessmentId, newOptions);
          } catch (err) {
            console.warn('[codex] captured session id but failed to persist:', err);
          }
          if (sessionCapturePollRef.current) {
            clearInterval(sessionCapturePollRef.current);
            sessionCapturePollRef.current = null;
          }
        }
      } catch {
        // Non-fatal — keep polling. Capture is best-effort.
      }
    };

    // Kick off first poll after 5s (gives Codex time to write the file
    // post-first-response), then every 5s after.
    sessionCapturePollRef.current = setInterval(poll, 5000);

    return () => {
      if (sessionCapturePollRef.current) {
        clearInterval(sessionCapturePollRef.current);
        sessionCapturePollRef.current = null;
      }
    };
  }, [authPhase, assessmentId, assessment]);

  const initTerminal = useCallback(async () => {
    if (!terminalRef.current || !mounted) return;
    // See the matching comment in terminal-view.tsx — bail-out is gated
    // on the existing xterm having a live DOM element. After Next.js
    // client-side navigation, the previous unmount disposed the xterm
    // but the session-store entry still says running, leading to a
    // blank pane on remount. Detect the stale entry and respawn.
    const liveTerm = !!session?.terminal?.element;
    if ((session?.status === 'running' || session?.status === 'spawning') && liveTerm) {
      return;
    }
    if (session && !liveTerm) {
      useTerminalStore.getState().removeSession(sessionKey);
    }

    // Dynamic import of xterm.js (client-side only)
    const [
      { Terminal },
      { FitAddon },
      { WebLinksAddon },
      { SearchAddon },
      { SerializeAddon },
      tauriPty,
    ] = await Promise.all([
      import('@xterm/xterm'),
      import('@xterm/addon-fit'),
      import('@xterm/addon-web-links'),
      import('@xterm/addon-search'),
      import('@xterm/addon-serialize'),
      import('tauri-pty'),
    ]);

    // Spawn session first to check container availability + grab project dir
    const result = await spawnSession(sessionKey, {
      assessmentId,
    });

    if (!result || !result.claudeAvailable) {
      // The session-spawn check is named for Claude historically but it
      // really only verifies that the Kali container is up. Codex shares
      // the same precondition, so we reuse the gating signal as-is.
      return;
    }

    const term = new Terminal({
      cursorBlink: true,
      fontSize: 13,
      fontFamily: "'JetBrains Mono', 'Fira Code', 'Cascadia Code', 'Menlo', monospace",
      lineHeight: 1.2,
      theme: {
        background: '#0a0a0a',
        foreground: '#e4e4e7',
        cursor: '#e4e4e7',
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
      scrollback: 10000,
      convertEol: true,
    });

    const fitAddon = new FitAddon();
    const webLinksAddon = new WebLinksAddon();
    const searchAddon = new SearchAddon();
    const serializeAddon = new SerializeAddon();
    term.loadAddon(fitAddon);
    term.loadAddon(webLinksAddon);
    term.loadAddon(searchAddon);
    term.loadAddon(serializeAddon);

    term.open(terminalRef.current);

    // Wheel scrolling. See terminal-view.tsx for the full rationale;
    // Codex's TUI behaves the same as Claude's around mouse-mode capture,
    // so the fix is symmetric: when the app is tracking the mouse, let the
    // wheel reach it (it scrolls its own transcript); otherwise scroll
    // xterm's local scrollback.
    const wheelTarget = terminalRef.current;
    const handleWheel = (e: WheelEvent) => {
      const mouseMode = term.modes?.mouseTrackingMode;
      if (mouseMode && mouseMode !== 'none') {
        return; // let xterm forward the wheel to the app
      }
      const lines = Math.sign(e.deltaY) *
        Math.max(1, Math.round(Math.abs(e.deltaY) / 17));
      term.scrollLines(lines);
      e.preventDefault();
      e.stopImmediatePropagation();
    };
    wheelTarget.addEventListener('wheel', handleWheel, {
      capture: true,
      passive: false,
    });

    try {
      fitAddon.fit();
    } catch {
      // Ignore fit errors on initial render
    }

    const cols = term.cols;
    const rows = term.rows;

    let pty: Awaited<ReturnType<typeof tauriPty.spawn>>;
    const tmuxSessionName = assessmentId ? `codex-assess-${assessmentId}` : undefined;
    try {
      const dockerStatus = await api.system.getDockerStatus();
      if (!dockerStatus.kali_running) {
        throw new Error(
          'Kali container is not running. Start it from the sidebar, then reopen the terminal.',
        );
      }

      const projectDir = result.workingDirContainer || '/opt/pentest';

      // Write Codex's MCP config so it sees the kali-pentest server. The
      // file is idempotent and bind-mounted, so this is cheap.
      try {
        await api.terminal.ensureCodexMcpConfig(projectDir);
      } catch {
        // Non-fatal — Codex still launches, just without the MCP tools.
        // The user can resolve by re-running the assessment after the
        // container is healthy.
      }

      // The CLI we drive in this pane is `codex` (see docker/Dockerfile.kali).
      // In login phase we run `codex login --device-auth` (prints URL +
      // 8-digit code, waits for browser authorize); in ready phase we run
      // `codex` itself — or `codex resume <session-id>` if this assessment
      // already has a captured session UUID stored, so reopening picks up
      // the prior conversation.
      //
      // Codex doesn't have a `--session-id <uuid>` pin like Claude — we
      // capture the UUID Codex chose post-spawn (see the polling effect
      // below). Once captured, every subsequent spawn for this assessment
      // routes through `codex resume <id>` so context is isolated to that
      // exact conversation file under `~/.codex/sessions/<id>.jsonl`.
      let codexCommandStr = 'codex';
      if (authPhase === 'logging_in') {
        codexCommandStr = 'codex login --device-auth';
      } else if (assessmentId && assessment) {
        const stored = (assessment.options as { codex_session_id?: string } | null | undefined)
          ?.codex_session_id;
        if (stored) {
          codexCommandStr = `codex resume ${stored}`;
        }
      }
      const rawCommand = codexCommandStr;

      // Resolve credential mode (OAuth | API key). For OAuth this is empty —
      // codex reads /root/.codex/auth.json. For BYO key it returns
      // OPENAI_API_KEY.
      const containerEnv = await api.codex.getContainerEnv().catch(() => null);
      const envFlags: string[] = [];
      if (containerEnv) {
        for (const [k, v] of containerEnv.env) {
          envFlags.push('-e', `${k}=${v}`);
        }
      }

      // Same MAESTRO_ASSESSMENT_ID propagation as terminal-view.tsx —
      // see the comment there. pdf-renderer + any cloud-binding agent
      // needs this env var to associate outputs with the right row.
      if (assessmentId) {
        envFlags.push('-e', `MAESTRO_ASSESSMENT_ID=${assessmentId}`);
      }

      const containerName = 'kali-pentest';
      const program = await api.system.resolveDockerPath().catch(() => 'docker');
      const useExec = authPhase === 'ready';
      const shellCmd = `cd ${JSON.stringify(projectDir)} && ${useExec ? 'exec ' : ''}${rawCommand}`;

      if (tmuxSessionName) {
        // Detached-create + separate-attach so the session survives any
        // PTY death except an explicit user end. See terminal-view.tsx
        // for the full rationale; same pattern applies here.
        // Enable tmux mouse mode + deep scrollback so the wheel scrolls the
        // pane history. tmux is a full-screen app on the host xterm.js, so
        // xterm's local scrollback is frozen — the real history lives in
        // tmux. xterm forwards the wheel to the app on mouse-tracking, but
        // tmux's default `mouse off` passes it through to Codex (which
        // doesn't scroll on wheel), so it's swallowed. `mouse on` lets tmux
        // intercept the wheel and scroll its history. See terminal-view.tsx
        // for the full rationale; same pattern applies here.
        const tmuxStartOrAttach =
          `tmux set -g history-limit 50000 2>/dev/null; ` +
          `tmux has-session -t ${tmuxSessionName} 2>/dev/null || ` +
          `tmux new-session -d -s ${tmuxSessionName} '${shellCmd}'; ` +
          `tmux set -g mouse on 2>/dev/null; ` +
          `exec tmux attach -t ${tmuxSessionName}`;
        pty = await tauriPty.spawn(
          program,
          [
            'exec', '-it', ...envFlags, containerName,
            '/bin/zsh', '-lc',
            tmuxStartOrAttach,
          ],
          { cols, rows },
        );
      } else {
        pty = await tauriPty.spawn(
          program,
          ['exec', '-it', ...envFlags, containerName, '/bin/zsh', '-lc', shellCmd],
          { cols, rows },
        );
      }
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : String(err);
      updateSessionStatus(sessionKey, 'error', undefined, `Failed to spawn PTY: ${errorMessage}`);
      term.dispose();
      return;
    }

    // If we spawned for the device-code login flow, start polling
    // /root/.codex/auth.json every 2s. When it appears (codex login
    // succeeded) we tear down this PTY and let the gating effect re-init
    // the terminal in 'ready' phase, which spawns with `exec codex` for a
    // clean working session.
    if (authPhase === 'logging_in') {
      authPollRef.current = setInterval(async () => {
        const authed = await api.terminal.checkCodexAuthInContainer().catch(() => false);
        if (!authed) return;
        if (authPollRef.current) {
          clearInterval(authPollRef.current);
          authPollRef.current = null;
        }
        try {
          const killResult = pty.kill() as unknown;
          if (killResult && typeof (killResult as Promise<unknown>).catch === 'function') {
            (killResult as Promise<unknown>).catch(() => { /* ESRCH or already-dead */ });
          }
        } catch { /* sync throw — same swallow */ }
        try { term.dispose(); } catch { /* ignore */ }
        initRef.current = false;
        setAuthPhase('ready');
      }, 2000);
    }

    pty.onData((data: Uint8Array | string) => {
      if (typeof data === 'string') {
        term.write(data);
        onPtyData?.(data);
      } else {
        const bytes = new Uint8Array(data);
        term.write(bytes);
        try {
          const text = new TextDecoder().decode(bytes);
          onPtyData?.(text);
        } catch {
          // Ignore decode errors
        }
      }
    });

    term.onData((data: string) => {
      // Read-only users can view the terminal but cannot type into it.
      if (isReadOnlyNow()) return;
      pty.write(data);
    });

    // PTY exit handler — see terminal-view.tsx for the full rationale.
    // v0.1.60: never auto-kill the tmux session and never auto-update
    // assessment status. Sessions only end on explicit UI action or
    // container shutdown.
    pty.onExit(async ({ exitCode: _exitCode }: { exitCode: number }) => {
      if (tmuxSessionName && tmuxPath) {
        try {
          const scrollback = await api.terminal.captureTmuxPane(tmuxSessionName);
          const sessionState = useTerminalStore.getState().sessions.get(sessionKey);
          if (sessionState?.sessionId && scrollback.length > 0) {
            await api.terminal.saveTranscript(sessionState.sessionId, scrollback);
          }
        } catch { /* tmux gone or transient — non-fatal */ }
      } else {
        try {
          const raw = serializeAddon.serialize();
          const sessionState = useTerminalStore.getState().sessions.get(sessionKey);
          if (sessionState?.sessionId && raw.length > 0) {
            await api.terminal.saveTranscript(sessionState.sessionId, raw);
          }
        } catch { /* ignore capture errors */ }
      }

      updateSessionStatus(sessionKey, 'detached');
    });

    const resizeObserver = new ResizeObserver(() => {
      try {
        fitAddon.fit();
        pty.resize(term.cols, term.rows);
      } catch {
        // Ignore resize errors
      }
    });

    if (terminalRef.current) {
      resizeObserver.observe(terminalRef.current);
    }

    useTerminalStore.getState().setSession(sessionKey, {
      sessionId: result.sessionId,
      assessmentId,
      terminal: term,
      ptyProcess: pty,
      status: 'running',
      tmuxSessionName,
    });

    if (assessmentId) {
      api.assessments.update(assessmentId, { status: 'running' }).then(() => {
        onAssessmentStatusChanged?.();
      }).catch(() => { /* ignore update errors */ });
    }

    registerCleanup(sessionKey, () => {
      resizeObserver.disconnect();
      wheelTarget.removeEventListener('wheel', handleWheel, { capture: true });
      try {
        const killResult = pty.kill() as unknown;
        if (killResult && typeof (killResult as Promise<unknown>).catch === 'function') {
          (killResult as Promise<unknown>).catch(() => { /* already dead */ });
        }
      } catch {
        // Ignore sync kill errors
      }
      term.dispose();
    });

    // Auto-type the wizard-composed prompt once Codex's TUI is ready.
    // Mirror of the Claude path in terminal-view.tsx — see comments there
    // for the cloud-clear vs in-session-Set rationale. Both brains share
    // assessment.options.pending_prompt, so we need to guard remount-typing
    // on the codex side too.
    if (
      authPhase === 'ready' &&
      assessmentId &&
      assessment &&
      pty &&
      !autoTypedAssessmentIds.has(assessmentId)
    ) {
      const pendingPrompt = (
        assessment.options as { pending_prompt?: string } | null | undefined
      )?.pending_prompt;
      if (pendingPrompt && pendingPrompt.trim().length > 0) {
        autoTypedAssessmentIds.add(assessmentId);
        setTimeout(() => {
          if (isReadOnlyNow()) return; // never auto-launch for read-only users
          try {
            pty.write(pendingPrompt);
          } catch (err) {
            console.warn('[codex-terminal] failed to auto-type pending prompt', err);
          }
        }, 4000);
        try {
          const cleared: Record<string, unknown> = {
            ...((assessment.options as Record<string, unknown> | null | undefined) || {}),
          };
          delete cleared.pending_prompt;
          await api.assessments.updateOptions(assessmentId, cleared);
        } catch (err) {
          console.warn('[codex-terminal] failed to clear pending_prompt', err);
        }
      }
    }

    if (onSessionStarted) {
      onSessionStarted(result.sessionId);
    }
  }, [
    sessionKey,
    assessmentId,
    mounted,
    authPhase,
    session?.status,
    spawnSession,
    registerCleanup,
    updateSessionStatus,
    onSessionStarted,
    onAssessmentStatusChanged,
    onPtyData,
    tmuxPath,
  ]);

  useEffect(() => {
    if (
      mounted &&
      !initRef.current &&
      (authPhase === 'ready' || authPhase === 'logging_in')
    ) {
      initRef.current = true;
      initTerminal();
    }
  }, [mounted, authPhase, initTerminal]);

  useEffect(() => {
    if (!terminalRef.current || !session?.terminal) return;

    const container = terminalRef.current;
    if (session.terminal.element && session.terminal.element.parentElement !== container) {
      container.innerHTML = '';
      container.appendChild(session.terminal.element);
    }
  }, [session?.terminal]);

  useEffect(() => {
    return () => {
      initRef.current = false;
    };
  }, []);

  const handleRestart = useCallback(async () => {
    initRef.current = false;
    await restartSession(sessionKey, {
      assessmentId,
    });
    setTimeout(() => {
      initRef.current = false;
      initTerminal();
    }, 100);
  }, [sessionKey, assessmentId, restartSession, initTerminal]);

  if (authPhase === 'checking') {
    return (
      <div className="flex flex-col h-full items-center justify-center text-muted-foreground">
        <Loader2 className="h-5 w-5 animate-spin mb-2" />
        <div className="text-sm">Checking Codex authentication…</div>
      </div>
    );
  }

  if (authPhase === 'cta') {
    return (
      <div className="flex flex-col h-full items-center justify-center px-6 text-center">
        <div className="rounded-full bg-primary/10 p-3 mb-4">
          <KeyRound className="h-6 w-6 text-primary" />
        </div>
        <h3 className="text-lg font-semibold mb-2">Connect Codex</h3>
        <p className="text-sm text-muted-foreground mb-6 max-w-md">
          Codex needs to authenticate inside the Kali container. Click below
          to start the device-code flow — it&apos;ll print a URL and 8-digit
          code right here in this pane. Open the URL in your browser, enter
          the code, and the terminal will switch to a working Codex session
          as soon as you&apos;re signed in.
        </p>
        <Button
          onClick={() => {
            initRef.current = false;
            setAuthPhase('logging_in');
          }}
        >
          <KeyRound className="h-4 w-4 mr-2" />
          Connect Codex
        </Button>
      </div>
    );
  }

  if (session?.status === 'error') {
    const errorType = session.errorMessage?.includes('not installed') || session.errorMessage?.includes('Not Found')
      ? 'claude-not-installed' as const
      : session.errorMessage?.includes('API key') || session.errorMessage?.includes('OPENAI')
        ? 'api-key-missing' as const
        : 'spawn-failed' as const;

    return (
      <div className="flex flex-col h-full">
        <TerminalError
          type={errorType}
          message={session.errorMessage}
          onRetry={handleRestart}
        />
      </div>
    );
  }

  const displayName = assessment
    ? assessment.name || `${assessment.type} Assessment`
    : undefined;

  return (
    <div className="flex flex-col h-full">
      <div
        ref={terminalRef}
        className="flex-1 min-h-0"
        style={{ backgroundColor: '#0a0a0a', padding: '4px' }}
      />
      <TerminalStatusBar
        status={session?.status || 'spawning'}
        assessmentName={displayName}
        exitCode={session?.exitCode}
        onRestart={handleRestart}
      />
    </div>
  );
}
