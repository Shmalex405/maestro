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
import { toast } from 'sonner';
import type { Assessment } from '@/lib/types';
import '@xterm/xterm/css/xterm.css';

// Cache the container's claude-auth-in-container check so subsequent
// TerminalView mounts (e.g. after the v0.1.60 key={…} remount that
// fires when the auto-create flips assessmentId from null → <id>) skip
// the spinner and go straight to 'ready'. Without this every key-driven
// remount flashed a "Checking Claude authentication…" spinner that felt
// like a stuck spinner to the user. 30s TTL — long enough to cover a
// burst of remounts, short enough to re-detect a sign-out.
let authedCache: { authed: boolean; ts: number } | null = null;
const AUTH_CACHE_TTL_MS = 30_000;

function cachedAuth(): boolean | null {
  if (!authedCache) return null;
  if (Date.now() - authedCache.ts > AUTH_CACHE_TTL_MS) return null;
  return authedCache.authed;
}

function setCachedAuth(authed: boolean): void {
  authedCache = { authed, ts: Date.now() };
}

/** Strip ANSI escape codes and HTML tags from serialized terminal output */
function stripAnsi(str: string): string {
  return str
    // Remove ANSI escape sequences (CSI, OSC, etc.)
    .replace(/\x1b\[[0-9;]*[a-zA-Z]/g, '')
    .replace(/\x1b\][^\x07]*\x07/g, '')
    .replace(/\x1b[()][A-Z0-9]/g, '')
    .replace(/\x1b[\x20-\x2F]*[\x40-\x7E]/g, '')
    // Remove HTML tags (serialize addon may include some)
    .replace(/<[^>]*>/g, '')
    // Collapse multiple blank lines
    .replace(/\n{3,}/g, '\n\n');
}

interface TerminalViewProps {
  assessmentId?: string;
  assessment?: Assessment | null;
  onSessionStarted?: (sessionId: string) => void;
  onAssessmentStatusChanged?: () => void;
  /** Callback that receives raw PTY data alongside xterm.write — used by the terminal parser */
  onPtyData?: (data: string) => void;
  /** Resolved path to tmux binary (bundled sidecar or system). Null disables tmux. */
  tmuxPath?: string | null;
}

export function TerminalView({
  assessmentId,
  assessment,
  onSessionStarted,
  onAssessmentStatusChanged,
  onPtyData,
  tmuxPath,
}: TerminalViewProps) {
  const terminalRef = useRef<HTMLDivElement>(null);
  const sessionKey = assessmentId || '__new__';
  const session = useTerminalStore((s) => s.sessions.get(sessionKey));
  const { spawnSession, killSession, restartSession, registerCleanup, updateSessionStatus } =
    useTerminalSession();
  const [mounted, setMounted] = useState(false);
  const initRef = useRef(false);

  // Container-side claude auth state. The host has its own claude auth
  // (macOS keychain, can't be shared), so the container at
  // /root/.claude/.credentials.json (bind-mounted from
  // ~/.kali-mcp-pentest/claude-home/) needs its own one-time login. When
  // missing we render a CTA → spawn `claude` (no exec) to run the OAuth
  // flow inline → poll the credentials file → auto-respawn with
  // `exec claude` once detected.
  // Initial auth phase: check the module-level cache first so a
  // remount-driven re-render (e.g. after auto-create) doesn't flash
  // "Checking Claude authentication…" when we already know the answer.
  const cached = cachedAuth();
  const [authPhase, setAuthPhase] = useState<'checking' | 'cta' | 'logging_in' | 'ready'>(
    cached === true ? 'ready' : cached === false ? 'cta' : 'checking',
  );
  const authPollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // Rolling buffer of recent terminal output + a one-shot latch, used to
  // detect Claude's OWN auth failure mid-session and flip back to the
  // Connect-Claude CTA. The static auth gate (check_claude_auth_in_container)
  // can't catch a dead *refresh* token — that only surfaces at runtime as
  // Claude's "Please run /login" / "API Error: 401". We match that CLI phrasing
  // SPECIFICALLY and never a bare "401", because the assessment legitimately
  // scans targets that return 401 and we must not mistake a target's response
  // for our own credential expiring.
  const authOutputBufferRef = useRef('');
  const loginPromptFiredRef = useRef(false);

  // Track mounted state
  useEffect(() => {
    setMounted(true);
    return () => setMounted(false);
  }, []);

  // Drop stale session entry on fresh mount. Next.js client-side
  // navigation unmounts/remounts the pane; the previous unmount disposed
  // the xterm via term.dispose() but the session-store entry can persist
  // with a dead terminal reference. xterm.js's `.element` getter may
  // still return the disposed wrapper element (which is no longer in
  // the DOM tree). The `.isConnected` check on that element is the
  // reliable liveness signal — if false, the xterm is dead and any
  // attempt to reuse it (early-return in init OR re-attach effect)
  // results in a blank pane until the user clicks Restart.
  //
  // Killing any orphan PTY here too — usually unmount cleanup did this
  // already, but if the cleanup raced with state the explicit kill
  // ensures we don't leak a docker exec process.
  useEffect(() => {
    if (!mounted) return;
    const existing = useTerminalStore.getState().sessions.get(sessionKey);
    if (!existing) return;
    const elem = existing.terminal?.element;
    const elemAlive = !!(elem && elem.isConnected);
    if (!elemAlive) {
      try {
        const pty = existing.ptyProcess as { kill?: () => unknown } | undefined;
        const result = pty?.kill?.();
        // pty.kill returns a Promise from tauri-pty; handle async
        // rejection (ESRCH when the process is already gone) so it
        // doesn't surface as an unhandled-rejection runtime error.
        if (result && typeof (result as Promise<unknown>).catch === 'function') {
          (result as Promise<unknown>).catch(() => { /* already dead */ });
        }
      } catch {
        // PTY may already be gone (sync throw path)
      }
      useTerminalStore.getState().removeSession(sessionKey);
    }
  }, [mounted, sessionKey]);

  // Check container claude auth once mounted. Sets phase to 'ready' if
  // /root/.claude/.credentials.json exists, otherwise 'cta'.
  useEffect(() => {
    if (!mounted) return;
    // If the cache resolved authPhase synchronously, no need to re-hit
    // the Tauri command. Cache validates within 30s; outside that we
    // re-check to detect a sign-out / container restart.
    if (cachedAuth() !== null) return;
    let cancelled = false;
    api.terminal.checkClaudeAuthInContainer().then((authed) => {
      if (cancelled) return;
      setCachedAuth(authed);
      setAuthPhase(authed ? 'ready' : 'cta');
    }).catch(() => {
      if (!cancelled) {
        setCachedAuth(false);
        setAuthPhase('cta');
      }
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

  const initTerminal = useCallback(async () => {
    if (!terminalRef.current || !mounted) return;
    // Fresh session: reset the runtime auth-failure detector.
    authOutputBufferRef.current = '';
    loginPromptFiredRef.current = false;
    // Bail-out only if the existing session is BOTH marked running AND
    // has a live xterm DOM element. After Next.js client-side navigation,
    // the previous unmount disposed the xterm via term.dispose() — but the
    // session entry in terminal-store still says status='running' (because
    // pty.onExit hadn't fired yet, or the cleanup raced). Without this
    // liveness check, remounting the pane after navigation hits the early
    // return and we render a blank container forever — user has to click
    // the Restart button manually. Detect the dead element and respawn.
    const liveTerm = !!session?.terminal?.element;
    if ((session?.status === 'running' || session?.status === 'spawning') && liveTerm) {
      return;
    }
    if (session && !liveTerm) {
      // Stale session record from a previous mount. Drop it so we don't
      // collide with the fresh init below (e.g. duplicate registerCleanup
      // entries pointing at the dead xterm).
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

    // Spawn session first to check claude availability
    const result = await spawnSession(sessionKey, {
      assessmentId,
    });

    if (!result || !result.claudeAvailable) {
      return; // Error state already set in store
    }

    // Create terminal
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

    // Add addons
    const fitAddon = new FitAddon();
    const webLinksAddon = new WebLinksAddon();
    const searchAddon = new SearchAddon();
    const serializeAddon = new SerializeAddon();
    term.loadAddon(fitAddon);
    term.loadAddon(webLinksAddon);
    term.loadAddon(searchAddon);
    term.loadAddon(serializeAddon);

    // Open terminal in DOM
    term.open(terminalRef.current);

    // Wheel scrolling.
    //
    // Two cases, distinguished by whether the foreground app has mouse
    // tracking enabled (term.modes.mouseTrackingMode):
    //
    //   1. App IS tracking the mouse (Claude's TUI under tmux — the live
    //      assessment). xterm's default behavior already forwards the wheel
    //      down as a mouse-event escape sequence, so here we do nothing and
    //      let it continue capturing to xterm's own handler. The forwarded
    //      wheel reaches tmux, which (with `mouse on` — set in the session
    //      bootstrap below) intercepts it and scrolls its pane history. Note
    //      that tmux, not Claude, is what scrolls: Claude streams to the
    //      normal buffer but doesn't act on wheel events itself, which is
    //      why an earlier xterm-only fix left users stuck — see the tmux
    //      `set -g mouse on` rationale at the new-session call.
    //
    //      (The version before that intercepted unconditionally and called
    //      term.scrollLines(), which scrolls xterm's LOCAL scrollback.
    //      Under tmux that's the alternate-screen buffer and effectively
    //      empty, so the wheel did nothing — and because it also stopped
    //      propagation, the event never reached tmux. That's why users
    //      were stuck on PageUp/PageDown to scroll a running assessment.)
    //
    //   2. App is NOT tracking the mouse (plain shell, no full-screen TUI).
    //      There's real local scrollback to move, so scroll it directly.
    const wheelTarget = terminalRef.current;
    const handleWheel = (e: WheelEvent) => {
      const mouseMode = term.modes?.mouseTrackingMode;
      if (mouseMode && mouseMode !== 'none') {
        // Let xterm forward the wheel down to tmux, which scrolls its history.
        return;
      }
      // xterm.js renders text rows at ~17px; convert pixel delta to lines.
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

    // Fit to container
    try {
      fitAddon.fit();
    } catch {
      // Ignore fit errors on initial render
    }

    const cols = term.cols;
    const rows = term.rows;

    // Spawn PTY process via tauri-pty.
    //
    // Design: the terminal pane runs INSIDE the Kali container, not on the
    // host. This keeps the pane's blast radius confined to the container —
    // `rm -rf ~`, accidental exfil, or a misbehaving Claude tool call all
    // stay inside a disposable sandbox. The host home dir is still reachable
    // via the same-path bind mount in docker.rs, so `cd /Users/you/project`
    // still works from inside the container for repo scanning.
    let pty: Awaited<ReturnType<typeof tauriPty.spawn>>;
    const tmuxSessionName = assessmentId ? `assess-${assessmentId}` : undefined;
    // True when the in-container tmux session ALREADY exists at mount — i.e.
    // we're reattaching to an assessment started before this app launch (or by
    // another flow), not starting it fresh. Captured BEFORE we spawn (our own
    // spawn would create it). Used to suppress wizard-prompt re-injection on
    // app restart (issue #19C — restart re-spawned the whole assessment).
    let sessionPreExisted = false;
    try {
      // Gate on Kali container being up — a running container is a
      // pre-condition for a sandboxed terminal. If it's not running, we
      // refuse rather than silently dropping back to a host shell.
      const dockerStatus = await api.system.getDockerStatus();
      if (!dockerStatus.kali_running) {
        throw new Error(
          'Kali container is not running. Start it from the sidebar, then reopen the terminal.',
        );
      }

      // The only CLI we drive is `claude` (see docker/Dockerfile.kali —
      // /usr/local/bin/claude). The legacy bundled-Maestro-CLI option was
      // removed in 0.1.20 along with local LLM support.
      //
      // Per-assessment session pinning so Resume works correctly:
      //   - First spawn for an assessment: generate a UUID, persist to
      //     assessment.options.claude_session_id, pass --session-id <uuid>.
      //     Claude writes its conversation graph to a file keyed by that
      //     UUID, so context is isolated per assessment.
      //   - Subsequent spawns (after CLI exited, or on Resume click): pass
      //     --resume <stored-uuid>. Claude reloads ONLY that conversation
      //     file. Different assessments never cross-contaminate because
      //     each owns a distinct UUID.
      // Auth phase is skipped — passing --session-id during the OAuth
      // flow can confuse the CLI; we only pin the session once we're
      // actually running claude in 'ready' phase.
      let claudeSessionFlag = '';
      if (authPhase === 'ready' && assessmentId && assessment) {
        const stored = (assessment.options as { claude_session_id?: string } | null | undefined)
          ?.claude_session_id;
        if (stored) {
          claudeSessionFlag = ` --resume ${stored}`;
        } else {
          const newId = crypto.randomUUID();
          try {
            const newOptions = {
              ...((assessment.options as Record<string, unknown> | null | undefined) || {}),
              claude_session_id: newId,
            };
            await api.assessments.updateOptions(assessmentId, newOptions);
            claudeSessionFlag = ` --session-id ${newId}`;
          } catch (err) {
            console.warn('[terminal] failed to persist claude_session_id; falling back to fresh session without resume capability', err);
            // Without --session-id, claude generates its own UUID and we
            // can't resume later. Better than blocking the spawn — user
            // still gets a working session, just no resume button.
          }
        }
      }
      // Materialize the container-scoped MCP config and pin claude to it.
      // The project's `.mcp.json` points at host paths (works for host-run
      // claude); inside the amd64 Kali container, host node_modules have
      // wrong-arch native modules and fail with "invalid ELF header".
      // `--strict-mcp-config` ignores the project file in favor of ours.
      await api.terminal.ensureClaudeMcpConfig().catch((err) => {
        console.warn('[terminal] ensureClaudeMcpConfig failed; falling back to project .mcp.json', err);
      });
      const mcpFlags = ' --mcp-config /root/.claude/maestro-mcp.json --strict-mcp-config';
      const rawCommand = `claude${mcpFlags}${claudeSessionFlag}`;

      // Resolve credential mode (OAuth | API key). The Tauri command returns
      // the env vars to pass via `docker exec -e`, and as a side effect
      // reconciles the container's auth (moves OAuth creds aside + configures
      // apiKeyHelper) to match the mode. For OAuth the env is just the model —
      // claude reads /root/.claude/.credentials.json. For BYO key it returns
      // MAESTRO_ANTHROPIC_KEY (consumed by the apiKeyHelper, NOT
      // ANTHROPIC_API_KEY — that name triggers an interactive prompt).
      const containerEnv = await api.claude.getContainerEnv().catch(() => null);
      const envFlags: string[] = [];
      if (containerEnv) {
        for (const [k, v] of containerEnv.env) {
          envFlags.push('-e', `${k}=${v}`);
        }
      }
      // Set CLAUDE_PROJECT_DIR explicitly so claude's `${CLAUDE_PROJECT_DIR}`
      // substitutions in the project's `.mcp.json` resolve cleanly. Without
      // this, `/mcp` shows a "Missing environment variables: CLAUDE_PROJECT_DIR"
      // warning even though our --strict-mcp-config (added in v0.1.48)
      // points claude at /root/.claude/maestro-mcp.json — claude still loads
      // the project file for diagnostics and complains about the unset var.
      const containerProjectDir = result.workingDirContainer || '/opt/pentest';
      envFlags.push('-e', `CLAUDE_PROJECT_DIR=${containerProjectDir}`);

      // Propagate the assessment ID into the container env. The team
      // lead reads $MAESTRO_ASSESSMENT_ID at startup and passes it to
      // the pdf-renderer (and any other agent that needs to bind file
      // outputs back to the cloud assessments row). Without this var,
      // generate_pdf_report has no way to know which assessment owns
      // the PDF — it just writes to disk and skips the cloud POST,
      // leaving the Reports page showing 0 reports despite the PDF
      // being there.
      if (assessmentId) {
        envFlags.push('-e', `MAESTRO_ASSESSMENT_ID=${assessmentId}`);
      }

      // `docker exec` into the running Kali container. -i keeps stdin open
      // for our PTY bytes; -t allocates a TTY inside the container so line
      // editing, colors, and Ctrl-C behave normally.
      //
      // shellCmd: in 'ready' phase we `exec claude` so the CLI replaces zsh
      // (smaller blast radius — if claude exits, the PTY closes; no shell
      // prompt left behind). In 'logging_in' phase we drop the `exec` so
      // when claude exits after login, zsh stays alive — it gets killed
      // anyway when the auth poller detects completion and we respawn.
      //
      // We `cd` into the writable container path of the project root before
      // launching claude so claude's discovery walk picks up the project's
      // `.claude/agents/` and `.claude/commands/` (slash commands). Default
      // container WORKDIR `/opt/pentest` has no `.claude/`.
      const containerName = 'kali-pentest';
      // Resolve absolute docker path — macOS GUI apps don't inherit the
      // user's PATH, so the bare command "docker" silently fails to spawn
      // and the pane stays blank.
      const program = await api.system.resolveDockerPath().catch(() => 'docker');
      const useExec = authPhase === 'ready';
      const projectDir = result.workingDirContainer || '/opt/pentest';
      // Claude Code keeps its UI state (trust prompts, MCP cache, command
      // history) in /root/.claude.json — a sibling of the bind-mounted
      // /root/.claude/ dir, NOT inside it. The file is wiped on every
      // container recreate (env-var drift, version bump). Claude itself
      // auto-backs it up to /root/.claude/backups/.claude.json.backup.<ts>
      // which IS persistent (inside the bind mount), so we restore from
      // the latest backup before each spawn. No-op if the file already
      // exists or no backup has ever been written.
      const restoreClaudeJson =
        'if [ ! -f /root/.claude.json ]; then ' +
        'b=$(ls -t /root/.claude/backups/.claude.json.backup.* 2>/dev/null | head -1); ' +
        '[ -n "$b" ] && cp "$b" /root/.claude.json; fi';
      const shellCmd = `unset CLAUDECODE; cd ${JSON.stringify(projectDir)} && ${restoreClaudeJson}; ${useExec ? 'exec ' : ''}${rawCommand}`;

      if (tmuxSessionName) {
        // tmux inside the container — must persist regardless of what the
        // host-side PTY does (close, signal-kill on navigate, app crash,
        // anything). Per user spec (v0.1.60): "the only time those sessions
        // will go inactive is if i close the assessment session in the UI
        // or the docker container is shut off."
        //
        // Pattern: detached-create + separate-attach. `tmux new-session -d`
        // creates the session WITHOUT attaching, so the tmux server runs
        // it independently of any client. The follow-up `tmux attach`
        // attaches our PTY as a client. When the PTY dies (navigate-away
        // signal kill, etc.) the client disconnects but the server keeps
        // the session alive — next mount's `tmux attach` reattaches.
        //
        // The previous `tmux new-session -A` (without -d) attached the
        // client AND created the session in one go. With some tmux
        // configurations the session lifetime gets entangled with the
        // initial attaching client; killing the client could take the
        // session down with it.
        // Enable tmux mouse mode + a deep scrollback so the wheel actually
        // scrolls. Inside the container Claude runs as a TUI under tmux, and
        // tmux is itself a full-screen app on the host xterm.js — so xterm's
        // own scrollback is the frozen alternate buffer and term.scrollLines()
        // has nothing to move. The real transcript history lives in tmux's
        // pane buffer. xterm already forwards the wheel down to the app when
        // mouse tracking is on (see the handleWheel comment above), but with
        // tmux's default `mouse off` tmux just passes the wheel through to
        // Claude, which doesn't scroll on wheel — so the event is swallowed
        // and the user is stuck on PageUp/PageDown. `mouse on` makes tmux
        // intercept the forwarded wheel and scroll its pane history (entering
        // copy-mode on wheel-up). `history-limit` is set BEFORE new-session so
        // the pane inherits the deep buffer (it only applies to panes created
        // after it's set). Both are idempotent across reattach.
        // Probe BEFORE the spawn below creates the session: if it's already
        // live, this mount is a reattach (app restart / navigation), so the
        // wizard prompt was already delivered in the original launch.
        if (assessmentId) {
          sessionPreExisted = await api.terminal
            .checkAssessmentSessionLive(assessmentId)
            .catch(() => false);
        }
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
        // Non-assessment pane — single exec, no tmux.
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

    // If we spawned for the login flow, start polling /root/.claude/.credentials.json
    // every 2s. When it appears (claude OAuth completed) we tear down this PTY
    // and let the gating effect re-init the terminal in 'ready' phase, which
    // spawns with `exec claude` for a clean working session.
    if (authPhase === 'logging_in') {
      authPollRef.current = setInterval(async () => {
        const authed = await api.terminal.checkClaudeAuthInContainer().catch(() => false);
        if (!authed) return;
        if (authPollRef.current) {
          clearInterval(authPollRef.current);
          authPollRef.current = null;
        }
        // pty.kill() is async and can reject with ESRCH if claude already
        // exited on its own after /login (common race — user finishes login,
        // claude exits cleanly, our poller fires, process is gone). Swallow
        // both sync and async forms.
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

    // Scan a chunk of terminal output for Claude's own auth-failure signature.
    // On a match we flip back to the Connect-Claude CTA (and invalidate the
    // auth cache so it doesn't immediately bounce back to 'ready'). Buffer the
    // last few KB so the phrase is caught even when split across chunks; strip
    // ANSI first so escape codes can't break the match.
    const scanForClaudeAuthFailure = (chunk: string) => {
      if (loginPromptFiredRef.current) return;
      const buf = (authOutputBufferRef.current + chunk).slice(-4000);
      authOutputBufferRef.current = buf;
      if (/please run \/login/i.test(stripAnsi(buf))) {
        loginPromptFiredRef.current = true;
        setCachedAuth(false);
        setAuthPhase('cta');
        toast.error('Claude needs to reconnect', {
          description:
            'Your Claude login expired. Reconnect to continue this assessment — your progress is preserved.',
        });
      }
    };

    // Wire bidirectional data
    pty.onData((data: Uint8Array | string) => {
      if (typeof data === 'string') {
        term.write(data);
        onPtyData?.(data);
        scanForClaudeAuthFailure(data);
      } else {
        const bytes = new Uint8Array(data);
        term.write(bytes);
        // Decode bytes to string for the parser
        try {
          const text = new TextDecoder().decode(bytes);
          onPtyData?.(text);
          scanForClaudeAuthFailure(text);
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

    // Handle PTY exit.
    //
    // v0.1.60 spec change: the host-side PTY dying is NEVER a signal that
    // the assessment is done. Possible reasons the PTY exits:
    //   - Navigation away from the assessment page (component unmount,
    //     v0.1.43 isConnected cleanup signal-kills the PTY)
    //   - User closed the Maestro window (PTY dies, container survives)
    //   - claude actually exited (user typed /exit, claude crashed)
    //   - tmux server itself died (very rare; container issue)
    //
    // For ALL of these we leave the tmux session alone — it's the
    // user's running assessment in the container, and only an explicit
    // user action (UI End-Session button) or container shutdown should
    // tear it down. So this handler now ONLY:
    //   1. snapshots scrollback into the local transcript log
    //   2. flips the local session-store entry to 'detached'
    //
    // It NO LONGER kills the tmux session, NO LONGER marks the
    // assessment status as completed/failed. Both of those caused the
    // "session disappears when I click around" bug.
    pty.onExit(async ({ exitCode: _exitCode }: { exitCode: number }) => {
      if (tmuxSessionName && tmuxPath) {
        // Best-effort scrollback capture for the transcript log so we
        // can render an offline view if the user later opens the
        // assessment without reattaching live.
        try {
          const scrollback = await api.terminal.captureTmuxPane(tmuxSessionName);
          const sessionState = useTerminalStore.getState().sessions.get(sessionKey);
          if (sessionState?.sessionId && scrollback.length > 0) {
            await api.terminal.saveTranscript(sessionState.sessionId, scrollback);
          }
        } catch { /* tmux gone or transient — non-fatal */ }
      } else {
        // No tmux — save raw xterm serialization for colored replay
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

    // Handle resize
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

    // Update store with running state
    useTerminalStore.getState().setSession(sessionKey, {
      sessionId: result.sessionId,
      assessmentId,
      terminal: term,
      ptyProcess: pty,
      status: 'running',
      tmuxSessionName,
    });

    // Mark assessment as running
    if (assessmentId) {
      api.assessments.update(assessmentId, { status: 'running' }).then(() => {
        onAssessmentStatusChanged?.();
      }).catch(() => { /* ignore update errors */ });
    }

    // Register cleanup
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

    // Auto-type the wizard-composed prompt into claude's REPL once on the
    // first spawn for this assessment. We do NOT press Enter — the user
    // reviews the prompt and submits it themselves (per design choice in
    // v0.1.89). After delivery we clear `pending_prompt` from
    // assessment.options so a remount/Resume doesn't double-type.
    // Durable per-device guard. The module-level `autoTypedAssessmentIds` Set
    // is reset on a full app reload, and the cloud-side `pending_prompt` clear
    // (below) has proven unreliable — so without a durable flag a reload (or
    // navigating back to a finished assessment) re-types the wizard prompt
    // EVERY time. localStorage survives reloads on this device, so we only ever
    // auto-type once per assessment, first-launch only.
    const autoTypedStorageKey = assessmentId ? `maestro:autoTyped:${assessmentId}` : null;
    const alreadyAutoTypedDurable =
      !!autoTypedStorageKey &&
      typeof window !== 'undefined' &&
      window.localStorage.getItem(autoTypedStorageKey) === '1';
    // Reattach (issue #19C): a pre-existing tmux session means the wizard prompt
    // was already typed in the original launch. Record that durably so we never
    // re-inject — even after this session later ends — then the gate below skips
    // via the in-memory Set / localStorage flag.
    if (sessionPreExisted && assessmentId) {
      autoTypedAssessmentIds.add(assessmentId);
      try {
        if (autoTypedStorageKey && typeof window !== 'undefined') {
          window.localStorage.setItem(autoTypedStorageKey, '1');
        }
      } catch {
        /* localStorage unavailable — the in-memory Set still suppresses re-type */
      }
    }
    if (
      authPhase === 'ready' &&
      assessmentId &&
      assessment &&
      pty &&
      !sessionPreExisted &&
      !autoTypedAssessmentIds.has(assessmentId) &&
      !alreadyAutoTypedDurable
    ) {
      const pendingPrompt = (
        assessment.options as { pending_prompt?: string } | null | undefined
      )?.pending_prompt;
      if (pendingPrompt && pendingPrompt.trim().length > 0) {
        // Claim the assessment-id BEFORE the setTimeout so concurrent
        // remounts (e.g. React strict-mode double-mount, key-driven
        // remount on auto-create) can't both schedule a write. Stays
        // claimed for the lifetime of this app session.
        autoTypedAssessmentIds.add(assessmentId);
        try {
          if (autoTypedStorageKey && typeof window !== 'undefined') {
            window.localStorage.setItem(autoTypedStorageKey, '1');
          }
        } catch {
          /* localStorage unavailable — in-memory Set + cloud clear still apply */
        }
        // 4s gives claude's TUI enough time to render its banner +
        // input prompt before we type into it. Shorter delays make
        // claude swallow the first few characters as boot input.
        setTimeout(() => {
          if (isReadOnlyNow()) return; // never auto-launch for read-only users
          try {
            pty.write(pendingPrompt);
          } catch (err) {
            console.warn('[terminal] failed to auto-type pending prompt', err);
          }
        }, 4000);
        // Clear the field in cloud-side options so a *different* app
        // session / device doesn't see pending_prompt and re-type. The
        // module-level Set above is what stops re-type within THIS app
        // session — this updateOptions is cross-session defense-in-depth.
        try {
          const cleared: Record<string, unknown> = {
            ...((assessment.options as Record<string, unknown> | null | undefined) || {}),
          };
          delete cleared.pending_prompt;
          await api.assessments.updateOptions(assessmentId, cleared);
        } catch (err) {
          console.warn('[terminal] failed to clear pending_prompt', err);
        }
      }
    }

    // Notify parent
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

  // Initialize terminal once mounted AND auth phase is one of the spawnable
  // states. 'cta' renders the connect button instead, 'checking' shows a
  // loader.
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

  // Reattach terminal when switching between assessments
  useEffect(() => {
    if (!terminalRef.current || !session?.terminal) return;

    const container = terminalRef.current;
    // If terminal is already attached to a different element, reattach
    if (session.terminal.element && session.terminal.element.parentElement !== container) {
      // Clear current container and re-append
      container.innerHTML = '';
      container.appendChild(session.terminal.element);
    }
  }, [session?.terminal]);

  // Cleanup on unmount
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
    // Re-initialize after restart
    setTimeout(() => {
      initRef.current = false;
      initTerminal();
    }, 100);
  }, [sessionKey, assessmentId, restartSession, initTerminal]);

  // Auth check still in flight — brief loader so we don't flash the CTA
  // for users whose container is already authenticated.
  if (authPhase === 'checking') {
    return (
      <div className="flex flex-col h-full items-center justify-center text-muted-foreground">
        <Loader2 className="h-5 w-5 animate-spin mb-2" />
        <div className="text-sm">Checking Claude authentication…</div>
      </div>
    );
  }

  // Container claude isn't authenticated. Show one-click CTA — kicks off
  // a PTY that runs `claude` (no exec) so the OAuth flow renders inline.
  // The poller above auto-respawns the pane in 'ready' phase as soon as
  // /root/.claude/.credentials.json appears.
  if (authPhase === 'cta') {
    return (
      <div className="flex flex-col h-full items-center justify-center px-6 text-center">
        <div className="rounded-full bg-primary/10 p-3 mb-4">
          <KeyRound className="h-6 w-6 text-primary" />
        </div>
        <h3 className="text-lg font-semibold mb-2">Connect Claude</h3>
        <p className="text-sm text-muted-foreground mb-6 max-w-md">
          Claude needs to authenticate inside the Kali container. Click below to
          start the sign-in flow — it&apos;ll run right here in this pane, and
          the terminal will switch to a working Claude session as soon as
          you&apos;re signed in.
        </p>
        <Button
          onClick={() => {
            initRef.current = false;
            setAuthPhase('logging_in');
          }}
        >
          <KeyRound className="h-4 w-4 mr-2" />
          Connect Claude
        </Button>
      </div>
    );
  }

  // Error states
  if (session?.status === 'error') {
    const errorType = session.errorMessage?.includes('not installed') || session.errorMessage?.includes('Not Found')
      ? 'claude-not-installed' as const
      : session.errorMessage?.includes('API key') || session.errorMessage?.includes('ANTHROPIC')
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
