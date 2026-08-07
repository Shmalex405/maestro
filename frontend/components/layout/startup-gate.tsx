'use client';

import { useEffect, useState, useRef, useCallback, type ReactNode } from 'react';
import { api, type PullProgress } from '@/lib/tauri-api';
import { useSettingsStore } from '@/lib/stores/settings-store';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Progress } from '@/components/ui/progress';
import { ScrollArea } from '@/components/ui/scroll-area';
import {
  CheckCircle2,
  Circle,
  Loader2,
  XCircle,
  AlertTriangle,
  Download,
  RefreshCw,
  RotateCcw,
  Play,
  ChevronDown,
  ChevronRight,
  Terminal,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { refreshSession, getUserFromToken, isCognitoConfigured } from '@/lib/cognito-auth';
import { useAuthStore } from '@/lib/stores/auth-store';
import {
  isBootstrapped,
  bootstrapNeedsRefresh,
  getBootstrap,
  saveBootstrap,
  discover,
} from '@/lib/desktop-bootstrap';
import { isReadOnlyNow } from '@/lib/read-only';
import { getSelfHostConfig, bootstrapFromSelfHost } from '@/lib/self-host';
import { setDataMode } from '@/lib/deployment-mode';
import { isTauri } from '@/lib/tauri-api';
import { invoke } from '@tauri-apps/api/core';
import { AuthGate } from './auth-gate';
import { DiscoveryGate } from './discovery-gate';

// Persist completion state in sessionStorage so HMR doesn't reset it.
// Module-level cache avoids reading storage on every render.
//
// IMPORTANT: do NOT read sessionStorage at module-init time. Static-export
// build evaluates this on the server (no sessionStorage → false), but the
// client hydrates with the runtime value (possibly true) — that's a
// hydration mismatch. Initialize false; the StartupGate component reads
// the real value inside useEffect.
const STORAGE_KEY = 'startup-gate-completed';
let hasCompleted = false;

function readHasCompleted(): boolean {
  if (typeof window === 'undefined') return false;
  try {
    return sessionStorage.getItem(STORAGE_KEY) === '1';
  } catch {
    return false;
  }
}

function markCompleted() {
  hasCompleted = true;
  try { sessionStorage.setItem(STORAGE_KEY, '1'); } catch { /* ignore */ }
}

type StartupState =
  | 'discovery_required'
  | 'auth_checking'
  | 'auth_required'
  | 'auth_refreshing'
  | 'checking'
  | 'docker_not_installed'
  /** Docker.app exists but isn't launched yet — gate shows "Open Docker Desktop" button. */
  | 'docker_not_running'
  /** Docker.app process running but daemon hung — gate shows "Restart Docker" button. */
  | 'docker_daemon_unresponsive'
  | 'starting_docker'
  | 'waiting_for_docker'
  | 'checking_image'
  | 'building_image'
  | 'starting_container'
  | 'connecting_mcp'
  | 'checking_claude'
  | 'ready'
  | 'skipped'
  | 'error';

/** How long to wait for the Docker daemon to become responsive after we
 *  open Docker.app. Cold-boot Docker Desktop on macOS routinely takes
 *  90-120s; the previous 60s window timed out users on first-after-reboot
 *  launches. We surface a "still waiting..." sub-line at 30s so the user
 *  knows the wait is normal. */
const DOCKER_WAIT_TIMEOUT_MS = 120_000;
const DOCKER_WAIT_HINT_AFTER_MS = 30_000;

/** Renders a "still waiting…" hint after 30s of waiting on the Docker
 *  daemon, so users on first-launch / cold-boot don't think the gate is
 *  frozen at the 60-90s mark. */
function DockerWaitHint() {
  const [showHint, setShowHint] = useState(false);
  useEffect(() => {
    const t = setTimeout(() => setShowHint(true), DOCKER_WAIT_HINT_AFTER_MS);
    return () => clearTimeout(t);
  }, []);
  if (!showHint) return null;
  return (
    <div className="rounded-md border border-blue-500/30 bg-blue-500/5 px-3 py-2 text-xs text-blue-300">
      Docker Desktop's first launch can take up to 2 minutes (it's booting a
      Linux VM). Hang tight — we'll continue automatically once the daemon
      responds.
    </div>
  );
}

/** Inline error/detail panel shown under the failed step row. Has a
 *  "Show details" expander for the underlying error text. */
function StepErrorDetail({ message }: { message: string }) {
  const [open, setOpen] = useState(false);
  if (!message) return null;
  // Short summary up to ~140 chars; full message in the expander.
  const short = message.length > 140 ? message.slice(0, 140) + '…' : message;
  return (
    <div className="ml-8 -mt-2 mb-1 space-y-1">
      <p className="text-xs text-destructive/90 leading-snug">{short}</p>
      {message.length > 140 && (
        <button
          onClick={() => setOpen((o) => !o)}
          className="flex items-center gap-1 text-[11px] text-muted-foreground hover:text-foreground"
        >
          {open ? (
            <ChevronDown className="h-3 w-3" />
          ) : (
            <ChevronRight className="h-3 w-3" />
          )}
          {open ? 'Hide details' : 'Show details'}
        </button>
      )}
      {open && (
        <pre className="text-[11px] whitespace-pre-wrap break-all bg-muted/40 rounded px-2 py-1.5 text-muted-foreground">
          {message}
        </pre>
      )}
    </div>
  );
}

interface StepDef {
  label: string;
  states: StartupState[];
  conditional?: boolean;
}

function buildSteps(includeAuth: boolean): StepDef[] {
  const steps: StepDef[] = [];

  if (includeAuth) {
    steps.push({ label: 'Authenticate', states: ['auth_checking', 'auth_required', 'auth_refreshing'] });
  }

  steps.push(
    { label: 'Check Docker', states: ['checking', 'docker_not_installed'] },
    {
      label: 'Start Docker Desktop',
      // The two diagnosed-failure states (not running / hung) both live on
      // this step — the user is actively here resolving the failure with
      // the action buttons we render below.
      states: [
        'starting_docker',
        'waiting_for_docker',
        'docker_not_running',
        'docker_daemon_unresponsive',
      ],
    },
    { label: 'Check Kali Image', states: ['checking_image', 'building_image'] },
    { label: 'Start Kali Container', states: ['starting_container'] },
    { label: 'Connect MCP Server', states: ['connecting_mcp'] },
    { label: 'Ready', states: ['checking_claude'] },
  );

  return steps;
}

function getStepStatus(
  steps: StepDef[],
  stepIndex: number,
  currentState: StartupState,
  errorStepIndex: number,
): 'completed' | 'active' | 'pending' | 'error' | 'warning' {
  if (currentState === 'error' && errorStepIndex >= 0) {
    if (stepIndex < errorStepIndex) return 'completed';
    if (stepIndex === errorStepIndex) return 'error';
    return 'pending';
  }

  // Find the current active step
  let activeStepIndex = -1;
  for (let i = 0; i < steps.length; i++) {
    if (steps[i].states.includes(currentState)) {
      activeStepIndex = i;
      break;
    }
  }

  if (activeStepIndex === -1) return 'pending';
  if (stepIndex < activeStepIndex) return 'completed';
  if (stepIndex === activeStepIndex) return 'active';
  return 'pending';
}

function getProgressPercent(state: StartupState): number {
  const map: Record<StartupState, number> = {
    discovery_required: 1,
    auth_checking: 2,
    auth_required: 2,
    auth_refreshing: 3,
    checking: 5,
    docker_not_installed: 5,
    docker_not_running: 8,
    docker_daemon_unresponsive: 8,
    starting_docker: 12,
    waiting_for_docker: 22,
    checking_image: 35,
    building_image: 48,
    starting_container: 60,
    connecting_mcp: 75,
    checking_claude: 92,
    ready: 100,
    skipped: 0,
    error: 0,
  };
  return map[state] ?? 0;
}

export function StartupGate({ children }: { children: ReactNode }) {
  const [state, setState] = useState<StartupState>(
    hasCompleted ? 'ready' : 'checking'
  );
  const [errorMessage, setErrorMessage] = useState('');
  const [buildLines, setBuildLines] = useState<string[]>([]);
  const [errorStepIndex, setErrorStepIndex] = useState(-1);
  const [claudeWarning, setClaudeWarning] = useState(false);
  const [includeAuthStep, setIncludeAuthStep] = useState(false);
  const [pullProgress, setPullProgress] = useState<PullProgress | null>(null);
  // Wall-clock of the last pull-progress event we received. Bumped on
  // every byte movement so we can flag a stalled pull when nothing has
  // arrived for ~45s (typical layer-extract gaps are <10s, so 45s is a
  // comfortable false-positive cushion).
  const [lastProgressAt, setLastProgressAt] = useState<number | null>(null);
  const [now, setNow] = useState(() => Date.now());
  const buildLogRef = useRef<HTMLDivElement>(null);
  const cleanupRef = useRef<(() => void) | null>(null);
  const pullCleanupRef = useRef<(() => void) | null>(null);

  const steps = buildSteps(includeAuthStep);

  // Auto-scroll build log
  useEffect(() => {
    if (buildLogRef.current) {
      buildLogRef.current.scrollTop = buildLogRef.current.scrollHeight;
    }
  }, [buildLines]);

  // Tick `now` once per second while a pull is in flight so the stall
  // detector re-renders without us having to push it from the event
  // handler. Cheap — one setState/sec, only active during pull.
  useEffect(() => {
    if (state !== 'building_image') return;
    const id = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(id);
  }, [state]);

  const handleError = useCallback((msg: string, stepIdx: number) => {
    setErrorMessage(msg);
    setErrorStepIndex(stepIdx);
    setState('error');
  }, []);

  const runStartup = useCallback(async () => {
    setErrorMessage('');
    setErrorStepIndex(-1);
    setBuildLines([]);
    setPullProgress(null);
    setLastProgressAt(null);
    setClaudeWarning(false);

    // === E2E TEST BYPASS ===
    // When MAESTRO_TEST_BYPASS_AUTH=1 is set in the binary's environment,
    // skip the entire startup pipeline (discovery + auth + Docker + MCP)
    // and jump straight to "ready". Used by the desktop end-to-end test
    // suite — see tests-e2e-desktop/. The env var is only readable via
    // the Rust side; if the Tauri command isn't available (e.g. running
    // under `next dev` without Tauri), this branch is silently skipped.
    if (isTauri()) {
      try {
        const flags = await invoke<{ bypass_auth: boolean }>(
          'get_test_mode_flags',
        );
        if (flags?.bypass_auth) {
          // setState('ready') alone is enough — the render path below
          // returns `<>{children}</>` whenever state === 'ready'.
          setState('ready');
          return;
        }
      } catch {
        // Command not registered or returned an error — fall through to
        // normal startup. Production builds will always take this branch.
      }
    }

    // === SELF-HOSTED BOOTSTRAP ===
    // A self-hosted deployment has no /api/discover to ask — the operator wrote
    // the backend URL and Cognito settings to ~/.kali-mcp-pentest/self-host.json
    // (see lib/self-host.ts). Synthesize the same Bootstrap discovery would have
    // produced and the rest of startup proceeds unchanged.
    //
    // This runs BEFORE the schema-refresh and discovery blocks below, and both
    // of those are gated on !selfHosted, so a self-hosted install never reaches
    // out to Groovy's platform at all — which is the entire point.
    //
    // We rewrite the bootstrap on every launch rather than only when missing:
    // the config file is the source of truth for a self-hoster, so an operator
    // who edits it (new backend URL, added an OAST listener) gets the change on
    // next launch instead of having to clear localStorage to escape a stale
    // cached bootstrap.
    let selfHosted = false;
    let localMode = false;
    if (isTauri()) {
      try {
        const cfg = await getSelfHostConfig();
        if (cfg?.mode === 'local') {
          // LOCAL MODE. No backend to route to and no pool to authenticate
          // against, so both the discovery gate and the auth gate are skipped
          // entirely and startup goes straight to Docker + MCP. Deliberately no
          // bootstrap is written — see bootstrapFromSelfHost, which throws for
          // exactly this config.
          localMode = true;
          selfHosted = true;
          setDataMode('local');
        } else if (cfg) {
          selfHosted = true;
          setDataMode('cloud');
          const email = useAuthStore.getState().user?.email ?? getBootstrap()?.email ?? '';
          saveBootstrap(bootstrapFromSelfHost(cfg, email));
        } else {
          // Managed install — discovery below resolves the backend.
          setDataMode('cloud');
        }
      } catch (err) {
        // Self-hosted mode was enabled but the config is unusable. Stop with a
        // real error rather than falling through to managed discovery, which
        // would point the operator at a Groovy endpoint they have no account on
        // and report a confusing "discovery failed" instead of the actual
        // problem with their file.
        handleError(
          err instanceof Error ? err.message : String(err),
          0,
        );
        return;
      }
    }

    // === BOOTSTRAP SELF-HEAL (schema refresh) ===
    // A bootstrap saved by an older app version can be "valid" yet predate a
    // discovery field the app now relies on (e.g. cognitoDomain for browser
    // sign-in). Re-run discovery once using the stored email to refresh it to
    // the current schema. One-time — saveBootstrap stamps the new version, so
    // bootstrapNeedsRefresh() returns false next launch. Never blocks startup:
    // on failure the existing bootstrap is kept and password login still works.
    if (isTauri() && !selfHosted && bootstrapNeedsRefresh()) {
      const bs = getBootstrap();
      if (bs?.email) {
        try {
          const r = await discover(bs.email);
          saveBootstrap({
            orgId: r.orgId,
            customerName: r.customerName,
            backendUrl: r.backendUrl,
            cognitoRegion: r.cognitoRegion,
            cognitoUserPoolId: r.cognitoUserPoolId,
            cognitoClientId: r.cognitoClientId,
            cognitoDomain: r.cognitoDomain,
            discoveredAt: new Date().toISOString(),
            email: bs.email,
          });
        } catch {
          // Keep the existing bootstrap; SRP password login still works.
        }
      }
    }

    // === DISCOVERY GATE (first-launch bootstrap) ===
    // In desktop production, if the app hasn't been bootstrapped yet, run
    // the email discovery flow so the user doesn't have to know their
    // backend URL. We trigger this whenever bootstrap is missing — even if
    // build-time Cognito env vars are present — because the cloud-routing
    // path needs `bootstrap.backendUrl` and that ONLY comes from discovery.
    // Skipping the gate when isCognitoConfigured() was the root cause of
    // v0.1.9's silent local-fallback bug: Cognito worked from env vars, so
    // the user could log in, but bootstrap.backendUrl was never populated
    // and isCloudUser() returned false → reads/writes silently went to
    // local SQLite.
    //
    // If the user is already authenticated when discovery is needed (e.g.
    // came in from a prior version that skipped the gate), run discovery
    // silently using their stored email instead of re-prompting.
    if (isTauri() && !selfHosted && !isBootstrapped()) {
      const authStore = useAuthStore.getState();
      const email = authStore.user?.email;
      if (authStore.isAuthenticated && email) {
        try {
          const result = await discover(email);
          saveBootstrap({
            orgId: result.orgId,
            customerName: result.customerName,
            backendUrl: result.backendUrl,
            cognitoRegion: result.cognitoRegion,
            cognitoUserPoolId: result.cognitoUserPoolId,
            cognitoClientId: result.cognitoClientId,
            cognitoDomain: result.cognitoDomain,
            discoveredAt: new Date().toISOString(),
            email,
          });
          // Continue with the rest of startup — bootstrap is now valid.
        } catch (err) {
          // Discovery failed even with a known email — fall through to the
          // interactive gate so the user can retry with a different email
          // or see the error.
          setState('discovery_required');
          return;
        }
      } else {
        setState('discovery_required');
        return; // DiscoveryGate handles it; onSuccess re-runs startup
      }
    }

    // === AUTH GATE ===
    // Skipped entirely in local mode — there is no user pool, and
    // isCognitoConfigured() reads BUILD-TIME env vars which a self-host binary
    // may still carry from its build environment. Gating on localMode rather
    // than on those being empty keeps a stray NEXT_PUBLIC_COGNITO_* from
    // demanding a login that can never succeed.
    if (!localMode && isCognitoConfigured()) {
      setIncludeAuthStep(true);
      setState('auth_checking');
      const authStore = useAuthStore.getState();

      if (authStore.isAuthenticated && !authStore.isTokenExpired()) {
        // Token valid — proceed to Docker checks
      } else if (authStore.refreshToken && authStore.user?.email) {
        // Token expired, try silent refresh
        setState('auth_refreshing');
        try {
          const session = await refreshSession(authStore.user.email, authStore.refreshToken);
          const idJwt = session.getIdToken().getJwtToken();
          const user = getUserFromToken(idJwt);
          authStore.setAuth(user, {
            accessToken: session.getAccessToken().getJwtToken(),
            idToken: idJwt,
            refreshToken: session.getRefreshToken().getToken(),
            expiresIn: 86400,
          });
        } catch {
          // Refresh failed — show login form
          authStore.clearAuth();
          setState('auth_required');
          return; // Stop — AuthGate handles login
        }
      } else {
        // No token — show login form
        setState('auth_required');
        return; // Stop — AuthGate handles login
      }
    }

    // === READ-ONLY FAST-PATH ===
    // Read-only users can only VIEW cloud data — they can't run assessments,
    // so they have no use for the Kali container or MCP server. Worse, the
    // image-pull path below calls set_toolkit_credentials, a blocked write for
    // read-only users, so the build can never complete and they'd be forced to
    // dismiss it by hand with "Skip for now". Short-circuit the whole
    // Docker/image/container/MCP pipeline for them and hand control straight to
    // the app. Cloud reads work off the auth token + bootstrap.backendUrl
    // alone, both established by the discovery + auth gates above. Reached only
    // when Cognito is configured (the auth gate ran and populated the user's
    // groups); local/no-auth dev has no groups so this is a no-op there.
    if (isReadOnlyNow()) {
      markCompleted();
      setState('skipped');
      return;
    }

    // === EXISTING STARTUP FLOW ===
    // Step index offset: auth step shifts all indices by 1 when present
    const s = isCognitoConfigured() ? 1 : 0;

    // Step 1: Diagnose Docker. Fan out into one of three failure states
    // (not_installed / not_running / daemon_unresponsive) or proceed.
    setState('checking');
    let diagnosis;
    try {
      diagnosis = await api.system.diagnoseDocker();
    } catch (e) {
      handleError(
        `Failed to check Docker state: ${e instanceof Error ? e.message : String(e)}`,
        s + 0,
      );
      return;
    }

    if (diagnosis.state === 'not_installed') {
      setState('docker_not_installed');
      return;
    }

    // Daemon not responding cases — surface specific UI.
    if (diagnosis.state === 'not_running') {
      setState('docker_not_running');
      return;
    }
    if (diagnosis.state === 'daemon_unresponsive') {
      setState('docker_daemon_unresponsive');
      return;
    }

    // Healthy — straight through to image check.
    let daemonRunning = true;

    // Step 3: Check Kali image
    setState('checking_image');
    let imageExists = false;
    try {
      imageExists = await api.system.checkKaliImageExists();
    } catch {
      handleError('Failed to check Kali image', s + 2);
      return;
    }

    // Self-hosted, image absent: stop here with something actionable.
    //
    // There is no local-build fallback in the pull chain below (see the long
    // comment at the anonymous-pull step), and a self-hosted install has no
    // backend to broker a registry credential from. So without a usable image
    // the run cannot proceed — say why, and say the ONE thing that fixes it.
    //
    // Which fix depends on where the image is supposed to come from, and the
    // configured tag tells us: a tag with no registry host in it (no "/", e.g.
    // "maestro-toolkit:local") cannot be pulled by anyone and must have been
    // built locally. A tag that names a repository ("ghcr.io/owner/img:tag") is
    // pullable, so the user just needs to fetch it.
    //
    // Getting this wrong is a dead end rather than an inconvenience: telling
    // someone who installed a signed .dmg to "run ./scripts/build-... from the
    // repo root" points them at a repo they do not have.
    if (selfHosted && !imageExists) {
      let expected = '';
      try {
        expected = await invoke<string>('get_configured_kali_image');
      } catch {
        // Best-effort — the generic wording below is still actionable.
      }

      const pullable = expected.includes('/');
      const named = expected || 'your configured KALI_IMAGE tag';

      handleError(
        pullable
          ? `Toolkit image not found locally (${named}). Fetch it, then restart ` +
              `Maestro:\n\n    docker pull ${expected}\n\n` +
              `It is around 15 GB, so expect a few minutes. Docker must be ` +
              `running. See SELF-HOSTING.md if the pull is denied.`
          : `Toolkit image not found locally (${named}). That tag names no ` +
              `registry, so it has to be built from source. From a checkout of ` +
              `the repository, run:\n\n    ./scripts/build-self-host-toolkit.sh\n\n` +
              `then restart Maestro. Expect 30-60 minutes and ~15 GB. If you ` +
              `installed Maestro from a packaged download rather than source, ` +
              `this build is not the intended path — see SELF-HOSTING.md.`,
        s + 2,
      );
      return;
    }

    // Detect Maestro version change since last successful image pull.
    // Docker doesn't auto-refresh `:latest` tags, so a desktop update
    // (v0.1.X→Y) leaves users with the cached old image even though the
    // remote one moved. We track the last-pulled version in localStorage
    // and run the pull again on first boot of a new desktop version.
    //
    // Without this, users hit confusing failures like "codex: command
    // not found" (v0.1.32 → cached v0.1.31 image where codex wasn't
    // installed yet).
    let currentDesktopVersion = '';
    let needsPullForUpgrade = false;
    try {
      const { getVersion } = await import('@tauri-apps/api/app');
      currentDesktopVersion = await getVersion();
      const lastPulledVersion = localStorage.getItem('maestro:last-pulled-version');
      // Self-hosted installs are excluded: their image is built locally from
      // docker/Dockerfile.kali (see scripts/build-self-host-toolkit.sh), not
      // pulled from a registry. Forcing a pull on version change would try to
      // fetch a local-only tag like `maestro-toolkit:local`, fail, and fall
      // through to a 30-60 minute rebuild on every desktop upgrade. The
      // operator owns the image lifecycle in that arrangement.
      if (!selfHosted && imageExists && lastPulledVersion !== currentDesktopVersion) {
        needsPullForUpgrade = true;
        console.log(
          `[startup] desktop version changed (${lastPulledVersion ?? 'none'} → ${currentDesktopVersion}), refreshing Kali image`,
        );
      }
    } catch {
      // Non-fatal — if we can't read the version, skip the upgrade pull.
      // Image still loads from cache; user can hit the Pull Latest button
      // in System Status if they need a refresh.
    }

    // Pull image from GHCR if missing OR if Maestro version changed.
    // Production path: fetch a short-lived pull credential from the
    // backend (`/api/v1/toolkit/registry-credentials`) using the Cognito
    // id token we got from the auth gate above, then pull with those
    // creds. Falls back to anonymous pull, then local build, if the
    // backend isn't reachable (e.g. offline dev install).
    if (!imageExists || needsPullForUpgrade) {
      setState('building_image');

      // Subscribe to progress events — docker.rs emits the same channel
      // for both pulls and local builds so the UI renders either.
      try {
        const unsub = await api.system.onBuildProgress((line: string) => {
          setBuildLines((prev) => {
            const next = [...prev, line];
            return next.length > 200 ? next.slice(-200) : next;
          });
        });
        cleanupRef.current = unsub;
      } catch {
        // Non-fatal: we just won't have live progress
      }

      // Subscribe to structured pull-progress events. Separate channel
      // from onBuildProgress because (a) local builds don't have layer
      // bytes to report, and (b) this stream is throttled server-side
      // to ~5 Hz so wiring it as React state is safe.
      try {
        const unsubPull = await api.system.onPullProgress((p) => {
          setPullProgress(p);
          setLastProgressAt(Date.now());
        });
        pullCleanupRef.current = unsubPull;
      } catch {
        // Non-fatal: the build-log fallback above still works.
      }

      const { getRegistryCredentials } = await import('@/lib/toolkit-api');

      // Authenticated pull using the backend-brokered read-only GHCR PAT.
      let pulled = false;
      try {
        const creds = await getRegistryCredentials();
        // Cache the credential in Rust AppState FIRST, so the container
        // lifecycle (create/recreate in start_container) also pulls
        // authenticated — not just this frontend pull. This is what makes
        // "logged in → toolkit just works" true end-to-end, including the
        // resilient recreate path that previously pulled anonymously.
        await api.system.setToolkitCredentials(
          creds.username,
          creds.password,
          creds.expires_at ?? null,
        );
        await api.system.pullKaliImageWithAuth(creds.username, creds.password);
        pulled = true;
      } catch (credErr) {
        console.warn(
          '[startup] authenticated pull failed, trying anonymous:',
          credErr instanceof Error ? credErr.message : String(credErr),
        );
      }

      // Anonymous pull — only works if the package was made public.
      if (!pulled) {
        try {
          await api.system.pullKaliImage();
          pulled = true;
        } catch (anonErr) {
          console.warn(
            '[startup] anonymous pull failed:',
            anonErr instanceof Error ? anonErr.message : String(anonErr),
          );
        }
      }

      // NO local-build fallback, NO hard error here. The old code tried
      // `build_kali_image()` (which can never work on a released binary —
      // CARGO_MANIFEST_DIR is baked to a CI runner path) and then bricked
      // startup with "Docker directory not found". Instead we ALWAYS fall
      // through to Step 4 (startKali). The Rust `start_container` is the
      // single source of truth for the resilient lifecycle: it obtains the
      // pinned image before tearing anything down, keeps the existing
      // container running (degraded — toolkit update pending) when the
      // image can't be pulled, and only returns an honest, actionable
      // error when there's genuinely no usable toolkit at all. So a failed
      // pull here is never fatal — the app stays up on whatever image it
      // already has.
      if (!pulled && imageExists) {
        // Best-effort upgrade pull failed but the cached image is still
        // usable. Log it and continue — user can hit Pull Latest in
        // System Status when networks/auth recover.
        console.warn(
          `[startup] version-change pull failed, continuing with cached image (Maestro v${currentDesktopVersion}). Use System Status → Pull Latest when ready.`,
        );
      }

      // Mark this Maestro version as having attempted an image refresh
      // so the next boot doesn't re-try on every launch — even if the
      // pull failed, we don't want every boot to re-attempt the broken
      // path. The user can force a retry via System Status → Pull Latest.
      if (currentDesktopVersion) {
        try {
          localStorage.setItem('maestro:last-pulled-version', currentDesktopVersion);
        } catch {
          // localStorage might be full or disabled — non-fatal
        }
      }

      cleanupRef.current?.();
      cleanupRef.current = null;
      pullCleanupRef.current?.();
      pullCleanupRef.current = null;
    }

    // Step 4: Start container
    //
    // Watchdog: the Rust lifecycle bounds each Docker daemon call (30s
    // each), but we add a hard ceiling on the whole step as a belt-and-
    // suspenders safety net so the gate can NEVER freeze indefinitely on
    // "Start Kali Container" — the symptom that previously forced users to
    // quit the app and restart Docker by hand. On timeout we surface a
    // retryable error (the error UI below has a Retry button) instead of
    // spinning forever. 4 min comfortably covers a slow cold-start container
    // create + first MCP boot while still being a finite bound.
    setState('starting_container');
    const STARTKALI_WATCHDOG_MS = 4 * 60_000;
    try {
      await Promise.race([
        api.system.startKali(),
        new Promise<never>((_, reject) =>
          setTimeout(
            () =>
              reject(
                new Error(
                  "Starting the Kali container took too long (over 4 minutes). " +
                    "Docker Desktop may be hung — restart Docker Desktop (or quit and reopen it), " +
                    'then click Retry.',
                ),
              ),
            STARTKALI_WATCHDOG_MS,
          ),
        ),
      ]);
    } catch (e) {
      handleError(
        `Failed to start Kali container: ${e instanceof Error ? e.message : String(e)}`,
        s + 3
      );
      return;
    }

    // Step 5: Start MCP server and wait for it to become healthy
    setState('connecting_mcp');
    try {
      await api.system.ensureMcpServer();
    } catch {
      // Non-fatal: the start_kali_container already tried, this is a retry
    }
    // Poll for health. After a fresh container recreate (e.g. v0.1.9
    // env-var drift), `npm install --production` inside the container can
    // take 2-4 minutes. The old 60s timeout was too short for that case
    // and the gate would proceed with MCP marked offline — leaving the
    // System Health badge red on the dashboard until manual Stop+Start.
    const mcpTimeout = Date.now() + 5 * 60_000;
    let mcpRetries = 0;
    while (Date.now() < mcpTimeout) {
      try {
        const status = await api.system.getStatus();
        if (status.mcp_server_connected) break;
        // Re-issue the start command at 60s and 180s in case the first
        // attempt's npm install crashed and exited.
        const elapsed = Date.now() - (mcpTimeout - 5 * 60_000);
        if ((elapsed > 60_000 && mcpRetries === 0) ||
            (elapsed > 180_000 && mcpRetries === 1)) {
          mcpRetries += 1;
          await api.system.ensureMcpServer().catch(() => {});
        }
      } catch {
        // ignore
      }
      await new Promise((r) => setTimeout(r, 2000));
    }

    // Step 6: Detect Claude Code CLI inside the container + tmux
    // (Ollama / local LLM checks were removed in 0.1.20 — Claude Code drives
    // all LLM calls now, and its auth lives inside the Kali container.)
    setState('checking_claude');
    try {
      const clis = await api.terminal.checkAvailableClis();
      // Claude Code is installed inside every Kali image we ship, so a
      // negative result here only matters when the user is running outside
      // the bundled container — surface as a non-fatal warning.
      if (!clis.claude) {
        setClaudeWarning(true);
      }
    } catch {
      setClaudeWarning(true);
    }

    // Detect tmux (bundled sidecar or system) — non-blocking
    try {
      const resolvedTmuxPath = await api.terminal.getTmuxPath();
      useSettingsStore.getState().setTmuxPath(resolvedTmuxPath);
    } catch {
      useSettingsStore.getState().setTmuxPath(null);
    }

    // No CLI picker anymore — Claude Code is the only driver. Mark the
    // gate complete and hand control to the app.
    markCompleted();
    setState('ready');
  }, [handleError]);

  /** Poll diagnoseDocker until it returns healthy (or until the configured
   *  timeout fires). Used by the "Open Docker Desktop" and "Restart Docker"
   *  action buttons after they've kicked off the relevant action. The user
   *  sees the "Start Docker Desktop" stage spinning during this wait. */
  const waitForDockerHealthy = useCallback(async () => {
    setState('waiting_for_docker');
    const deadline = Date.now() + DOCKER_WAIT_TIMEOUT_MS;
    while (Date.now() < deadline) {
      try {
        const d = await api.system.diagnoseDocker();
        if (d.state === 'healthy') {
          // Healthy — re-run startup to continue with image check.
          runStartup();
          return;
        }
      } catch {
        // Diagnosis itself errored — try again.
      }
      await new Promise((r) => setTimeout(r, 2000));
    }
    handleError(
      'Docker Desktop did not become responsive within 2 minutes. ' +
        'Open Docker Desktop manually and check that the whale icon is solid (not animating), ' +
        'then click Retry.',
      isCognitoConfigured() ? 2 : 1,
    );
  }, [runStartup, handleError]);

  const handleOpenDocker = useCallback(async () => {
    setState('starting_docker');
    try {
      await api.system.openDockerDesktop();
    } catch (e) {
      handleError(
        `Failed to open Docker Desktop: ${e instanceof Error ? e.message : String(e)}`,
        isCognitoConfigured() ? 2 : 1,
      );
      return;
    }
    void waitForDockerHealthy();
  }, [handleError, waitForDockerHealthy]);

  const handleRestartDocker = useCallback(async () => {
    setState('starting_docker');
    try {
      await api.system.restartDockerDesktop();
    } catch (e) {
      handleError(
        `Failed to restart Docker Desktop: ${e instanceof Error ? e.message : String(e)}`,
        isCognitoConfigured() ? 2 : 1,
      );
      return;
    }
    void waitForDockerHealthy();
  }, [handleError, waitForDockerHealthy]);

  const handleAuthSuccess = useCallback(() => {
    // Auth complete — re-run startup (will pass auth check this time)
    runStartup();
  }, [runStartup]);

  const handleDiscoverySuccess = useCallback(() => {
    // Bootstrap saved — re-run startup (isCognitoConfigured() is now true)
    runStartup();
  }, [runStartup]);

  // Run startup on mount.
  //
  // We intentionally read hasCompleted via readHasCompleted() here
  // (rather than the module-level cached `hasCompleted`) so that on the
  // first ever client mount we get the persisted value from
  // sessionStorage. The module-level value is a stale default-false
  // because we can't read storage during SSR / static-export build
  // without breaking hydration. After this initial read, the module
  // cache stays in sync with markCompleted() / explicit resets below.
  useEffect(() => {
    if (!hasCompleted) hasCompleted = readHasCompleted();
    if (hasCompleted) {
      setState('ready');
      return;
    }

    runStartup();

    return () => {
      cleanupRef.current?.();
      pullCleanupRef.current?.();
    };
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  // Ready or skipped: render children
  if (state === 'ready' || state === 'skipped') {
    return <>{children}</>;
  }

  // First-launch discovery: ask for email, auto-configure Cognito + backend URL
  if (state === 'discovery_required') {
    return <DiscoveryGate onSuccess={handleDiscoverySuccess} />;
  }

  // Auth required: show login form (replaces entire card)
  if (state === 'auth_required') {
    return <AuthGate onSuccess={handleAuthSuccess} />;
  }

  // Render startup gate UI
  return (
    <div className="flex items-center justify-center min-h-[calc(100vh-8rem)]">
      <Card className="w-full max-w-lg">
        <CardHeader>
          <CardTitle className="text-xl">Starting Services</CardTitle>
          <CardDescription>
            {state === 'docker_not_installed'
              ? 'Docker Desktop is required but not installed'
              : state === 'error'
                ? 'An error occurred during startup'
                : 'Setting up the security testing environment...'}
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          {/* Progress bar */}
          {state !== 'docker_not_installed' && (
            <Progress value={getProgressPercent(state)} className="h-2" />
          )}

          {/* Steps list */}
          <div className="space-y-3">
            {steps.map((step, idx) => {
              let status = getStepStatus(steps, idx, state, errorStepIndex);

              // Show warning icon for CLI step if none found
              if (step.label === 'Verify CLI' && claudeWarning && status === 'completed') {
                status = 'warning';
              }

              return (
                <div key={step.label}>
                  <div className="flex items-center gap-3">
                    {status === 'completed' && (
                      <CheckCircle2 className="h-5 w-5 text-green-500 shrink-0" />
                    )}
                    {status === 'active' && (
                      <Loader2 className="h-5 w-5 text-primary animate-spin shrink-0" />
                    )}
                    {status === 'pending' && (
                      <Circle className="h-5 w-5 text-muted-foreground/40 shrink-0" />
                    )}
                    {status === 'error' && (
                      <XCircle className="h-5 w-5 text-destructive shrink-0" />
                    )}
                    {status === 'warning' && (
                      <AlertTriangle className="h-5 w-5 text-yellow-500 shrink-0" />
                    )}
                    <span
                      className={
                        status === 'active'
                          ? 'text-sm font-medium text-foreground'
                          : status === 'completed'
                            ? 'text-sm text-muted-foreground'
                            : status === 'error'
                              ? 'text-sm text-destructive'
                              : status === 'warning'
                                ? 'text-sm text-yellow-500'
                                : 'text-sm text-muted-foreground/50'
                      }
                    >
                      {step.label}
                      {status === 'active' && state === 'auth_refreshing' && (
                        <span className="ml-1 text-xs text-muted-foreground">
                          (refreshing session...)
                        </span>
                      )}
                      {status === 'active' && state === 'waiting_for_docker' && (
                        <span className="ml-1 text-xs text-muted-foreground">
                          (waiting for daemon...)
                        </span>
                      )}
                      {status === 'active' && state === 'docker_not_running' && (
                        <span className="ml-1 text-xs text-yellow-500/80">
                          (not running)
                        </span>
                      )}
                      {status === 'active' && state === 'docker_daemon_unresponsive' && (
                        <span className="ml-1 text-xs text-orange-500/80">
                          (daemon not responding)
                        </span>
                      )}
                      {status === 'active' && state === 'building_image' && (
                        <span className="ml-1 text-xs text-muted-foreground">
                          (downloading toolkit...)
                        </span>
                      )}
                      {step.label === 'Ready' && status === 'warning' && (
                        <span className="ml-1 text-xs text-yellow-500/70">
                          (CLI not found)
                        </span>
                      )}
                    </span>
                  </div>
                  {/* Inline detail under the failed step row */}
                  {status === 'error' && errorMessage && (
                    <StepErrorDetail message={errorMessage} />
                  )}
                </div>
              );
            })}
          </div>

          {/* Build log + first-run heads-up */}
          {(state === 'building_image' || (state === 'error' && buildLines.length > 0)) && (
            <div className="space-y-2">
              {state === 'building_image' && (
                <div className="rounded-md border border-blue-500/30 bg-blue-500/5 px-3 py-2 text-xs text-blue-300">
                  <div className="font-medium">First-launch download in progress</div>
                  <div className="text-blue-300/80 mt-0.5">
                    Maestro pulls a ~6 GB Kali toolkit image the first time you run the app. Expect 5–15 minutes on a typical broadband connection.
                  </div>
                </div>
              )}

              {/* Live pull progress: shows a real % bar, MB done/total, MB/s,
                  and a stall warning if no bytes have moved in ~45s. Falls
                  back gracefully when pullProgress is null (e.g. on a local
                  build path that doesn't emit layer events). */}
              {state === 'building_image' && pullProgress && (() => {
                const warming = pullProgress.pct < 0;
                const pct = warming ? 0 : Math.min(100, pullProgress.pct);
                const stalled =
                  !warming &&
                  lastProgressAt !== null &&
                  now - lastProgressAt > 45_000 &&
                  pullProgress.pct < 100;
                return (
                  <div className="rounded-md border bg-muted/50 px-3 py-3 space-y-2">
                    <div className="flex items-center justify-between text-xs">
                      <span className="font-medium">
                        {warming ? 'Preparing download…' : `${pct.toFixed(1)}%`}
                      </span>
                      <span className="font-mono text-[10px] text-muted-foreground">
                        {pullProgress.mb_done.toFixed(0)} / {pullProgress.mb_total > 0 ? `${pullProgress.mb_total.toFixed(0)} MB` : '— MB'}
                        {pullProgress.mbps > 0 && ` · ${pullProgress.mbps.toFixed(1)} MB/s`}
                      </span>
                    </div>
                    <Progress
                      value={warming ? undefined : pct}
                      className={cn('h-2', stalled && 'opacity-60')}
                    />
                    <div className="flex items-center justify-between text-[10px] text-muted-foreground/80">
                      <span>
                        {pullProgress.layers_done} of {pullProgress.layers} layers complete
                      </span>
                      {stalled && (
                        <span className="text-amber-400">
                          No data received in {Math.round((now - (lastProgressAt ?? now)) / 1000)}s — pull may be stalled
                        </span>
                      )}
                    </div>
                  </div>
                );
              })()}

              <div className="rounded-md border bg-muted/50">
                <div className="px-3 py-2 text-xs font-medium text-muted-foreground border-b flex items-center justify-between">
                  <span>Build Output</span>
                  {state === 'building_image' && buildLines.length > 0 && (
                    <span className="font-mono text-[10px] text-muted-foreground/70">
                      {buildLines.length} updates
                    </span>
                  )}
                </div>
                <ScrollArea className="h-40">
                  <div ref={buildLogRef} className="p-3 font-mono text-xs leading-relaxed">
                    {buildLines.slice(-50).map((line, i) => (
                      <div key={i} className="text-muted-foreground whitespace-pre-wrap break-all">
                        {line}
                      </div>
                    ))}
                  </div>
                </ScrollArea>
              </div>
            </div>
          )}

          {/* Docker not installed */}
          {state === 'docker_not_installed' && (
            <div className="space-y-3">
              <p className="text-sm text-muted-foreground">
                Docker Desktop is required to run the Kali Linux security tools.
                Please install it and retry.
              </p>
              <Button
                variant="default"
                className="w-full"
                onClick={() => {
                  window.open('https://www.docker.com/products/docker-desktop/', '_blank');
                }}
              >
                <Download className="mr-2 h-4 w-4" />
                Download Docker Desktop
              </Button>
              <Button
                variant="outline"
                className="w-full"
                onClick={() => runStartup()}
              >
                <RefreshCw className="mr-2 h-4 w-4" />
                Retry
              </Button>
            </div>
          )}

          {/* Docker installed but not running yet */}
          {state === 'docker_not_running' && (
            <div className="space-y-3">
              <div className="rounded-md border border-yellow-500/30 bg-yellow-500/5 px-3 py-2 text-xs text-yellow-200">
                <div className="font-medium">Docker Desktop isn't running</div>
                <div className="text-yellow-200/80 mt-0.5">
                  We found Docker Desktop installed but it isn't started.
                  We'll launch it for you — first boot can take 1–2 minutes.
                </div>
              </div>
              <Button variant="default" className="w-full" onClick={handleOpenDocker}>
                <Play className="mr-2 h-4 w-4" />
                Open Docker Desktop
              </Button>
              <Button variant="outline" className="w-full" onClick={() => runStartup()}>
                <RefreshCw className="mr-2 h-4 w-4" />
                Retry diagnosis
              </Button>
            </div>
          )}

          {/* Docker GUI running but daemon hung — needs hard restart */}
          {state === 'docker_daemon_unresponsive' && (
            <div className="space-y-3">
              <div className="rounded-md border border-orange-500/30 bg-orange-500/5 px-3 py-2 text-xs text-orange-200">
                <div className="font-medium">Docker Desktop is running but the daemon isn't responding</div>
                <div className="text-orange-200/80 mt-0.5">
                  This usually means Docker's Linux VM is hung. The fastest fix is a hard restart —
                  we'll quit Docker Desktop cleanly and relaunch it.
                </div>
              </div>
              <Button variant="default" className="w-full" onClick={handleRestartDocker}>
                <RotateCcw className="mr-2 h-4 w-4" />
                Restart Docker Desktop
              </Button>
              <Button variant="outline" className="w-full" onClick={() => runStartup()}>
                <RefreshCw className="mr-2 h-4 w-4" />
                Retry diagnosis
              </Button>
            </div>
          )}

          {/* "Still waiting" hint after 30s of waiting_for_docker */}
          {state === 'waiting_for_docker' && (
            <DockerWaitHint />
          )}

          {/* Error state */}
          {state === 'error' && (
            <div className="space-y-3">
              <p className="text-sm text-destructive">{errorMessage}</p>
              <Button
                variant="default"
                className="w-full"
                onClick={() => {
                  hasCompleted = false;
                  try { sessionStorage.removeItem(STORAGE_KEY); } catch { /* ignore */ }
                  runStartup();
                }}
              >
                <RefreshCw className="mr-2 h-4 w-4" />
                Retry
              </Button>
            </div>
          )}

          {/* Skip link */}
          <div className="text-center">
            <button
              onClick={() => {
                markCompleted();
                setState('skipped');
              }}
              className="text-xs text-muted-foreground/60 hover:text-muted-foreground underline underline-offset-2"
            >
              Skip for now
            </button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
