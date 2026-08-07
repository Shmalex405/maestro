// Where this install's data lives.
//
// Maestro runs in one of two shapes:
//
//   LOCAL — everything on this machine. Findings, assessments, reports and
//           projects live in the local SQLite DB (~/.pentest/data/pentest.db),
//           read and written through Tauri commands. No backend, no sign-in,
//           nothing to provision. Single operator.
//
//   CLOUD — a backend holds the data and multiple users share it. Covers BOTH
//           a self-hosted team deployment (deploy/terraform/maestro-self-host)
//           and a managed subscription. The distinction between those two
//           matters for how the app is *configured* (local file vs discovery),
//           but not for how data is *routed* — both go through cloudRequest.
//           See lib/self-host.ts for the configuration side.
//
// The routing decision is therefore binary, which is why this module exposes
// `local | cloud` rather than mirroring the three-way config distinction.
//
// ── Why the getter is synchronous ────────────────────────────────────────────
//
// The mode lives in the Rust config, which is only reachable through an async
// `invoke`. But the dispatch sites in tauri-api.ts are plain expression-bodied
// methods (`list: (p) => cloudRequest(...)`), and making all ~37 of them await
// a mode lookup would be both noisy and a per-call round trip. So the mode is
// resolved ONCE during startup (`resolveDataMode`), cached in localStorage, and
// read synchronously thereafter — the same arrangement `getBootstrap()` uses.

const STORAGE_KEY = 'maestro-data-mode';

export type DataMode = 'local' | 'cloud';

/** The default is deliberately `cloud`, not `local`.
 *
 *  Every install that existed before local mode shipped is cloud-backed and has
 *  no value under this key. Defaulting to `local` would silently repoint those
 *  users at an empty SQLite database on first launch after upgrading — their
 *  findings would appear to have vanished. Defaulting to `cloud` means the
 *  worst case for a misdetected local install is a visible "no backend
 *  configured" error, which is recoverable and obvious.
 *
 *  Local mode is therefore opt-IN: it is only ever set by an explicit signal
 *  from the Rust config. */
const DEFAULT_MODE: DataMode = 'cloud';

export function getDataMode(): DataMode {
  if (typeof window === 'undefined') return DEFAULT_MODE;
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    return raw === 'local' || raw === 'cloud' ? raw : DEFAULT_MODE;
  } catch {
    return DEFAULT_MODE;
  }
}

/** True when reads and writes should go to the local SQLite DB. */
export function isLocalMode(): boolean {
  return getDataMode() === 'local';
}

export function setDataMode(mode: DataMode): void {
  if (typeof window === 'undefined') return;
  try {
    localStorage.setItem(STORAGE_KEY, mode);
  } catch {
    // A blocked localStorage leaves the default in place. Cloud mode failing
    // loudly beats local mode failing silently.
  }
}

/** Clear the cached mode so the next resolve re-reads the Rust config. Used by
 *  the first-run picker after it writes a new config. */
export function clearDataMode(): void {
  if (typeof window === 'undefined') return;
  try {
    localStorage.removeItem(STORAGE_KEY);
  } catch {
    /* ignore */
  }
}

/** Human-readable label for the mode, for status surfaces. */
export function dataModeLabel(mode: DataMode = getDataMode()): string {
  return mode === 'local' ? 'Local' : 'Team';
}

// ── Team-only capabilities ───────────────────────────────────────────────────
//
// Local mode is not a crippled cloud mode; it is a genuinely smaller product.
// These features are backed by Postgres-native schema that the local SQLite DB
// does not have — the attack graph in particular relies on an accumulating
// node/edge union plus a recursive-CTE pathfinder, and footholds/capabilities
// have no local tables at all.
//
// Listing them here (rather than scattering `isLocalMode()` checks through the
// UI) keeps the boundary auditable: if a feature is unavailable locally, it says
// so in one place, and the UI can explain WHY rather than rendering an empty
// panel that looks broken.

export type TeamOnlyFeature =
  | 'attack-graph'
  | 'post-exploitation'
  | 'scheduled-dast'
  | 'user-management'
  | 'cross-assessment-cache';

const TEAM_ONLY_REASON: Record<TeamOnlyFeature, string> = {
  'attack-graph':
    'The attack-graph explorer needs the Postgres graph substrate and its recursive-CTE pathfinder. Deploy a team backend to enable it.',
  'post-exploitation':
    'Post-exploitation campaigns persist footholds and capabilities in Postgres. Deploy a team backend to enable it.',
  'scheduled-dast':
    'Scheduled scans run on an always-on cloud runner, so they need a team backend.',
  'user-management':
    'There is only one user in local mode — invites and roles need a team backend with a Cognito pool.',
  'cross-assessment-cache':
    'Cross-assessment recon/SAST caching is stored server-side. Deploy a team backend to enable it.',
};

/** Whether a feature is usable in the current mode.
 *
 *  Every entry in TeamOnlyFeature is currently cloud-gated by the same
 *  condition, so `feature` is not consulted — it is part of the signature so
 *  call sites read as a question about a specific capability, and so a future
 *  feature that IS available locally can be carved out without touching them. */
export function isFeatureAvailable(feature: TeamOnlyFeature): boolean {
  return feature in TEAM_ONLY_REASON && !isLocalMode();
}

/** Why a feature is unavailable, or null when it is available. Render this
 *  instead of an empty panel — "not in local mode, here's why" is a far better
 *  experience than a spinner that never resolves. */
export function featureUnavailableReason(feature: TeamOnlyFeature): string | null {
  return isFeatureAvailable(feature) ? null : TEAM_ONLY_REASON[feature];
}
