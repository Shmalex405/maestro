// Desktop bootstrap: the one-time "hand this app a URL + Cognito settings so
// it knows who it's talking to" flow.
//
// On first launch, the desktop app hits the Groovy platform's /api/discover
// endpoint with the user's email and gets back the backend URL and Cognito
// config for that customer. We cache the result in localStorage so subsequent
// launches skip the discovery step.
//
// Build-time env var NEXT_PUBLIC_MAESTRO_PLATFORM_URL points at the platform.

export interface Bootstrap {
  orgId: string;
  customerName: string;
  backendUrl: string;
  cognitoRegion: string;
  cognitoUserPoolId: string;
  cognitoClientId: string;
  // Hosted UI domain host (no scheme), e.g. "login.maestro.groovysec.com".
  // Optional: absent in bootstraps written before browser-OAuth shipped, and
  // empty until the platform publishes it. Gates the browser sign-in only.
  cognitoDomain?: string;
  // OAST listener for the `oast` verification oracle (blind SSRF/SQLi/XXE/SSTI,
  // where the target's callback is the only proof). Absent when the org has no
  // listener — the oracle then reports `oast_unavailable` and blind findings
  // stay honest unverified candidates.
  //
  // `server` arrives from discovery (a hostname, like backendUrl). `token` does
  // NOT: it gates polling for interactions carrying target IPs and blind-payload
  // exfil, so it must come from an authenticated source — the org's own backend
  // config store, or MAESTRO_OAST_TOKEN for a self-hosted listener. A listener
  // that requires auth and has no token here simply stays unavailable, which the
  // oracle reports honestly.
  oast?: { server: string; token?: string };
  discoveredAt: string; // ISO
  email: string;        // the email that produced this bootstrap
  // Schema version of the discovery payload this bootstrap was saved from.
  // Bumped whenever /api/discover starts returning a new field the app relies
  // on. A stored bootstrap older than BOOTSTRAP_SCHEMA_VERSION is silently
  // re-discovered on startup (see bootstrapNeedsRefresh). Absent ⇒ legacy v1.
  schemaVersion?: number;
}

const STORAGE_KEY = 'maestro-bootstrap';

// Bump this when /api/discover adds a field the app depends on, so existing
// users' cached bootstraps auto-refresh instead of silently missing it.
//   v1: original (orgId, backendUrl, cognito region/pool/client)
//   v2: + cognitoDomain (browser-OAuth Hosted UI)
//   v3: + oast (listener for the verification oracle) — existing installs
//       re-discover once so the oracle stops reporting oast_unavailable
export const BOOTSTRAP_SCHEMA_VERSION = 3;

export const PLATFORM_URL =
  process.env.NEXT_PUBLIC_MAESTRO_PLATFORM_URL || 'https://app.maestro.groovysec.com';

export function getBootstrap(): Bootstrap | null {
  if (typeof window === 'undefined') return null;
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return null;
    return JSON.parse(raw) as Bootstrap;
  } catch {
    return null;
  }
}

export function saveBootstrap(b: Bootstrap): void {
  if (typeof window === 'undefined') return;
  // Always stamp the current schema version so every freshly-discovered
  // bootstrap is up to date, regardless of which call site saved it.
  localStorage.setItem(
    STORAGE_KEY,
    JSON.stringify({ ...b, schemaVersion: BOOTSTRAP_SCHEMA_VERSION }),
  );
}

export function clearBootstrap(): void {
  if (typeof window === 'undefined') return;
  localStorage.removeItem(STORAGE_KEY);
}

/** A stored bootstrap is only usable if it carries the cloud routing target
 *  (`backendUrl`) AND the Cognito config needed to authenticate. A partial
 *  object — e.g. written by an older app version, or a half-completed save —
 *  would otherwise pass as "bootstrapped", cause the startup gate to skip
 *  discovery, and leave every `cloudRequest` throwing "No cloud backend
 *  configured": blank data panels with no server-side error to explain them.
 *  Validating here makes a partial bootstrap re-run discovery and self-heal. */
export function isValidBootstrap(b: Bootstrap | null): b is Bootstrap {
  const nonEmpty = (v: unknown): v is string =>
    typeof v === 'string' && v.trim() !== '';
  return (
    !!b &&
    nonEmpty(b.backendUrl) &&
    nonEmpty(b.cognitoRegion) &&
    nonEmpty(b.cognitoUserPoolId) &&
    nonEmpty(b.cognitoClientId)
  );
}

export function isBootstrapped(): boolean {
  return isValidBootstrap(getBootstrap());
}

/** True when a usable bootstrap exists but predates the current discovery
 *  schema (e.g. saved before a new field like cognitoDomain was added). The
 *  startup gate re-runs discovery once to backfill it — a general mechanism so
 *  future field additions reach existing users without a per-field patch. */
export function bootstrapNeedsRefresh(): boolean {
  const b = getBootstrap();
  if (!isValidBootstrap(b)) return false; // not bootstrapped → normal flow
  return (b.schemaVersion ?? 1) < BOOTSTRAP_SCHEMA_VERSION;
}

export interface DiscoveryResponse {
  orgId: string;
  customerName: string;
  backendUrl: string;
  authProvider: 'cognito';
  cognitoRegion: string;
  cognitoUserPoolId: string;
  cognitoClientId: string;
  cognitoDomain?: string;
  // Hostname only — the polling token never rides this unauthenticated
  // endpoint. See the note in app/api/discover/route.web.ts.
  oast?: { server: string };
  recognized: boolean;
}

export async function discover(email: string): Promise<DiscoveryResponse> {
  const url = `${PLATFORM_URL.replace(/\/+$/, '')}/api/discover?email=${encodeURIComponent(email)}`;
  const res = await fetch(url, {
    method: 'GET',
    headers: { Accept: 'application/json' },
  });

  if (!res.ok) {
    const body = await res.text().catch(() => '');
    throw new Error(`Discovery failed (${res.status}): ${body || res.statusText}`);
  }

  return (await res.json()) as DiscoveryResponse;
}
