// Thin client for the backend's /api/v1/toolkit endpoints.
//
// The credentials endpoint brokers a GHCR read-only PAT so the desktop
// can pull the private docker-kali image without storing the PAT locally.
// See backend-rs/src/routes/toolkit.rs for the server side.

import { getBootstrap } from './desktop-bootstrap';
import { useAuthStore } from './stores/auth-store';
import { getValidIdToken } from './tauri-api';

export interface RegistryCredentials {
  registry: string;
  username: string;
  password: string;
  image: string;
  /** Unix-seconds expiry of the credential (a short-lived GitHub App
   *  installation token). Absent for the legacy long-lived PAT. The desktop
   *  caches the credential in Rust AppState (via set_toolkit_credentials) so
   *  the container lifecycle can pull the private image authenticated. */
  expires_at?: number | null;
}

function backendBaseUrl(): string {
  const bootstrap = getBootstrap();
  if (bootstrap?.backendUrl) return bootstrap.backendUrl.replace(/\/+$/, '');
  const web = useAuthStore.getState().backendUrl;
  if (web) return web.replace(/\/+$/, '');
  throw new Error(
    'Backend URL is not configured — complete the login flow first.'
  );
}

/** Build auth headers, using the shared `getValidIdToken` helper that
 *  handles refresh-on-expiry. Without this, the toolkit endpoint bails
 *  on stale tokens with "Not authenticated." even when a refresh would
 *  succeed — the symptom users saw on first launch of v0.1.33+ where
 *  the auto-pull silently failed and dropped to the (broken) anonymous
 *  fallback. */
async function authHeaders(): Promise<Headers> {
  const idToken = await getValidIdToken();
  if (!idToken) {
    throw new Error('Not authenticated. Sign in to Maestro Cloud first.');
  }
  const h = new Headers();
  h.set('Authorization', `Bearer ${idToken}`);
  h.set('Accept', 'application/json');
  return h;
}

export async function getRegistryCredentials(): Promise<RegistryCredentials> {
  const res = await fetch(
    `${backendBaseUrl()}/api/v1/toolkit/registry-credentials`,
    { headers: await authHeaders() }
  );
  if (!res.ok) {
    let msg = `${res.status} ${res.statusText}`;
    try {
      const body = await res.json();
      if (body?.detail) msg = body.detail;
    } catch {
      /* ignore */
    }
    throw new Error(`Failed to fetch toolkit credentials: ${msg}`);
  }
  return res.json();
}
