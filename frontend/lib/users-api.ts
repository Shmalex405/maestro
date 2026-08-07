// Thin client for the backend's /api/v1/users admin endpoints.
//
// Uses the Cognito idToken from the auth store as the Bearer token; the
// backend verifies it via JWKS + enforces the ALLOWED_ORG_ID tenancy
// guard + checks the `admin` group for mutating calls.

import { getBootstrap } from './desktop-bootstrap';
import { useAuthStore } from './stores/auth-store';

export interface UserListItem {
  id: string;
  email: string;
  status: string;
  enabled?: boolean;
  roles: string[];
  created_at?: string;
  last_modified_at?: string;
}

/** Assignable roles. 'read_only' grants view-only access; 'user' is a plain
 *  org member; 'admin' can manage other users. */
export type UserRole = 'admin' | 'user' | 'read_only';

export interface InviteUserRequest {
  email: string;
  role?: UserRole;
}

export interface InviteUserResponse {
  id: string;
  email: string;
  status: string;
  roles: string[];
}

function backendBaseUrl(): string {
  // Desktop: bootstrap (set by the discovery flow) holds the per-org
  // backend URL. Fall back to the auth store's backendUrl for web mode.
  const bootstrap = getBootstrap();
  if (bootstrap?.backendUrl) return bootstrap.backendUrl.replace(/\/+$/, '');
  const web = useAuthStore.getState().backendUrl;
  if (web) return web.replace(/\/+$/, '');
  throw new Error(
    'Backend URL is not configured — complete the login flow first.'
  );
}

async function authHeaders(): Promise<Headers> {
  const { idToken } = useAuthStore.getState();
  if (!idToken) {
    throw new Error('Not authenticated.');
  }
  const h = new Headers();
  h.set('Authorization', `Bearer ${idToken}`);
  h.set('Content-Type', 'application/json');
  h.set('Accept', 'application/json');
  return h;
}

async function handleErr(res: Response): Promise<never> {
  let msg = `${res.status} ${res.statusText}`;
  try {
    const body = await res.json();
    if (body?.detail) msg = body.detail;
  } catch {
    /* ignore */
  }
  throw new Error(msg);
}

export async function listUsers(): Promise<UserListItem[]> {
  const res = await fetch(`${backendBaseUrl()}/api/v1/users`, {
    headers: await authHeaders(),
  });
  if (!res.ok) await handleErr(res);
  return res.json();
}

export async function inviteUser(
  req: InviteUserRequest
): Promise<InviteUserResponse> {
  const res = await fetch(`${backendBaseUrl()}/api/v1/users`, {
    method: 'POST',
    headers: await authHeaders(),
    body: JSON.stringify(req),
  });
  if (!res.ok) await handleErr(res);
  return res.json();
}

export async function disableUser(idOrEmail: string): Promise<void> {
  const res = await fetch(
    `${backendBaseUrl()}/api/v1/users/${encodeURIComponent(idOrEmail)}`,
    { method: 'DELETE', headers: await authHeaders() }
  );
  if (!res.ok) await handleErr(res);
}

export async function resendInvite(idOrEmail: string): Promise<void> {
  const res = await fetch(
    `${backendBaseUrl()}/api/v1/users/${encodeURIComponent(idOrEmail)}/resend-invite`,
    { method: 'POST', headers: await authHeaders() }
  );
  if (!res.ok) await handleErr(res);
}

export async function setUserRole(
  idOrEmail: string,
  role: UserRole
): Promise<void> {
  const res = await fetch(
    `${backendBaseUrl()}/api/v1/users/${encodeURIComponent(idOrEmail)}/role`,
    {
      method: 'PATCH',
      headers: await authHeaders(),
      body: JSON.stringify({ role }),
    }
  );
  if (!res.ok) await handleErr(res);
}
