/**
 * Browser-based OAuth sign-in for the desktop app (Cognito Hosted UI + PKCE).
 *
 * RFC 8252 ("OAuth 2.0 for Native Apps") flow: the user authenticates in their
 * real system browser (where their password manager lives), Cognito redirects
 * to the custom scheme `maestro://auth/callback`, the deep-link plugin hands the
 * URL back to us, and we exchange the authorization code for tokens via PKCE
 * (no client secret — the desktop app client is public).
 *
 * This module is desktop-only. All Tauri plugin APIs are dynamically imported
 * inside functions so the web build never evaluates them.
 *
 * The end state is identical to the SRP path: a { accessToken, idToken,
 * refreshToken, expiresIn } bundle handed to the auth store. Everything
 * downstream (refresh, cloudRequest, read-only gating) is unchanged.
 */

import { getCognitoConfig, getUserFromToken } from './cognito-auth';

export const OAUTH_REDIRECT_URI = 'maestro://auth/callback';
export const OAUTH_LOGOUT_URI = 'maestro://auth/logout';
const OAUTH_SCOPES = 'openid email profile';
const CALLBACK_TIMEOUT_MS = 5 * 60 * 1000; // 5 min to complete browser login

export interface OAuthTokens {
  accessToken: string;
  idToken: string;
  refreshToken: string;
  expiresIn: number; // seconds
}

export interface BrowserLoginResult {
  user: ReturnType<typeof getUserFromToken>;
  tokens: OAuthTokens;
}

// ── PKCE / random primitives (Web Crypto, available in the Tauri webview) ──

function base64UrlEncode(bytes: Uint8Array): string {
  let str = '';
  for (const b of bytes) str += String.fromCharCode(b);
  return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** A URL-safe random string with `bytes` of entropy. */
function randomUrlSafe(bytes = 32): string {
  const buf = new Uint8Array(bytes);
  crypto.getRandomValues(buf);
  return base64UrlEncode(buf);
}

/** Generate a PKCE verifier + S256 challenge pair. */
async function generatePkce(): Promise<{ verifier: string; challenge: string }> {
  const verifier = randomUrlSafe(64); // 86 chars — within the 43–128 spec range
  const digest = await crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(verifier)
  );
  return { verifier, challenge: base64UrlEncode(new Uint8Array(digest)) };
}

// ── URL builders ──

function origin(domain: string): string {
  // `domain` is a bare host (e.g. login.maestro.groovysec.com). Tolerate a
  // value that already includes a scheme.
  return domain.startsWith('http') ? domain.replace(/\/+$/, '') : `https://${domain}`;
}

function buildAuthorizeUrl(opts: {
  domain: string;
  clientId: string;
  state: string;
  nonce: string;
  challenge: string;
  prompt?: 'login';
}): string {
  const p = new URLSearchParams({
    response_type: 'code',
    client_id: opts.clientId,
    redirect_uri: OAUTH_REDIRECT_URI,
    scope: OAUTH_SCOPES,
    state: opts.state,
    nonce: opts.nonce,
    code_challenge: opts.challenge,
    code_challenge_method: 'S256',
  });
  if (opts.prompt) p.set('prompt', opts.prompt);
  return `${origin(opts.domain)}/oauth2/authorize?${p.toString()}`;
}

/** Exchange an authorization code for tokens (PKCE, public client). */
export async function exchangeCode(opts: {
  domain: string;
  clientId: string;
  code: string;
  verifier: string;
}): Promise<OAuthTokens> {
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    client_id: opts.clientId,
    code: opts.code,
    redirect_uri: OAUTH_REDIRECT_URI,
    code_verifier: opts.verifier,
  });
  const res = await fetch(`${origin(opts.domain)}/oauth2/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
  });
  if (!res.ok) {
    const detail = await res.text().catch(() => '');
    throw new Error(`Token exchange failed (${res.status}): ${detail || res.statusText}`);
  }
  const json = (await res.json()) as {
    access_token: string;
    id_token: string;
    refresh_token: string;
    expires_in: number;
  };
  return {
    accessToken: json.access_token,
    idToken: json.id_token,
    refreshToken: json.refresh_token,
    expiresIn: json.expires_in,
  };
}

/**
 * Fallback refresh via the Hosted UI token endpoint (grant_type=refresh_token).
 * The SRP path's refreshSession() is the primary refresh; this exists in case
 * Hosted-UI-issued refresh tokens misbehave with the SDK (see plan §4).
 */
export async function refreshViaToken(opts: {
  domain: string;
  clientId: string;
  refreshToken: string;
}): Promise<Omit<OAuthTokens, 'refreshToken'>> {
  const body = new URLSearchParams({
    grant_type: 'refresh_token',
    client_id: opts.clientId,
    refresh_token: opts.refreshToken,
  });
  const res = await fetch(`${origin(opts.domain)}/oauth2/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
  });
  if (!res.ok) {
    const detail = await res.text().catch(() => '');
    throw new Error(`Token refresh failed (${res.status}): ${detail || res.statusText}`);
  }
  const json = (await res.json()) as {
    access_token: string;
    id_token: string;
    expires_in: number;
  };
  return {
    accessToken: json.access_token,
    idToken: json.id_token,
    expiresIn: json.expires_in,
  };
}

// ── Enterprise sign-out helpers (WS6) ──

/**
 * Revoke a refresh token server-side so it cannot mint new sessions, even if
 * cached or stolen. Best-effort — never throws (sign-out must always proceed).
 */
export async function revokeRefreshToken(opts: {
  domain: string;
  clientId: string;
  refreshToken: string;
}): Promise<void> {
  try {
    const body = new URLSearchParams({
      token: opts.refreshToken,
      client_id: opts.clientId,
    });
    await fetch(`${origin(opts.domain)}/oauth2/revoke`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString(),
    });
  } catch {
    /* sign-out continues regardless */
  }
}

/** Hosted UI logout URL — destroys the browser's Cognito SSO cookie. */
export function buildLogoutUrl(opts: { domain: string; clientId: string }): string {
  const p = new URLSearchParams({
    client_id: opts.clientId,
    logout_uri: OAUTH_LOGOUT_URI,
  });
  return `${origin(opts.domain)}/logout?${p.toString()}`;
}

/** Open a URL in the system browser (Tauri opener plugin). */
async function openInSystemBrowser(url: string): Promise<void> {
  const { openUrl } = await import('@tauri-apps/plugin-opener');
  await openUrl(url);
}

/**
 * Open the Hosted UI logout endpoint in the system browser. Best-effort.
 */
export async function openLogout(): Promise<void> {
  const { clientId, domain } = getCognitoConfig();
  if (!domain || !clientId) return;
  try {
    await openInSystemBrowser(buildLogoutUrl({ domain, clientId }));
  } catch {
    /* best-effort */
  }
}

// ── Browser login orchestrator ──

interface PendingLogin {
  state: string;
  verifier: string;
  domain: string;
  clientId: string;
  authorizeUrl: string;
  resolve: (r: BrowserLoginResult) => void;
  reject: (e: Error) => void;
  cleanup: () => void;
}

let pending: PendingLogin | null = null;

function parseCallback(url: string): { code?: string; state?: string; error?: string } | null {
  if (!url.startsWith('maestro://auth/callback')) return null;
  // Custom-scheme URLs don't always parse host/query reliably across platforms;
  // read the query string directly after the first '?'.
  const qi = url.indexOf('?');
  const q = new URLSearchParams(qi >= 0 ? url.slice(qi + 1) : '');
  return {
    code: q.get('code') ?? undefined,
    state: q.get('state') ?? undefined,
    error: q.get('error') ?? undefined,
  };
}

/**
 * Launch the browser sign-in. Resolves with the user + token bundle once the
 * deep-link callback returns and the code is exchanged. Rejects on state
 * mismatch, OAuth error, timeout, or cancellation. Only one login may be
 * pending at a time.
 *
 * `prompt: 'login'` forces a fresh credential prompt (used after explicit
 * sign-out so a lingering SSO cookie can't bypass authentication).
 */
export async function startBrowserLogin(
  opts: { prompt?: 'login' } = {}
): Promise<BrowserLoginResult> {
  if (pending) {
    throw new Error('A browser sign-in is already in progress.');
  }
  const { clientId, domain } = getCognitoConfig();
  if (!domain || !clientId) {
    throw new Error('Browser OAuth is not configured (no Hosted UI domain).');
  }

  const { verifier, challenge } = await generatePkce();
  const state = randomUrlSafe(24);
  const nonce = randomUrlSafe(24);
  const authorizeUrl = buildAuthorizeUrl({
    domain,
    clientId,
    state,
    nonce,
    challenge,
    prompt: opts.prompt,
  });

  const { onOpenUrl } = await import('@tauri-apps/plugin-deep-link');

  return new Promise<BrowserLoginResult>((resolve, reject) => {
    let unlisten: (() => void) | undefined;
    let timer: ReturnType<typeof setTimeout> | undefined;

    const cleanup = () => {
      if (timer) clearTimeout(timer);
      if (unlisten) unlisten();
      pending = null;
    };

    pending = { state, verifier, domain, clientId, authorizeUrl, resolve, reject, cleanup };

    const handleUrls = (urls: string[]) => {
      for (const url of urls) {
        const cb = parseCallback(url);
        if (!cb) continue;
        if (cb.error) {
          cleanup();
          reject(new Error(`Sign-in was denied (${cb.error}).`));
          return;
        }
        if (cb.state !== state) {
          // Not ours (or tampered) — ignore stale callbacks, fail on mismatch
          // only when a code is present for this in-flight login.
          if (cb.code) {
            cleanup();
            reject(new Error('Sign-in state mismatch — please try again.'));
          }
          return;
        }
        if (!cb.code) {
          cleanup();
          reject(new Error('Sign-in callback missing authorization code.'));
          return;
        }
        const code = cb.code;
        exchangeCode({ domain, clientId, code, verifier })
          .then((tokens) => {
            cleanup();
            resolve({ user: getUserFromToken(tokens.idToken), tokens });
          })
          .catch((e) => {
            cleanup();
            reject(e instanceof Error ? e : new Error(String(e)));
          });
        return;
      }
    };

    timer = setTimeout(() => {
      cleanup();
      reject(new Error('Sign-in timed out. Please try again.'));
    }, CALLBACK_TIMEOUT_MS);

    onOpenUrl(handleUrls)
      .then((fn) => {
        unlisten = fn;
        return openInSystemBrowser(authorizeUrl);
      })
      .catch((e) => {
        cleanup();
        reject(e instanceof Error ? e : new Error(String(e)));
      });
  });
}

/** Re-open the authorize URL for the in-flight login (user missed/closed it). */
export async function reopenAuthorizeUrl(): Promise<void> {
  if (pending) await openInSystemBrowser(pending.authorizeUrl);
}

/** Cancel the in-flight browser login, if any. */
export function cancelBrowserLogin(): void {
  if (pending) {
    const p = pending;
    p.cleanup();
    p.reject(new Error('cancelled'));
  }
}
