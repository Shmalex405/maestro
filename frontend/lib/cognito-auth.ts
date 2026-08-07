/**
 * Client-side Cognito authentication for the desktop app.
 *
 * Uses amazon-cognito-identity-js (SRP auth, no client secret needed).
 * This runs entirely in the Tauri webview — no server required.
 */

import {
  CognitoUserPool,
  CognitoUser,
  AuthenticationDetails,
  CognitoUserSession,
  CognitoRefreshToken,
} from 'amazon-cognito-identity-js';
import { getBootstrap } from './desktop-bootstrap';

// Bootstrap (set by the discovery flow on first launch) takes precedence.
// Build-time env vars are a fallback for local dev and for the case where
// the app is built with baked-in Cognito settings.
const ENV_USER_POOL_ID = process.env.NEXT_PUBLIC_COGNITO_USER_POOL_ID || '';
const ENV_CLIENT_ID = process.env.NEXT_PUBLIC_COGNITO_DESKTOP_CLIENT_ID || '';
// Hosted UI domain host (no scheme), e.g. "login.maestro.groovysec.com".
// Used only by the browser-OAuth sign-in path (oauth-pkce.ts); empty disables it.
const ENV_COGNITO_DOMAIN = process.env.NEXT_PUBLIC_COGNITO_DOMAIN || '';

let poolInstance: CognitoUserPool | null = null;
let poolKey = ''; // poolId+clientId used to build the current instance

export interface CognitoConfig {
  userPoolId: string;
  clientId: string;
  domain: string; // Hosted UI host (no scheme); '' when not configured
}

function resolveCognitoConfig(): CognitoConfig {
  const bootstrap = getBootstrap();
  if (bootstrap?.cognitoUserPoolId && bootstrap?.cognitoClientId) {
    return {
      userPoolId: bootstrap.cognitoUserPoolId,
      clientId: bootstrap.cognitoClientId,
      domain: bootstrap.cognitoDomain || ENV_COGNITO_DOMAIN,
    };
  }
  return {
    userPoolId: ENV_USER_POOL_ID,
    clientId: ENV_CLIENT_ID,
    domain: ENV_COGNITO_DOMAIN,
  };
}

/** Full Cognito config (pool + client + Hosted UI domain) for the OAuth path. */
export function getCognitoConfig(): CognitoConfig {
  return resolveCognitoConfig();
}

export function getCognitoPool(): CognitoUserPool {
  const { userPoolId, clientId } = resolveCognitoConfig();
  if (!userPoolId || !clientId) {
    throw new Error(
      'Cognito not configured. Complete the first-launch discovery flow or set NEXT_PUBLIC_COGNITO_USER_POOL_ID / NEXT_PUBLIC_COGNITO_DESKTOP_CLIENT_ID.'
    );
  }
  const key = `${userPoolId}:${clientId}`;
  if (!poolInstance || poolKey !== key) {
    poolInstance = new CognitoUserPool({ UserPoolId: userPoolId, ClientId: clientId });
    poolKey = key;
  }
  return poolInstance;
}

/**
 * Result from signIn — either a session (success) or a new-password
 * challenge (user has a temp password and must set a permanent one).
 */
export type SignInResult =
  | { type: 'success'; session: CognitoUserSession }
  | { type: 'new_password_required'; cognitoUser: CognitoUser };

/**
 * Authenticate with email + password using SRP flow.
 * Returns a session on success, or a new-password challenge if the user
 * was created with a temporary password (first login).
 */
export function signIn(
  email: string,
  password: string
): Promise<SignInResult> {
  return new Promise((resolve, reject) => {
    const pool = getCognitoPool();
    const user = new CognitoUser({ Username: email, Pool: pool });
    const authDetails = new AuthenticationDetails({
      Username: email,
      Password: password,
    });

    user.authenticateUser(authDetails, {
      onSuccess: (session) => resolve({ type: 'success', session }),
      onFailure: (err) => reject(err),
      totpRequired: () => {
        reject(new Error('MFA_REQUIRED'));
      },
      newPasswordRequired: () => {
        // Return the CognitoUser so the caller can call
        // completeNewPassword() with the user's chosen password.
        resolve({ type: 'new_password_required', cognitoUser: user });
      },
    });
  });
}

/**
 * Complete the NEW_PASSWORD_REQUIRED challenge — sets a permanent password.
 * Call with the CognitoUser from the signIn result.
 */
export function completeNewPassword(
  cognitoUser: CognitoUser,
  newPassword: string
): Promise<CognitoUserSession> {
  return new Promise((resolve, reject) => {
    cognitoUser.completeNewPasswordChallenge(newPassword, {}, {
      onSuccess: (session) => resolve(session),
      onFailure: (err) => reject(err),
    });
  });
}

/**
 * Refresh an expired session using a stored refresh token.
 * Returns a new CognitoUserSession. Throws if the refresh token is
 * revoked or the account has been disabled.
 */
export function refreshSession(
  email: string,
  refreshTokenStr: string
): Promise<CognitoUserSession> {
  return new Promise((resolve, reject) => {
    const pool = getCognitoPool();
    const user = new CognitoUser({ Username: email, Pool: pool });
    const refreshToken = new CognitoRefreshToken({
      RefreshToken: refreshTokenStr,
    });

    user.refreshSession(refreshToken, (err, session) => {
      if (err) return reject(err);
      resolve(session);
    });
  });
}

/**
 * Trigger a password-reset email. Cognito sends a verification code to
 * the user's registered email. The caller follows up with
 * confirmPasswordReset() once the user has the code.
 */
export function forgotPassword(email: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const pool = getCognitoPool();
    const user = new CognitoUser({ Username: email, Pool: pool });
    user.forgotPassword({
      onSuccess: () => resolve(),
      onFailure: (err) => reject(err),
      inputVerificationCode: () => resolve(),
    });
  });
}

/**
 * Complete password reset using the verification code Cognito emailed.
 */
export function confirmPasswordReset(
  email: string,
  code: string,
  newPassword: string
): Promise<void> {
  return new Promise((resolve, reject) => {
    const pool = getCognitoPool();
    const user = new CognitoUser({ Username: email, Pool: pool });
    user.confirmPassword(code, newPassword, {
      onSuccess: () => resolve(),
      onFailure: (err) => reject(err),
    });
  });
}

/**
 * Sign out the current user (clears local Cognito state).
 */
export function signOut(): void {
  const pool = getCognitoPool();
  const user = pool.getCurrentUser();
  if (user) {
    user.signOut();
  }
}

/**
 * Extract user groups from the ID token JWT.
 * Groups are in the `cognito:groups` claim.
 */
export function getGroupsFromToken(idToken: string): string[] {
  try {
    const payload = JSON.parse(atob(idToken.split('.')[1]));
    return payload['cognito:groups'] || [];
  } catch {
    return [];
  }
}

/**
 * Extract user info from the ID token JWT.
 */
export function getUserFromToken(idToken: string): {
  email: string;
  name: string;
  groups: string[];
  orgId?: string;
} {
  try {
    const payload = JSON.parse(atob(idToken.split('.')[1]));
    return {
      email: payload.email || '',
      name: payload.name || payload.email || '',
      groups: payload['cognito:groups'] || [],
      orgId: payload['custom:org_id'] || undefined,
    };
  } catch {
    return { email: '', name: '', groups: [] };
  }
}

/**
 * Check if Cognito is configured (bootstrap OR env vars present).
 */
export function isCognitoConfigured(): boolean {
  const { userPoolId, clientId } = resolveCognitoConfig();
  return Boolean(userPoolId && clientId);
}

/**
 * Feature flag for the browser-based OAuth sign-in (Hosted UI + PKCE).
 * True only when Cognito is configured AND a Hosted UI domain is known.
 * Until the platform publishes COGNITO_DOMAIN (via discovery or env), this is
 * false and the app uses the existing SRP password login unchanged.
 */
export function isBrowserOAuthConfigured(): boolean {
  const { userPoolId, clientId, domain } = resolveCognitoConfig();
  return Boolean(userPoolId && clientId && domain);
}
