// Self-hosted deployment support.
//
// The managed arrangement discovers a user's backend by sending their email to
// Groovy's /api/discover. That endpoint is part of the proprietary control
// plane; a self-hoster does not run it. Instead they write a local config file
// (or set env vars) and the app reads it via the `get_self_host_config` Tauri
// command — see src-tauri/src/commands/self_host.rs.
//
// The whole design goal here is that self-hosting adds ONE branch and changes
// nothing else: we synthesize the exact `Bootstrap` object discovery would have
// produced, and every downstream consumer (Cognito auth, cloud routing, the
// OAST oracle) keeps working through its normal path. See SELF-HOSTING.md.

import { invoke } from '@tauri-apps/api/core';
import { isTauri } from './tauri-api';
import type { Bootstrap } from './desktop-bootstrap';
import { BOOTSTRAP_SCHEMA_VERSION } from './desktop-bootstrap';

/** Mirror of the Rust `SelfHostConfig` (serde camelCase). */
export interface SelfHostConfig {
  /** `local` — all data in the local SQLite DB, no backend, no sign-in.
   *  `team`  — the operator's own backend, multiple users, shared data.
   *
   *  In local mode every field below except orgId/customerName is empty, and
   *  that is valid: there is nothing to route to and nothing to authenticate
   *  against. Do NOT build a Bootstrap from a local config — see
   *  bootstrapFromSelfHost. */
  mode: 'local' | 'team';
  orgId: string;
  customerName: string;
  backendUrl: string;
  cognitoRegion: string;
  cognitoUserPoolId: string;
  cognitoClientId: string;
  cognitoDomain: string;
  oastServer: string;
  oastToken: string;
}

/** Mirror of the Rust `SelfHostStatus`. Three states — see the Rust doc. */
interface SelfHostStatus {
  enabled: boolean;
  config: SelfHostConfig | null;
  error: string | null;
}

// Cached across calls within a session. The config is read from disk at
// process start and an operator changing it mid-session would need to restart
// the app anyway (the container env is built from it at container-create time),
// so re-reading on every startup retry buys nothing.
//
// `undefined` = not yet asked. `null` = asked, and this is a managed install.
let cached: SelfHostConfig | null | undefined;

/**
 * Resolve the active self-hosted config, or null for a managed install.
 *
 * Throws ONLY when self-hosted mode is enabled but its config is unusable.
 * That case has to be fatal: silently falling back to managed discovery would
 * present as "self-hosting doesn't work", point the operator at a Groovy
 * endpoint they have no account on, and report a discovery failure instead of
 * the actual problem with their file.
 *
 * A failure to reach the command at all is NOT that case — it means this build
 * can't answer (command not registered, no Tauri backend under `next dev`, IPC
 * hiccup). Managed installs have no self-host config, so treating that as fatal
 * would hard-block startup for everyone. We fall through, matching how the
 * startup gate handles `get_test_mode_flags`.
 */
export async function getSelfHostConfig(): Promise<SelfHostConfig | null> {
  if (cached !== undefined) return cached;

  // Web/dev builds outside Tauri have no Rust side to ask.
  if (!isTauri()) {
    cached = null;
    return cached;
  }

  let status: SelfHostStatus;
  try {
    status = await invoke<SelfHostStatus>('get_self_host_config');
  } catch {
    cached = null;
    return cached;
  }

  if (!status?.enabled) {
    cached = null;
    return cached;
  }

  if (status.error) {
    // Not cached — a fatal config error should be re-evaluated if the operator
    // fixes the file and hits Retry, rather than sticking for the session.
    throw new Error(status.error);
  }

  cached = status.config ?? null;
  return cached;
}

/**
 * True when this install is self-hosted. Never throws — a misconfigured
 * self-host reads as "not self-hosted" here so callers that only need a yes/no
 * (e.g. "should I skip the discovery refresh?") don't have to handle errors.
 * The authoritative, throwing check is getSelfHostConfig().
 */
export async function isSelfHosted(): Promise<boolean> {
  try {
    return (await getSelfHostConfig()) !== null;
  } catch {
    return false;
  }
}

/**
 * Build the Bootstrap that discovery would have returned.
 *
 * `email` is the signed-in user's address when known. It's recorded only so the
 * bootstrap shape matches the managed one; nothing in the self-hosted path
 * resolves anything from it, because there is no email-to-org mapping to do.
 *
 * TEAM MODE ONLY. A local config has no backendUrl or Cognito settings, so the
 * result would fail isValidBootstrap — and a stored invalid bootstrap is worse
 * than none, because the startup gate would treat the install as bootstrapped,
 * skip the gate, and then fail every cloudRequest. Local mode deliberately
 * stores no bootstrap at all; the dispatch layer routes to Tauri commands
 * instead of a URL. Throwing here makes a mis-wired caller loud rather than
 * silently broken.
 */
export function bootstrapFromSelfHost(
  cfg: SelfHostConfig,
  email = '',
): Bootstrap {
  if (cfg.mode === 'local') {
    throw new Error(
      'bootstrapFromSelfHost called with a local-mode config. Local mode has no ' +
        'backend and stores no bootstrap — route data through the local Tauri ' +
        'commands instead (see lib/deployment-mode.ts).',
    );
  }
  return {
    orgId: cfg.orgId,
    customerName: cfg.customerName,
    backendUrl: cfg.backendUrl,
    cognitoRegion: cfg.cognitoRegion,
    cognitoUserPoolId: cfg.cognitoUserPoolId,
    cognitoClientId: cfg.cognitoClientId,
    // Empty string and undefined mean the same thing downstream (browser
    // sign-in disabled, SRP password login still available), but normalizing to
    // undefined keeps the stored object identical in shape to a discovered one
    // rather than carrying an empty-string field discovery never writes.
    cognitoDomain: cfg.cognitoDomain || undefined,
    // Unlike the managed path, the token CAN travel with the server here: it
    // came off the operator's own disk, not an unauthenticated HTTP response.
    oast: cfg.oastServer
      ? { server: cfg.oastServer, token: cfg.oastToken || undefined }
      : undefined,
    discoveredAt: new Date().toISOString(),
    email,
    schemaVersion: BOOTSTRAP_SCHEMA_VERSION,
  };
}

/** Test seam — resets the module cache. */
export function __resetSelfHostCacheForTests(): void {
  cached = undefined;
}
