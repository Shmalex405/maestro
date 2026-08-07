// Version compatibility check between the desktop app and the customer's backend.
//
// On startup (after login), the desktop calls GET /api/v1/version on the customer
// backend and compares:
//
//   - backend.version vs MIN_BACKEND_VERSION (this desktop requires at least X)
//   - this-desktop.version vs backend.minDesktopVersion (this backend requires at least Y)
//
// If either check fails, we surface a banner so the user knows *why* a feature
// may be missing and who to contact (their admin = backend upgrade, Groovy = app
// upgrade via the Tauri updater).

import { getBootstrap } from './desktop-bootstrap';

// Bumped whenever the desktop relies on a new backend feature.
// When you add an endpoint or schema field required for the app to work,
// bump the backend's version too and raise this constant.
export const MIN_BACKEND_VERSION = '1.0.0';

// Desktop app version — read from tauri.conf.json at build time.
// NEXT_PUBLIC_APP_VERSION is populated by the build script.
export const DESKTOP_VERSION = process.env.NEXT_PUBLIC_APP_VERSION || '0.0.0';

export interface VersionInfo {
  backendVersion: string;
  minDesktopVersion: string;
  backendName: string;
}

export type CompatibilityStatus =
  | { ok: true; info: VersionInfo }
  | {
      ok: false;
      reason: 'backend_too_old' | 'desktop_too_old' | 'unreachable';
      info?: VersionInfo;
      message: string;
    };

// Compare semver-ish strings. Only major.minor.patch — no pre-release handling.
// Returns -1, 0, or 1.
export function compareVersions(a: string, b: string): number {
  const pa = a.split('.').map((n) => parseInt(n, 10) || 0);
  const pb = b.split('.').map((n) => parseInt(n, 10) || 0);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const x = pa[i] ?? 0;
    const y = pb[i] ?? 0;
    if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}

export async function checkVersionCompatibility(): Promise<CompatibilityStatus> {
  const bootstrap = getBootstrap();
  if (!bootstrap?.backendUrl) {
    return {
      ok: false,
      reason: 'unreachable',
      message: 'Backend URL not configured. Complete the first-launch setup.',
    };
  }

  let info: VersionInfo;
  try {
    const res = await fetch(`${bootstrap.backendUrl.replace(/\/+$/, '')}/api/v1/version`, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!res.ok) {
      throw new Error(`${res.status} ${res.statusText}`);
    }
    const body = await res.json();
    info = {
      backendVersion: body.version,
      minDesktopVersion: body.minDesktopVersion,
      backendName: body.name,
    };
  } catch (err) {
    return {
      ok: false,
      reason: 'unreachable',
      message: `Could not reach backend at ${bootstrap.backendUrl}: ${
        err instanceof Error ? err.message : String(err)
      }`,
    };
  }

  if (compareVersions(info.backendVersion, MIN_BACKEND_VERSION) < 0) {
    return {
      ok: false,
      reason: 'backend_too_old',
      info,
      message: `Your organization's Maestro backend is running ${info.backendVersion}; this version of the desktop app needs at least ${MIN_BACKEND_VERSION}. Ask your Maestro administrator to upgrade the backend.`,
    };
  }

  if (compareVersions(DESKTOP_VERSION, info.minDesktopVersion) < 0) {
    return {
      ok: false,
      reason: 'desktop_too_old',
      info,
      message: `Your Maestro desktop app (${DESKTOP_VERSION}) is older than the minimum required by your backend (${info.minDesktopVersion}). Restart the app to pull the latest update.`,
    };
  }

  return { ok: true, info };
}
