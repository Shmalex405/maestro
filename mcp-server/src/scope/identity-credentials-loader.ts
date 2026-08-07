import * as fs from "fs";
import * as yaml from "yaml";
import { hasCloudSession, cloudRequest } from "../integrations/cloud-session";

// Resolves identity credential refs (named in scope.yml identity_targets, e.g.
// `sa_key_ref`) into their actual credential entries. Credentials live under an
// `identity_credentials` map keyed by ref name, loaded from the cloud backend
// (when in a cloud session) or the local credentials YAML otherwise — mirroring
// scope-config.ts's cloud/local fallback.
//
// Each identity_credentials value is shaped like:
//   { kind, path?, value?, tenant_id?, client_id?, client_secret?,
//     username?, password?, domain? }
// For google_workspace the relevant entry is `kind: "sa_json"` with
// `path: "/mnt/host-home/.kali-mcp-pentest/identity/<ref>.json"`.

/**
 * Load the full identity_credentials map. Prefers the cloud backend when a
 * cloud session is active, falling back to the local credentials YAML. Always
 * returns an object (empty on any failure) — never throws.
 */
export async function loadIdentityCredentials(): Promise<Record<string, any>> {
  if (hasCloudSession()) {
    try {
      const res = await cloudRequest<{ value?: any }>("/configs/credentials");
      return (res?.value?.identity_credentials ?? {}) as Record<string, any>;
    } catch (err) {
      console.warn(
        "[identity-credentials] cloud fetch failed, falling back to local YAML:",
        err
      );
    }
  }
  return loadLocalIdentityCredentials();
}

function loadLocalIdentityCredentials(): Record<string, any> {
  const configPath =
    process.env.CREDENTIALS_CONFIG_PATH || "../config/credentials.yml";
  // e.g. "../config/credentials.yml" → "../config/credentials.local.yml"
  const localPath = configPath.replace(/\.yml$/, ".local.yml");
  for (const candidate of [localPath, configPath]) {
    try {
      if (!fs.existsSync(candidate)) continue;
      const content = fs.readFileSync(candidate, "utf-8");
      const parsed = yaml.parse(content) as { identity_credentials?: Record<string, any> };
      return parsed?.identity_credentials ?? {};
    } catch (err) {
      console.warn(`[identity-credentials] failed to parse ${candidate}:`, err);
    }
  }
  return {};
}

/**
 * Resolve a single named credential ref to its identity_credentials entry, or
 * null if not found / unavailable.
 */
export async function resolveCredentialRef(ref: string): Promise<any | null> {
  if (!ref) return null;
  try {
    const creds = await loadIdentityCredentials();
    return creds[ref] ?? null;
  } catch {
    return null;
  }
}
