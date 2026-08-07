/**
 * Cross-assessment cache client — Phase 4/5 of the caching plan.
 *
 * Thin wrappers over the cloud `/sast-cache` and `/recon-cache` endpoints
 * so scanner tools can do lookup-then-run-then-upsert without each tool
 * file repeating the HTTP boilerplate.
 *
 * All requests go through `cloudRequest`, which uses the desktop's
 * cloud session token. When the session is absent (offline mode, or no
 * cloud account configured), every lookup returns `{ cached: false }`
 * and every upsert is a no-op — the scanner just runs as if the cache
 * didn't exist. That degradation is intentional: the cache is purely
 * an optimization, never a correctness dependency.
 *
 * See `docs/caching-cross-assessment-design.md` Phase 4 (SAST) + Phase 5
 * (recon) for the schema and key derivation rules.
 */
import { hasCloudSession, cloudRequest, CloudSessionError } from "./cloud-session";

// ── SAST cache types ──────────────────────────────────────────────────

export interface SastCacheKey {
  target_id: string;
  commit_sha: string;
  scanner: string;
  scanner_version: string;
  rule_pack_hash: string;
  dependency_lock_hash?: string;
}

export interface SastCacheEntry {
  id: string;
  target_id: string;
  commit_sha: string;
  scanner: string;
  scanner_version: string;
  rule_pack_hash: string;
  dependency_lock_hash: string | null;
  finding_fingerprints: string[];
  raw_output_s3_key: string | null;
  scan_started_at: string;
  scan_completed_at: string;
  expires_at: string;
}

export interface SastCacheLookupResponse {
  cached: boolean;
  entry: SastCacheEntry | null;
}

export interface SastCacheUpsertBody extends SastCacheKey {
  finding_fingerprints: string[];
  raw_output_s3_key?: string;
  scan_started_at: string;
  scan_completed_at: string;
  ttl_days?: number;
}

// ── Recon cache types ─────────────────────────────────────────────────

export type ReconScanType = "ports" | "subdomains" | "services" | "tls" | "dns";

export interface ReconCacheEntry {
  id: string;
  target_id: string;
  scan_type: ReconScanType;
  snapshot: unknown;
  scanner_version: string | null;
  scan_completed_at: string;
  expires_at: string;
}

export interface ReconCacheLookupResponse {
  cached: boolean;
  entry: ReconCacheEntry | null;
}

export interface ReconCacheUpsertBody {
  target_id: string;
  scan_type: ReconScanType;
  snapshot: unknown;
  scanner_version?: string;
  scan_completed_at: string;
  ttl_days?: number;
}

// ── SAST cache operations ─────────────────────────────────────────────

/**
 * Look up a cached SAST scan result. Returns `{ cached: false, entry: null }`
 * when no session is configured, when the request fails for any reason,
 * or when no matching non-expired entry exists.
 *
 * Failures are swallowed (logged via console.warn) rather than thrown
 * because cache lookups are advisory — the caller will just run the
 * scanner. We never want the cache layer to fail the assessment.
 */
export async function sastCacheLookup(
  key: SastCacheKey
): Promise<SastCacheLookupResponse> {
  if (!hasCloudSession()) {
    return { cached: false, entry: null };
  }
  const params = new URLSearchParams({
    target_id: key.target_id,
    commit_sha: key.commit_sha,
    scanner: key.scanner,
    scanner_version: key.scanner_version,
    rule_pack_hash: key.rule_pack_hash,
  });
  if (key.dependency_lock_hash) {
    params.set("dependency_lock_hash", key.dependency_lock_hash);
  }
  try {
    return await cloudRequest<SastCacheLookupResponse>(
      `/sast-cache/lookup?${params.toString()}`
    );
  } catch (err) {
    if (err instanceof CloudSessionError) {
      console.warn(`[cache-client] sastCacheLookup failed: ${err.message}`);
    } else {
      console.warn(`[cache-client] sastCacheLookup unexpected error: ${err}`);
    }
    return { cached: false, entry: null };
  }
}

/**
 * Upsert a SAST cache entry after a scanner ran. No-op when no cloud
 * session is configured. Failures are logged but not thrown — a write
 * failure means the next run will rescan, which is fine.
 */
export async function sastCacheUpsert(
  body: SastCacheUpsertBody
): Promise<SastCacheEntry | null> {
  if (!hasCloudSession()) {
    return null;
  }
  try {
    return await cloudRequest<SastCacheEntry>("/sast-cache", {
      method: "POST",
      body,
    });
  } catch (err) {
    if (err instanceof CloudSessionError) {
      console.warn(`[cache-client] sastCacheUpsert failed: ${err.message}`);
    } else {
      console.warn(`[cache-client] sastCacheUpsert unexpected error: ${err}`);
    }
    return null;
  }
}

// ── Recon cache operations ────────────────────────────────────────────

export async function reconCacheLookup(
  target_id: string,
  scan_type: ReconScanType
): Promise<ReconCacheLookupResponse> {
  if (!hasCloudSession()) {
    return { cached: false, entry: null };
  }
  const params = new URLSearchParams({ target_id, scan_type });
  try {
    return await cloudRequest<ReconCacheLookupResponse>(
      `/recon-cache/lookup?${params.toString()}`
    );
  } catch (err) {
    if (err instanceof CloudSessionError) {
      console.warn(`[cache-client] reconCacheLookup failed: ${err.message}`);
    } else {
      console.warn(`[cache-client] reconCacheLookup unexpected error: ${err}`);
    }
    return { cached: false, entry: null };
  }
}

export async function reconCacheUpsert(
  body: ReconCacheUpsertBody
): Promise<ReconCacheEntry | null> {
  if (!hasCloudSession()) {
    return null;
  }
  try {
    return await cloudRequest<ReconCacheEntry>("/recon-cache", {
      method: "POST",
      body,
    });
  } catch (err) {
    if (err instanceof CloudSessionError) {
      console.warn(`[cache-client] reconCacheUpsert failed: ${err.message}`);
    } else {
      console.warn(`[cache-client] reconCacheUpsert unexpected error: ${err}`);
    }
    return null;
  }
}

// ── Key derivation helpers ────────────────────────────────────────────

import { createHash } from "node:crypto";

/**
 * SHA-256 a string and return the hex digest. Used to derive
 * `rule_pack_hash` (from concatenated rule file contents) and
 * `dependency_lock_hash` (from lockfile contents).
 */
export function sha256Hex(input: string): string {
  return createHash("sha256").update(input).digest("hex");
}

/**
 * Hash a list of file contents in a stable order. Used by scanners that
 * key their cache on multiple rule files — sort the inputs first, then
 * concatenate with NUL separators so the hash is deterministic.
 */
export function hashFileContents(
  files: Array<{ name: string; content: string }>
): string {
  const sorted = [...files].sort((a, b) => a.name.localeCompare(b.name));
  const combined = sorted.map((f) => `${f.name}\0${f.content}`).join("\0\0");
  return sha256Hex(combined);
}
