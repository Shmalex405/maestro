/**
 * Deterministic vuln → capability lookup (Layer A of the post-exploitation layer,
 * see docs/RFC-POST-EXPLOITATION-LAYER.md §4.2).
 *
 * The `grants`/`requires` capability model currently lives only as prose inside an
 * LLM prompt (chain-analysis-agent-impl.ts) and is discarded after one inference.
 * This helper promotes the `vuln_capability_map` in config/chain-patterns.yml to a
 * real, auditable lookup so a finding's capabilities can be stamped DETERMINISTICALLY
 * (the LLM is then only needed for emergent chains the catalog doesn't cover).
 *
 * Pure + cache-backed; trivially unit-testable. The live caller (chain-analysis
 * dual-write into the graph substrate) uses `capabilitiesFor(vulnType)`.
 */

import * as fs from "fs";
import * as yaml from "yaml";

export interface VulnCapability {
  grants: string[];
  requires: string[];
  severity_base?: string;
}

let cache: Record<string, VulnCapability> | null = null;
let cachePath: string | null = null;

function defaultPatternsPath(): string {
  return process.env.CHAIN_PATTERNS_PATH || "../config/chain-patterns.yml";
}

/** Load + normalize the `vuln_capability_map` section. Cached per path. */
export function loadVulnCapabilityMap(path?: string): Record<string, VulnCapability> {
  const p = path || defaultPatternsPath();
  if (cache && cachePath === p) return cache;
  try {
    const doc = yaml.parse(fs.readFileSync(p, "utf-8")) as any;
    const raw = (doc?.vuln_capability_map ?? {}) as Record<string, any>;
    const out: Record<string, VulnCapability> = {};
    for (const [key, v] of Object.entries(raw)) {
      out[key] = {
        grants: Array.isArray(v?.grants) ? v.grants.map(String) : [],
        requires: Array.isArray(v?.requires) ? v.requires.map(String) : [],
        severity_base: typeof v?.severity_base === "string" ? v.severity_base : undefined,
      };
    }
    cache = out;
    cachePath = p;
    return out;
  } catch (e) {
    console.warn(`[chain-capabilities] failed to load ${p}:`, e);
    return {};
  }
}

/** For tests: drop the cached map so a different fixture path is reloaded. */
export function _resetCache(): void {
  cache = null;
  cachePath = null;
}

/** Normalize a free-text vuln type / finding label to a candidate map key
 *  ("SQL Injection" → "sql_injection", "Reflected XSS" → "reflected_xss"). */
export function normalizeVulnType(raw: string): string {
  return raw
    .toLowerCase()
    .trim()
    .replace(/[\s\-/]+/g, "_")
    .replace(/[^a-z0-9_]/g, "");
}

/** Common finding labels → canonical `vuln_capability_map` keys. The catalog uses
 *  short keys (`sqli`, `idor`); scanners/agents emit longer human labels. */
const ALIASES: Record<string, string> = {
  sql_injection: "sqli",
  sqlinjection: "sqli",
  reflected_xss: "xss_reflected",
  stored_xss: "xss_stored",
  persistent_xss: "xss_stored",
  dom_xss: "xss_dom",
  dombased_xss: "xss_dom",
  cross_site_scripting: "xss_reflected",
  server_side_request_forgery: "ssrf",
  os_command_injection: "command_injection",
  command_inj: "command_injection",
  rce: "command_injection",
  remote_code_execution: "command_injection",
  server_side_template_injection: "ssti",
  template_injection: "ssti",
  insecure_direct_object_reference: "idor",
  bola: "idor",
  broken_object_level_authorization: "idor",
  directory_traversal: "path_traversal",
  lfi: "path_traversal",
  local_file_inclusion: "path_traversal",
  jwt: "jwt_weakness",
  jwt_vuln: "jwt_weakness",
};

/**
 * Resolve the grants/requires capabilities for a vuln type. Match order:
 *   1. exact catalog key, 2. normalized key, 3. alias → catalog key.
 * Returns null when the catalog has no entry (caller falls back to the LLM for
 * emergent chains rather than fabricating capabilities).
 */
export function capabilitiesFor(vulnType: string, path?: string): VulnCapability | null {
  if (!vulnType) return null;
  const map = loadVulnCapabilityMap(path);
  if (map[vulnType]) return map[vulnType];
  const norm = normalizeVulnType(vulnType);
  if (map[norm]) return map[norm];
  const alias = ALIASES[norm];
  if (alias && map[alias]) return map[alias];
  return null;
}
