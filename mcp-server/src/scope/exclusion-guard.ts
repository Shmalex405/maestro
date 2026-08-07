/**
 * Cross-cutting, deny-wins scope-exclusion guard.
 *
 * WHY THIS EXISTS — a real gap in the per-dimension scope dispatcher
 * (`validateToolScope` in tool-scope.ts):
 *   1. The dispatcher validates a call against EXACTLY ONE dimension
 *      (identity → ai → cloud → k8s → network) and early-returns; its terminal
 *      branch is `return { valid: true }`, so a target arriving under an arg name
 *      the extractor doesn't recognize is ALLOWED (fail-open).
 *   2. `never_touch`-style exclusions were documented in scope.yml but enforced
 *      almost nowhere: cloud-account ARN exclusions lived in dead code
 *      (`validateCloudArn`, zero callers); identity / AI per-target exclusions had
 *      no backing code at all. The scope.yml promise to "never touch krbtgt /
 *      breakglass" was therefore unenforced.
 *
 * This guard runs BEFORE the dimension dispatch and on the agent path
 * (base-agent.ts) too, scanning every target-bearing arg against the UNION of
 * every dimension's exclusion list. The first match denies. Excluded targets are
 * never tested — even when reachable from a foothold during post-exploitation,
 * which is the whole point of a "never touch" list.
 *
 * Design mirrors the non-destructive backstop (`destructive-guard.ts`): the core
 * is a set of PURE functions (`collectExclusionPatterns` / `screenExclusions` /
 * `matchesExclusion`) that are trivially unit-testable, with `checkExclusions` as
 * the thin config-loading wrapper the live chokepoints call. Like that backstop,
 * the never-false-positive half matters as much as the block half: a fence that
 * breaks live assessments is worse than no fence.
 */

import { getScopeConfig } from "./scope-config";

export interface ExclusionResult {
  blocked: boolean;
  /** Present when blocked — the user-facing violation message. */
  reason?: string;
  /** The arg key whose value matched (for logging/tests). */
  arg?: string;
  /** The exclusion pattern that matched (for logging/tests). */
  pattern?: string;
}

/**
 * Arg names that carry a target / resource / principal a tool will act against.
 * This is the integration seam — when a new tool routes access through a
 * differently-named arg, add it here so the fence covers it. Kept intentionally
 * broad (network + cloud + k8s + identity + M365 + AI surfaces).
 */
export const TARGET_ARG_KEYS: string[] = [
  // network / host
  "target", "domain", "cidr", "url", "host", "rhost", "rhosts", "endpoint", "base_url",
  // cloud / k8s
  "cloud_account_id", "cluster_id", "namespace", "arn", "role_arn", "resource_arn",
  "resource", "bucket", "object_id",
  // identity / principals
  "tenant_id", "identity_target_id", "ai_target_id", "principal", "principal_arn",
  "upn", "user_principal_name", "user", "username", "target_user", "impersonate_user",
  // M365
  "mailbox", "site", "sharepoint_url",
];

/** Extract the string leaves of one exclusion entry. scope.yml exclusions are a
 *  mix of bare strings (`"krbtgt"`, `"arn:aws:s3:::prod-*"`) and object forms
 *  (`{resource_group: "..."}`, `{mailbox: "..."}`, `{site: "..."}`); both yield
 *  the value(s) we match against. */
function leafStrings(entry: unknown): string[] {
  if (typeof entry === "string") return entry ? [entry] : [];
  if (entry && typeof entry === "object") {
    return Object.values(entry as Record<string, unknown>).filter(
      (v): v is string => typeof v === "string" && v.length > 0
    );
  }
  return [];
}

/** Union of every exclusion pattern across all scope dimensions. */
export function collectExclusionPatterns(config: any): string[] {
  const out: string[] = [];
  const pushAll = (arr: unknown) => {
    if (Array.isArray(arr)) for (const e of arr) out.push(...leafStrings(e));
  };
  pushAll(config?.exclusions); // network (flat list)
  for (const a of config?.cloud_accounts ?? []) pushAll(a?.exclusions); // cloud ARN globs
  for (const t of config?.identity_targets ?? []) pushAll(t?.exclusions); // identity principals
  for (const t of config?.ai_targets ?? []) pushAll(t?.exclusions); // ai
  for (const k of config?.kubernetes ?? []) pushAll(k?.namespaces_excluded); // k8s namespaces
  return out;
}

function normalizeHost(v: string): string {
  let s = v;
  try {
    if (v.includes("://")) s = new URL(v).hostname;
  } catch {
    /* not a URL — keep raw */
  }
  return s.replace(/:\d+$/, "");
}

/**
 * Does `value` match exclusion `pattern`?
 *   - glob: a pattern containing '*' is matched as a regex ('*' → '.*', other
 *     regex specials escaped) — covers ARN/resource globs like
 *     `arn:aws:s3:::production-*`.
 *   - bare: matched exactly OR as a domain/hierarchy suffix (mirrors
 *     validator.ts `matchesDomainPattern`: `host.corp.com` matches `corp.com`),
 *     so a never-touch domain covers its subdomains but a substring never
 *     false-matches (`"krbtgt"` does NOT match `"krbtgt-svc-readonly"`).
 */
export function matchesExclusion(value: string, pattern: string): boolean {
  if (!pattern || !value) return false;
  if (pattern.includes("*")) {
    const re = new RegExp(
      "^" + pattern.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*") + "$"
    );
    return re.test(value);
  }
  return value === pattern || value.endsWith("." + pattern);
}

/**
 * PURE core: given tool args and the union of exclusion patterns, return the
 * first target-bearing arg value that matches an exclusion. Deny-wins.
 */
export function screenExclusions(
  args: Record<string, unknown> | undefined,
  patterns: string[]
): ExclusionResult {
  if (!patterns.length) return { blocked: false };
  const argObj = args ?? {};
  for (const key of TARGET_ARG_KEYS) {
    const raw = argObj[key];
    if (typeof raw !== "string" || !raw) continue;
    const candidates = [raw];
    const host = normalizeHost(raw);
    if (host !== raw) candidates.push(host);
    for (const cand of candidates) {
      for (const pattern of patterns) {
        if (matchesExclusion(cand, pattern)) {
          return {
            blocked: true,
            arg: key,
            pattern,
            reason: `Target "${raw}" (arg "${key}") matches never-touch / exclusion pattern "${pattern}". Excluded targets are never tested, even when reachable from a foothold.`,
          };
        }
      }
    }
  }
  return { blocked: false };
}

/**
 * Config-loading wrapper used by the live scope chokepoints (tool-scope.ts and
 * base-agent.ts). Loads the active scope (cloud-backed or local YAML) and screens
 * the call's args against every dimension's exclusions.
 */
export async function checkExclusions(
  args: Record<string, unknown> | undefined
): Promise<ExclusionResult> {
  const config = (await getScopeConfig()) as any;
  return screenExclusions(args, collectExclusionPatterns(config));
}
