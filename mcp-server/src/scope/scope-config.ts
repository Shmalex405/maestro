import * as fs from "fs";
import * as yaml from "yaml";
import {
  hasCloudSession,
  cloudRequest,
  CloudSessionError,
} from "../integrations/cloud-session";

export interface NetworkScope {
  cidr: string;
  environment: string;
  notes?: string;
}

export interface DomainScope {
  pattern: string;
  environment: string;
}

export interface CloudAccount {
  id: string;
  provider: 'aws' | 'azure' | 'gcp';
  account_id?: string;
  subscription_id?: string;
  project_id?: string;
  regions?: string[];
  services_in_scope?: string[];
  exclusions?: string[];
  notes?: string;
}

export interface KubernetesCluster {
  id: string;
  cluster: string;
  provider?: string;
  namespaces_in_scope?: string[];
  namespaces_excluded?: string[];
  notes?: string;
}

export interface ScopeConfig {
  networks: NetworkScope[];
  domains: DomainScope[];
  exclusions: string[];
  cloud_accounts?: CloudAccount[];
  kubernetes?: KubernetesCluster[];
  /** Identity/IDP targets (Entra/M365/AD/Okta/Google Workspace/Ping/...). Read
   *  loosely by the identity scope validator; passed through verbatim. */
  identity_targets?: any[];
  /** AI/LLM targets (model_api/chat_app/agent/rag_app/mcp_server). Read loosely by
   *  the AI scope validator; passed through verbatim. Fail-closed like
   *  identity_targets — no entry, no AI testing. */
  ai_targets?: any[];
}

let scopeConfig: ScopeConfig | null = null;
let lastLoadTime = 0;
const RELOAD_INTERVAL_MS = 5000; // Re-read source every 5 seconds

/**
 * Normalize the cloud-shape ScopeConfig (what the desktop UI writes via
 * `cloudRequest('/configs/scope', PUT)`) into the internal MCP shape used by
 * the validators. Differences handled:
 *   - exclusions: cloud is `{pattern, reason}[]`; MCP expects `string[]`.
 *   - apps[].domains: cloud groups domains under per-app entries; MCP folds
 *     them into the top-level domains list so existing validators see them.
 *   - kubernetes: cloud uses `{clusters: [{name, namespaces}]}`; MCP expects
 *     a flat array with `id`/`cluster`/`namespaces_in_scope` fields.
 *   - cloud_accounts: not in the frontend scope type yet — passed through
 *     verbatim if present so future schema growth keeps working.
 */
function normalizeCloudScope(input: unknown): ScopeConfig {
  const src = (input ?? {}) as Record<string, unknown>;

  const networks = Array.isArray(src.networks)
    ? (src.networks as NetworkScope[])
    : [];

  // Top-level domains plus app-scoped domains, all folded together.
  const topDomains: DomainScope[] = Array.isArray(src.domains)
    ? (src.domains as DomainScope[])
    : [];
  const apps = Array.isArray(src.apps) ? (src.apps as Array<Record<string, unknown>>) : [];
  const appDomains: DomainScope[] = apps.flatMap((a) =>
    Array.isArray(a?.domains) ? (a.domains as DomainScope[]) : []
  );
  const domains: DomainScope[] = [...topDomains, ...appDomains].map((d) => ({
    pattern: String(d.pattern || ""),
    environment: String(d.environment || "production"),
  })).filter((d) => d.pattern.length > 0);

  // Cloud exclusions are `{pattern, reason}[]`; old YAML uses bare strings.
  const exclusions: string[] = Array.isArray(src.exclusions)
    ? (src.exclusions as Array<unknown>)
        .map((e) =>
          typeof e === "string"
            ? e
            : ((e as Record<string, unknown>)?.pattern as string | undefined)
        )
        .filter((e): e is string => typeof e === "string" && e.length > 0)
    : [];

  // Kubernetes shape transform.
  let kubernetes: KubernetesCluster[] | undefined;
  const k8sRaw = src.kubernetes as
    | KubernetesCluster[]
    | { clusters?: Array<{ name?: string; namespaces?: string[] }> }
    | undefined;
  if (Array.isArray(k8sRaw)) {
    kubernetes = k8sRaw;
  } else if (k8sRaw && Array.isArray(k8sRaw.clusters)) {
    kubernetes = k8sRaw.clusters
      .filter((c) => typeof c?.name === "string" && c.name.length > 0)
      .map((c) => ({
        id: c.name as string,
        cluster: c.name as string,
        namespaces_in_scope: Array.isArray(c.namespaces) ? c.namespaces : [],
      }));
  }

  const cloud_accounts = Array.isArray(src.cloud_accounts)
    ? (src.cloud_accounts as CloudAccount[])
    : undefined;

  // Identity targets pass through verbatim so a cloud-routed scope keeps the
  // identity dimension (otherwise identity tools fail-closed under cloud).
  const identity_targets = Array.isArray(src.identity_targets)
    ? (src.identity_targets as any[])
    : [];

  // AI targets pass through verbatim too (same reasoning — otherwise AI tools
  // fail-closed under a cloud-routed scope).
  const ai_targets = Array.isArray(src.ai_targets)
    ? (src.ai_targets as any[])
    : [];

  return { networks, domains, exclusions, cloud_accounts, kubernetes, identity_targets, ai_targets };
}

/**
 * Try to load the scope config from the active cloud backend. Returns null
 * if no session is configured or the call fails — caller falls back to the
 * local YAML in that case.
 */
async function loadCloudScope(): Promise<ScopeConfig | null> {
  if (!hasCloudSession()) return null;
  try {
    const res = await cloudRequest<{ value?: unknown }>("/configs/scope");
    const value = res?.value ?? {};
    return normalizeCloudScope(value);
  } catch (err) {
    if (err instanceof CloudSessionError) {
      console.warn(
        `[scope-config] cloud fetch failed (${err.status}): ${err.message} — falling back to local YAML`
      );
    } else {
      console.warn(`[scope-config] cloud fetch error, falling back to local YAML:`, err);
    }
    return null;
  }
}

/**
 * Load scope from disk YAML. Used both as the offline path and as the
 * fallback when the cloud is unreachable or the user is unauthenticated.
 *
 * Priority order:
 *   1. `<scope.yml>.local` next to SCOPE_CONFIG_PATH — gitignored personal
 *      override so individual users keep real targets out of the committed
 *      template.
 *   2. SCOPE_CONFIG_PATH itself.
 */
function loadLocalScope(): ScopeConfig {
  const configPath = process.env.SCOPE_CONFIG_PATH || "../config/scope.yml";
  // e.g. "../config/scope.yml" → "../config/scope.local.yml"
  const localPath = configPath.replace(/\.yml$/, ".local.yml");
  for (const candidate of [localPath, configPath]) {
    try {
      if (!fs.existsSync(candidate)) continue;
      const content = fs.readFileSync(candidate, "utf-8");
      return yaml.parse(content) as ScopeConfig;
    } catch (error) {
      console.warn(`[scope-config] failed to parse ${candidate}:`, error);
    }
  }
  console.warn("[scope-config] no scope file found, using empty scope");
  return { networks: [], domains: [], exclusions: [] };
}

export async function loadScopeConfig(): Promise<ScopeConfig> {
  const fromCloud = await loadCloudScope();
  scopeConfig = fromCloud ?? loadLocalScope();
  lastLoadTime = Date.now();
  return scopeConfig;
}

export async function getScopeConfig(): Promise<ScopeConfig> {
  const now = Date.now();
  if (!scopeConfig || (now - lastLoadTime) > RELOAD_INTERVAL_MS) {
    return loadScopeConfig();
  }
  return scopeConfig;
}

export function updateScopeConfig(newConfig: Partial<ScopeConfig>): void {
  if (scopeConfig) {
    scopeConfig = { ...scopeConfig, ...newConfig };
  }
}
