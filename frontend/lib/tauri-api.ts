/**
 * Tauri API Bridge
 *
 * This module provides the interface between the Next.js frontend and the
 * Tauri Rust backend. It replaces HTTP API calls with Tauri invoke commands.
 *
 * When running as a web app (non-Tauri), it falls back to HTTP API calls.
 */

import type {
  // Terminal types
  TerminalSession,
  SpawnTerminalParams,
  SpawnTerminalResult,
  TmuxSessionInfo,
  // Core types
  Assessment,
  AssessmentEvent,
  AssessmentType,
  AssessmentStatus,
  AssessmentOptions,
  Finding,
  FindingStatus,
  Report,
  ReportFile,
  ReportFormat,
  Severity,
  AgentName,
  AgentState,
  AuditLog,
  Project,
  CreateProjectParams,
  UpdateProjectParams,
  // Config types
  ScopeConfig,
  IdentityTarget,
  CredentialsConfig,
  ToolsConfig,
  AgentsConfig,
  ClaudeAuthState,
  ClaudeContainerEnv,
  ClaudeCredentialMode,
  CodexAuthState,
  CodexContainerEnv,
  CodexCredentialMode,
  Repository,
  AddRepositoryParams,
  // Cloud types
  CloudConfig,
  CloudStatus,
  CloudAuthProvidersResponse,
  CloudLoginResponse,
  CloudSyncResponse,
  CacheStatsResponse,
  CacheStatsDelta,
  BaselineResponse,
  Target,
  Scan,
  ScanDiff,
  ScanSchedule,
  ScanFindingDetail,
  ScanConfig,
  OrgCacheSettings,
  OrgCacheSettingsUpdate,
  DriftAlertsSummary,
  // Integrations types
  IntegrationsConfig,
  JiraProject,
  JiraBoard,
  JiraIssueType,
  JiraEpic,
  JiraSearchResult,
  CreateJiraTicketsRequest,
  CreateJiraTicketsResult,
  // Tool types
  ScanPortsParams,
  ScanPortsResult,
  EnumerateSubdomainsParams,
  EnumerateSubdomainsResult,
  FingerprintServicesParams,
  FingerprintServicesResult,
  DiscoverHostsParams,
  DiscoverHostsResult,
  WebTechnologyScanParams,
  WebTechnologyScanResult,
  RunNucleiParams,
  RunNucleiResult,
  RunNiktoParams,
  RunNiktoResult,
  RunWpscanParams,
  RunWpscanResult,
  SearchExploitsParams,
  SearchExploitsResult,
  RunSqlmapParams,
  RunSqlmapResult,
  FuzzEndpointsParams,
  FuzzEndpointsResult,
  TestXssParams,
  TestXssResult,
  CrawlSiteParams,
  CrawlSiteResult,
  RunMetasploitParams,
  RunMetasploitResult,
  ValidateCveParams,
  ValidateCveResult,
  ScanRepositoryParams,
  ScanRepositoryResult,
  ScanSecretsParams,
  ScanSecretsResult,
  ScanDependenciesParams,
  ScanDependenciesResult,
  AnalyzeCodeContextParams,
  AnalyzeCodeContextResult,
  DetectLanguagesParams,
  DetectLanguagesResult,
  CreateFindingParams,
  GenerateReportParams,
  GenerateReportResult,
  CreateJiraTicketParams,
  CreateJiraTicketResult,
  ImportCycodeFindingsParams,
  ImportCycodeFindingsResult,
  CycodeFinding,
  // New Import types
  Import,
  ImportedFinding,
  ParsedFinding,
  PreviewCsvResult,
  ImportCsvResult,
  ListImportsParams,
  ListImportedFindingsParams,
  CreateValidationAssessmentParams,
  ImportStats,
  // Agent types
  RunOrchestratorParams,
  RunAgentParams,
  // Scan snapshot types
  ScanSnapshot,
  // System types
  DockerStatus,
  SystemStatus,
  ToolInfo,
  PaginatedResult,
  FindingsFilter,
  AssessmentsFilter,
  FindingsStats,
  DashboardStats,
  PendingPrompt,
  HelpResources,
  CloudCorrelation,
  CoverageCell,
  PersistedAttackGraph,
  GraphKind,
  GraphSubstrateNode,
  GraphSubstrateEdge,
  GraphPathsQuery,
  GraphPathsResponse,
  Foothold,
} from './types';
import { isReadOnlyNow, isMutatingMethod } from './read-only';
import { isLocalMode } from './deployment-mode';
import { localApi } from './local-api';

// =============================================================================
// LOCAL / CLOUD DISPATCH
// =============================================================================
//
// Local mode keeps everything in the local SQLite DB, reached through Tauri
// commands; cloud mode (self-hosted team OR managed) goes over HTTP. Both
// branches are passed as thunks so only the selected one is ever built — some
// cloud branches construct URLSearchParams, and evaluating both would be waste
// at best and a side effect at worst.
//
// `isLocalMode()` is a synchronous localStorage read (see deployment-mode.ts),
// which is what lets these stay one-line expression bodies.
function route<T>(local: () => Promise<T>, cloud: () => Promise<T>): Promise<T> {
  return isLocalMode() ? local() : cloud();
}

// =============================================================================
// READ-ONLY WRITE GUARD
// =============================================================================
//
// Read-only users may view everything but mutate nothing. Every write funnels
// through either `invoke` (Tauri/local commands) or `cloudRequest` (cloud HTTP
// API), so guarding both is a hard guarantee no missed button can mutate
// state. See lib/read-only.ts for the role definition.

/** Command-name prefixes that mutate state. A read-only user is blocked from
 *  invoking any Tauri command matching one of these. Reads (get_/list_/check_/
 *  fetch_/load_/detect_/spawn_ a view terminal, etc.) are intentionally absent. */
const READ_ONLY_WRITE_PREFIXES = [
  'set_', 'save_', 'create_', 'update_', 'delete_', 'remove_', 'add_',
  'record_', 'run_', 'cancel_', 'import_', 'invite_', 'disable_', 'assign_',
  'activate_', 'clear_', 'complete_', 'finalize_', 'kill_',
];

/** Exact commands that match a write prefix but are NOT org-data mutations —
 *  they're local session/cache file housekeeping a viewer still triggers during
 *  normal use (watching a live terminal, signing out). Allowlisted so the
 *  view experience and clean sign-out keep working for read-only users. */
const READ_ONLY_WRITE_ALLOW = new Set<string>([
  // Local persistence of on-screen terminal scrollback / chat (SQLite).
  'save_terminal_transcript',
  'save_assessment_chat_messages',
  // Sign-out cleanup of local container-session files (runs for everyone).
  'clear_cloud_session_file',
  'clear_merged_credentials_file',
  'clear_merged_scope_file',
]);

function readOnlyBlocksCommand(cmd: string): boolean {
  if (READ_ONLY_WRITE_ALLOW.has(cmd)) return false;
  return READ_ONLY_WRITE_PREFIXES.some((p) => cmd.startsWith(p));
}

// =============================================================================
// ENVIRONMENT DETECTION & TAURI API IMPORTS
// =============================================================================

// Dynamic imports for Tauri APIs (only available in Tauri context)
let tauriInvoke: (<T>(cmd: string, args?: Record<string, unknown>) => Promise<T>) | null = null;
let tauriListen: (<T>(event: string, handler: (event: { payload: T }) => void) => Promise<() => void>) | null = null;
let tauriInitialized = false;
/**
 * Aggregated Kali pull progress, emitted on `startup:pull-progress`.
 * Matches `PullProgressPayload` in `src-tauri/src/commands/system.rs`.
 *
 * Field notes for the UI:
 *  - `pct < 0` means "warming up" — no layer has reported a total yet,
 *    so the bar should be indeterminate (don't show 0% — looks stalled).
 *  - `mb_done` / `mb_total` are MB (1e6 bytes), not MiB. Display as-is.
 *  - `mbps` is averaged over the whole pull, not instantaneous — stable
 *    on the eye but lags real-time speed by a few seconds.
 *  - `status` is the latest raw docker line; only useful for diagnostics.
 */
/**
 * One node in the in-app user-guide tree. A top-level `.md` file is a leaf
 * page; a top-level folder is a section (`is_section: true`) whose `children`
 * are the pages inside it. `slug` is the path from the guide root with `.md`
 * stripped — e.g. `getting-started` or `cloud-accounts/aws`.
 */
export interface UserGuideEntry {
  slug: string;
  title: string;
  summary: string;
  is_section?: boolean;
  children?: UserGuideEntry[];
}

export interface PullProgress {
  pct: number;
  mb_done: number;
  mb_total: number;
  mbps: number;
  layers: number;
  layers_done: number;
  status: string | null;
}

/**
 * Result of the save-time credential probe for an Add Cloud Account
 * submission. Mirrors `ValidationResult` in
 * `src-tauri/src/commands/cloud_validation.rs`.
 *
 *  - `ok` is the single source of truth the Add Account button gates on.
 *  - `identity` is the human-readable principal the credential resolved
 *    to (an STS ARN, a subscription name, a service-account email, …).
 *    Empty on failure.
 *  - `details` is a secondary line — account/subscription/project
 *    identifier — shown under the identity in the success state.
 *  - `error` is the trimmed CLI stderr (or a synthesized message) when
 *    `ok === false`. Empty on success.
 */
export interface CloudAccountValidationResult {
  ok: boolean;
  identity: string;
  details: string;
  error: string;
  /** True when the failure is an expired SSO session that couldn't be
   *  silently refreshed — the UI should pop the in-app re-auth. */
  needs_reauth?: boolean;
}

/**
 * Result of a save-time identity-target credential probe. Mirrors the
 * cloud-account shape (`validate_identity_target` in the Rust backend)
 * so the Identity Targets dialog can reuse the same success/failure UI:
 *
 *  - `ok` gates the save button.
 *  - `identity` is the principal the credential resolved to (a delegated
 *    admin email, an Okta org user, a service-principal app id, …).
 *  - `details` is a secondary identifier line shown under the identity.
 *  - `error` is the trimmed CLI/HTTP error when `ok === false`.
 *  - `needs_reauth` is set when the failure is a recoverable expired
 *    session the UI should re-prompt for.
 */
export interface IdentityTargetValidationResult {
  ok: boolean;
  identity: string;
  details: string;
  error: string;
  needs_reauth?: boolean;
}

/**
 * Result of a save-time AI-target config validation. Mirrors the identity/cloud
 * shape (`validate_ai_target` in the Rust backend) so the AI Targets dialog can
 * reuse the same success/failure UI. `ok` gates the save button; `identity` is the
 * `kind:endpoint (model …)` the target resolved to; `error` is the missing-field
 * message when `ok === false`. (No live probe — structural validation only.)
 */
export interface AiTargetValidationResult {
  ok: boolean;
  identity: string;
  details: string;
  error: string;
  needs_reauth?: boolean;
}

// Re-export the canonical IdentityTarget type so pages can pull it from
// the api module alongside the validation result (mirrors how the cloud
// page consumes CloudAccountValidationResult).
export type { IdentityTarget };

/**
 * AWS SSO device-authorization session returned by `aws_sso_start_device_auth`.
 * Mirrors `DeviceAuthSession` in `src-tauri/src/commands/aws_sso.rs`.
 * The frontend stashes this in component state during the polling phase
 * so subsequent `aws_sso_poll_device_auth` calls have everything they
 * need (clientId/clientSecret + deviceCode + region).
 */
export interface AwsSsoDeviceAuthSession {
  userCode: string;
  verificationUri: string;
  verificationUriComplete: string;
  deviceCode: string;
  expiresIn: number;
  interval: number;
  clientId: string;
  clientSecret: string;
  region: string;
}

/**
 * Polling tick result. `Pending` is the normal state during the
 * 1–10-minute window the user has to approve; `Authorized` is the
 * terminal success carrying the OIDC access token.
 */
export type AwsSsoPollResult =
  | { status: 'pending' }
  | {
      status: 'authorized';
      access_token: string;
      expires_at: number;
      refresh_token: string | null;
    };

export interface AwsSsoAccount {
  accountId: string;
  accountName: string | null;
  emailAddress: string | null;
}

export interface AwsSsoAccountRole {
  accountId: string;
  roleName: string;
}

/**
 * Shape persisted to the macOS keyring under the `aws_source` blob.
 * One of {sso, access_keys, profile} is populated based on `kind` —
 * the backend probe in `cloud_validation.rs` reads this when running
 * AssumeRole, mints short-lived IAM creds (for SSO) or injects keys
 * directly (for the other two), and authenticates the assume-role
 * call with the result.
 */
export type AwsSourceCredentialsBlob =
  | {
      kind: 'sso';
      sso: {
        start_url: string;
        region: string;
        access_token: string;
        expires_at: number;
        source_account_id: string;
        source_role_name: string;
        // Refresh-grant material — lets the backend silently renew the
        // access token for the whole SSO session window (auth-handler
        // refresh-on-use pattern). Absent on legacy/pre-refresh blobs.
        refresh_token?: string | null;
        client_id?: string;
        client_secret?: string;
      };
    }
  | {
      kind: 'access_keys';
      access_keys: {
        access_key_id: string;
        secret_access_key: string;
      };
    }
  | {
      kind: 'profile';
      profile: { name: string };
    };

/**
 * One named entry in the `aws_sources` library — a source-credential blob
 * plus an id + display name. Mirrors `AwsSourceEntry` in
 * `src-tauri/src/commands/cloud_validation.rs`.
 */
export type AwsSourceEntry = { id: string; name: string } & AwsSourceCredentialsBlob;

/**
 * The `aws_sources` keyring blob: a library of named source identities
 * plus which one is the default (used when an assessment doesn't pick one
 * explicitly). Mirrors `AwsSourcesLibrary` in cloud_validation.rs.
 */
export interface AwsSourcesLibrary {
  default_id: string | null;
  sources: AwsSourceEntry[];
}

/**
 * Result of installing assume-role session credentials into the container
 * for a cloud assessment. Mirrors `CloudSessionResult` in cloud_validation.rs.
 */
export interface CloudSessionResult {
  ok: boolean;
  identity: string;
  expiration: string;
  error: string;
  /** True when injection failed because the SSO session expired and
   *  couldn't be silently refreshed — the UI should prompt re-auth. */
  needs_reauth?: boolean;
}

/** Serializable chat message for DB persistence (matches Rust AssessmentChatMessage) */
export interface PersistedChatMessage {
  id: string;
  msg_type: string;      // "welcome" | "user" | "assistant" | "tool_call" | "system" | "findings"
  content?: string | null;
  variant?: string | null;  // For system messages
  session_key?: string | null; // For terminal messages (legacy)
  timestamp?: string | null;
  // Tool call fields
  tool_name?: string | null;
  tool_call_id?: string | null;
  tool_arguments?: string | null; // JSON string
  tool_result?: string | null;    // JSON string
  tool_status?: string | null;    // "running" | "completed" | "failed"
  tool_duration_ms?: number | null;
}

let tauriAvailable = false;

// Initialize Tauri APIs asynchronously
const initTauri = async () => {
  if (tauriInitialized) return tauriAvailable;
  tauriInitialized = true;

  try {
    // Check if we're in a Tauri environment
    if (typeof window !== 'undefined') {
      const core = await import('@tauri-apps/api/core');
      const event = await import('@tauri-apps/api/event');
      tauriInvoke = core.invoke;
      tauriListen = event.listen;
      tauriAvailable = true;
      console.log('Tauri APIs initialized successfully');
    }
  } catch (e) {
    console.log('Not running in Tauri environment, using HTTP fallback');
    tauriAvailable = false;
  }

  return tauriAvailable;
};

// Initialize on module load (client-side only)
if (typeof window !== 'undefined') {
  initTauri();
}

const isTauri = (): boolean => {
  return tauriAvailable && tauriInvoke !== null;
};

const invoke = async <T>(cmd: string, args?: object): Promise<T> => {
  // Ensure Tauri is initialized
  await initTauri();

  // Read-only users cannot run write commands — hard block at the data layer.
  if (readOnlyBlocksCommand(cmd) && isReadOnlyNow()) {
    throw new Error(
      `Read-only access — "${cmd}" is disabled for your role.`
    );
  }

  if (!tauriInvoke) {
    throw new Error(`Tauri not available. Command: ${cmd}`);
  }
  return tauriInvoke<T>(cmd, args as Record<string, unknown>);
};

const listen = async <T>(
  event: string,
  handler: (payload: T) => void
): Promise<() => void> => {
  // Ensure Tauri is initialized
  await initTauri();

  if (!tauriListen) {
    return () => {};
  }
  return tauriListen<T>(event, (e) => handler(e.payload));
};

// =============================================================================
// HTTP FALLBACK (for web-only mode)
// =============================================================================

const API_BASE_URL = process.env.NEXT_PUBLIC_DEPLOY_MODE === 'web'
  ? ''
  : (process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3001');

class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
    this.name = 'ApiError';
  }
}

async function httpRequest<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
  // In web mode, route through the authenticated Next.js proxy
  let url: string;
  if (process.env.NEXT_PUBLIC_DEPLOY_MODE === 'web') {
    // /api/* endpoints -> /api/proxy/*
    // /tools/* endpoints -> /api/proxy-tools/tools/*
    if (endpoint.startsWith('/api/')) {
      url = `/api/proxy${endpoint.slice(4)}`;
    } else if (endpoint.startsWith('/tools')) {
      url = `/api/proxy-tools${endpoint}`;
    } else {
      url = `/api/proxy${endpoint}`;
    }
  } else {
    url = `${API_BASE_URL}${endpoint}`;
  }

  const response = await fetch(url, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...options.headers,
    },
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({}));
    throw new ApiError(response.status, error.message || `Request failed: ${response.statusText}`);
  }

  const text = await response.text();
  return text ? JSON.parse(text) : (null as T);
}

// =============================================================================
// CLOUD ROUTING — entity reads/writes go to the authenticated org's cloud
// backend, period. There is no local-SQLite fallback in production: the
// startup-gate enforces discovery + auth before any data API is called, so
// the only way a cloudRequest fires without credentials is a bug — which we
// surface as a 401 toast rather than masking with stale local data.
//
// Token refresh happens inline via getValidIdToken(). Expired sessions
// throw CloudSessionExpired, which clears auth state and routes the user
// back to the login screen.
// =============================================================================

/** Get a valid Cognito ID token, refreshing from the stored refresh token if
 *  the current one is expired (or about to expire). Returns null if there is
 *  no path to a valid token (revoked refresh token, missing email, etc.).
 *  De-dupes concurrent refresh attempts via an in-flight promise.
 *
 *  Exported so other modules that talk to the backend (e.g. toolkit-api.ts
 *  for the GHCR PAT broker) reuse the same refresh path instead of reading
 *  idToken raw and bailing on expiry.
 */
let inflightRefresh: Promise<string | null> | null = null;
export async function getValidIdToken(): Promise<string | null> {
  if (typeof window === 'undefined') return null;

  const authRaw = localStorage.getItem('maestro-auth');
  const auth = authRaw ? JSON.parse(authRaw) : null;
  const state = auth?.state;
  const idToken: string | undefined = state?.idToken;
  const tokenExpiry: number | undefined = state?.tokenExpiry;
  const refreshToken: string | undefined = state?.refreshToken;
  const email: string | undefined = state?.user?.email;

  // 30s safety buffer — refresh slightly before the wire-level expiry so an
  // in-flight request never lands at the server with a just-expired token.
  if (idToken && tokenExpiry && Date.now() < tokenExpiry - 30_000) {
    void persistCloudSession(idToken, tokenExpiry);
    return idToken;
  }
  if (!refreshToken || !email) return null;

  if (inflightRefresh) return inflightRefresh;
  inflightRefresh = (async () => {
    try {
      const { refreshSession: cognitoRefreshSession } = await import('./cognito-auth');
      const { useAuthStore } = await import('./stores/auth-store');
      const session = await cognitoRefreshSession(email, refreshToken);
      const newIdToken = session.getIdToken().getJwtToken();
      const newAccessToken = session.getAccessToken().getJwtToken();
      const newRefreshToken = session.getRefreshToken().getToken();
      const expSeconds = session.getIdToken().getExpiration();
      const newExpiry = expSeconds * 1000;
      useAuthStore.setState({
        idToken: newIdToken,
        accessToken: newAccessToken,
        refreshToken: newRefreshToken,
        tokenExpiry: newExpiry,
      });
      void persistCloudSession(newIdToken, newExpiry);
      return newIdToken;
    } catch (err) {
      console.warn('[tauri-api] Cognito refresh failed; clearing auth', err);
      const { useAuthStore } = await import('./stores/auth-store');
      useAuthStore.getState().clearAuth();
      void clearCloudSession();
      return null;
    } finally {
      inflightRefresh = null;
    }
  })();
  return inflightRefresh;
}

/** Mirror the active cloud session to a host file the local MCP server reads,
 *  so MCP-driven writes (create_finding, etc.) can land in the org cloud
 *  instead of local SQLite. Memoized by token so we don't re-write on every
 *  cloud read. Best-effort — failure to write doesn't block the request. */
let lastPersistedToken: string | null = null;
async function persistCloudSession(idToken: string, tokenExpiry: number): Promise<void> {
  if (typeof window === 'undefined') return;
  if (lastPersistedToken === idToken) return;
  if (!isTauri()) return; // file lives on the host disk; web mode doesn't apply
  try {
    const bootstrapRaw = localStorage.getItem('maestro-bootstrap');
    const bootstrap = bootstrapRaw ? JSON.parse(bootstrapRaw) : null;
    const backendUrl: string | undefined = bootstrap?.backendUrl;
    if (!backendUrl) return;
    await invoke('write_cloud_session_file', {
      backend_url: backendUrl,
      id_token: idToken,
      token_expiry: tokenExpiry,
    });
    lastPersistedToken = idToken;
    // Same trigger, same source (the stored bootstrap) — keeps the OAST config
    // in step with the session without a separate call site.
    await persistOastConfig();
  } catch (err) {
    console.warn('[tauri-api] persistCloudSession failed', err);
  }
}

/** Mirror the org's OAST listener config to a host file the local MCP server
 *  reads, so the `oast` oracle has a listener for blind-vulnerability
 *  verification. Without it every blind SSRF / SQLi / XXE / SSTI finding stays
 *  an unverified candidate.
 *
 *  Runs alongside persistCloudSession because both derive from the stored
 *  bootstrap, and doing it here means the file self-heals on any cloud
 *  interaction rather than needing a dedicated call site at sign-in.
 *
 *  The token deliberately does NOT come from discovery — see the note in
 *  app/api/discover/route.web.ts. A listener that requires auth and has no
 *  token available simply stays unavailable, which the oracle reports honestly
 *  rather than guessing. */
let lastPersistedOast: string | null = null;
async function persistOastConfig(): Promise<void> {
  if (typeof window === 'undefined') return;
  if (!isTauri()) return;
  try {
    const bootstrapRaw = localStorage.getItem('maestro-bootstrap');
    const bootstrap = bootstrapRaw ? JSON.parse(bootstrapRaw) : null;
    const server: string | undefined = bootstrap?.oast?.server;
    const token: string | undefined = bootstrap?.oast?.token;
    if (!server) return;
    const fingerprint = `${server}|${token ?? ''}`;
    if (lastPersistedOast === fingerprint) return;
    await invoke('write_oast_config_file', { server, token: token ?? null });
    lastPersistedOast = fingerprint;
  } catch (err) {
    console.warn('[tauri-api] persistOastConfig failed', err);
  }
}

async function clearCloudSession(): Promise<void> {
  if (typeof window === 'undefined') return;
  if (!isTauri()) return;
  try {
    await invoke('clear_cloud_session_file');
    await invoke('clear_merged_credentials_file');
    await invoke('clear_merged_scope_file');
    await invoke('clear_oast_config_file');
    lastPersistedToken = null;
    lastPersistedOast = null;
    lastPersistedCredentialsHash = null;
    lastPersistedScopeHash = null;
  } catch (err) {
    console.warn('[tauri-api] clearCloudSession failed', err);
  }
}

/** Reset the in-memory persist memo so the next cloudRequest re-writes
 *  cloud-session.json against the current bootstrap.backendUrl. Used when
 *  the active cloud account changes — the token may not change but the
 *  backendUrl just did, and the MCP server reads the URL from that file. */
export function resetCloudSessionMemo(): void {
  lastPersistedToken = null;
  lastPersistedCredentialsHash = null;
  lastPersistedScopeHash = null;
}

/** Push the merged CredentialsConfig (cloud shared metadata + local
 *  keychain secrets) to a host-side JSON file the in-container MCP server
 *  reads. The MCP scope/credentials loaders prefer this file over the
 *  legacy local YAML so org-scoped scope and per-user secrets configured
 *  via the desktop UI flow into the assessment runtime. Memoized by
 *  content hash so back-to-back reads of the same config don't churn the
 *  file. Best-effort — failures don't block the user. */
let lastPersistedCredentialsHash: string | null = null;
function hashCredentialsForPersist(config: import('./types').CredentialsConfig): string {
  // Content hash to skip redundant file writes. Must reflect the FULL config.
  // Do NOT pass a key array as the JSON.stringify replacer: an array replacer
  // is an ALLOWLIST applied at EVERY depth, so `Object.keys(config).sort()`
  // (= ["applications","test_accounts"]) stripped every nested app and field —
  // the hash collapsed to {"applications":{},"test_accounts":{}} and never
  // changed when an app was added/edited. The merged-file write was then
  // skipped forever after the first one, so UI-created creds (e.g. a new
  // session app) never reached credentials-merged.json and the assessment ran
  // on stale auth.
  return JSON.stringify(config);
}
async function persistMergedCredentials(
  config: import('./types').CredentialsConfig,
): Promise<void> {
  if (typeof window === 'undefined') return;
  if (!isTauri()) return;
  try {
    const next = hashCredentialsForPersist(config);
    if (next === lastPersistedCredentialsHash) return;
    await invoke('write_merged_credentials_file', { value: config });
    lastPersistedCredentialsHash = next;
  } catch (err) {
    console.warn('[tauri-api] persistMergedCredentials failed', err);
  }
}

/** Push the cloud-stored scope (apps + their domains and repo_paths,
 *  cloud_accounts, kubernetes, exclusions) to a host-side JSON file
 *  the docker.rs bind builder reads at container-create time. The
 *  container's read view is derived from this — without it, in-scope
 *  repos aren't reachable from the assessment terminal. Memoized by
 *  content hash so repeated reads of the same scope don't churn the
 *  file. Best-effort — failures don't block the user. */
let lastPersistedScopeHash: string | null = null;
async function persistMergedScope(scope: import('./types').ScopeConfig): Promise<void> {
  if (typeof window === 'undefined') return;
  if (!isTauri()) return;
  try {
    const next = JSON.stringify(scope);
    if (next === lastPersistedScopeHash) return;
    await invoke('write_merged_scope_file', { value: scope });
    lastPersistedScopeHash = next;
  } catch (err) {
    console.warn('[tauri-api] persistMergedScope failed', err);
  }
}

/** Wrapper around cloudRequest that returns a default value when the
 *  backend returns 404 — i.e. the endpoint isn't deployed yet. Lets the
 *  desktop ship features that depend on backend changes still in flight,
 *  showing graceful empty states instead of hard errors. Use this for
 *  endpoint groups that we KNOW are still being added (repositories,
 *  audit-logs, dashboard/stats, etc.) — not for general fallback. */
async function cloudRequestOrDefault<T>(
  endpoint: string,
  defaultValue: T,
  options: RequestInit = {}
): Promise<T> {
  try {
    return await cloudRequest<T>(endpoint, options);
  } catch (err) {
    if (err instanceof ApiError && err.status === 404) {
      console.info(
        `[tauri-api] ${endpoint} not yet available on backend (404) — returning default empty state`
      );
      return defaultValue;
    }
    throw err;
  }
}

/** Called when cloudRequest gets 401 / refresh fails / session is otherwise
 *  unrecoverable. Toasts the user and clears auth state so the startup gate
 *  routes them to the login page. De-duped via a flag so a burst of failed
 *  cloud reads doesn't fire 10 toasts. */
let notifiedSessionExpired = false;
async function notifyCloudSessionExpired(): Promise<void> {
  if (typeof window === 'undefined') return;
  if (notifiedSessionExpired) return;
  notifiedSessionExpired = true;
  setTimeout(() => { notifiedSessionExpired = false; }, 30_000);
  try {
    const [{ toast }, { useAuthStore }] = await Promise.all([
      import('sonner'),
      import('./stores/auth-store'),
    ]);
    toast.error('Cloud session expired — please sign in again.', { duration: 6000 });
    useAuthStore.getState().clearAuth();
    void clearCloudSession();
  } catch (err) {
    console.warn('[tauri-api] notifyCloudSessionExpired failed', err);
  }
}

/** Called when cloudRequest gets a 403 whose detail starts with one of the
 *  structured prefixes the backend emits for tenancy failures. Both prefixes
 *  signal a state that re-logging won't fix — the Cognito user's
 *  `custom:org_id` attribute is missing or wrong — so the right UX is a
 *  sticky toast that points at the actual remediation, not a session-reset.
 *  Burst-deduped like notifyCloudSessionExpired so a 20-request dashboard
 *  load doesn't stack 20 toasts. */
let notifiedProvisioningError: string | null = null;
async function notifyAccountProvisioningError(detail: string): Promise<void> {
  if (typeof window === 'undefined') return;
  const kind = detail.startsWith('ACCOUNT_NOT_PROVISIONED:')
    ? 'missing'
    : detail.startsWith('WRONG_TENANT:')
      ? 'wrong'
      : null;
  if (!kind) return;
  if (notifiedProvisioningError === kind) return;
  notifiedProvisioningError = kind;
  setTimeout(() => { notifiedProvisioningError = null; }, 60_000);
  try {
    const { toast } = await import('sonner');
    const message = kind === 'missing'
      ? 'Your account is missing org provisioning (custom:org_id). Contact your administrator to restore it.'
      : 'Your account is provisioned for a different tenant than this backend. Contact your administrator.';
    toast.error(message, { duration: Infinity, id: 'account-provisioning' });
  } catch (err) {
    console.warn('[tauri-api] notifyAccountProvisioningError failed', err);
  }
}

// Wipe the on-disk cloud session whenever the auth store transitions to a
// signed-out state. Subscribed once at module load so MCP writes stop hitting
// the cloud immediately when the user clicks "Sign out".
//
// Also runs a 15-min heartbeat that re-validates / refreshes the token even
// when the user isn't actively clicking. Long-running assessments call MCP
// tools (create_finding, etc.) for hours; without this heartbeat the
// cloud-session.json file goes stale once the JWT TTLs out (~1 hour) and the
// MCP write tools start throwing CloudSessionError mid-assessment.
if (typeof window !== 'undefined') {
  void (async () => {
    try {
      const { useAuthStore } = await import('./stores/auth-store');
      let prevToken = useAuthStore.getState().idToken;
      useAuthStore.subscribe((s) => {
        const currentToken = s.idToken;
        if (prevToken && !currentToken) {
          void clearCloudSession();
        }
        prevToken = currentToken;
      });

      // Heartbeat — refresh the cloud session file every 15 min so MCP write
      // tools keep working through long assessments. getValidIdToken handles
      // the refresh+rewrite logic; we just need to call it on a timer.
      const HEARTBEAT_MS = 15 * 60 * 1000;
      setInterval(() => {
        void getValidIdToken().catch(() => {});
      }, HEARTBEAT_MS);
    } catch (err) {
      console.warn('[tauri-api] auth store subscribe failed', err);
    }
  })();
}

/** Variant of cloudRequest that returns the response body as a Blob —
 *  used for binary downloads like PDFs where the backend writes
 *  Content-Disposition: attachment instead of a JSON URL envelope. Same
 *  auth + 401 handling as cloudRequest. */
async function cloudFetchBlob(endpoint: string): Promise<Blob> {
  if (typeof window === 'undefined') {
    throw new ApiError(0, 'cloudFetchBlob called server-side');
  }
  const bootstrapRaw = localStorage.getItem('maestro-bootstrap');
  const bootstrap = bootstrapRaw ? JSON.parse(bootstrapRaw) : null;
  const backendUrl: string | undefined = bootstrap?.backendUrl;
  if (!backendUrl) {
    throw new ApiError(401, 'No cloud backend configured');
  }

  const idToken = await getValidIdToken();
  if (!idToken) {
    void notifyCloudSessionExpired();
    throw new ApiError(401, 'Cloud session expired. Please log in again.');
  }

  const url = `${backendUrl.replace(/\/+$/, '')}/api/v1${endpoint}`;
  const response = await fetch(url, {
    headers: { Authorization: `Bearer ${idToken}` },
  });

  if (!response.ok) {
    if (response.status === 401) void notifyCloudSessionExpired();
    const text = await response.text().catch(() => '');
    throw new ApiError(
      response.status,
      text || `Cloud download failed: ${response.statusText}`,
    );
  }

  return response.blob();
}

/** Hits the per-org cloud backend at `${bootstrap.backendUrl}/api/v1${endpoint}`
 *  with a valid Cognito ID token (refreshing inline if needed). Pass `endpoint`
 *  without the `/api/v1` prefix — e.g. `/findings`, `/assessments`. Throws on
 *  expired session — caller should surface to the user rather than fall back
 *  to local data. */
async function cloudRequest<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
  if (typeof window === 'undefined') {
    throw new ApiError(0, 'cloudRequest called server-side');
  }

  // Read-only users cannot mutate cloud state. Block any mutating HTTP verb
  // before it leaves the client. `/events` telemetry is exempt — it's a
  // fire-and-forget viewing side effect, not a user-initiated change.
  if (
    isMutatingMethod(options.method) &&
    !endpoint.endsWith('/events') &&
    isReadOnlyNow()
  ) {
    throw new ApiError(
      403,
      'Read-only access — this action is disabled for your role.'
    );
  }
  const bootstrapRaw = localStorage.getItem('maestro-bootstrap');
  const bootstrap = bootstrapRaw ? JSON.parse(bootstrapRaw) : null;
  const backendUrl: string | undefined = bootstrap?.backendUrl;
  if (!backendUrl) {
    throw new ApiError(401, 'No cloud backend configured');
  }

  const idToken = await getValidIdToken();
  if (!idToken) {
    void notifyCloudSessionExpired();
    throw new ApiError(401, 'Cloud session expired. Please log in again.');
  }

  const baseTrim = backendUrl.replace(/\/+$/, '');
  const url = `${baseTrim}/api/v1${endpoint}`;

  const response = await fetch(url, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${idToken}`,
      ...options.headers,
    },
  });

  if (!response.ok) {
    if (response.status === 401) {
      // Backend rejected our token (revoked / pool change / clock skew).
      // Surface a toast and clear auth so startup-gate routes to login.
      void notifyCloudSessionExpired();
    }
    const errorBody = await response.json().catch(() => ({}));
    const detail = errorBody.detail || errorBody.message || `Cloud request failed: ${response.statusText}`;
    if (response.status === 403 && typeof detail === 'string') {
      void notifyAccountProvisioningError(detail);
    }
    throw new ApiError(response.status, detail);
  }

  const text = await response.text();
  return text ? JSON.parse(text) : (null as T);
}

/** Helper: build a cloud query string from an arbitrary params object. Skips
 *  null/undefined and stringifies primitives. Drop-in for the existing
 *  ListXxxParams shapes used by the read methods. */
function buildQuery(params?: Record<string, unknown>): string {
  if (!params) return '';
  const entries = Object.entries(params)
    .filter(([, v]) => v !== undefined && v !== null && v !== '')
    .map(([k, v]) => [k, String(v)] as [string, string]);
  if (entries.length === 0) return '';
  return '?' + new URLSearchParams(entries).toString();
}

// =============================================================================
// CONFIG SPLIT HELPERS — split per-user secrets out of org-shared metadata
// before writing to cloud, and merge them back on read.
// =============================================================================

/** Fields on a CredentialApp that hold actual auth material. Everything
 *  else (name, base_url, auth_type, login_url, login_payload, header_name,
 *  token_field, token_url, environment) is org-shared metadata. Keep this
 *  list in sync with `CredentialApp` in `types.ts` whenever new auth
 *  styles get added. */
const CREDENTIAL_SECRET_FIELDS = [
  'username',
  'password',
  'token',
  'client_id',
  'client_secret',
] as const;

function splitCredentials(config: import('./types').CredentialsConfig): {
  shared: import('./types').CredentialsConfig;
  secrets: Record<string, Record<string, string>>;
} {
  const shared: import('./types').CredentialsConfig = {
    applications: {},
    test_accounts: config.test_accounts, // shared (no secrets in test_accounts shape)
    // identity_credentials carries the IDP token/SA-key refs an
    // IdentityTarget points at. Inline token values DO live here (the
    // SA-key path is just a container file path, not a secret) — they
    // round-trip through the same org-shared store as the app catalog
    // so the in-container MCP can resolve sa_key_ref/credential_ref.
    identity_credentials: config.identity_credentials,
  };
  const secrets: Record<string, Record<string, string>> = {};
  for (const [appName, app] of Object.entries(config.applications || {})) {
    const appShared: Record<string, unknown> = { ...app };
    const appSecrets: Record<string, string> = {};
    for (const field of CREDENTIAL_SECRET_FIELDS) {
      if (app[field] !== undefined) {
        appSecrets[field] = String(app[field]);
        delete appShared[field];
      }
    }
    shared.applications[appName] = appShared as unknown as import('./types').CredentialApp;
    if (Object.keys(appSecrets).length > 0) {
      secrets[appName] = appSecrets;
    }
  }
  return { shared, secrets };
}

function mergeCredentials(
  shared: Partial<import('./types').CredentialsConfig> | undefined,
  secrets: Record<string, Record<string, string>>,
): import('./types').CredentialsConfig {
  const applications: import('./types').CredentialsConfig['applications'] = {};
  for (const [appName, app] of Object.entries(shared?.applications || {})) {
    applications[appName] = { ...app, ...(secrets[appName] || {}) };
  }
  return {
    applications,
    test_accounts: shared?.test_accounts,
    identity_credentials: shared?.identity_credentials,
  };
}

/** Same shape for integrations — Jira API token + GitHub PAT are the only
 *  secret fields. The rest (url, project_key, email, username, enabled)
 *  is org-shared. */
function splitIntegrations(config: import('./types').IntegrationsConfig): {
  shared: import('./types').IntegrationsConfig;
  secrets: Record<string, Record<string, string>>;
} {
  const shared: import('./types').IntegrationsConfig = {};
  const secrets: Record<string, Record<string, string>> = {};
  if (config.jira) {
    const { api_token, ...rest } = config.jira;
    shared.jira = rest as import('./types').JiraIntegration;
    if (api_token) secrets.jira = { api_token };
  }
  if (config.github) {
    const { personal_access_token, ...rest } = config.github;
    shared.github = rest as import('./types').GitHubIntegration;
    if (personal_access_token) secrets.github = { personal_access_token };
  }
  return { shared, secrets };
}

function mergeIntegrations(
  shared: Partial<import('./types').IntegrationsConfig> | undefined,
  secrets: Record<string, Record<string, string>>,
): import('./types').IntegrationsConfig {
  const out: import('./types').IntegrationsConfig = {};
  if (shared?.jira || secrets.jira) {
    out.jira = {
      ...(shared?.jira ?? { enabled: false }),
      ...(secrets.jira || {}),
    } as import('./types').JiraIntegration;
  }
  if (shared?.github || secrets.github) {
    out.github = {
      ...(shared?.github ?? { enabled: false }),
      ...(secrets.github || {}),
    } as import('./types').GitHubIntegration;
  }
  return out;
}

// =============================================================================
// UNIFIED API CLIENT
// =============================================================================

// Single-flight guards (A3, UI-freeze fix): dedupe concurrent system/docker
// status polls. Six components poll these, and each invoke hits docker — so
// without this, overlapping calls stack up. Concurrent callers share one
// in-flight request; it clears when settled.
let _systemStatusInFlight: Promise<SystemStatus> | null = null;
let _dockerStatusInFlight: Promise<DockerStatus> | null = null;

export const api = {
  // ===========================================================================
  // SYSTEM & DOCKER
  // ===========================================================================

  system: {
    /** Get overall system status (single-flight — concurrent pollers share one
     *  request so they don't stack redundant get_system_status calls). */
    getStatus: (): Promise<SystemStatus> => {
      const existing = _systemStatusInFlight;
      if (existing) return existing;
      const p: Promise<SystemStatus> = (
        isTauri() ? invoke<SystemStatus>('get_system_status') : httpRequest<SystemStatus>('/api/system/status')
      ).finally(() => {
        _systemStatusInFlight = null;
      });
      _systemStatusInFlight = p;
      return p;
    },

    /** Get Docker/Kali container status (single-flight — see getStatus). */
    getDockerStatus: (): Promise<DockerStatus> => {
      const existing = _dockerStatusInFlight;
      if (existing) return existing;
      const p: Promise<DockerStatus> = (
        isTauri() ? invoke<DockerStatus>('get_docker_status') : httpRequest<DockerStatus>('/api/system/docker')
      ).finally(() => {
        _dockerStatusInFlight = null;
      });
      _dockerStatusInFlight = p;
      return p;
    },

    /** Start the Kali container */
    startKali: (): Promise<void> =>
      isTauri()
        ? invoke('start_kali_container')
        : httpRequest('/api/system/docker/start', { method: 'POST' }),

    /** Stop the Kali container */
    stopKali: (): Promise<void> =>
      isTauri()
        ? invoke('stop_kali_container')
        : httpRequest('/api/system/docker/stop', { method: 'POST' }),

    /** Get list of available tools */
    getTools: (): Promise<ToolInfo[]> =>
      isTauri()
        ? invoke('get_available_tools')
        : httpRequest('/api/system/tools'),

    /** Check if a target is in scope */
    validateScope: (target: string): Promise<{ valid: boolean; reason?: string; environment?: string }> =>
      isTauri()
        ? invoke('validate_scope', { target })
        : httpRequest('/api/config/scope/validate', {
            method: 'POST',
            body: JSON.stringify({ target }),
          }),

    /** Check if Docker CLI is installed */
    checkDockerInstalled: (): Promise<boolean> =>
      isTauri()
        ? invoke('check_docker_installed')
        : Promise.resolve(false),

    /** Absolute path to the docker binary. macOS GUI apps don't inherit the
     *  user's full PATH, so callers spawning a docker subprocess (terminal
     *  PTY) must use this resolved path. */
    resolveDockerPath: (): Promise<string> =>
      isTauri()
        ? invoke('resolve_docker_path')
        : Promise.resolve('docker'),

    /** Open Docker Desktop application */
    openDockerDesktop: (): Promise<void> =>
      isTauri()
        ? invoke('open_docker_desktop')
        : Promise.reject(new Error('Docker Desktop control requires the desktop app')),

    /** Diagnose the current Docker state (installed / running / hung / healthy).
     *  Used by the startup gate to render targeted error messages instead of
     *  a generic "didn't start in 60s" timeout. */
    diagnoseDocker: (): Promise<{ state: 'not_installed' | 'not_running' | 'daemon_unresponsive' | 'healthy' }> =>
      isTauri()
        ? invoke('diagnose_docker')
        : Promise.resolve({ state: 'not_installed' }),

    /** Hard-restart Docker Desktop: clean quit + relaunch. Used when the
     *  daemon is hung (Engine running, but socket /_ping doesn't respond). */
    restartDockerDesktop: (): Promise<void> =>
      isTauri()
        ? invoke('restart_docker_desktop')
        : Promise.reject(new Error('Docker Desktop control requires the desktop app')),

    /** Check if the Kali Docker image exists */
    checkKaliImageExists: (): Promise<boolean> =>
      isTauri()
        ? invoke('check_kali_image_exists')
        : Promise.resolve(false),

    /** Pull the Kali Docker image from GHCR (anonymous — only works if image was made public) */
    pullKaliImage: (): Promise<void> =>
      isTauri()
        ? invoke('pull_kali_image')
        : Promise.reject(new Error('Docker image pulling requires the desktop app')),

    /**
     * Pull the Kali Docker image with GHCR credentials brokered by the
     * backend. The username + password come from
     * `/api/v1/toolkit/registry-credentials`, which the desktop calls
     * after Cognito login. PAT never lives in the client binary.
     */
    pullKaliImageWithAuth: (username: string, password: string): Promise<void> =>
      isTauri()
        ? invoke('pull_kali_image_with_auth', { username, password })
        : Promise.reject(new Error('Docker image pulling requires the desktop app')),

    /**
     * Cache the backend-brokered GHCR credential in Rust AppState so the
     * container lifecycle (create/recreate) pulls the PRIVATE toolkit image
     * authenticated — not just the frontend startup-gate. Call this right
     * after `getRegistryCredentials()`, before starting the container.
     * No-op outside Tauri.
     */
    setToolkitCredentials: (
      username: string,
      password: string,
      expiresAt?: number | null,
    ): Promise<void> =>
      isTauri()
        ? invoke('set_toolkit_credentials', { username, password, expiresAt: expiresAt ?? null })
        : Promise.resolve(),

    /** Subscribe to Docker image build/pull progress events */
    onBuildProgress: (handler: (line: string) => void): Promise<() => void> =>
      listen<string>('startup:build-progress', handler),

    /**
     * Subscribe to structured pull-progress events emitted while the Kali
     * image is downloading. Each event carries the aggregated state across
     * every layer — see `PullProgress` for the field semantics. The Rust
     * side throttles to ~5 Hz so this handler won't run thousands of times
     * per second on a multi-gig pull.
     */
    onPullProgress: (handler: (p: PullProgress) => void): Promise<() => void> =>
      listen<PullProgress>('startup:pull-progress', handler),

    /** Ensure MCP server is running inside the container. Returns true if already healthy. */
    ensureMcpServer: (): Promise<boolean> =>
      isTauri()
        ? invoke('ensure_mcp_server')
        : Promise.resolve(false),
  },

  // ===========================================================================
  // CLAUDE AUTHENTICATION
  // ===========================================================================
  //
  // Two credential modes for the `claude` CLI inside the Kali container:
  //   - oauth   (default): container's /root/.claude/.credentials.json
  //   - api_key (BYO):     ANTHROPIC_API_KEY in macOS Keychain
  //
  // Tauri-only — no HTTP fallback because the cloud frontend doesn't own
  // these credentials.

  claude: {
    getAuthState: (): Promise<ClaudeAuthState> =>
      isTauri()
        ? invoke('get_claude_auth_state')
        : Promise.reject(new Error('Claude auth is only available in the desktop app')),

    setMode: (mode: ClaudeCredentialMode): Promise<void> =>
      isTauri()
        ? invoke('set_active_credential_mode', { mode })
        : Promise.reject(new Error('Claude auth is only available in the desktop app')),

    setApiKey: (key: string): Promise<void> =>
      isTauri()
        ? invoke('set_claude_api_key', { key })
        : Promise.reject(new Error('Claude auth is only available in the desktop app')),

    clearApiKey: (): Promise<void> =>
      isTauri()
        ? invoke('clear_claude_api_key')
        : Promise.reject(new Error('Claude auth is only available in the desktop app')),

    testApiKey: (key: string): Promise<boolean> =>
      isTauri()
        ? invoke('test_claude_api_key', { key })
        : Promise.reject(new Error('Claude auth is only available in the desktop app')),

    /** Returns the env vars to inject on `docker exec` for the active mode. */
    getContainerEnv: (): Promise<ClaudeContainerEnv> =>
      isTauri()
        ? invoke('get_claude_container_env')
        : Promise.reject(new Error('Claude auth is only available in the desktop app')),
  },

  // ===========================================================================
  // CODEX AUTHENTICATION (parallel of `claude` above — OpenAI / GPT-5.5)
  // ===========================================================================
  //
  // Two credential modes for the `codex` CLI inside the Kali container:
  //   - oauth   (default): container's /root/.codex/auth.json (device-code flow)
  //   - api_key (BYO):     OPENAI_API_KEY in macOS Keychain
  //
  // Tauri-only — no HTTP fallback because the cloud frontend doesn't own
  // these credentials.

  codex: {
    getAuthState: (): Promise<CodexAuthState> =>
      isTauri()
        ? invoke('get_codex_auth_state')
        : Promise.reject(new Error('Codex auth is only available in the desktop app')),

    setMode: (mode: CodexCredentialMode): Promise<void> =>
      isTauri()
        ? invoke('set_active_codex_credential_mode', { mode })
        : Promise.reject(new Error('Codex auth is only available in the desktop app')),

    setApiKey: (key: string): Promise<void> =>
      isTauri()
        ? invoke('set_codex_api_key', { key })
        : Promise.reject(new Error('Codex auth is only available in the desktop app')),

    clearApiKey: (): Promise<void> =>
      isTauri()
        ? invoke('clear_codex_api_key')
        : Promise.reject(new Error('Codex auth is only available in the desktop app')),

    testApiKey: (key: string): Promise<boolean> =>
      isTauri()
        ? invoke('test_codex_api_key', { key })
        : Promise.reject(new Error('Codex auth is only available in the desktop app')),

    /** Returns the env vars to inject on `docker exec` for the active mode. */
    getContainerEnv: (): Promise<CodexContainerEnv> =>
      isTauri()
        ? invoke('get_codex_container_env')
        : Promise.reject(new Error('Codex auth is only available in the desktop app')),
  },

  // ===========================================================================
  // TERMINAL SESSIONS
  // ===========================================================================

  terminal: {
    /** Spawn a new terminal session (registers in DB + checks claude availability) */
    spawn: (params: SpawnTerminalParams): Promise<SpawnTerminalResult> =>
      isTauri()
        ? invoke('spawn_terminal_session', { params })
        : Promise.reject(new Error('Terminal sessions require the desktop app')),

    /** List all terminal sessions */
    list: (): Promise<TerminalSession[]> =>
      isTauri()
        ? invoke('list_terminal_sessions')
        : Promise.reject(new Error('Terminal sessions require the desktop app')),

    /** Get a single terminal session */
    get: (id: string): Promise<TerminalSession | null> =>
      isTauri()
        ? invoke('get_terminal_session', { id })
        : Promise.reject(new Error('Terminal sessions require the desktop app')),

    /** End a terminal session */
    end: (id: string, exitCode?: number): Promise<void> =>
      isTauri()
        ? invoke('end_terminal_session', { id, exit_code: exitCode })
        : Promise.reject(new Error('Terminal sessions require the desktop app')),

    /** Link a session to an assessment */
    linkToAssessment: (sessionId: string, assessmentId: string): Promise<void> =>
      isTauri()
        ? invoke('link_session_to_assessment', { session_id: sessionId, assessment_id: assessmentId })
        : Promise.reject(new Error('Terminal sessions require the desktop app')),

    /** Check if claude CLI is installed */
    checkClaude: (): Promise<boolean> =>
      isTauri()
        ? invoke('check_claude_installed')
        : Promise.resolve(false),

    /** Check if codex CLI is installed (host or baked into container) */
    checkCodex: (): Promise<boolean> =>
      isTauri()
        ? invoke('check_codex_installed')
        : Promise.resolve(false),

    /** Check which CLIs are available */
    checkAvailableClis: (): Promise<{ maestro: boolean; claude: boolean; codex: boolean; maestro_command: string }> =>
      isTauri()
        ? invoke('check_available_clis')
        : Promise.resolve({ maestro: false, claude: false, codex: false, maestro_command: 'maestro' }),

    /** Record a brain selection event (Claude vs Codex) for usage telemetry.
     *  Fire-and-forget — safe to ignore errors. */
    recordBrainSelected: (brain: 'claude' | 'codex', assessmentId?: string): Promise<void> =>
      isTauri()
        ? invoke('record_brain_selected', { brain, assessmentId: assessmentId ?? null })
        : Promise.resolve(),

    /** Check whether Claude is authenticated inside the Kali container.
     *  Reads /root/.claude/.credentials.json existence in the container. */
    checkClaudeAuthInContainer: (): Promise<boolean> =>
      isTauri()
        ? invoke('check_claude_auth_in_container')
        : Promise.resolve(false),

    /** Check whether Codex is authenticated inside the Kali container.
     *  Reads /root/.codex/auth.json existence in the container. */
    checkCodexAuthInContainer: (): Promise<boolean> =>
      isTauri()
        ? invoke('check_codex_auth_in_container')
        : Promise.resolve(false),

    /** Write `~/.codex/config.toml` so the Codex CLI sees the kali-pentest
     *  MCP server. Idempotent — safe to call before every Codex session. */
    ensureCodexMcpConfig: (projectRoot: string): Promise<void> =>
      isTauri()
        ? invoke('ensure_codex_mcp_config', { projectRoot })
        : Promise.reject(new Error('Codex MCP config requires the desktop app')),

    /** Write `~/.kali-mcp-pentest/claude-home/maestro-mcp.json` so the
     *  Claude CLI inside the container can find the kali-pentest MCP
     *  server using the container's amd64 install rather than the host's
     *  (cross-arch hosts hit "invalid ELF header" on native modules
     *  otherwise). Idempotent — safe to call before every Claude spawn. */
    ensureClaudeMcpConfig: (): Promise<void> =>
      isTauri()
        ? invoke('ensure_claude_mcp_config')
        : Promise.reject(new Error('Claude MCP config requires the desktop app')),

    /** Find the newest Codex session file in the container with mtime
     *  later than `afterUnix`. Returns the bare UUID (no extension) or
     *  null if nothing matches. Codex doesn't let us pin a session ID
     *  upfront like Claude does, so we capture the UUID it chose after
     *  the user's first prompt+response writes a session file. */
    captureCodexSessionId: (afterUnix: number): Promise<string | null> =>
      isTauri()
        ? invoke('capture_codex_session_id', { afterUnix })
        : Promise.resolve(null),

    /** Check whether an assessment's tmux session is live inside the container.
     *  Returns true → reopening the pane will reattach to a running claude. */
    checkAssessmentSessionLive: (assessmentId: string): Promise<boolean> =>
      isTauri()
        ? invoke('check_assessment_session_live', { assessmentId })
        : Promise.resolve(false),

    /** Returns true iff Claude's conversation file for this session id still
     *  exists in the container. The UI uses this before offering Resume on a
     *  completed assessment: present → reload the conversation; absent (e.g.
     *  claude-home was reset) → offer a clearly-labeled fresh start rather
     *  than `claude --resume` silently opening an empty prompt. */
    checkClaudeSessionResumable: (sessionId: string): Promise<boolean> =>
      isTauri()
        ? invoke('check_claude_session_resumable', { sessionId })
        : Promise.resolve(false),

    /** Returns the IDs of assessments with live tmux sessions in the container.
     *  Use this for list/sidebar views — one docker exec covers any N rows. */
    listLiveAssessmentSessions: (): Promise<string[]> =>
      isTauri()
        ? invoke('list_live_assessment_sessions')
        : Promise.resolve([]),

    /** Kill an assessment's in-container tmux session(s) for both brains.
     *  Best-effort — resolves even if no session exists. Called on delete so
     *  the running CLI stops and the live badge clears immediately. */
    killAssessmentSessions: (assessmentId: string): Promise<void> =>
      isTauri()
        ? invoke('kill_assessment_sessions', { assessmentId })
        : Promise.resolve(),

    /** Get the working directory for terminal sessions */
    getWorkingDir: (): Promise<string> =>
      isTauri()
        ? invoke('get_terminal_working_dir')
        : Promise.reject(new Error('Terminal sessions require the desktop app')),

    /** Save transcript for a terminal session */
    saveTranscript: (sessionId: string, transcript: string): Promise<void> =>
      isTauri()
        ? invoke('save_terminal_transcript', { session_id: sessionId, transcript })
        : Promise.reject(new Error('Terminal sessions require the desktop app')),

    /** List terminal sessions for a specific assessment */
    listForAssessment: (assessmentId: string): Promise<TerminalSession[]> =>
      isTauri()
        ? invoke('get_terminal_sessions_for_assessment', { assessment_id: assessmentId })
        : Promise.reject(new Error('Terminal sessions require the desktop app')),

    /** Save chat messages for an assessment */
    saveChatMessages: (assessmentId: string, messages: PersistedChatMessage[]): Promise<void> =>
      isTauri()
        ? invoke('save_assessment_chat_messages', { assessment_id: assessmentId, messages })
        : Promise.reject(new Error('Terminal sessions require the desktop app')),

    /** Load chat messages for an assessment */
    loadChatMessages: (assessmentId: string): Promise<PersistedChatMessage[]> =>
      isTauri()
        ? invoke('load_assessment_chat_messages', { assessment_id: assessmentId })
        : Promise.reject(new Error('Terminal sessions require the desktop app')),

    // tmux session management
    /** Check if tmux is available (bundled sidecar or system) */
    checkTmuxInstalled: (): Promise<boolean> =>
      isTauri()
        ? invoke('check_tmux_installed')
        : Promise.resolve(false),

    /** Get the resolved tmux binary path (bundled sidecar or system) */
    getTmuxPath: (): Promise<string | null> =>
      isTauri()
        ? invoke('get_tmux_path')
        : Promise.resolve(null),

    /** Check if a tmux session exists */
    checkTmuxSession: (name: string): Promise<boolean> =>
      isTauri()
        ? invoke('check_tmux_session', { sessionName: name })
        : Promise.resolve(false),

    /** List all assessment tmux sessions */
    listTmuxSessions: (): Promise<TmuxSessionInfo[]> =>
      isTauri()
        ? invoke('list_tmux_sessions')
        : Promise.resolve([]),

    /** Capture the scrollback of a tmux pane (with ANSI escape codes) */
    captureTmuxPane: (name: string): Promise<string> =>
      isTauri()
        ? invoke('capture_tmux_pane', { sessionName: name })
        : Promise.reject(new Error('tmux requires the desktop app')),

    /** Kill a tmux session */
    killTmuxSession: (name: string): Promise<void> =>
      isTauri()
        ? invoke('kill_tmux_session', { sessionName: name })
        : Promise.reject(new Error('tmux requires the desktop app')),
  },

  // ===========================================================================
  // HELP — slash commands + agents reference (read from .claude/ at runtime)
  // ===========================================================================
  help: {
    listResources: (): Promise<HelpResources> =>
      isTauri()
        ? invoke('list_help_resources')
        : Promise.resolve({ commands: [], agents: [], project_root: '' } as HelpResources),

    listUserGuide: (): Promise<UserGuideEntry[]> =>
      isTauri()
        ? invoke('list_user_guide')
        : Promise.resolve([]),

    readUserGuideDoc: (slug: string): Promise<string> =>
      isTauri()
        ? invoke('read_user_guide_doc', { slug })
        : Promise.resolve(''),
  },

  // ===========================================================================
  // ASSESSMENTS
  // ===========================================================================

  assessments: {
    /** List assessments with optional filtering */
    list: (params?: AssessmentsFilter & { page?: number; limit?: number }): Promise<PaginatedResult<Assessment>> =>
      route(
        () => localApi.assessments.list(params as Record<string, unknown> | undefined),
        () => cloudRequest(`/assessments${buildQuery(params as Record<string, unknown>)}`),
      ),

    /** Get a single assessment by ID */
    get: (id: string): Promise<Assessment> =>
      route(
        () => localApi.assessments.get(id),
        () => cloudRequest(`/assessments/${id}`),
      ),

    /** Tool-execution provenance for an assessment (which security tools ran). */
    listToolExecutions: (id: string): Promise<import('./types').ToolExecution[]> =>
      route(
        // Tool provenance is captured server-side at promotion time; local runs
        // have no promotion step. Empty, not an error — the execution overview
        // already renders a labeled placeholder for missing coverage.
        () => localApi.assessments.listToolExecutions(),
        () => cloudRequest(`/assessments/${id}/tool-executions`),
      ),

    /** Per-test results for an assessment (the {agent}-results.json rows run
     *  through the provenance gate). Graceful-404 / empty: older backends and
     *  un-promoted runs simply have no per-test coverage captured — the
     *  execution overview renders a labeled placeholder for that case rather
     *  than erroring. */
    listTestResults: (id: string): Promise<import('./types').ExecutionTestResult[]> =>
      cloudRequestOrDefault(
        `/assessments/${id}/test-results`,
        [] as import('./types').ExecutionTestResult[],
      ),

    /** Scope-validation decisions recorded at tool-dispatch time (both allowed
     *  and rejected calls), rolled up per (target, in_scope). Graceful-404 /
     *  empty for the same reason as listTestResults. */
    listScopeDecisions: (id: string): Promise<import('./types').ScopeTargetDecision[]> =>
      cloudRequestOrDefault(
        `/assessments/${id}/scope-decisions`,
        [] as import('./types').ScopeTargetDecision[],
      ),

    /** Create a new assessment */
    create: (data: {
      name?: string;
      type: AssessmentType;
      targets?: string[];
      repo_paths?: string[];
      phases?: AgentName[];
      credential_app?: string;
      jira_project?: string;
      email_recipients?: string[];
      severity_threshold?: Severity;
      options?: AssessmentOptions;
      assessment_config?: import('./types').AssessmentConfig;
      project_id?: string;
      start?: boolean;
    }): Promise<Assessment> =>
      route(
        () => localApi.assessments.create(data as unknown as Record<string, unknown>),
        () => cloudRequest('/assessments', { method: 'POST', body: JSON.stringify(data) }),
      ),

    /** Update an assessment (type, name, status, targets) */
    update: (id: string, data: {
      type?: AssessmentType;
      name?: string;
      status?: AssessmentStatus;
      targets?: string[];
    }): Promise<Assessment> =>
      route(
        () => localApi.assessments.update(id, data as unknown as Record<string, unknown>),
        () => cloudRequest(`/assessments/${id}`, { method: 'PATCH', body: JSON.stringify(data) }),
      ),

    /** Replace the assessment.options JSON blob. Caller is responsible
     *  for merging existing options with new fields. Used to persist
     *  per-assessment metadata like the Claude session UUID. */
    updateOptions: (id: string, options: Record<string, unknown>): Promise<Assessment> =>
      isTauri()
        ? invoke('update_assessment_options', { id, options })
        : cloudRequest(`/assessments/${id}/options`, { method: 'PATCH', body: JSON.stringify(options) }),

    /** Start an assessment that was created but not started */
    start: (id: string): Promise<Assessment> =>
      cloudRequest(`/assessments/${id}/start`, { method: 'POST' }),

    /** Cancel a running assessment */
    cancel: (id: string): Promise<void> =>
      route(
        () => localApi.assessments.cancel(id),
        () => cloudRequest(`/assessments/${id}/cancel`, { method: 'POST' }),
      ),

    /** Pause a running assessment (can be resumed later) */
    pause: (id: string): Promise<void> =>
      route(
        () => localApi.assessments.pause(id),
        () => cloudRequest(`/assessments/${id}/pause`, { method: 'POST' }),
      ),

    /** Resume a paused/failed/cancelled assessment from its last checkpoint */
    resume: (id: string): Promise<Assessment> =>
      route(
        () => localApi.assessments.resume(id),
        () => cloudRequest(`/assessments/${id}/resume`, { method: 'POST' }),
      ),

    /** Delete an assessment */
    delete: (id: string): Promise<void> =>
      route(
        () => localApi.assessments.delete(id),
        () => cloudRequest(`/assessments/${id}`, { method: 'DELETE' }),
      ),

    /** Get assessment report */
    getReport: (id: string): Promise<Report> =>
      cloudRequest(`/assessments/${id}/report`),

    /** Generate report for assessment */
    generateReport: (id: string, format?: ReportFormat): Promise<Report> =>
      cloudRequest(`/assessments/${id}/report`, {
        method: 'POST',
        body: JSON.stringify({ format: format || 'markdown' }),
      }),

    /**
     * Manually "complete" an assessment: pushes its findings from the
     * in-container local MCP store to the cloud dashboard and flips the
     * assessment status to 'completed'. Called by the desktop's
     * "Complete & Push" button when the user knows the run is done and
     * wants the dashboard to reflect it.
     *
     * Pass `findingIds` to push only a curated subset (matches the
     * agent-driven flow). Omit it to push every finding currently in
     * the local store.
     */
    complete: (
      id: string,
      findingIds?: string[],
    ): Promise<{
      assessment_id: string;
      mode: string;
      requested: number;
      found_local: number;
      pushed: number;
      failed: number;
      assessment_status: string;
      errors: unknown;
    }> =>
      invoke('complete_assessment', {
        assessmentId: id,
        findingIds: findingIds ?? null,
      }),

    /** Persistent activity-feed events for an assessment. The desktop's
     *  real-time activity-feed.tsx renders tool_call / finding_detected
     *  blocks live; persisting them lets a teammate (or post-run viewer)
     *  scroll through the full timeline regardless of when their app was
     *  open. Both list and create are graceful-404 — older backends
     *  without the endpoint just see an empty timeline. */
    listEvents: (id: string, params?: { event_type?: string; limit?: number }): Promise<AssessmentEvent[]> =>
      cloudRequestOrDefault(
        `/assessments/${id}/events${buildQuery(params as Record<string, unknown>)}`,
        [] as AssessmentEvent[],
      ),

    createEvent: (
      id: string,
      event: {
        event_type: 'tool_call' | 'tool_result' | 'finding_detected' | 'phase_change' | 'guidance_request' | 'orchestrator_message' | 'error';
        tool?: string;
        target?: string;
        details?: Record<string, unknown>;
        ref_finding_id?: string;
      },
    ): Promise<AssessmentEvent | null> =>
      cloudRequestOrDefault<AssessmentEvent | null>(
        `/assessments/${id}/events`,
        null,
        { method: 'POST', body: JSON.stringify(event) },
      ),

    /** Subscribe to assessment events (Tauri uses event listener, HTTP uses SSE) */
    subscribe: (
      assessmentId: string,
      handlers: {
        onStatusChange?: (status: string, message?: string) => void;
        onProgress?: (percent: number, currentTool: string) => void;
        onFindingCreated?: (finding: Finding) => void;
        onCompleted?: (assessment: Assessment) => void;
        onError?: (message: string) => void;
        onLog?: (level: string, message: string) => void;
      }
    ): Promise<() => void> => {
      if (isTauri()) {
        // Tauri event-based subscription
        const unsubscribers: Array<() => void> = [];

        const setup = async () => {
          if (handlers.onStatusChange) {
            unsubscribers.push(
              await listen<{ status: string; message?: string }>(
                `assessment:${assessmentId}:status`,
                (p) => handlers.onStatusChange!(p.status, p.message)
              )
            );
          }
          if (handlers.onProgress) {
            unsubscribers.push(
              await listen<{ percent: number; currentTool: string }>(
                `assessment:${assessmentId}:progress`,
                (p) => handlers.onProgress!(p.percent, p.currentTool)
              )
            );
          }
          if (handlers.onFindingCreated) {
            unsubscribers.push(
              await listen<Finding>(
                `assessment:${assessmentId}:finding`,
                handlers.onFindingCreated
              )
            );
          }
          if (handlers.onCompleted) {
            unsubscribers.push(
              await listen<Assessment>(
                `assessment:${assessmentId}:completed`,
                handlers.onCompleted
              )
            );
          }
          if (handlers.onError) {
            unsubscribers.push(
              await listen<{ message: string }>(
                `assessment:${assessmentId}:error`,
                (p) => handlers.onError!(p.message)
              )
            );
          }
          if (handlers.onLog) {
            unsubscribers.push(
              await listen<{ level: string; message: string }>(
                `assessment:${assessmentId}:log`,
                (p) => handlers.onLog!(p.level, p.message)
              )
            );
          }
        };

        setup();
        return Promise.resolve(() => unsubscribers.forEach((u) => u()));
      } else {
        // HTTP SSE subscription
        const eventSource = new EventSource(
          `${API_BASE_URL}/api/assessments/${assessmentId}/events`
        );

        eventSource.addEventListener('status_change', (e) => {
          const data = JSON.parse((e as MessageEvent).data);
          handlers.onStatusChange?.(data.status, data.message);
        });

        eventSource.addEventListener('progress', (e) => {
          const data = JSON.parse((e as MessageEvent).data);
          handlers.onProgress?.(data.percent, data.currentTool);
        });

        eventSource.addEventListener('finding_created', (e) => {
          handlers.onFindingCreated?.(JSON.parse((e as MessageEvent).data));
        });

        eventSource.addEventListener('completed', (e) => {
          handlers.onCompleted?.(JSON.parse((e as MessageEvent).data));
        });

        eventSource.addEventListener('error', (e) => {
          const data = (e as MessageEvent).data;
          if (data) {
            handlers.onError?.(JSON.parse(data).message);
          }
        });

        eventSource.addEventListener('log', (e) => {
          const data = JSON.parse((e as MessageEvent).data);
          handlers.onLog?.(data.level, data.message);
        });

        return Promise.resolve(() => eventSource.close());
      }
    },
  },

  // ===========================================================================
  // PROJECTS
  // ===========================================================================

  projects: {
    /** List all projects */
    list: (status?: 'active' | 'archived'): Promise<Project[]> =>
      route(
        () => localApi.projects.list(status),
        () => cloudRequest(`/projects${status ? `?status=${status}` : ''}`),
      ),

    /** Get a single project by ID */
    get: (id: string): Promise<Project | null> =>
      route(
        () => localApi.projects.get(id),
        () => cloudRequest(`/projects/${id}`),
      ),

    /** Create a new project */
    create: (data: CreateProjectParams): Promise<Project> =>
      route(
        () => localApi.projects.create(data as unknown as Record<string, unknown>),
        () => cloudRequest('/projects', { method: 'POST', body: JSON.stringify(data) }),
      ),

    /** Update a project */
    update: (id: string, data: UpdateProjectParams): Promise<Project> =>
      route(
        () => localApi.projects.update(id, data as unknown as Record<string, unknown>),
        () => cloudRequest(`/projects/${id}`, { method: 'PATCH', body: JSON.stringify(data) }),
      ),

    /** Delete a project */
    delete: (id: string): Promise<void> =>
      route(
        () => localApi.projects.delete(id),
        () => cloudRequest(`/projects/${id}`, { method: 'DELETE' }),
      ),

    /** Assign an assessment to a project (or unassign if projectId is null) */
    assignAssessment: (assessmentId: string, projectId: string | null): Promise<void> =>
      cloudRequest(`/assessments/${assessmentId}/project`, {
        method: 'PUT',
        body: JSON.stringify({ project_id: projectId }),
      }),
  },

  // ===========================================================================
  // FINDINGS
  // ===========================================================================

  findings: {
    /** List findings with filtering */
    list: (params?: FindingsFilter & { page?: number; limit?: number; sort?: string; snapshot_id?: string }): Promise<PaginatedResult<Finding>> =>
      route(
        () => localApi.findings.list(params),
        () => cloudRequest(`/findings${buildQuery(params as Record<string, unknown>)}`),
      ),

    /** Get a single finding */
    get: (id: string): Promise<Finding> =>
      route(
        () => localApi.findings.get(id),
        () => cloudRequest(`/findings/${id}`),
      ),

    /** Create a new finding */
    create: (data: CreateFindingParams): Promise<Finding> =>
      route(
        () => localApi.findings.create(data as unknown as Record<string, unknown>),
        () => cloudRequest('/findings', { method: 'POST', body: JSON.stringify(data) }),
      ),

    /** Update a finding. `attest` (migration 0036) is a tri-state toggle:
     *  true → human-attest, false → un-attest, omitted → unchanged. */
    update: (id: string, data: Partial<Finding> & { attest?: boolean }): Promise<Finding> =>
      route(
        // The local command returns unit; re-read so callers still get the
        // updated row and the two branches stay interchangeable.
        async () => {
          await localApi.findings.update(id, data as Record<string, unknown>);
          return localApi.findings.get(id);
        },
        () => cloudRequest(`/findings/${id}`, { method: 'PATCH', body: JSON.stringify(data) }),
      ),

    /** Bulk triage (workbench action bar). Migration 0036. Returns updated count. */
    bulkUpdate: (body: {
      ids: string[];
      status?: string;
      assigned_to?: string;
      add_tags?: string[];
      remove_tags?: string[];
      attest?: boolean;
    }): Promise<{ updated: number }> =>
      route(
        // No local bulk command. Sequential rather than concurrent: these are
        // writes to one SQLite file, and the connection already sets a busy
        // timeout for the MCP server — piling on parallel writers invites
        // SQLITE_BUSY for no gain at local scale.
        async () => {
          const { ids, ...fields } = body;
          for (const id of ids) {
            await localApi.findings.update(id, fields as Record<string, unknown>);
          }
          return { updated: ids.length };
        },
        () => cloudRequest('/findings/bulk', { method: 'PATCH', body: JSON.stringify(body) }),
      ),

    /** Finding comments / activity (migration 0036). */
    comments: {
      // Comments are a collaboration feature with no local table. Reads return
      // empty (the panel renders its own empty state); writes throw, because a
      // silently-discarded comment is worse than a visible refusal.
      list: (findingId: string): Promise<import('./types').FindingComment[]> =>
        route(
          () => localApi.findings.comments.list(),
          () => cloudRequestOrDefault(`/findings/${findingId}/comments`, [] as import('./types').FindingComment[]),
        ),
      create: (findingId: string, body: string): Promise<import('./types').FindingComment> =>
        route(
          () => localApi.findings.comments.create() as Promise<import('./types').FindingComment>,
          () => cloudRequest(`/findings/${findingId}/comments`, { method: 'POST', body: JSON.stringify({ body }) }),
        ),
    },

    /** Delete a finding */
    delete: (id: string): Promise<void> =>
      route(
        () => localApi.findings.delete(id),
        () => cloudRequest(`/findings/${id}`, { method: 'DELETE' }),
      ),

    /** Create a Jira ticket for a finding. Stays local-routed: the user's
     *  personal Jira API token lives in their keychain (per-user secret,
     *  never sent to cloud). Once Integrations config is split into
     *  org-shared (project key, URL) cloud + per-user (token) local, this
     *  path keeps using the local invoke for the auth side. */
    createJiraTicket: (id: string, params: Omit<CreateJiraTicketParams, 'finding_id'>): Promise<CreateJiraTicketResult> =>
      isTauri()
        ? invoke('create_jira_ticket', { finding_id: id, ...params })
        : httpRequest(`/api/findings/${id}/jira`, {
            method: 'POST',
            body: JSON.stringify(params),
          }),

    /** Get finding statistics */
    stats: (category?: string, target?: string, search?: string, exploitable?: string, project_id?: string, scan_only?: string): Promise<FindingsStats> => {
      const params = new URLSearchParams();
      if (category) params.set('category', category);
      if (target) params.set('target', target);
      if (search) params.set('search', search);
      if (exploitable) params.set('exploitable', exploitable);
      if (project_id) params.set('project_id', project_id);
      // 'true' → scope all tiles to scheduled-DAST findings only. Migration 0035.
      if (scan_only) params.set('scan_only', scan_only);
      const qs = params.toString();
      return route(
        // scan_only scopes to scheduled-DAST findings, which local mode has no
        // table for — the filter is simply inapplicable rather than ignored.
        () => localApi.findings.stats(category, target, search, exploitable, project_id),
        () => cloudRequest(`/findings/stats${qs ? `?${qs}` : ''}`),
      );
    },

    /** Coverage rollup (dashboard W3 heatmap): findings grouped by
     *  (category, surface) with count + worst severity per cell. */
    coverage: (): Promise<CoverageCell[]> =>
      cloudRequestOrDefault('/findings/coverage', [] as CoverageCell[]),

    /** Export findings */
    export: (format: 'json' | 'csv' | 'markdown', filter?: FindingsFilter): Promise<string> =>
      route(
        () => localApi.findings.export(format, filter as { severity?: string; status?: string } | undefined),
        () => cloudRequest(`/findings/export?format=${format}${filter ? `&${new URLSearchParams(filter as Record<string, string>).toString()}` : ''}`),
      ),

    /** Create a scan snapshot for an assessment */
    createSnapshot: (assessmentId: string): Promise<ScanSnapshot> =>
      route(
        () => localApi.findings.createSnapshot(assessmentId),
        () => cloudRequest('/scan-snapshots', { method: 'POST', body: JSON.stringify({ assessment_id: assessmentId }) }),
      ),

    /** List scan history (snapshots) — returns [] if backend doesn't yet
     *  expose /scan-snapshots. */
    scanHistory: (target?: string): Promise<ScanSnapshot[]> =>
      route(
        () => localApi.findings.scanHistory(target),
        () => cloudRequestOrDefault(
          `/scan-snapshots${target ? `?target=${encodeURIComponent(target)}` : ''}`,
          [] as ScanSnapshot[],
        ),
      ),
  },

  // ===========================================================================
  // TARGETS — canonical target identity (backend-rs/routes/targets.rs)
  // ===========================================================================

  targets: {
    /** List the org's targets (active by default). `source` filters by origin
     *  (the Scheduled DAST page passes 'dast' so it shows only targets added there). */
    list: (params?: {
      target_type?: string;
      include_archived?: boolean;
      source?: string;
      application_id?: string;
    }): Promise<Target[]> =>
      cloudRequestOrDefault(
        `/targets${buildQuery(params as Record<string, unknown>)}`,
        [] as Target[],
      ),

    /** Get a single target by id. */
    get: (id: string): Promise<Target> => cloudRequest(`/targets/${id}`),

    /** Canonicalize a raw target string and upsert into the targets table,
     *  returning the stable target row. `source` tags how it was created
     *  ('dast' from the Scheduled DAST Targets page). */
    resolve: (
      raw_value: string,
      target_type?: string,
      metadata?: Record<string, unknown>,
      source?: string,
    ): Promise<Target> =>
      cloudRequest('/targets/resolve', {
        method: 'POST',
        body: JSON.stringify({ raw_value, target_type, metadata, source }),
      }),

    /** Assign (or clear, with '') a target's application. Migration 0038. */
    update: (id: string, body: { application_id?: string }): Promise<Target> =>
      cloudRequest(`/targets/${id}`, { method: 'PATCH', body: JSON.stringify(body) }),

    /** Archive (soft-delete) a target — removes it from the active list. */
    archive: (id: string): Promise<void> =>
      cloudRequest(`/targets/${id}`, { method: 'DELETE' }),
  },

  // ===========================================================================
  // APPLICATIONS — grouping layer above targets (backend-rs/routes/applications.rs)
  // ===========================================================================

  applications: {
    list: (): Promise<import('./types').Application[]> =>
      cloudRequestOrDefault('/applications', [] as import('./types').Application[]),
    create: (body: {
      name: string;
      description?: string;
      team?: string;
      criticality?: string;
      environment?: string;
    }): Promise<import('./types').Application> =>
      cloudRequest('/applications', { method: 'POST', body: JSON.stringify(body) }),
    update: (
      id: string,
      body: Partial<{ name: string; description: string; team: string; criticality: string; environment: string }>,
    ): Promise<import('./types').Application> =>
      cloudRequest(`/applications/${id}`, { method: 'PATCH', body: JSON.stringify(body) }),
    remove: (id: string): Promise<void> =>
      cloudRequest(`/applications/${id}`, { method: 'DELETE' }),
  },

  // ===========================================================================
  // SCANS — continuous-DAST run history (backend-rs/routes/scans.rs)
  // ===========================================================================

  scans: {
    /** Scan history (newest first). Omit target_id for an org-wide history. */
    list: (params?: { target_id?: string; limit?: number }): Promise<Scan[]> =>
      cloudRequestOrDefault(
        `/scans${params ? buildQuery(params as Record<string, unknown>) : ''}`,
        [] as Scan[],
      ),

    /** new vs still-present vs fixed since the latest scan for a target. */
    diff: (params: { target_id: string }): Promise<ScanDiff> =>
      cloudRequestOrDefault(`/scans/diff${buildQuery(params as Record<string, unknown>)}`, {
        latest_scan_id: null,
        since: null,
        new: [],
        fixed: [],
        still_present_count: 0,
      } as ScanDiff),

    /** Record a scan run (per target). */
    record: (body: Record<string, unknown>): Promise<Scan> =>
      cloudRequest('/scans', { method: 'POST', body: JSON.stringify(body) }),

    /** Full findings (description + evidence) for a single run — the Scans-tab
     *  drill-down. GET /scans/:id/findings. */
    findings: (scanId: string): Promise<ScanFindingDetail[]> =>
      cloudRequestOrDefault(`/scans/${scanId}/findings`, [] as ScanFindingDetail[]),

    /** CI scan-now: make a target's schedule due immediately (WS5). */
    trigger: (body: { target_id: string; policy_id?: string; auth_mode?: string }): Promise<{ status: string; message: string }> =>
      cloudRequest('/scans/trigger', { method: 'POST', body: JSON.stringify(body) }),
  },

  // ===========================================================================
  // API KEYS — CI tokens (backend-rs/routes/api_keys.rs)
  // ===========================================================================

  apiKeys: {
    list: (): Promise<import('./types').ApiKey[]> =>
      cloudRequestOrDefault('/api-keys', [] as import('./types').ApiKey[]),
    mint: (name: string): Promise<import('./types').ApiKey> =>
      cloudRequest('/api-keys', { method: 'POST', body: JSON.stringify({ name }) }),
    revoke: (id: string): Promise<void> =>
      cloudRequest(`/api-keys/${id}`, { method: 'DELETE' }),
  },

  // ===========================================================================
  // REPORT SUBSCRIPTIONS — scheduled delivery (backend-rs/routes/report_subscriptions.rs)
  // ===========================================================================

  reportSubscriptions: {
    list: (): Promise<import('./types').ReportSubscription[]> =>
      cloudRequestOrDefault('/report-subscriptions', [] as import('./types').ReportSubscription[]),
    create: (body: { recipients: string[]; cadence?: string; application_id?: string; target_id?: string }): Promise<import('./types').ReportSubscription> =>
      cloudRequest('/report-subscriptions', { method: 'POST', body: JSON.stringify(body) }),
    update: (id: string, body: { recipients?: string[]; cadence?: string; enabled?: boolean }): Promise<import('./types').ReportSubscription> =>
      cloudRequest(`/report-subscriptions/${id}`, { method: 'PATCH', body: JSON.stringify(body) }),
    remove: (id: string): Promise<void> =>
      cloudRequest(`/report-subscriptions/${id}`, { method: 'DELETE' }),
  },

  // ===========================================================================
  // DAST SETTINGS — SLA thresholds + AI auto-escalate (org_settings, mig 0036).
  // Reads the FULL org-settings response via cloudRequest (the Tauri
  // get_org_settings command predates these fields).
  // ===========================================================================

  dastSettings: {
    get: (): Promise<import('./types').OrgCacheSettings> =>
      cloudRequest('/org-settings'),
    update: (body: import('./types').OrgCacheSettingsUpdate): Promise<import('./types').OrgCacheSettings> =>
      cloudRequest('/org-settings', { method: 'PUT', body: JSON.stringify(body) }),
  },

  // ===========================================================================
  // SCAN CONFIGS — per-target auth + scope for the DAST run
  // (backend-rs/routes/scan_configs.rs)
  // ===========================================================================

  scanConfigs: {
    /** The auth + scope config for a target (empty defaults when unset). */
    get: (params: { target_id: string }): Promise<ScanConfig> =>
      cloudRequestOrDefault(
        `/scan-configs${buildQuery(params as Record<string, unknown>)}`,
        { target_id: params.target_id, auth: {}, scope: {} } as ScanConfig,
      ),

    /** Upsert the auth + scope config for a target. */
    upsert: (body: { target_id: string; auth: unknown; scope: unknown }): Promise<ScanConfig> =>
      cloudRequest('/scan-configs', { method: 'POST', body: JSON.stringify(body) }),
  },

  // ===========================================================================
  // SCAN SCHEDULES — continuous-DAST cadence (backend-rs/routes/scan_schedules.rs)
  // ===========================================================================

  scanSchedules: {
    /** List the org's scan schedules. */
    list: (): Promise<ScanSchedule[]> =>
      cloudRequestOrDefault('/scan-schedules', [] as ScanSchedule[]),

    /** Upsert a schedule. Provide exactly one of target_id / application_id
     *  (application = fan out to all its targets). auth_mode 'authed'|'unauthed'. */
    upsert: (body: {
      target_id?: string;
      application_id?: string;
      auth_mode?: string;
      cadence: string;
      scan_type?: string;
      enabled?: boolean;
      next_run_at?: string;
      policy_id?: string;
      window_start?: string;
      window_end?: string;
      timezone?: string;
    }): Promise<ScanSchedule> =>
      cloudRequest('/scan-schedules', { method: 'POST', body: JSON.stringify(body) }),

    /** Remove a schedule. */
    remove: (id: string): Promise<void> =>
      cloudRequest(`/scan-schedules/${id}`, { method: 'DELETE' }),
  },

  // ===========================================================================
  // SCAN POLICIES — attack-library subsets (backend-rs/routes/scan_policies.rs)
  // ===========================================================================

  scanPolicies: {
    /** Built-in presets (builtin:*) + the org's custom policies. */
    list: (): Promise<import('./types').ScanPolicy[]> =>
      cloudRequestOrDefault('/scan-policies', [] as import('./types').ScanPolicy[]),
    create: (body: { name: string; description?: string; categories: string[]; test_ids: string[] }): Promise<import('./types').ScanPolicy> =>
      cloudRequest('/scan-policies', { method: 'POST', body: JSON.stringify(body) }),
    update: (id: string, body: { name: string; description?: string; categories: string[]; test_ids: string[] }): Promise<import('./types').ScanPolicy> =>
      cloudRequest(`/scan-policies/${id}`, { method: 'PATCH', body: JSON.stringify(body) }),
    remove: (id: string): Promise<void> =>
      cloudRequest(`/scan-policies/${id}`, { method: 'DELETE' }),
  },

  // ===========================================================================
  // CLOUD INVENTORY — reachability correlation (backend-rs/routes/cloud_inventory.rs)
  // ===========================================================================

  cloudInventory: {
    /** Deployed + reachable + vulnerable correlations (Coverage Dashboard W4).
     *  Read-only join of exposed cloud_assets × CVE findings × reachability.
     *  Omit target_id for an org-wide view. */
    correlations: (params?: { target_id?: string }): Promise<CloudCorrelation[]> =>
      cloudRequestOrDefault(
        `/cloud/inventory/correlations${
          params?.target_id ? buildQuery(params as Record<string, unknown>) : ''
        }`,
        [] as CloudCorrelation[],
      ),

    /** Persisted escalation / attack-path graphs (W5). Omit target_id for org-wide. */
    attackPaths: (params?: { target_id?: string }): Promise<PersistedAttackGraph[]> =>
      cloudRequestOrDefault(
        `/cloud/attack-paths${
          params?.target_id ? buildQuery(params as Record<string, unknown>) : ''
        }`,
        [] as PersistedAttackGraph[],
      ),
  },

  // ===========================================================================
  // ATTACK-GRAPH SUBSTRATE (/graph/*) — the persistent, accumulating node/edge
  // union behind the interactive explorer. Org-scoped via the cloud session.
  // ===========================================================================
  graph: {
    /** Kind registry: built-ins + this org's custom kinds (powers FE styling). */
    kinds: (): Promise<GraphKind[]> =>
      cloudRequestOrDefault('/graph/kinds', [] as GraphKind[]),

    /** Accumulated nodes, optionally filtered by kind / target / search text. */
    nodes: (params?: {
      kind?: string;
      target_id?: string;
      q?: string;
      limit?: number;
    }): Promise<GraphSubstrateNode[]> =>
      cloudRequestOrDefault(
        `/graph/nodes${buildQuery(params as Record<string, unknown>)}`,
        [] as GraphSubstrateNode[],
      ),

    /** Accumulated edges, optionally filtered by endpoint / exploited. */
    edges: (params?: {
      src_key?: string;
      dst_key?: string;
      exploited?: boolean;
      limit?: number;
    }): Promise<GraphSubstrateEdge[]> =>
      cloudRequestOrDefault(
        `/graph/edges${buildQuery(params as Record<string, unknown>)}`,
        [] as GraphSubstrateEdge[],
      ),

    /** Pathfinding / reachability over the union (recursive, cycle-guarded). */
    paths: (body: GraphPathsQuery): Promise<GraphPathsResponse> =>
      cloudRequest('/graph/paths', { method: 'POST', body: JSON.stringify(body) }),

    /** Org-wide footholds (post-exploit), for the "paths from footholds" lens.
     *  Each foothold's node_key (when set) maps to a graph node. */
    footholds: (): Promise<Foothold[]> =>
      cloudRequestOrDefault('/footholds', [] as Foothold[]),
  },

  // ===========================================================================
  // REPORTS
  // ===========================================================================

  reports: {
    /** List all reports */
    list: (params?: { page?: number; limit?: number }): Promise<PaginatedResult<Report>> =>
      route(
        () => localApi.reports.list(params as Record<string, unknown> | undefined),
        () => cloudRequest(`/reports${buildQuery(params as Record<string, unknown>)}`),
      ),

    /** Get a single report */
    get: (id: string): Promise<Report> =>
      route(
        () => localApi.reports.get(id),
        () => cloudRequest(`/reports/${id}`),
      ),

    /** Generate a new report */
    generate: (params: GenerateReportParams): Promise<GenerateReportResult> =>
      cloudRequest('/reports', { method: 'POST', body: JSON.stringify(params) }),

    /** Download report URL — used for href attributes. The cloud backend
     *  serves the file behind the auth-required download endpoint. */
    download: (id: string, format: ReportFormat): string => {
      const bootstrapRaw = typeof window !== 'undefined' ? localStorage.getItem('maestro-bootstrap') : null;
      const bootstrap = bootstrapRaw ? JSON.parse(bootstrapRaw) : null;
      const base = bootstrap?.backendUrl?.replace(/\/+$/, '') || API_BASE_URL;
      return `${base}/api/v1/reports/${id}/download?format=${format}`;
    },

    /** Export report (async) — returns the cloud download URL */
    exportFile: (id: string, format: ReportFormat): Promise<string> =>
      cloudRequest<{ url: string }>(`/reports/${id}/download?format=${format}`).then((r) => r.url),

    /** Local report files on disk (reports/ directory). Authenticated users
     *  always read from cloud — this is empty for them. Kept on disk only so
     *  the host-side MCP server can write PDFs to a known path. */
    listFiles: async (): Promise<ReportFile[]> => [],

    /** Read a local report file's content. Cloud users read via /reports/{id};
     *  this only stays for legacy callers and returns empty in authenticated
     *  mode. */
    readFile: async (_filePath: string): Promise<string> => '',

    /** Generate a PDF from markdown via the local MCP server (Playwright
     *  inside the Kali container). Stays local-routed because the
     *  rendering pipeline lives in the user's container, not the cloud
     *  backend. The MCP tool itself persists a Report row to the cloud
     *  via the cloud-session bridge after writing the PDF, so the cloud
     *  reflects the new report alongside the local file. */
    generatePdf: (params: {
      markdown_content: string;
      title?: string;
      output_filename?: string;
    }): Promise<{ path?: string }> =>
      isTauri()
        ? invoke('generate_pdf_report', { params })
        : Promise.reject(new Error('PDF generation requires the desktop app')),

    /** Fetch a short-lived presigned URL for a report artifact.
     *  `disposition: 'inline'` → S3 serves with Content-Disposition: inline,
     *  suitable for an iframe src. `'attachment'` → Content-Disposition:
     *  attachment, suitable for a download click. The backend gates on
     *  org membership; the URL itself is what the webview/browser
     *  actually follows so it works without an auth header. */
    artifactUrl: (
      id: string,
      disposition: 'inline' | 'attachment' = 'inline',
    ): Promise<string> =>
      cloudRequest<{ url: string }>(
        `/reports/${id}/artifact-url?disposition=${disposition}`,
      ).then((r) => r.url),

    /** Download a cloud report to disk. v1.0.12 tried to fetch the
     *  bytes into a blob and click `<a download href="blob:...">`,
     *  which is the standard browser pattern — but on macOS in wry
     *  0.53 / Tauri 2.9 the webview surfaces the Downloads-folder
     *  TCC prompt and then never actually writes the file even after
     *  the user grants permission. We do the GET in Rust instead:
     *  `download_url_to_downloads` fetches the bytes with `reqwest`
     *  and `std::fs::write`s them to `~/Downloads/<filename>`, which
     *  blocks until TCC resolves and just works. Returns the saved
     *  path so we can surface it in the toast. */
    downloadToDisk: async (
      id: string,
      format: ReportFormat,
      filename: string,
      hasArtifact: boolean = false,
    ): Promise<string> => {
      if (hasArtifact && format === 'pdf') {
        const url = await api.reports.artifactUrl(id, 'attachment');
        return invoke<string>('download_url_to_downloads', {
          url,
          filename,
          authHeader: null,
        });
      }
      // Legacy path — backend re-renders markdown / pre-S3 PDFs and
      // streams the bytes back; needs a Cognito bearer.
      const bootstrapRaw = localStorage.getItem('maestro-bootstrap');
      const bootstrap = bootstrapRaw ? JSON.parse(bootstrapRaw) : null;
      const backendUrl: string | undefined = bootstrap?.backendUrl;
      if (!backendUrl) {
        throw new ApiError(401, 'No cloud backend configured');
      }
      const idToken = await getValidIdToken();
      if (!idToken) {
        void notifyCloudSessionExpired();
        throw new ApiError(401, 'Cloud session expired. Please log in again.');
      }
      const url = `${backendUrl.replace(/\/+$/, '')}/api/v1/reports/${id}/download?format=${format}`;
      return invoke<string>('download_url_to_downloads', {
        url,
        filename,
        authHeader: `Bearer ${idToken}`,
      });
    },

    /** Legacy no-op kept for callers that still expect a `.openFile`
     *  method on the reports API. Cloud reports render inline via
     *  artifactUrl() + iframe; there is no host-disk path to open
     *  in production. Web mode users hit this same no-op. */
    openFile: async (_filePath: string): Promise<void> => {
      // Intentional no-op. Cloud-only architecture — there is no
      // local file to open.
    },
  },

  // ===========================================================================
  // CONFIGURATION
  // ===========================================================================

  config: {
    // Org-shared configs route through `/api/v1/configs/{kind}`. Backend
    // stores opaque JSONB; shape validation lives here on the desktop side.
    // The cloud unwraps `{kind, value, ...}` so we map to the typed shape.
    // Empty `value` means the org hasn't saved yet — components fall back
    // to defaults.
    scope: {
      // First-load returns { value: {} } from the backend (no row yet).
      // Components expect typed arrays — provide a well-shaped empty default
      // so first-paint doesn't crash trying to .map() over undefined fields.
      get: async (): Promise<ScopeConfig> => {
        const r = await cloudRequest<{ value: Partial<ScopeConfig> }>('/configs/scope');
        const merged: ScopeConfig = {
          networks: r.value?.networks ?? [],
          domains: r.value?.domains ?? [],
          exclusions: r.value?.exclusions ?? [],
          apps: r.value?.apps,
          cloud_accounts: r.value?.cloud_accounts ?? [],
          kubernetes: r.value?.kubernetes ?? [],
          identity_targets: r.value?.identity_targets ?? [],
        };
        // Mirror to a host file the container's bind builder reads —
        // keeps the container's read view in sync with the cloud scope.
        void persistMergedScope(merged);
        return merged;
      },

      update: async (config: ScopeConfig): Promise<ScopeConfig> => {
        const r = await cloudRequest<{ value: ScopeConfig }>('/configs/scope', {
          method: 'PUT',
          body: JSON.stringify({ value: config }),
        });
        // Refresh the host-file mirror immediately so the next container
        // start picks up the new scope without needing a fresh get.
        void persistMergedScope(r.value);
        return r.value;
      },

      validate: (target: string): Promise<{ valid: boolean; reason?: string; environment?: string }> =>
        api.system.validateScope(target),

      // Pre-flight check before launching a cloud assessment. Verifies the
      // chosen account/regions/services match what's configured in scope.
      // Returns ok=false on hard errors (account not found); soft mismatches
      // (region/service not in configured list) come back as warnings the
      // wizard can surface before the user commits to launch.
      validateCloud: async (
        accountId: string,
        regions: string[],
        services: string[],
      ): Promise<import('./types').CloudScopeValidation> => {
        if (!isTauri()) {
          // Web-only mode has no local Tauri command — return a permissive
          // pass so the wizard doesn't block. Real validation happens at
          // assessment-runtime in the MCP server's scope guard.
          return { ok: true, warnings: [], errors: [] };
        }
        return await invoke<import('./types').CloudScopeValidation>('validate_cloud_scope', {
          accountId,
          regions,
          services,
        });
      },

      // Save-time credential probe: runs a non-mutating call against the
      // cloud the user just configured, to confirm the credential
      // actually resolves before we persist the account. Returns
      // {ok, identity, details, error} — see CloudAccountValidationResult.
      validateAccountCredential: async (
        account: import('./types').CloudAccountScope,
        sourceCredentialId?: string,
      ): Promise<CloudAccountValidationResult> => {
        if (!isTauri()) {
          return {
            ok: false,
            identity: '',
            details: '',
            error:
              'Credential validation requires the desktop app — the probe shells out to cloud CLIs in the Kali container.',
          };
        }
        return await invoke<CloudAccountValidationResult>('validate_cloud_account', {
          account,
          sourceCredentialId: sourceCredentialId ?? null,
        });
      },

      // Save-time identity-target probe: runs a non-mutating call against
      // the IDP (Okta /users, GWS admin SDK, Entra Graph, …) to confirm
      // the credential resolves before persisting. Mirrors
      // validateAccountCredential — see IdentityTargetValidationResult.
      validateIdentityTarget: async (
        target: import('./types').IdentityTarget,
      ): Promise<IdentityTargetValidationResult> => {
        if (!isTauri()) {
          return {
            ok: false,
            identity: '',
            details: '',
            error:
              'Identity validation requires the desktop app — the probe shells out to IDP CLIs/APIs in the Kali container.',
          };
        }
        return await invoke<IdentityTargetValidationResult>('validate_identity_target', {
          target,
        });
      },

      // Save-time AI-target structural validation (validate_ai_target in the Rust
      // backend) — confirms the kind's required fields (endpoint, credential_ref,
      // declared_tools for agents) before persisting. No live probe; mirrors
      // validateIdentityTarget. See AiTargetValidationResult.
      validateAiTarget: async (
        target: import('./types').AiTarget,
      ): Promise<AiTargetValidationResult> => {
        if (!isTauri()) {
          return {
            ok: false,
            identity: '',
            details: '',
            error:
              'AI target validation requires the desktop app — the live endpoint probe runs in the Kali container.',
          };
        }
        return await invoke<AiTargetValidationResult>('validate_ai_target', {
          target,
        });
      },

      // -----------------------------------------------------------------
      // AWS SSO sign-in wizard
      // -----------------------------------------------------------------
      //
      // When the AssumeRole probe fails with "Unable to locate
      // credentials," the Add Cloud Account dialog switches into a
      // setup-credentials state. The user picks how they want Maestro
      // to authenticate before assuming the role, and we cache the
      // resolved source credentials in the macOS keyring at the
      // `aws_source` blob (see `secrets.rs`).
      //
      // The SSO path uses AWS's OIDC device-code flow:
      //   1. startAwsSsoDeviceAuth(startUrl, region) returns a code
      //      + verification URL the user opens in a browser
      //   2. pollAwsSsoDeviceAuth(session) is called on a ~5s timer
      //      until the user has approved
      //   3. listAwsSsoAccounts / listAwsSsoAccountRoles let the wizard
      //      discover what the user can reach; usually we auto-pick
      //      the same account as the target Role ARN
      //   4. The wizard writes the resolved access token + source
      //      (account, role) pair into `aws_source` via setAwsSourceCreds
      startAwsSsoDeviceAuth: async (
        startUrl: string,
        region: string,
      ): Promise<AwsSsoDeviceAuthSession> => {
        if (!isTauri()) throw new Error('AWS SSO sign-in requires the desktop app');
        return await invoke<AwsSsoDeviceAuthSession>('aws_sso_start_device_auth', {
          startUrl,
          region,
        });
      },

      pollAwsSsoDeviceAuth: async (
        session: AwsSsoDeviceAuthSession,
      ): Promise<AwsSsoPollResult> => {
        if (!isTauri()) throw new Error('AWS SSO sign-in requires the desktop app');
        return await invoke<AwsSsoPollResult>('aws_sso_poll_device_auth', { session });
      },

      listAwsSsoAccounts: async (
        accessToken: string,
        region: string,
      ): Promise<AwsSsoAccount[]> => {
        if (!isTauri()) throw new Error('AWS SSO sign-in requires the desktop app');
        return await invoke<AwsSsoAccount[]>('aws_sso_list_accounts', {
          accessToken,
          region,
        });
      },

      listAwsSsoAccountRoles: async (
        accessToken: string,
        region: string,
        accountId: string,
      ): Promise<AwsSsoAccountRole[]> => {
        if (!isTauri()) throw new Error('AWS SSO sign-in requires the desktop app');
        return await invoke<AwsSsoAccountRole[]>('aws_sso_list_account_roles', {
          accessToken,
          region,
          accountId,
        });
      },

      // Cache the resolved source credentials in the keyring. Frontend
      // builds the right shape for `kind` (sso / access_keys / profile)
      // and ships the whole blob; the backend probe reads it on the
      // next AssumeRole verify.
      setAwsSourceCredentials: async (blob: AwsSourceCredentialsBlob): Promise<void> => {
        if (!isTauri()) throw new Error('AWS source credentials require the desktop app');
        return await invoke('set_secret_blob', { kind: 'aws_source', value: blob });
      },

      clearAwsSourceCredentials: async (): Promise<void> => {
        if (!isTauri()) return;
        return await invoke('clear_secret_blob', { kind: 'aws_source' });
      },

      // Read the currently cached source credential (if any) so the UI
      // can show what identity Maestro will assume roles FROM. Returns
      // null when nothing has been set up yet (fresh install / never ran
      // the wizard) — the keyring returns an empty `{}` in that case,
      // which has no `kind` discriminant.
      getAwsSourceCredentials: async (): Promise<AwsSourceCredentialsBlob | null> => {
        if (!isTauri()) return null;
        try {
          const r = await invoke<{ value: AwsSourceCredentialsBlob | Record<string, never> | null }>(
            'get_secret_blob',
            { kind: 'aws_source' },
          );
          const v = r?.value;
          if (!v || typeof v !== 'object' || !('kind' in v)) return null;
          return v as AwsSourceCredentialsBlob;
        } catch {
          return null;
        }
      },

      // -----------------------------------------------------------------
      // AWS source-credential LIBRARY (multiple named identities)
      // -----------------------------------------------------------------
      //
      // Stored in the `aws_sources` keyring blob. A deployment can hold
      // several assume-from identities and pick one per assessment (a
      // default, overridable at launch). Helpers below read-modify-write
      // the whole blob — the keyring API is replace-only.

      // List the library. Migrates a legacy single `aws_source` blob into
      // the collection (as "Default") on first read so existing installs
      // light up without losing their configured source.
      listAwsSources: async (): Promise<AwsSourcesLibrary> => {
        if (!isTauri()) return { default_id: null, sources: [] };
        try {
          const r = await invoke<{ value: Partial<AwsSourcesLibrary> | Record<string, never> | null }>(
            'get_secret_blob',
            { kind: 'aws_sources' },
          );
          const v = r?.value;
          if (v && typeof v === 'object' && Array.isArray((v as AwsSourcesLibrary).sources)) {
            const lib = v as AwsSourcesLibrary;
            return { default_id: lib.default_id ?? null, sources: lib.sources };
          }
        } catch {
          /* fall through to migration */
        }
        // Migration from the legacy single-source slot.
        const legacy = await api.config.scope.getAwsSourceCredentials();
        if (legacy) {
          const entry = { id: 'default', name: 'Default', ...legacy } as AwsSourceEntry;
          const lib: AwsSourcesLibrary = { default_id: 'default', sources: [entry] };
          try {
            await invoke('set_secret_blob', { kind: 'aws_sources', value: lib });
            await invoke('clear_secret_blob', { kind: 'aws_source' });
          } catch {
            /* best-effort migration */
          }
          return lib;
        }
        return { default_id: null, sources: [] };
      },

      // Append a named source. The first one added becomes the default.
      addAwsSource: async (name: string, blob: AwsSourceCredentialsBlob): Promise<string> => {
        if (!isTauri()) throw new Error('Source credentials require the desktop app');
        const lib = await api.config.scope.listAwsSources();
        const rand =
          (globalThis.crypto as Crypto | undefined)?.randomUUID?.() ?? String(Date.now());
        const id = `src_${rand}`;
        const entry = { id, name, ...blob } as AwsSourceEntry;
        const sources = [...lib.sources, entry];
        const default_id = lib.default_id ?? id;
        await invoke('set_secret_blob', {
          kind: 'aws_sources',
          value: { default_id, sources } satisfies AwsSourcesLibrary,
        });
        return id;
      },

      deleteAwsSource: async (id: string): Promise<void> => {
        if (!isTauri()) return;
        const lib = await api.config.scope.listAwsSources();
        const sources = lib.sources.filter((s) => s.id !== id);
        const default_id = lib.default_id === id ? (sources[0]?.id ?? null) : lib.default_id;
        await invoke('set_secret_blob', {
          kind: 'aws_sources',
          value: { default_id, sources } satisfies AwsSourcesLibrary,
        });
      },

      setDefaultAwsSource: async (id: string): Promise<void> => {
        if (!isTauri()) return;
        const lib = await api.config.scope.listAwsSources();
        await invoke('set_secret_blob', {
          kind: 'aws_sources',
          value: { default_id: id, sources: lib.sources } satisfies AwsSourcesLibrary,
        });
      },

      // Replace an existing source's name + credential payload in place,
      // preserving its id and default status. Used by the Edit dialog (so
      // fixing e.g. a profile-name typo doesn't require delete + re-add).
      updateAwsSource: async (
        id: string,
        name: string,
        blob: AwsSourceCredentialsBlob,
      ): Promise<void> => {
        if (!isTauri()) return;
        const lib = await api.config.scope.listAwsSources();
        const sources = lib.sources.map((s) =>
          s.id === id ? ({ id, name, ...blob } as AwsSourceEntry) : s,
        );
        await invoke('set_secret_blob', {
          kind: 'aws_sources',
          value: { default_id: lib.default_id, sources } satisfies AwsSourcesLibrary,
        });
      },

      // -----------------------------------------------------------------
      // Assessment-time assume-role injection (Layer 3)
      // -----------------------------------------------------------------
      // Resolve the chosen source, assume the account's role, and install
      // the session into the running Kali container so the assessment
      // authenticates as that identity. Spawns a background refresher.
      startCloudAssessmentCredentials: async (
        account: import('./types').CloudAccountScope,
        sourceCredentialId?: string,
        useBackend?: boolean,
        useFederation?: boolean,
        operatorLabel?: string,
      ): Promise<CloudSessionResult> => {
        if (!isTauri()) {
          return {
            ok: false,
            identity: '',
            expiration: '',
            error: 'Cloud assessment credentials require the desktop app.',
          };
        }
        return await invoke<CloudSessionResult>('start_cloud_assessment_credentials', {
          account,
          sourceCredentialId: sourceCredentialId ?? null,
          useBackend: useBackend ?? false,
          useFederation: useFederation ?? false,
          operatorLabel: operatorLabel ?? null,
        });
      },

      stopCloudAssessmentCredentials: async (accountId: string): Promise<void> => {
        if (!isTauri()) return;
        return await invoke('stop_cloud_assessment_credentials', { accountId });
      },
    },

    // Credentials hold target-app login info for assessments (URLs, auth
    // types, plus the secrets needed to actually log in). Storage is split:
    // org-shared metadata (name, base_url, auth_type, login_url, etc.) lives
    // in cloud `org_configs` so teammates inherit the app catalog; per-user
    // secrets (username, password, token, client_secret) live in the OS
    // keychain via `set_secret_blob` and never leave the user's machine.
    // Both halves merge into the same `CredentialsConfig` shape so existing
    // UI components don't need to change.
    credentials: {
      get: async (): Promise<CredentialsConfig> => {
        const [shared, secrets] = await Promise.all([
          cloudRequest<{ value: Partial<CredentialsConfig> | Record<string, never> }>('/configs/credentials')
            .then((r) => r.value as Partial<CredentialsConfig>)
            .catch(() => ({} as Partial<CredentialsConfig>)),
          isTauri()
            ? invoke<{ value: Record<string, Record<string, string>> }>('get_secret_blob', { kind: 'credentials' })
                .then((r) => r.value || {})
                .catch(() => ({} as Record<string, Record<string, string>>))
            : Promise.resolve({} as Record<string, Record<string, string>>),
        ]);
        const merged = mergeCredentials(shared, secrets);
        // Mirror the merged tree to the host file the in-container MCP
        // reads — keeps the assessment runtime in sync with what the user
        // sees in the desktop UI without requiring a save.
        void persistMergedCredentials(merged);
        return merged;
      },

      update: async (config: CredentialsConfig): Promise<CredentialsConfig> => {
        const { shared, secrets } = splitCredentials(config);
        await Promise.all([
          cloudRequest<{ value: Partial<CredentialsConfig> }>('/configs/credentials', {
            method: 'PUT',
            body: JSON.stringify({ value: shared }),
          }),
          isTauri()
            ? invoke('set_secret_blob', { kind: 'credentials', value: secrets })
            : Promise.resolve(),
        ]);
        // Refresh the host-file mirror immediately so the next assessment
        // run picks up the change without needing a re-read on the get path.
        void persistMergedCredentials(config);
        return config;
      },

      // Connection-testing is now driven by `validate_cloud_account` (see
      // commands::cloud_validation::validate_cloud_account in the Rust
      // backend). The previous `test_credential_connection` Tauri command
      // was never registered, so this wrapper was always broken in desktop
      // mode and has been removed.
    },

    // Identity-provider (IDP) credential helpers. Secrets never go inline
    // in scope.yml — an IdentityTarget references them by credential_ref /
    // sa_key_ref into credentials.yml `identity_credentials`. The one
    // exception is a service-account key, which is written to a file in
    // the Kali container by the Rust side (so it never sits in the config
    // store); this helper returns that container path so the caller can
    // persist it as `{ kind: 'sa_json', path }`.
    identity: {
      saveSaKey: async (credRef: string, keyJson: string): Promise<string> => {
        if (!isTauri()) {
          throw new Error(
            'Saving a service-account key requires the desktop app — it writes the key into the Kali container.',
          );
        }
        // Tauri maps camelCase JS args → snake_case Rust params
        // (credRef → cred_ref, keyJson → key_json).
        return await invoke<string>('save_identity_sa_key', {
          credRef,
          keyJson,
        });
      },
    },

    tools: {
      get: (): Promise<ToolsConfig> =>
        cloudRequest<{ value: ToolsConfig | Record<string, never> }>('/configs/tools').then(
          (r) => (r.value as ToolsConfig) ?? ({} as ToolsConfig),
        ),

      update: (config: ToolsConfig): Promise<ToolsConfig> =>
        cloudRequest<{ value: ToolsConfig }>('/configs/tools', {
          method: 'PUT',
          body: JSON.stringify({ value: config }),
        }).then((r) => r.value),
    },

    agents: {
      get: (): Promise<AgentsConfig> =>
        cloudRequest<{ value: AgentsConfig | Record<string, never> }>('/configs/agents').then(
          (r) => (r.value as AgentsConfig) ?? ({} as AgentsConfig),
        ),

      update: (config: AgentsConfig): Promise<AgentsConfig> =>
        cloudRequest<{ value: AgentsConfig }>('/configs/agents', {
          method: 'PUT',
          body: JSON.stringify({ value: config }),
        }).then((r) => r.value),
    },

    cloud: {
      /** Get cloud sync configuration */
      get: (): Promise<CloudConfig> =>
        isTauri()
          ? invoke('get_cloud_config')
          : httpRequest('/api/config/cloud'),

      /** Save cloud sync configuration */
      update: (config: CloudConfig): Promise<void> =>
        isTauri()
          ? invoke('save_cloud_config_cmd', config)
          : httpRequest('/api/config/cloud', {
              method: 'PUT',
              body: JSON.stringify(config),
            }),

      /** Test connection to cloud backend */
      testConnection: (api_url: string): Promise<boolean> =>
        isTauri()
          ? invoke('test_cloud_connection', { api_url })
          : httpRequest('/api/config/cloud/test', {
              method: 'POST',
              body: JSON.stringify({ api_url }),
            }),

      /** Get available auth providers from backend */
      getAuthProviders: (api_url: string): Promise<CloudAuthProvidersResponse> =>
        isTauri()
          ? invoke('get_cloud_auth_providers', { api_url })
          : httpRequest('/api/config/cloud/providers', {
              method: 'POST',
              body: JSON.stringify({ api_url }),
            }),

      /** Get cloud status (connection, auth, sync) */
      getStatus: (): Promise<CloudStatus> =>
        isTauri()
          ? invoke('get_cloud_status')
          : httpRequest('/api/config/cloud/status'),

      /** Login with email and password */
      login: (email: string, password: string): Promise<CloudLoginResponse> =>
        isTauri()
          ? invoke('cloud_login', { email, password })
          : httpRequest('/api/config/cloud/login', {
              method: 'POST',
              body: JSON.stringify({ email, password }),
            }),

      /** Logout (clear tokens) */
      logout: (): Promise<void> =>
        isTauri()
          ? invoke('cloud_logout')
          : httpRequest('/api/config/cloud/logout', { method: 'POST' }),

      /** Sync data with cloud */
      sync: (): Promise<CloudSyncResponse> =>
        isTauri()
          ? invoke('sync_with_cloud')
          : httpRequest('/api/config/cloud/sync', { method: 'POST' }),

      /** Set tokens from external auth flow (Cognito/OIDC) */
      setTokens: (tokens: {
        access_token: string;
        token_type: string;
        expires_in: number;
        refresh_token?: string;
      }): Promise<void> =>
        isTauri()
          ? invoke('set_cloud_tokens', tokens)
          : httpRequest('/api/config/cloud/tokens', {
              method: 'POST',
              body: JSON.stringify(tokens),
            }),

      // -------------------------------------------------------------------
      // Multi-account management. The single-account commands above
      // implicitly target the active account, so existing call sites
      // (status, sync, login) keep working — these add CRUD + active
      // switching on top.
      // -------------------------------------------------------------------

      /** List all saved cloud accounts. */
      listAccounts: (): Promise<import('./types').CloudAccountSummary[]> =>
        isTauri()
          ? invoke('list_cloud_accounts')
          : httpRequest('/api/config/cloud/accounts'),

      /** Get a single account by id (for the edit page). */
      getAccount: (id: string): Promise<import('./types').CloudAccountResponse> =>
        isTauri()
          ? invoke('get_cloud_account', { id })
          : httpRequest(`/api/config/cloud/accounts/${id}`),

      /** Create a new account; returns the generated id. */
      addAccount: (input: import('./types').CloudAccountInput): Promise<string> =>
        isTauri()
          ? invoke('add_cloud_account', { input })
          : httpRequest('/api/config/cloud/accounts', {
              method: 'POST',
              body: JSON.stringify(input),
            }),

      /** Update an existing account in place. */
      updateAccount: (id: string, input: import('./types').CloudAccountInput): Promise<void> =>
        isTauri()
          ? invoke('update_cloud_account', { id, input })
          : httpRequest(`/api/config/cloud/accounts/${id}`, {
              method: 'PUT',
              body: JSON.stringify(input),
            }),

      /** Delete an account and its stored tokens. */
      removeAccount: (id: string): Promise<void> =>
        isTauri()
          ? invoke('remove_cloud_account', { id })
          : httpRequest(`/api/config/cloud/accounts/${id}`, { method: 'DELETE' }),

      /** Switch which account is active. Caller invalidates RQ + rewrites
       *  cloud-session.json after this returns (see setActiveCloudAccount
       *  wrapper). */
      setActive: (id: string): Promise<void> =>
        isTauri()
          ? invoke('set_active_cloud_account', { id })
          : httpRequest(`/api/config/cloud/accounts/${id}/activate`, { method: 'POST' }),

      /** Cache stats — per-assessment LLM cost + cache hit telemetry.
       *  Phase 0 of the caching plan (docs/caching-plan-2026-05-22.md).
       *  Returns null when no LLM activity has been recorded for the
       *  assessment yet (or cloud is disabled / not authenticated). */
      getCacheStats: (assessmentId: string): Promise<CacheStatsResponse | null> =>
        isTauri()
          ? invoke('get_cache_stats_for_assessment', { assessment_id: assessmentId })
          : httpRequest(`/api/cache-stats/${assessmentId}`),

      /** Record a token-usage delta against an assessment. The backend
       *  atomically adds these counts to the running totals for
       *  (org_id, assessment_id). Returns the updated row. */
      recordCacheStats: (delta: CacheStatsDelta): Promise<CacheStatsResponse> =>
        isTauri()
          ? invoke('record_cache_stats', { delta })
          : httpRequest('/api/cache-stats', {
              method: 'POST',
              body: JSON.stringify(delta),
            }),

      /** Fetch the baseline-aware findings response for a target.
       *  Returns null when cloud isn't authenticated. Used by the
       *  team lead at Phase 1.5 of an assessment + by the "Baseline
       *  reuse" panel in the desktop. */
      getBaselineFindings: (
        targetId: string,
        maxAgeDays?: number,
      ): Promise<BaselineResponse | null> =>
        isTauri()
          ? invoke('get_baseline_findings_for_target', {
              target_id: targetId,
              max_age_days: maxAgeDays ?? null,
            })
          : httpRequest(
              `/api/findings/baseline?target_id=${encodeURIComponent(targetId)}${
                maxAgeDays != null ? `&max_age_days=${maxAgeDays}` : ''
              }`,
            ),

      /** Read this org's cache configuration. */
      getOrgSettings: (): Promise<OrgCacheSettings> =>
        isTauri()
          ? invoke('get_org_settings')
          : httpRequest('/api/org-settings'),

      /** Partial-update this org's cache configuration. Omitted fields
       *  stay at their current value (backend uses COALESCE). */
      updateOrgSettings: (update: OrgCacheSettingsUpdate): Promise<OrgCacheSettings> =>
        isTauri()
          ? invoke('update_org_settings', { body: update })
          : httpRequest('/api/org-settings', {
              method: 'PUT',
              body: JSON.stringify(update),
            }),

      /** Rolling-30-day drift alerts summary. Drives the "needs review"
       *  badge + the auto-disable threshold check. */
      getDriftAlertsSummary: (): Promise<DriftAlertsSummary> =>
        isTauri()
          ? invoke('get_drift_alerts_summary')
          : httpRequest('/api/cache-drift-alerts/summary'),
    },

    integrations: {
      // Same split pattern as credentials — Jira project key + URL +
      // GitHub org are org-shared (cloud); Jira API token + GitHub PAT
      // stay in the OS keychain. Merged into IntegrationsConfig for the
      // UI; split on save.
      get: async (): Promise<IntegrationsConfig> => {
        const [shared, secrets] = await Promise.all([
          cloudRequest<{ value: Partial<IntegrationsConfig> | Record<string, never> }>('/configs/integrations')
            .then((r) => r.value as Partial<IntegrationsConfig>)
            .catch(() => ({} as Partial<IntegrationsConfig>)),
          isTauri()
            ? invoke<{ value: Record<string, Record<string, string>> }>('get_secret_blob', { kind: 'integrations' })
                .then((r) => r.value || {})
                .catch(() => ({} as Record<string, Record<string, string>>))
            : Promise.resolve({} as Record<string, Record<string, string>>),
        ]);
        return mergeIntegrations(shared, secrets);
      },

      update: async (config: IntegrationsConfig): Promise<IntegrationsConfig> => {
        const { shared, secrets } = splitIntegrations(config);
        await Promise.all([
          cloudRequest<{ value: Partial<IntegrationsConfig> }>('/configs/integrations', {
            method: 'PUT',
            body: JSON.stringify({ value: shared }),
          }),
          isTauri()
            ? invoke('set_secret_blob', { kind: 'integrations', value: secrets })
            : Promise.resolve(),
        ]);
        return config;
      },
    },
  },

  // ===========================================================================
  // JIRA
  // ===========================================================================

  jira: {
    /** Test Jira connection with explicit credentials (pre-save) */
    testConnection: (params: { url: string; email: string; api_token: string }): Promise<{ status: string; user?: string; error?: string }> =>
      httpRequest('/api/jira/test', {
        method: 'POST',
        body: JSON.stringify(params),
      }),

    /** List Jira projects using explicit credentials (pre-save) */
    listProjectsWithCredentials: (params: { url: string; email: string; api_token: string }): Promise<{ status: string; projects?: JiraProject[]; error?: string }> =>
      httpRequest('/api/jira/projects', {
        method: 'POST',
        body: JSON.stringify(params),
      }),

    /** List Jira projects using saved config */
    listProjects: (): Promise<{ status: string; projects?: JiraProject[]; error?: string }> =>
      httpRequest('/api/jira/projects'),

    /** List Jira boards, optionally filtered by project */
    listBoards: (projectKey?: string): Promise<{ status: string; boards?: JiraBoard[]; error?: string }> =>
      httpRequest(`/api/jira/boards${projectKey ? `?project=${encodeURIComponent(projectKey)}` : ''}`),

    /** List issue types for a project */
    listIssueTypes: (projectKey: string): Promise<{ status: string; issueTypes?: JiraIssueType[]; error?: string }> =>
      httpRequest(`/api/jira/issue-types/${encodeURIComponent(projectKey)}`),

    /** List open epics for a project */
    listEpics: (projectKey: string): Promise<{ status: string; epics?: JiraEpic[]; error?: string }> =>
      httpRequest(`/api/jira/epics/${encodeURIComponent(projectKey)}`),

    /** Search Jira issues by text within a project */
    searchIssues: (projectKey: string, query: string, options?: { issueType?: string; maxResults?: number }): Promise<{ status: string; results?: JiraSearchResult[]; error?: string }> => {
      const params = new URLSearchParams();
      if (query) params.set('q', query);
      if (options?.issueType) params.set('issueType', options.issueType);
      if (options?.maxResults) params.set('maxResults', String(options.maxResults));
      return httpRequest(`/api/jira/search/${encodeURIComponent(projectKey)}?${params.toString()}`);
    },

    /** Create ticket(s) from findings */
    createTickets: (request: CreateJiraTicketsRequest): Promise<CreateJiraTicketsResult> =>
      httpRequest('/api/jira/tickets', {
        method: 'POST',
        body: JSON.stringify(request),
      }),
  },

  // ===========================================================================
  // REPOSITORIES
  // ===========================================================================

  repositories: {
    /** List configured repositories. Cloud rows carry `default_path` —
     *  the creator's clone path, kept as a hint. We override with the
     *  current user's local clone path (from `repo-paths.json`) when one
     *  is set, so each teammate sees their own filesystem location. */
    list: async (): Promise<Repository[]> => {
      const [rows, localPaths] = await Promise.all([
        cloudRequestOrDefault('/repositories', [] as Repository[]),
        isTauri()
          ? invoke<Record<string, string>>('get_local_repo_paths').catch(() => ({} as Record<string, string>))
          : Promise.resolve({} as Record<string, string>),
      ]);
      return rows.map((r) => ({
        ...r,
        path: localPaths[r.id] ?? r.path,
      }));
    },

    /** Get a single repository by ID — same per-user path merge as list(). */
    get: async (id: string): Promise<Repository> => {
      const [r, localPaths] = await Promise.all([
        cloudRequest<Repository>(`/repositories/${id}`),
        isTauri()
          ? invoke<Record<string, string>>('get_local_repo_paths').catch(() => ({} as Record<string, string>))
          : Promise.resolve({} as Record<string, string>),
      ]);
      return { ...r, path: localPaths[r.id] ?? r.path };
    },

    /** Add a new repository — POST cloud, then save creator's local path
     *  to the per-user mapping so subsequent reads keep showing it. */
    add: async (params: AddRepositoryParams): Promise<Repository> => {
      const created = await cloudRequest<Repository>('/repositories', {
        method: 'POST',
        body: JSON.stringify(params),
      });
      if (isTauri() && params.path) {
        await invoke('set_local_repo_path', {
          repo_id: created.id,
          path: params.path,
        }).catch(() => { /* non-fatal; UI still has cloud path */ });
      }
      return { ...created, path: params.path ?? created.path };
    },

    /** Set or clear this user's local clone path for an already-existing
     *  cloud repo entry. Used by the "Locate clone" button when a teammate
     *  is opening a repo someone else originally added. */
    setLocalPath: async (repoId: string, path: string | null): Promise<void> => {
      if (!isTauri()) return;
      await invoke('set_local_repo_path', { repo_id: repoId, path });
    },

    /** Remove a repository */
    remove: (id: string): Promise<void> =>
      cloudRequest(`/repositories/${id}`, { method: 'DELETE' }),

    /** Update repository settings */
    update: (id: string, params: Partial<AddRepositoryParams>): Promise<Repository> =>
      cloudRequest(`/repositories/${id}`, { method: 'PATCH', body: JSON.stringify(params) }),

    /** Scan a repository for security issues */
    scan: (params: { id: string; scan_types?: string[] }): Promise<{ repository_id: string; findings_count: number; scan_duration_ms: number; findings: Array<{ rule_id: string; severity: string; message: string; file_path: string; line_start: number; line_end?: number; code_snippet?: string }> }> =>
      isTauri()
        ? invoke('scan_repository', { params })
        : httpRequest('/api/repositories/scan', {
            method: 'POST',
            body: JSON.stringify(params),
          }),

    // Removed: detectLanguages + browse. Both wrapped Tauri commands
    // (`detect_languages`, `browse_directory`) that were never registered
    // in invoke_handler!. No callers — see KNOWN_DEAD_WRAPPERS in the
    // tauri-bridge wiring test for the audit trail.
  },

  // ===========================================================================
  // IMPORTS (CSV/Cycode/etc.)
  // ===========================================================================

  imports: {
    /** Preview CSV content without saving */
    previewCsv: (csvContent: string): Promise<PreviewCsvResult> =>
      isTauri()
        ? invoke('preview_csv', { csv_content: csvContent })
        : httpRequest('/api/imports/preview', {
            method: 'POST',
            body: JSON.stringify({ csv_content: csvContent }),
          }),

    /** Import CSV and save to database */
    importCsv: (
      csvContent: string,
      options?: {
        name?: string;
        source?: string;
        filename?: string;
        selected_indices?: number[];
      }
    ): Promise<ImportCsvResult> =>
      cloudRequest('/imports', {
        method: 'POST',
        body: JSON.stringify({ csv_content: csvContent, ...options }),
      }),

    /** List all imports — returns [] if /imports isn't yet on the backend. */
    list: (params?: ListImportsParams): Promise<Import[]> =>
      cloudRequestOrDefault(
        `/imports${buildQuery(params as Record<string, unknown>)}`,
        [] as Import[],
      ),

    /** Get a single import by ID */
    get: (id: string): Promise<Import | null> =>
      cloudRequest(`/imports/${id}`),

    /** Delete an import and all its findings */
    delete: (id: string): Promise<void> =>
      cloudRequest(`/imports/${id}`, { method: 'DELETE' }),

    /** Get import statistics */
    getStats: (): Promise<ImportStats> =>
      cloudRequest('/imports/stats'),
  },

  importedFindings: {
    /** List imported findings — returns [] if /imported-findings isn't yet
     *  on the backend. */
    list: (params?: ListImportedFindingsParams): Promise<ImportedFinding[]> =>
      cloudRequestOrDefault(
        `/imported-findings${buildQuery(params as Record<string, unknown>)}`,
        [] as ImportedFinding[],
      ),

    /** Get a single imported finding */
    get: (id: string): Promise<ImportedFinding | null> =>
      cloudRequest(`/imported-findings/${id}`),

    /** Update imported finding status */
    updateStatus: (
      id: string,
      status: ImportedFinding['status'],
      linkedFindingId?: string,
      linkedAssessmentId?: string
    ): Promise<void> =>
      cloudRequest(`/imported-findings/${id}/status`, {
        method: 'PATCH',
        body: JSON.stringify({
          status,
          linked_finding_id: linkedFindingId,
          linked_assessment_id: linkedAssessmentId,
        }),
      }),

    /** Link imported findings to a repository */
    linkToRepository: (findingIds: string[], repositoryId: string): Promise<void> =>
      cloudRequest('/imported-findings/link-repository', {
        method: 'POST',
        body: JSON.stringify({ finding_ids: findingIds, repository_id: repositoryId }),
      }),

    /** Create validation assessment for imported findings */
    createValidationAssessment: (params: CreateValidationAssessmentParams): Promise<Assessment> =>
      cloudRequest('/imported-findings/validate', {
        method: 'POST',
        body: JSON.stringify(params),
      }),

    /** Get pending validation findings (shortcut) */
    getPending: (): Promise<ImportedFinding[]> =>
      cloudRequest('/imported-findings?status=imported'),
  },

  // Legacy alias for backwards compatibility
  cycode: {
    /** Import findings from Cycode CSV */
    importCsv: (csvContent: string): Promise<ImportCycodeFindingsResult> =>
      isTauri()
        ? invoke<ImportCsvResult>('import_csv', { csv_content: csvContent, source: 'cycode' }).then((r) => ({
            imported: r.imported_count,
            findings: [] as ImportedFinding[],
            errors: r.errors,
          }))
        : httpRequest('/api/imports', {
            method: 'POST',
            body: JSON.stringify({ csv_content: csvContent, source: 'cycode' }),
          }),

    /** Parse CSV for preview (doesn't save) */
    previewCsv: (csvContent: string): Promise<CycodeFinding[]> =>
      isTauri()
        ? invoke<PreviewCsvResult>('preview_csv', { csv_content: csvContent }).then((r) =>
            r.findings.map((f) => ({
              ...f,
              id: '',
              import_id: '',
              status: 'imported' as const,
              created_at: '',
              updated_at: '',
              severity: f.severity as Severity,
            }))
          )
        : httpRequest('/api/imports/preview', {
            method: 'POST',
            body: JSON.stringify({ csv_content: csvContent }),
          }),

    /** Get imported findings pending validation */
    getPendingValidation: (): Promise<CycodeFinding[]> =>
      isTauri()
        ? invoke('list_imported_findings', { params: { status: 'imported' } })
        : httpRequest('/api/imported-findings?status=imported'),

    /** Create validation assessment for imported findings */
    createValidationAssessment: (findingIds: string[], repoPath?: string): Promise<Assessment> =>
      isTauri()
        ? invoke('create_validation_assessment', { params: { finding_ids: findingIds, repository_id: repoPath } })
        : httpRequest('/api/imported-findings/validate', {
            method: 'POST',
            body: JSON.stringify({ finding_ids: findingIds, repository_id: repoPath }),
          }),
  },

  // ===========================================================================
  // AGENTS
  // ===========================================================================

  agents: {
    /** Run the full orchestrator */
    runOrchestrator: (params: RunOrchestratorParams): Promise<{ assessment_id: string }> =>
      isTauri()
        ? invoke('run_orchestrator', { params })
        : httpRequest('/api/agents/orchestrator', {
            method: 'POST',
            body: JSON.stringify(params),
          }),

    /** Run a specific agent */
    runAgent: (agent: AgentName, params: RunAgentParams): Promise<{ agent_id: string }> =>
      isTauri()
        ? invoke('run_agent', { agent, params })
        : httpRequest(`/api/agents/${agent}`, {
            method: 'POST',
            body: JSON.stringify(params),
          }),

    /** Get agent status */
    getStatus: (agentId: string): Promise<AgentState> =>
      isTauri()
        ? invoke('get_agent_status', { agent_id: agentId })
        : httpRequest(`/api/agents/status/${agentId}`),

    /** Cancel a running agent */
    cancel: (agentId: string): Promise<void> =>
      isTauri()
        ? invoke('cancel_agent', { agent_id: agentId })
        : httpRequest(`/api/agents/${agentId}`, { method: 'DELETE' }),

    /** List all running agents */
    listRunning: (): Promise<AgentState[]> =>
      isTauri()
        ? invoke('list_running_agents')
        : httpRequest('/api/agents/running'),
  },

  // ===========================================================================
  // DIRECT TOOL EXECUTION — REMOVED
  // ===========================================================================
  //
  // The `tools.*` wrappers here used to call `invoke('tool_<name>', ...)`
  // Tauri commands that wrapped MCP tool calls. The Rust intermediary was
  // never built, so every `isTauri()` branch threw "command not found" at
  // runtime. Components reach MCP tools directly via the autonomous-runner
  // HTTP server on :3001 instead. See KNOWN_DEAD_WRAPPERS in the
  // tauri-bridge wiring test for the full deletion audit trail.

  // ===========================================================================
  // INTERACTIVE PROMPTS + GUIDANCE — REMOVED
  // ===========================================================================
  //
  // The `prompts.*` and `guidance.*` wrappers called Tauri commands
  // (`get_pending_prompts`, `respond_to_prompt`, `get_pending_guidance`,
  // `respond_to_guidance`) that were never registered. No callers in any
  // component — the live OTP/guidance flow is driven by the assessment
  // chat's SSE stream from the cloud backend, not this in-process API.
  // See KNOWN_DEAD_WRAPPERS in the tauri-bridge wiring test.

  // ===========================================================================
  // AUDIT LOGS
  // ===========================================================================

  auditLogs: {
    /** List audit logs — returns empty paginated result if /audit-logs
     *  isn't yet exposed on the backend. */
    list: (params?: {
      tool?: string;
      target?: string;
      from?: string;
      to?: string;
      page?: number;
      limit?: number;
    }): Promise<PaginatedResult<AuditLog>> =>
      cloudRequestOrDefault(
        `/audit-logs${buildQuery(params as Record<string, unknown>)}`,
        { data: [], total: 0, page: 1, limit: params?.limit ?? 50, hasMore: false } as PaginatedResult<AuditLog>,
      ),
  },

  // ===========================================================================
  // DASHBOARD
  // ===========================================================================

  dashboard: {
    /** Get dashboard statistics — returns null sentinel if backend doesn't
     *  yet expose this aggregate endpoint (the dashboard primarily uses
     *  findings.stats and assessments.list, both of which already exist). */
    getStats: (): Promise<DashboardStats | null> =>
      cloudRequestOrDefault<DashboardStats | null>('/dashboard/stats', null),
  },

  // ===========================================================================
  // CONTEXT (Contextual Intelligence) + TEMPLATES — REMOVED
  // ===========================================================================
  //
  // The `context.*` and `templates.*` sections wrapped Tauri commands
  // (`get_target_context`, `get_finding_context`, `list_templates`,
  // `get_template`, `create_template`, `update_template`, `delete_template`,
  // `use_template`, `get_template_categories`) that were never registered
  // in invoke_handler!. No callers in any component — both features were
  // designed but never reached UI. See KNOWN_DEAD_WRAPPERS in the
  // tauri-bridge wiring test for the audit trail.
};

// =============================================================================
// UTILITY EXPORTS
// =============================================================================

export { isTauri, ApiError };
export type { PendingPrompt };
