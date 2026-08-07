/**
 * Comprehensive Type Definitions for Pentest Platform
 *
 * This file contains all TypeScript interfaces for:
 * - MCP Tool parameters and responses
 * - Frontend data models
 * - Tauri command contracts
 * - Configuration schemas
 */

// =============================================================================
// TERMINAL SESSION TYPES
// =============================================================================

export interface TerminalSession {
  id: string;
  assessment_id?: string;
  status: string;
  command: string;
  created_at: string;
  ended_at?: string;
  exit_code?: number;
  transcript?: string;
}

export interface SpawnTerminalParams {
  assessment_id?: string;
  assessment_type?: string;
  targets?: string[];
  initial_prompt?: string;
  cols?: number;
  rows?: number;
}

export interface SpawnTerminalResult {
  session_id: string;
  claude_available: boolean;
  working_dir: string;
  working_dir_container?: string;
  cli_command: string;
}

export interface TmuxSessionInfo {
  name: string;
  last_activity: string;
  is_attached: boolean;
}

// =============================================================================
// CORE ENUMS
// =============================================================================

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
// 'incomplete' = ran but never completed (went idle / archived while running
// without promoting deliverables) — neutral, not an error. Set by the backend
// reaper (migration 0042); distinct from 'failed' (a real error).
export type AssessmentStatus = 'not_started' | 'pending' | 'running' | 'completed' | 'failed' | 'incomplete' | 'cancelled' | 'paused';
export type FindingStatus = 'open' | 'in_progress' | 'remediated' | 'accepted' | 'false_positive';
export type AgentStatus = 'idle' | 'running' | 'completed' | 'failed' | 'cancelled';

export type AssessmentType =
  | 'full'
  | 'recon'
  | 'vuln_scan'
  | 'web_app'
  | 'api_security'
  | 'cloud_assessment'
  | 'combined'
  | 'code_scan'
  | 'exploit_validation'
  | 'cycode_validation'
  | 'custom';

export type AuthType =
  | 'none'
  | 'basic'
  | 'bearer'
  | 'api_key'
  | 'session'
  | 'oauth2'
  | 'otp_email';

/**
 * Active Claude credential mode. Replaces the old LLMProvider enum after
 * Ollama removal — the desktop only ever talks to Anthropic now, but the
 * *path* it takes (OAuth or BYO key) varies per user.
 */
export type ClaudeCredentialMode = 'oauth' | 'api_key';

/**
 * Active Codex credential mode — parallel of `ClaudeCredentialMode` for the
 * second brain. Same two modes; the difference is which CLI consumes them
 * (`codex` vs `claude`) and which env vars get injected at container exec.
 */
export type CodexCredentialMode = 'oauth' | 'api_key';

export type ReportFormat = 'markdown' | 'html' | 'pdf' | 'json';

// =============================================================================
// RECON TOOL TYPES
// =============================================================================

export interface ScanPortsParams {
  target: string;
  scan_type: 'quick' | 'full' | 'stealth' | 'udp';
  ports?: string; // e.g., "1-1000" or "22,80,443"
}

export interface ScanPortsResult {
  target: string;
  ports: Array<{
    port: number;
    state: 'open' | 'closed' | 'filtered';
    service?: string;
    version?: string;
  }>;
  scan_time: number;
}

export interface EnumerateSubdomainsParams {
  domain: string;
  passive_only?: boolean;
}

export interface EnumerateSubdomainsResult {
  domain: string;
  subdomains: string[];
  count: number;
}

export interface FingerprintServicesParams {
  target: string;
  ports?: string;
}

export interface FingerprintServicesResult {
  target: string;
  services: Array<{
    port: number;
    service: string;
    version: string;
    product?: string;
    extra_info?: string;
  }>;
}

export interface DiscoverHostsParams {
  cidr: string;
}

export interface DiscoverHostsResult {
  cidr: string;
  hosts: Array<{
    ip: string;
    hostname?: string;
    mac?: string;
    vendor?: string;
  }>;
  count: number;
}

export interface WebTechnologyScanParams {
  target: string;
}

export interface WebTechnologyScanResult {
  target: string;
  technologies: Array<{
    name: string;
    category: string;
    version?: string;
    confidence: number;
  }>;
  headers: Record<string, string>;
}

// =============================================================================
// VULNERABILITY SCANNING TOOL TYPES
// =============================================================================

export interface RunNucleiParams {
  target: string;
  templates?: string[];
  severity?: Severity[];
  rate_limit?: number;
  tags?: string[];
  exclude_tags?: string[];
}

export interface NucleiVulnerability {
  template_id: string;
  name: string;
  severity: Severity;
  matched_at: string;
  description?: string;
  reference?: string[];
  cve?: string;
  cwe?: string;
  extracted_results?: string[];
}

export interface RunNucleiResult {
  target: string;
  vulnerabilities: NucleiVulnerability[];
  templates_used: number;
  scan_time: number;
}

export interface RunNiktoParams {
  target: string;
  tuning?: string;
}

export interface RunNiktoResult {
  target: string;
  findings: Array<{
    id: string;
    method: string;
    uri: string;
    description: string;
    osvdb?: string;
  }>;
}

export interface RunWpscanParams {
  target: string;
  enumerate?: ('users' | 'plugins' | 'themes' | 'all')[];
  api_token?: string;
}

export interface RunWpscanResult {
  target: string;
  wordpress_version?: string;
  theme?: { name: string; version?: string };
  plugins: Array<{ name: string; version?: string; vulnerabilities?: string[] }>;
  users: Array<{ id: number; login: string }>;
  vulnerabilities: Array<{
    title: string;
    type: string;
    fixed_in?: string;
    references: string[];
  }>;
}

export interface SearchExploitsParams {
  query: string;
  exact_match?: boolean;
}

export interface SearchExploitsResult {
  query: string;
  exploits: Array<{
    id: string;
    title: string;
    path: string;
    platform: string;
    type: string;
    date: string;
  }>;
}

// =============================================================================
// WEB APPLICATION TOOL TYPES
// =============================================================================

export interface RunSqlmapParams {
  target: string;
  level?: 1 | 2 | 3 | 4 | 5;
  risk?: 1 | 2 | 3;
  technique?: string; // e.g., "BEUSTQ"
  data?: string; // POST data
  cookie?: string;
  headers?: Record<string, string>;
  tamper?: string[];
}

export interface RunSqlmapResult {
  target: string;
  vulnerable: boolean;
  injection_points: Array<{
    parameter: string;
    type: string;
    title: string;
    payload: string;
  }>;
  database_type?: string;
  current_user?: string;
  current_db?: string;
  is_dba?: boolean;
}

export interface FuzzEndpointsParams {
  target: string;
  wordlist?: string;
  extensions?: string[];
  status_codes?: number[];
  threads?: number;
  rate?: number;
}

export interface FuzzEndpointsResult {
  target: string;
  discovered: Array<{
    url: string;
    status: number;
    size: number;
    words: number;
    lines: number;
  }>;
}

export interface TestXssParams {
  target: string;
  params?: string[];
  crawl?: boolean;
}

export interface TestXssResult {
  target: string;
  vulnerable: boolean;
  vulnerabilities: Array<{
    url: string;
    parameter: string;
    payload: string;
    context: string;
  }>;
}

export interface CrawlSiteParams {
  target: string;
  depth?: number;
  include_subdomains?: boolean;
}

export interface CrawlSiteResult {
  target: string;
  urls: string[];
  forms: Array<{
    action: string;
    method: string;
    inputs: Array<{ name: string; type: string }>;
  }>;
  endpoints: string[];
  parameters: Array<{ url: string; params: string[] }>;
}

// =============================================================================
// EXPLOITATION TOOL TYPES
// =============================================================================

export interface RunMetasploitParams {
  module: string;
  target: string;
  options?: Record<string, string | number | boolean>;
  check_only?: boolean;
}

export interface RunMetasploitResult {
  module: string;
  target: string;
  status: 'success' | 'failed' | 'not_executed';
  reason?: string;
  check_result?: 'vulnerable' | 'not_vulnerable' | 'unknown';
  session_id?: number;
  output?: string;
}

export interface ValidateCveParams {
  cve_id: string;
  target: string;
}

export interface ValidateCveResult {
  cve_id: string;
  target: string;
  exploitable: boolean;
  method?: string;
  evidence?: string;
  module_used?: string;
}

export interface ExecuteCustomExploitParams {
  script_path: string;
  target: string;
  args?: string[];
}

export interface ExecuteCustomExploitResult {
  script_path: string;
  target: string;
  success: boolean;
  output: string;
  error?: string;
}

// =============================================================================
// CODE SECURITY SCANNING TOOL TYPES
// =============================================================================

export type CodeScanType =
  | 'sast'
  | 'secrets'
  | 'dependencies'
  | 'iac'
  | 'python'
  | 'javascript'
  | 'all';

export interface ScanRepositoryParams {
  repo_path: string;
  scan_types?: CodeScanType[];
  severity_threshold?: Severity;
  include_git_history?: boolean;
}

export interface CodeFinding {
  id: string;
  rule_id: string;
  title: string;
  severity: Severity;
  file_path: string;
  line_start: number;
  line_end?: number;
  code_snippet?: string;
  description: string;
  remediation?: string;
  cwe?: string;
  owasp?: string;
  scanner: string;
}

export interface ScanRepositoryResult {
  repo_path: string;
  scan_id: string;
  languages_detected: string[];
  findings: CodeFinding[];
  summary: {
    total: number;
    by_severity: Record<Severity, number>;
    by_scanner: Record<string, number>;
  };
  scan_time: number;
}

export interface ScanSemgrepParams {
  repo_path: string;
  rulesets?: string[];
  severity?: Severity;
}

export interface ScanBanditParams {
  repo_path: string;
  severity?: Severity;
  confidence?: 'low' | 'medium' | 'high';
}

export interface ScanNjsscanParams {
  repo_path: string;
}

export interface ScanSecretsParams {
  repo_path: string;
  include_git_history?: boolean;
  verify?: boolean;
}

export interface SecretFinding {
  id: string;
  type: string;
  file_path: string;
  line: number;
  match: string; // Redacted
  entropy?: number;
  verified?: boolean;
}

export interface ScanSecretsResult {
  repo_path: string;
  secrets: SecretFinding[];
  count: number;
}

export interface ScanDependenciesParams {
  repo_path: string;
  package_managers?: ('pip' | 'npm' | 'cargo' | 'maven' | 'gradle')[];
}

export interface DependencyVulnerability {
  package: string;
  version: string;
  vulnerability_id: string;
  severity: Severity;
  title: string;
  fixed_version?: string;
  url?: string;
}

export interface ScanDependenciesResult {
  repo_path: string;
  vulnerabilities: DependencyVulnerability[];
  total_packages: number;
  vulnerable_packages: number;
}

export interface ScanIacParams {
  repo_path: string;
  frameworks?: ('terraform' | 'cloudformation' | 'kubernetes' | 'dockerfile')[];
}

export interface IacFinding {
  id: string;
  resource: string;
  file_path: string;
  check_id: string;
  title: string;
  severity: Severity;
  guideline?: string;
}

export interface ScanIacResult {
  repo_path: string;
  findings: IacFinding[];
  resources_scanned: number;
}

export interface AnalyzeCodeContextParams {
  file_path: string;
  line_start: number;
  line_end: number;
  vulnerability_type?: string;
}

export interface AnalyzeCodeContextResult {
  file_path: string;
  code_snippet: string;
  language: string;
  analysis: {
    vulnerability_confirmed: boolean;
    explanation: string;
    sink?: string;
    source?: string;
    data_flow?: string[];
    recommended_fix?: string;
  };
  related_endpoints?: string[];
}

export interface DetectLanguagesParams {
  repo_path: string;
}

export interface DetectLanguagesResult {
  repo_path: string;
  languages: Array<{
    name: string;
    percentage: number;
    files: number;
    lines: number;
  }>;
  frameworks_detected: string[];
}

// =============================================================================
// REPORTING TOOL TYPES
// =============================================================================

export interface CreateFindingParams {
  title: string;
  severity: Severity;
  target: string;
  description: string;
  evidence?: string;
  remediation?: string;
  cve?: string;
  cycode_ref?: string;
}

export interface GenerateReportParams {
  finding_ids?: string[];
  assessment_id?: string;
  format: ReportFormat;
  include_evidence?: boolean;
  include_remediation?: boolean;
  include_executive_summary?: boolean;
  template?: string;
}

export interface GenerateReportResult {
  report_id: string;
  format: ReportFormat;
  content: string;
  findings_count: number;
  path?: string;
}

export interface CreateJiraTicketParams {
  finding_id: string;
  project_key: string;
  assignee?: string;
  labels?: string[];
}

export interface CreateJiraTicketResult {
  ticket_key: string;
  url: string;
  status: string;
}

export interface UploadReportParams {
  report_id: string;
  destinations: ('sharepoint' | 'email')[];
  email_recipients?: string[];
  sharepoint_path?: string;
}

// =============================================================================
// IMPORT TYPES
// =============================================================================

/** An import batch record */
export interface Import {
  id: string;
  name: string;
  source: 'cycode' | 'csv' | 'manual';
  filename?: string;
  findings_count: number;
  status: 'pending' | 'processing' | 'completed' | 'failed';
  error_message?: string;
  created_at: string;
  updated_at: string;
}

/** A finding imported from an external source */
export interface ImportedFinding {
  id: string;
  import_id: string;
  original_id?: string;
  vulnerability_type: string;
  severity: Severity;
  file_path?: string;
  line_number?: number;
  code_snippet?: string;
  description: string;
  remediation?: string;
  cwe?: string;
  status: 'imported' | 'validating' | 'confirmed' | 'false_positive';
  linked_finding_id?: string;
  linked_assessment_id?: string;
  repository_id?: string;
  created_at: string;
  updated_at: string;
}

/** Parsed finding from CSV (preview, not yet saved) */
export interface ParsedFinding {
  original_id?: string;
  vulnerability_type: string;
  severity: string;
  file_path?: string;
  line_number?: number;
  code_snippet?: string;
  description: string;
  remediation?: string;
  cwe?: string;
}

/** Column mapping detected from CSV headers */
export interface ColumnMapping {
  id?: number;
  vulnerability_type?: number;
  severity?: number;
  file_path?: number;
  line_number?: number;
  code_snippet?: number;
  description?: number;
  remediation?: number;
  cwe?: number;
}

/** Result of CSV preview */
export interface PreviewCsvResult {
  findings: ParsedFinding[];
  total_count: number;
  errors: string[];
  column_mapping: ColumnMapping;
}

/** Result of CSV import */
export interface ImportCsvResult {
  import: Import;
  imported_count: number;
  errors: string[];
}

/** Parameters for listing imports */
export interface ListImportsParams {
  source?: string;
  limit?: number;
  offset?: number;
}

/** Parameters for listing imported findings */
export interface ListImportedFindingsParams {
  import_id?: string;
  status?: string;
  severity?: string;
  repository_id?: string;
  limit?: number;
  offset?: number;
}

/** Parameters for creating a validation assessment */
export interface CreateValidationAssessmentParams {
  finding_ids: string[];
  repository_id?: string;
  name?: string;
}

/** Import statistics */
export interface ImportStats {
  total_imports: number;
  total_findings: number;
  by_status: {
    pending_validation: number;
    validating: number;
    confirmed: number;
    false_positive: number;
  };
  by_severity: {
    critical: number;
    high: number;
  };
}

// Legacy aliases for backwards compatibility
export type CycodeFinding = ImportedFinding;
export interface ImportCycodeFindingsParams {
  csv_content: string;
}
export interface ImportCycodeFindingsResult {
  imported: number;
  findings: ImportedFinding[];
  errors?: string[];
}

// =============================================================================
// AGENT ORCHESTRATION TYPES
// =============================================================================

export type AgentName =
  | 'recon'
  | 'auth'
  | 'vuln-scan'
  | 'web-app'
  | 'exploit'
  | 'security-scan'
  | 'code-intel'
  | 'qa'
  | 'report'
  | 'api-security'
  | 'infra-security'
  | 'compliance'
  | 'chain-analysis';

export interface RunOrchestratorParams {
  mode: 'full' | 'selective' | 'pipelined' | 'dual-track' | 'extreme' | 'sequential';
  agents?: AgentName[];
  targets?: string[];
  repo_paths?: string[];
  jira_project?: string;
  email_recipients?: string[];
  credential_app?: string;
  options?: AssessmentOptions;
  assessment_config?: AssessmentConfig;
}

// =============================================================================
// ASSESSMENT CONFIG TYPES (Browser Auth & Session Persistence)
// =============================================================================

export interface BrowserLoginStep {
  action: 'navigate' | 'fill' | 'click' | 'wait_for' | 'screenshot' | 'evaluate';
  url?: string;
  selector?: string;
  text?: string;
  value?: string;
  timeout?: number;
  description?: string;
}

export interface AuthConfig {
  type?: AuthType;
  app_name?: string;
  browser_login?: BrowserLoginStep[];
}

export interface BrowserConfig {
  spa?: boolean;
  persist_session?: boolean;
  start_url?: string;
}

export interface FocusConfig {
  include?: string[];
  exclude?: string[];
  priority_endpoints?: string[];
}

export interface AssessmentConfig {
  mode: 'interactive' | 'autonomous';
  targets?: string[];
  repo_paths?: string[];
  auth?: AuthConfig;
  focus?: FocusConfig;
  browser?: BrowserConfig;
  phases?: {
    order?: string[];
    skip?: string[];
  };
  reporting?: {
    jira_project?: string;
    email_recipients?: string[];
    format?: string;
  };
  notes?: string;
}

export interface RunAgentParams {
  targets?: string[];
  repo_paths?: string[];
  quick_scan?: boolean;
  severity_threshold?: Severity;
  credential_app?: string;
  test_types?: string[];
  findings?: string[]; // Finding IDs for exploit agent
}

export interface AgentState {
  id: string;
  agent_name: AgentName;
  status: AgentStatus;
  started_at: string;
  completed_at?: string;
  current_step: string;
  progress: number;
  findings: AgentFinding[];
  errors: string[];
  tool_calls_count: number;
  iterations: number;
}

export interface AgentFinding {
  title: string;
  severity: Severity;
  target: string;
  description?: string;
  evidence?: string;
  source_tool: string;
}

// =============================================================================
// INTERACTIVE TOOL TYPES
// =============================================================================

export interface PromptForOtpParams {
  app_name: string;
  email_hint?: string;
}

export interface PromptForInputParams {
  prompt_text: string;
  input_type?: 'text' | 'password' | 'code';
  timeout_seconds?: number;
}

export interface PendingPrompt {
  id: string;
  type: 'otp' | 'input' | 'guidance';
  prompt_text: string;
  created_at: string;
  expires_at: string;
  app_name?: string;
  screenshot_path?: string;
  options?: string[];
}

// =============================================================================
// PROJECT TYPES
// =============================================================================

export type ProjectStatus = 'active' | 'archived';

/**
 * A project's own scope — mirrors the backend `scope` JSONB column.
 *
 * Networks / domains / repos / exclusions are entered inline (same shape
 * as the global `ScopeConfig`). Cloud accounts and identity targets are
 * NOT re-entered here: they're REFERENCED by id (the org's existing
 * configured `cloud_accounts` / `identity_targets`), so no credential
 * material ever lives on a project.
 */
export interface ProjectScope {
  networks: ScopeNetwork[];
  domains: ScopeDomain[];
  repos: string[];                  // repo paths or git URLs
  cloud_account_ids: string[];      // references to the org's configured cloud accounts
  identity_target_ids: string[];    // references to the org's configured identity targets
  exclusions: ScopeExclusion[];
}

/** An empty project scope — the safe default for a brand-new project. */
export const EMPTY_PROJECT_SCOPE: ProjectScope = {
  networks: [],
  domains: [],
  repos: [],
  cloud_account_ids: [],
  identity_target_ids: [],
  exclusions: [],
};

export interface Project {
  id: string;
  name: string;
  description?: string;
  status: ProjectStatus;
  assessment_count: number;
  /** The project's own scope (backend `scope` JSONB). Optional because
   *  older rows / the list endpoint may omit it. */
  scope?: ProjectScope;
  created_at: string;
  updated_at: string;
}

export interface CreateProjectParams {
  name: string;
  description?: string;
  status?: ProjectStatus;
  scope?: ProjectScope;
}

export interface UpdateProjectParams {
  name?: string;
  description?: string;
  status?: ProjectStatus;
  scope?: ProjectScope;
}

// =============================================================================
// CONFIGURATION TYPES
// =============================================================================

export interface ScopeNetwork {
  cidr: string;
  environment: string;
  notes?: string;
}

export interface ScopeDomain {
  pattern: string;
  environment: string;
  notes?: string;
}

export interface ScopeExclusion {
  pattern: string;
  reason: string;
}

export interface ScopeApp {
  id: string;
  name: string;
  description?: string;
  environment: string;
  domains: ScopeDomain[];
  repo_paths?: string[];
}

export interface CloudAccountScope {
  id: string;
  provider: 'aws' | 'azure' | 'gcp';
  account_id?: string;
  subscription_id?: string;
  tenant_id?: string;
  project_id?: string;
  regions: string[];
  auth_method: string;
  // AWS auth fields
  role_arn?: string;
  external_id?: string;
  aws_profile?: string;
  access_key_id?: string;
  secret_access_key?: string;
  // Azure auth fields
  client_id?: string;
  client_secret?: string;
  // GCP auth fields
  service_account_key?: string;
  // Scope is now derived from a live credential probe at save time
  // rather than user-curated. Persisted as [] until the probe ships.
  services_in_scope: string[];
  resource_groups_in_scope?: string[];
  exclusions: string[];
  notes: string;
}

export interface K8sClusterScope {
  id: string;
  cluster: string;
  provider: string;
  auth_method: string;
  kubeconfig_path?: string;
  api_server?: string;
  token?: string;
  namespaces_in_scope: string[];
  namespaces_excluded: string[];
  notes: string;
}

export interface CloudScopeValidation {
  ok: boolean;
  warnings: string[];
  errors: string[];
}

/**
 * One identity-provider (IDP) target in scope. The field names here are
 * FIXED — the backend scope validator reads `.provider` (which is kept
 * equal to `kind`) and the identity agents read the rest. Secrets never
 * live inline: tokens/SA keys are stashed under `identity_credentials`
 * in credentials.yml and referenced here by `credential_ref` / `sa_key_ref`.
 */
export interface IdentityTarget {
  /** Unique key, e.g. "gws-groovy". */
  id: string;
  kind:
    | 'active_directory'
    | 'entra_id'
    | 'm365'
    | 'okta'
    | 'google_workspace'
    | 'ping';
  /** Set EQUAL to `kind` — the backend validator reads `.provider`. */
  provider: string;
  display_name?: string;
  /** Primary domain / customer id / tenant id / Okta org / Ping env. */
  tenant_id?: string;
  domain?: string;
  base_url?: string;
  /** service_account | api_token | service_principal | domain_creds | oauth | none */
  auth_method: string;
  /** Key into credentials.yml `identity_credentials` for a token-style secret. */
  credential_ref?: string;
  /** Key into credentials.yml `identity_credentials` for a service-account key. */
  sa_key_ref?: string;
  /** Google Workspace delegated admin subject (impersonated principal). */
  delegated_subject?: string;
  /** Lockout Mandate — accounts that must NEVER be touched (break-glass / execs). */
  exclusions: string[];
  lockout_threshold?: number;
  notes?: string;
}

/**
 * One stored identity secret, referenced from an IdentityTarget by
 * `credential_ref` / `sa_key_ref`. Either a path (SA JSON written to a
 * container file) or an inline `value` (token). Mirrors the backend
 * `identity_credentials` map in credentials.yml.
 */
export interface IdentityCredentialEntry {
  kind: 'sa_json' | 'okta_token' | 'ping_oauth' | 'api_token' | string;
  /** Container file path for sa_json-style credentials. */
  path?: string;
  /** Inline secret value for token-style credentials. */
  value?: string;
}

/**
 * One `scope.yml` `ai_targets[]` entry — a customer-owned AI/LLM system the AI
 * red-team agents are authorized to assess. Mirrors `IdentityTarget`, fails closed
 * like `cloud_accounts`: no entry, no AI testing. The `endpoint` MUST also resolve
 * into an in-scope `domains`/`networks` entry (the mcp-server validator enforces
 * this). See docs/ai-surface-plan.md.
 */
export interface AiTarget {
  /** Unique key, e.g. "support-bot". */
  id: string;
  kind: 'model_api' | 'chat_app' | 'agent' | 'rag_app' | 'mcp_server';
  /** custom | openai | anthropic | azure_openai | bedrock | vertex */
  provider: string;
  display_name?: string;
  /** HTTP endpoint — must also be in scope domains/networks. */
  endpoint?: string;
  base_url?: string;
  /** The model the customer claims is behind the endpoint. */
  model?: string;
  /** The endpoint's request body shape — a JSON template with a {{PROMPT}}
   *  placeholder where the user message goes. REQUIRED to run the probes; there
   *  is no assumed default. E.g. OpenAI: {"model":"gpt-4o","messages":[{"role":"user","content":"{{PROMPT}}"}]} */
  request_template?: string;
  /** Where the assistant's reply text lives in the response JSON (dot/bracket
   *  path), e.g. `choices.0.message.content` (OpenAI) or `content.0.text` (Anthropic).
   *  Optional — helps the probes read just the reply. */
  response_path?: string;
  /** bearer | api_key | session | none */
  auth_method: string;
  /** Name of a Config → Credentials application whose login this AI target reuses.
   *  When set, a FRESH bearer is minted per run via that app's server-side login
   *  (shared with the web/API assessment) — no static token that expires mid-run.
   *  Takes precedence over `credential_ref`. */
  app_credential?: string;
  /** Key into credentials.yml for the endpoint's secret. Static-token fallback. */
  credential_ref?: string;
  /** Declared system prompt, if the customer shares it. */
  system_prompt_known?: string;
  /** For `agent` targets — the exposed tool set (the excessive-agency blast radius). */
  declared_tools?: string[];
  /** Declared input/output guardrails the customer claims. */
  declared_guardrails?: string[];
  /** N-trials default for nondeterministic tests (ai-surface-plan §8). */
  trials?: number;
  /** Probe for cross-kind capabilities (agent/rag/mcp) beyond the declared kind
   *  (AI-RECON-05). Default true; false honors the declared kind only. */
  cross_kind_probe?: boolean;
  exclusions?: string[];
  notes?: string;
}

export interface ScopeConfig {
  apps?: ScopeApp[];
  networks: ScopeNetwork[];
  domains: ScopeDomain[];
  exclusions: ScopeExclusion[];
  cloud_accounts: CloudAccountScope[];
  kubernetes: K8sClusterScope[];
  identity_targets?: IdentityTarget[];
  ai_targets?: AiTarget[];
}

export interface CredentialApp {
  name: string;
  environment: string;
  base_url: string;
  auth_type: AuthType;
  /** Intended privilege level of this credential's identity (admin |
   *  privileged | standard | readonly). Calibrates access-control findings.
   *  Unset ⇒ unknown ⇒ no downgrade. */
  role?: string;
  // Basic auth
  username?: string;
  password?: string;
  // Bearer / API key
  token?: string;
  header_name?: string;
  // Session
  login_url?: string;
  login_payload?: Record<string, string>;
  token_field?: string;
  // OAuth2
  client_id?: string;
  client_secret?: string;
  token_url?: string;
  scopes?: string[];
  // OTP
  initiate_url?: string;
  verify_url?: string;
  email?: string;
}

export interface CredentialsConfig {
  applications: Record<string, CredentialApp>;
  test_accounts?: Record<string, {
    username: string;
    password?: string;
    role: string;
  }>;
  /** Identity-provider secrets, keyed by the `credential_ref` / `sa_key_ref`
   *  an IdentityTarget points at. Kept out of `applications` so the
   *  IDP credential flow round-trips without colliding with app logins. */
  identity_credentials?: Record<string, IdentityCredentialEntry>;
}

export interface NmapConfig {
  default_ports: string;
  timing_template: 1 | 2 | 3 | 4 | 5;
  max_rate: number;
}

export interface NucleiConfig {
  templates: string[];
  severity: string;
  rate_limit: number;
  bulk_size: number;
  concurrency: number;
  custom_templates_path?: string;
}

export interface SqlmapConfig {
  level: 1 | 2 | 3 | 4 | 5;
  risk: 1 | 2 | 3;
  threads: number;
  technique: string;
}

export interface FfufConfig {
  wordlist: string;
  rate: number;
  timeout: number;
}

export interface MetasploitConfig {
  check_mode: boolean;
  threads: number;
}

export interface SemgrepConfig {
  rulesets: string[];
  severity: string;
  timeout: number;
}

export interface ToolsConfig {
  nmap: NmapConfig;
  nuclei: NucleiConfig;
  sqlmap: SqlmapConfig;
  ffuf: FfufConfig;
  metasploit: MetasploitConfig;
  semgrep?: SemgrepConfig;
}

/** Snapshot of Claude credential state — drives the /config/claude page. */
export interface ClaudeAuthState {
  mode: ClaudeCredentialMode;
  /** True iff the container's /root/.claude/.credentials.json is present. */
  oauth_authenticated: boolean;
  /** True iff a BYO Anthropic API key is in the OS keychain. */
  api_key_present: boolean;
}

/** Env vars to inject on `docker exec` when launching Claude Code. */
export interface ClaudeContainerEnv {
  mode: ClaudeCredentialMode;
  /** Tuples of [name, value]. Empty for OAuth mode. */
  env: Array<[string, string]>;
  /** Set if the requested mode couldn't be resolved (e.g. API-key mode
   *  selected but no key saved). Caller should warn but still proceed —
   *  the resolved `mode` will be a working fallback. */
  fallback_reason?: string;
}

/** Snapshot of Codex credential state — drives the /config/codex page. */
export interface CodexAuthState {
  mode: CodexCredentialMode;
  /** True iff the container's /root/.codex/auth.json is present. */
  oauth_authenticated: boolean;
  /** True iff a BYO OpenAI API key is in the OS keychain. */
  api_key_present: boolean;
}

/** Env vars to inject on `docker exec` when launching the Codex CLI. */
export interface CodexContainerEnv {
  mode: CodexCredentialMode;
  /** Tuples of [name, value]. Empty for OAuth mode. */
  env: Array<[string, string]>;
  /** Set if the requested mode couldn't be resolved (e.g. API-key mode
   *  selected but no key saved). Caller should warn but still proceed —
   *  the resolved `mode` will be a working fallback. */
  fallback_reason?: string;
}

export interface AgentConfig {
  enabled: boolean;
  timeout_minutes: number;
  max_iterations?: number;
  auto_start?: boolean;
  requires_approval?: boolean;
}

export interface AgentsConfig {
  recon: AgentConfig;
  'vuln-scan': AgentConfig;
  'web-app': AgentConfig;
  exploit: AgentConfig;
  'security-scan': AgentConfig;
  report: AgentConfig;
}

// =============================================================================
// REPOSITORY MANAGEMENT TYPES
// =============================================================================

export type RepoSourceType = 'local' | 'github';

export interface Repository {
  id: string;
  name: string;
  path: string;
  container_path: string; // Path inside Kali container
  source_type: RepoSourceType;
  github_owner?: string;
  github_repo?: string;
  github_url?: string;
  languages: string[];
  last_scan?: string;
  last_scan_findings?: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  default_scan_config: {
    scan_types: CodeScanType[];
    severity_threshold: Severity;
    include_git_history: boolean;
  };
  created_at: string;
  updated_at: string;
}

export interface AddRepositoryParams {
  name: string;
  path: string;
  source_type?: RepoSourceType;
  github_owner?: string;
  github_repo?: string;
  default_scan_config?: {
    scan_types?: CodeScanType[];
    severity_threshold?: Severity;
    include_git_history?: boolean;
  };
}

// =============================================================================
// ASSESSMENT TYPES (EXTENDED)
// =============================================================================

export interface AssessmentOptions {
  // Recon options
  recon?: {
    scan_type: 'quick' | 'full' | 'stealth' | 'udp';
    custom_ports?: string;
    enumerate_subdomains?: boolean;
    passive_only?: boolean;
    fingerprint_services?: boolean;
    technology_detection?: boolean;
  };
  // Vuln scan options
  vuln_scan?: {
    nuclei_templates?: string[];
    nuclei_severity?: Severity[];
    nuclei_rate_limit?: number;
    run_nikto?: boolean;
    run_wpscan?: boolean;
  };
  // Web app options
  web_app?: {
    sqlmap_level?: 1 | 2 | 3 | 4 | 5;
    sqlmap_risk?: 1 | 2 | 3;
    sqlmap_technique?: string;
    fuzz_endpoints?: boolean;
    fuzz_wordlist?: string;
    fuzz_extensions?: string[];
    test_xss?: boolean;
    xss_crawl?: boolean;
    crawl_depth?: number;
  };
  // Exploit options
  exploit?: {
    auto_validate_critical?: boolean;
    auto_validate_high?: boolean;
    cve_whitelist?: string[];
  };
  // Code scan options
  code_scan?: {
    scan_types?: CodeScanType[];
    severity_threshold?: Severity;
    include_git_history?: boolean;
    rulesets?: string[];
  };
  // Report options
  report?: {
    format?: ReportFormat;
    include_evidence?: boolean;
    include_remediation?: boolean;
    create_jira_tickets?: boolean;
    jira_project?: string;
    email_recipients?: string[];
  };
  // Cloud scope — set by the new-assessment wizard for cloud_assessment
  // and combined types. Read by the orchestrator (to pick scope for
  // cloud-recon / cloud-exploit) and the desktop terminal header (to
  // render provider/account/region branding).
  cloud_scope?: {
    account_id: string;
    regions: string[];
    services: string[];
    k8s_cluster_id?: string;
  };
  // Brain choice at create-time. The terminal still allows toggling
  // mid-assessment via its own switch; this is the initial selection.
  brain?: 'claude' | 'codex';
}

/**
 * Persistent activity-feed event for an assessment. Mirrors the
 * `assessment_events` table; written by the desktop as it drives the
 * assessment + read by post-run viewers / teammates.
 */
export type AssessmentEventType =
  | 'tool_call'
  | 'tool_result'
  | 'finding_detected'
  | 'phase_change'
  | 'guidance_request'
  | 'orchestrator_message'
  | 'error';

export interface AssessmentEvent {
  id: string;
  assessment_id: string;
  event_type: AssessmentEventType;
  tool?: string;
  target?: string;
  details?: Record<string, unknown>;
  ref_finding_id?: string;
  created_at: string;
}

export interface Assessment {
  id: string;
  name: string;
  type: AssessmentType;
  status: AssessmentStatus;
  project_id?: string;
  targets?: string[];
  /** Canonical target_id values resolved from `targets` via the targets
   *  canonicalization helper (Phase 2 of caching plan). Populated by
   *  the cloud backend on every response. Empty on assessments that
   *  predate migration 0018 or whose backfill repair hasn't run yet. */
  target_ids?: string[];
  repo_paths?: string[];
  created_at: string;
  updated_at?: string;
  credential_app?: string;
  jira_project?: string;
  email_recipients?: string[];
  severity_threshold?: Severity;
  options?: AssessmentOptions;
  phases?: AgentName[];
  progress: number;
  current_step?: string;
  started_at: string;
  completed_at?: string;
  findings_count: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  error_message?: string;
  report_id?: string;
  agent_states?: Record<AgentName, AgentState>;
  /** Set when the row has been soft-archived (the user's "close out"
   *  action). Truthy = archived; dashboard renders a small badge so
   *  archived runs stay distinguishable in the history rail. */
  archived_at?: string | null;
}

// =============================================================================
// FINDING TYPES (EXTENDED)
// =============================================================================

export type FindingCategory = 'web_app' | 'code_security' | 'cloud' | 'infrastructure' | 'identity' | 'ai' | 'other';

export interface Finding {
  id: string;
  assessment_id?: string;
  title: string;
  /** Effective severity — calibrated when present, scanner-original
   *  otherwise. This is what the table badge + tile counts use.
   *  See `original_severity` + `calibrated_severity` for the raw values. */
  severity: Severity;
  /** Scanner-original severity. Preserved on the row so the UI can
   *  show "was HIGH ↓" next to a downgraded badge. Always populated. */
  original_severity?: Severity;
  /** Post-calibration severity. Undefined / null when calibration didn't
   *  run or kept the original. When present, equals `severity`. */
  calibrated_severity?: Severity | null;
  /** Which calibration rule fired (e.g. "Rule 1 — outcome anchored"). */
  calibration_rule?: string | null;
  /** Short prose justification for the calibrated severity. */
  calibration_justification?: string | null;
  description: string;
  target: string;
  evidence?: string;
  evidence_type?: 'text' | 'image' | 'json';
  remediation?: string;
  cve?: string;
  cwe?: string;
  cvss?: number;
  cycode_ref?: string;
  source_tool?: string;
  source?: string;
  category?: FindingCategory;
  status: FindingStatus;
  created_at: string;
  updated_at?: string;
  validated_at?: string;
  validation_method?: string;
  jira_ticket?: string;
  jira_url?: string;
  tags?: string[];
  exploitable?: string;
  // Code context (for SAST findings)
  file_path?: string;
  line_start?: number;
  line_end?: number;
  code_snippet?: string;
  // Per-vuln dedup (v0.1.54+) — populated by the cloud backend's
  // upsert logic. Same fingerprint → same row, occurrence_count
  // increments, last_seen_at refreshes. Backend computes fingerprint
  // from (org_id, target, normalized_title, file_path, line_start).
  fingerprint?: string;
  occurrence_count?: number;
  first_seen_at?: string;
  last_seen_at?: string;
  last_assessment_id?: string;
  // Remediation / "patched" tracking (migration 0034). Set by the cloud
  // upsert when a finding that WAS exploitable is re-tested and no longer
  // reproduces. `remediated_at` present ⇒ patched (drives the Remediated
  // tab + ✓ Fixed badge). Cleared on regression (it came back exploitable).
  remediated_at?: string | null;
  /** The exploitable value held before being patched ('true' | 'potentially'). */
  prior_exploitable?: string | null;
  /** The assessment whose re-test proved the fix. */
  remediated_in_assessment_id?: string | null;
  /** Scheduled-DAST scan that produced this finding (migration 0035). Present
   *  only for findings from a deterministic/scheduled scan; null/undefined for
   *  LLM-assessment findings. Drives the Scheduled DAST → Vulnerabilities view. */
  scan_id?: string | null;
  /** Triage owner (user id / email). Migration 0036. */
  assigned_to?: string | null;
  /** Human attestation — the top validation tier. Migration 0036. */
  attested_at?: string | null;
  attested_by?: string | null;
  /** Derived validation tier (migrations 0036 + 0049). Drives the AI escalation
   *  bridge. `oracle_verified` outranks `ai_confirmed`: an oracle re-proved the
   *  finding in code, rather than an agent claiming it. */
  validation_tier?:
    | 'unproven'
    | 'ai_confirmed'
    | 'oracle_verified'
    | 'not_exploitable'
    | 'human_attested';
  /** Oracle verdict (migration 0049). `verified` is earned in code by a named
   *  oracle and can never be asserted by an agent — see
   *  docs/oracle-verification-layer.md. */
  verdict?: 'candidate' | 'verified' | 'refuted' | null;
  /** Which oracle earned the verdict (idempotent_replay | differential | …). */
  oracle_kind?: string | null;
  /** Machine evidence the oracle observed, including its negative control. */
  receipt_json?: unknown;
  /** The re-runnable proof recipe — what a human signer replays before signing. */
  capsule_json?: unknown;
  /** Replays attempted vs succeeded. `verified` requires they match. */
  replay_n?: number | null;
  replay_successes?: number | null;
  verified_at?: string | null;
  /** The vulnerability mechanism the finding claims, bound to the receipt so a
   *  proof by a different mechanism is caught rather than silently accepted. */
  claimed_mechanism?: string | null;
}

/** A comment / activity entry on a finding. Mirrors backend `FindingComment`. */
export interface FindingComment {
  id: string;
  finding_id: string;
  org_id?: string | null;
  author?: string | null;
  body: string;
  created_at: string;
}

// =============================================================================
// REPORT TYPES (EXTENDED)
// =============================================================================

export interface Report {
  id: string;
  assessment_id: string;
  name: string;
  title?: string;
  content?: string;
  format: ReportFormat;
  file_path?: string;
  /** True when the row's PDF bytes are stored in the per-customer S3
   *  bucket and can be fetched via /reports/{id}/artifact-url. False
   *  for legacy rows whose bytes only live on the originating machine
   *  (those fall back to the local-file open path). */
  has_artifact?: boolean;
  // Nullable in the backend schema (Option<DateTime<Utc>>), so the
  // frontend treats it as optional and falls back to "—" in the UI when
  // the row was inserted without a timestamp.
  created_at?: string;
  findings_count: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  exploitable_count: number;
}

// =============================================================================
// REPORT FILE TYPES (FILESYSTEM)
// =============================================================================

export interface ReportFile {
  name: string;
  path: string;
  format: 'markdown' | 'pdf';
  size: number;
  modified_at: string;
  title?: string;
}

// =============================================================================
// SYSTEM & STATUS TYPES
// =============================================================================

export interface DockerStatus {
  available: boolean;
  kali_running: boolean;
  /** Deep health: running AND on the expected image (not "running == healthy"). */
  kali_healthy: boolean;
  kali_image_version?: string;
  container_id?: string;
  uptime_seconds?: number;
  /** Toolkit image this app build pins (only present on SystemStatus.docker). */
  image_expected?: string;
  /** Image the running container was actually created from. */
  image_actual?: string | null;
  /** Whether the running container matches the pinned image (no drift). */
  image_current?: boolean;
}

export interface SystemStatus {
  healthy: boolean;
  docker: DockerStatus;
  database_connected: boolean;
  mcp_server_connected: boolean;
  /** Tools the MCP server actually advertises — proof it's functional, not
   *  merely answering /health. Null/undefined when unreachable. */
  mcp_tool_count?: number | null;
  /** Active Claude credential mode (replaces the old llm_provider field). */
  claude_auth_mode: ClaudeCredentialMode;
  /** Whether the active mode actually has a usable credential. */
  claude_authenticated: boolean;
  uptime_seconds: number;
  version: string;
}

export interface ToolInfo {
  name: string;
  category: 'recon' | 'vuln-scan' | 'web-app' | 'exploit' | 'code-scan' | 'reporting' | 'agents' | 'interactive';
  description: string;
  requires_scope: boolean;
  parameters: Array<{
    name: string;
    type: string;
    required: boolean;
    description: string;
    default?: unknown;
    enum?: unknown[];
  }>;
}

// =============================================================================
// AUDIT LOG TYPES
// =============================================================================

// Mirrors `backend-rs/src/routes/audit_logs.rs::AuditLogRow` —
// the backend writes one row per entity mutation (assessment.create,
// finding.update, etc.). `details` is a free-form JSON blob with
// per-action context (what changed, etc.). The legacy fields
// (timestamp / tool / target / result_status / execution_time_ms) are
// kept as optionals so older API versions or tool-execution logs the
// frontend may still encounter render gracefully.
export interface AuditLog {
  id: string;
  action: string;
  resource_type: string;
  resource_id?: string;
  details?: Record<string, unknown> | null;
  user_id?: string;
  user_email?: string;
  org_id?: string;
  created_at?: string;
  // Legacy / tool-execution audit fields (backwards compatibility)
  timestamp?: string;
  tool?: string;
  target?: string;
  arguments?: Record<string, unknown>;
  user?: string;
  session_id?: string;
  assessment_id?: string;
  result_status?: 'success' | 'failed' | 'blocked';
  execution_time_ms?: number;
  error?: string;
}

// =============================================================================
// PAGINATION & FILTERING
// =============================================================================

export interface PaginatedResult<T> {
  data: T[];
  total: number;
  page: number;
  limit: number;
  hasMore: boolean;
}

export interface FindingsFilter {
  severity?: Severity[];
  status?: FindingStatus[];
  target?: string;
  search?: string;
  assessment_id?: string;
  /** Scope findings to a single project (the backend joins through the
   *  project's assigned assessments). */
  project_id?: string;
  /** A single FindingCategory, or a comma-separated union of categories for a
   *  surface lens (e.g. `cloud,infrastructure` for Cloud / Infra). The backend
   *  `category_clause` unions their source-pattern sets. */
  category?: FindingCategory | (string & {});
  has_cve?: boolean;
  has_jira?: boolean;
  date_from?: string;
  date_to?: string;
  /** 'true' → only scheduled-DAST findings (scan_id IS NOT NULL), excluding
   *  LLM-assessment findings. Powers the Scheduled DAST → Vulnerabilities view.
   *  Migration 0035. */
  scan_only?: string;
  /** Exact per-scan attribution — only findings produced by this scan run.
   *  Migration 0035. */
  scan_id?: string;
}

export interface AssessmentsFilter {
  type?: AssessmentType[];
  status?: AssessmentStatus[];
  date_from?: string;
  date_to?: string;
  /** Scope to the assessments assigned to a single project. */
  project_id?: string;
  /** Default is to hide soft-archived rows. Set true to surface
   *  closed-out assessments (e.g. the dashboard's history rail). */
  include_archived?: boolean;
}

// =============================================================================
// STATISTICS TYPES
// =============================================================================

export interface FindingsStats {
  total: number;
  by_severity: Record<Severity, number>;
  by_status: Record<FindingStatus, number>;
  by_category: Record<FindingCategory, number>;
  by_tool: Record<string, number>;
  exploitable: number;
  exploitable_count: number;
  /** Count of findings with `exploitable = 'true'` (full PoC executed). */
  fully_exploited_count: number;
  /** Count of findings with `exploitable = 'potentially'` (partial / code-only). */
  partial_exploited_count: number;
  /** Count of findings re-tested as no-longer-exploitable (remediated_at set).
   *  Powers the Remediated tab badge. Migration 0034. */
  remediated_count?: number;
  with_cve: number;
  with_jira: number;
}

export interface DashboardStats {
  assessments: {
    total: number;
    running: number;
    completed_today: number;
    completed_week: number;
  };
  findings: FindingsStats;
  recent_assessments: Assessment[];
  recent_findings: Finding[];
  agents: {
    running: AgentState[];
    recent_completed: AgentState[];
  };
}

// =============================================================================
// CLOUD SYNC TYPES
// =============================================================================

export type CloudAuthProvider = 'local' | 'cognito' | 'oidc';

export interface CloudConfig {
  enabled: boolean;
  api_url: string;
  auth_provider: CloudAuthProvider;
  email?: string;
  // Cognito settings
  cognito_region?: string;
  cognito_user_pool_id?: string;
  cognito_client_id?: string;
  // OIDC settings
  oidc_issuer?: string;
  oidc_client_id?: string;
  // Sync settings
  auto_sync: boolean;
  sync_interval_seconds: number;
}

export interface CloudStatus {
  enabled: boolean;
  connected: boolean;
  authenticated: boolean;
  user_email?: string;
  last_sync_at?: string;
  pending_changes: number;
  sync_in_progress: boolean;
  last_error?: string;
}

/**
 * Per-assessment LLM cost + cache telemetry.
 *
 * Source of truth: `backend-rs/src/routes/cache_stats.rs` (CacheStatsResponse).
 * Schema: `backend-rs/migrations/0017_cache_stats.sql`.
 *
 * `effective_input_tokens` = input + 0.1*cache_read + 1.25*cache_create.
 * `cost_usd_without_cache` is the counterfactual: what this assessment
 * would have cost with no caching at all. `savings_usd` is the difference.
 */
/**
 * Tool-execution provenance (P1) — one row per MCP security tool that ran during
 * an assessment. Proves the tool actually executed; `installed` is the independent
 * binary-availability probe that survives the handler soft-fail pattern.
 */
export interface ToolExecution {
  tool_name: string;
  binary: string | null;
  installed: boolean | null;
  version: string | null;
  run_count: number;
  ok_count: number;
  fail_count: number;
  last_exit_code: number | null;
}

// =============================================================================
// EXECUTION OVERVIEW — the in-app twin of the harness trace analyzer.
// Both producers emit this same shape: the harness from LLM transcripts
// (tests-e2e-assessment/analyze-trace.mjs), the app from the cloud DB
// (use-assessment-execution.ts). SOURCE OF TRUTH is
// tests-e2e-assessment/execution-overview.schema.json; this and
// mcp-server/src/logging/execution-overview.ts mirror it (parity-tested).
// Option-B blocks (test_results, scope) are optional; the `provenance`
// discriminator lets the UI label "measured" (db) vs "approximated" (derived).
// =============================================================================

export type TestOutcome = 'PASS' | 'FAIL' | 'N_A' | 'BLOCKED';

/** One per-test result, imported from a {agent}-results.json checkpoint and run
 *  through the provenance gate (enforced=true when a PASS/N_A was forced BLOCKED). */
export interface ExecutionTestResult {
  test_id: string;
  status: TestOutcome;
  finding_count: number;
  notes?: string | null;
  enforced?: boolean;
  enforced_reason?: string | null;
  agent?: string | null;
}

/** A scope-validation decision recorded at tool-dispatch time (both allowed and
 *  rejected calls), rolled up per (assessment, target, in_scope). */
export interface ScopeTargetDecision {
  target: string;
  in_scope: boolean;
  dimension?: 'network' | 'cloud' | 'k8s' | 'identity' | string | null;
  reason?: string | null;
  attempts?: number;
}

export interface ExecutionPhase {
  name: string; // agent / phase label, e.g. "recon-infra"
  status?: 'completed' | 'partial' | 'blocked' | 'running';
  started_at?: string | null;
  ended_at?: string | null;
  tool_call_count?: number;
  finding_count?: number;
}

export type ExecutionVerdict = 'complete' | 'partial' | 'blocked' | 'failed' | 'unknown';

export interface ExecutionTokenUsage {
  inputTokens: number;
  outputTokens: number;
  cacheCreationInputTokens: number;
  cacheReadInputTokens: number;
  totalTokens: number;
}

export interface ExecutionOverview {
  schemaVersion: 1;
  executionId: string;
  source: 'harness-trace' | 'production';
  generatedAt: string;
  model?: string | null;

  success: {
    ok: boolean;
    verdict?: ExecutionVerdict;
    summary: string;
    hardFailures: string[];
    softWarnings: string[];
    degenerateRun?: boolean;
  };

  counts: {
    toolExecutions: number;
    distinctTools: number;
    subagentSpawns: number;
    distinctAgentTypes: number;
    turns: number;
    steps: number;
    findingsCreated: number;
    errors: number;
    retries: number;
  };

  targets?: Array<{
    target: string;
    inScope?: boolean | null;
    dimension?: string | null;
    reason?: string | null;
    toolExecutions?: number;
  }>;

  testRollup: {
    total: number;
    pass: number;
    fail: number;
    n_a: number;
    blocked: number;
    skipped: number;
    byStatus?: Record<string, number>;
  };

  integrity: {
    consistent: boolean;
    fakedPass: Array<{ testId: string; tool: string; claimedStatus: string; backingToolCalls: number }>;
    provenanceBlocked: string[];
    unverifiable: Array<{ testId: string; reason: string }>;
  };

  duration: { startTs: string | null; endTs: string | null; wallMs: number | null };
  tokens: ExecutionTokenUsage;
  costUsd?: number | null;
  findingsBySeverity: { critical: number; high: number; medium: number; low: number; info?: number };
  findingsTotal: number;

  /** Production-only: which Option-B blocks are DB-sourced vs derived/absent. */
  provenance?: {
    test_results?: 'db' | 'derived' | 'absent';
    scope?: 'db' | 'derived' | 'absent';
    phases?: 'db' | 'derived' | 'absent';
  };
}

export interface CacheStatsResponse {
  id: string;
  org_id: string;
  assessment_id: string | null;
  provider: 'anthropic' | 'openai' | string;
  model: string | null;
  input_tokens: number;
  output_tokens: number;
  cache_read_input_tokens: number;
  cache_creation_input_tokens: number;
  effective_input_tokens: number;
  cost_usd: number;
  cost_usd_without_cache: number;
  savings_usd: number;
  cache_hit_pct: number;
  request_count: number;
  requests_with_extended_ttl: number;
  requests_without_cache_beta: number;
  created_at: string;
  updated_at: string;
}

/**
 * Delta payload for recordCacheStats. All counts are additive unless
 * `replace: true` is set. assessment_id is required.
 */
export interface CacheStatsDelta {
  assessment_id: string;
  provider?: 'anthropic' | 'openai';
  model?: string;
  input_tokens?: number;
  output_tokens?: number;
  cache_read_input_tokens?: number;
  cache_creation_input_tokens?: number;
  request_count?: number;
  requests_with_extended_ttl?: number;
  requests_without_cache_beta?: number;
  replace?: boolean;
}

/**
 * Per-org cache configuration. Mirrors `OrgSettingsResponse` in
 * backend-rs/src/routes/org_settings.rs. Owned by the cache settings
 * page at /config/cache-settings.
 */
export interface OrgCacheSettings {
  org_id: string;
  caching_enabled: boolean;
  full_revalidation_interval: number;
  sast_cache_ttl_days: number;
  recon_cache_ttl_days: number;
  baseline_max_age_days: number;
  drift_alert_threshold: number;
  // DAST triage SLA + auto-escalate (migration 0036). Optional because the
  // Tauri get_org_settings command predates them; the DAST settings page reads
  // the full set via cloudRequest('/org-settings').
  sla_critical_days?: number;
  sla_high_days?: number;
  sla_medium_days?: number;
  sla_low_days?: number;
  dast_auto_escalate_enabled?: boolean;
  dast_auto_escalate_severities?: string;
  dast_webhook_url?: string | null;
}

/** Partial-update body for the cache settings PUT. Every field optional. */
export interface OrgCacheSettingsUpdate {
  caching_enabled?: boolean;
  full_revalidation_interval?: number;
  sast_cache_ttl_days?: number;
  recon_cache_ttl_days?: number;
  baseline_max_age_days?: number;
  drift_alert_threshold?: number;
  sla_critical_days?: number;
  sla_high_days?: number;
  sla_medium_days?: number;
  sla_low_days?: number;
  dast_auto_escalate_enabled?: boolean;
  dast_auto_escalate_severities?: string;
  dast_webhook_url?: string;
}

/** Rolling-30-day summary of drift alerts. Mirrors the JSON returned by
 *  GET /cache-drift-alerts/summary. */
export interface DriftAlertsSummary {
  alerts_30d: number;
  unacknowledged: number;
  threshold: number;
  threshold_breached: boolean;
}

/**
 * Per-finding row in the baseline response. Mirrors
 * `BaselineFinding` in backend-rs/src/routes/findings.rs.
 */
export interface BaselineFinding {
  id: string;
  fingerprint: string | null;
  title: string;
  severity: string;
  calibrated_severity: string | null;
  calibration_rule: string | null;
  exploitable: string | null;
  status: string;
  first_seen_at: string;
  last_seen_at: string;
  validation_age_days: number;
  occurrence_count: number;
  file_path: string | null;
  line_start: number | null;
  evidence_excerpt: string | null;
  last_assessment_id: string | null;
}

/**
 * Baseline-aware findings response from GET /findings/baseline.
 * Surfaced by the desktop "Baseline reuse" panel and by the team lead's
 * Phase 1.5 fetch step.
 */
export interface BaselineResponse {
  target_id: string;
  baseline: BaselineFinding[];
  force_full_revalidation: boolean;
  assessments_since_last_full_revalidation: number;
  full_revalidation_interval: number | null;
  baseline_max_age_days: number;
  caching_enabled: boolean;
}

// =============================================================================
// TARGETS / SCANS / SCAN SCHEDULES — the continuous-DAST data spine
// (mirrors backend-rs/src/routes/{targets,scans,scan_schedules}.rs)
// =============================================================================

/** Canonical target identity. Mirrors `TargetResponse` in routes/targets.rs. */
export interface Target {
  id: string;
  org_id: string;
  /** 'web' | 'host' | 'cidr' | 'repo' | 'cloud_account'. */
  target_type: string;
  canonical_value: string;
  raw_values: unknown;
  fingerprint: string;
  metadata: Record<string, unknown>;
  first_seen_at: string;
  last_seen_at: string;
  archived_at?: string | null;
  /** Application this target belongs to (migration 0038). NULL = unassigned. */
  application_id?: string | null;
  /** How the target was created (migration 0043): 'dast' (added on the Scheduled
   *  DAST Targets page) | 'assessment' | 'scope' | null. */
  source?: string | null;
}

/** An application — the grouping layer above targets (migration 0038). */
export interface Application {
  id: string;
  org_id: string;
  name: string;
  description?: string | null;
  team?: string | null;
  /** 'low' | 'medium' | 'high' | 'critical'. */
  criticality: string;
  environment?: string | null;
  created_at: string;
  updated_at: string;
  /** Targets assigned (returned by the list endpoint). */
  target_count?: number;
}

/** A single continuous-DAST run. Mirrors `ScanView` in routes/scans.rs. */
export interface Scan {
  id: string;
  target_id: string;
  assessment_id?: string | null;
  /** 'deterministic' | 'dast' | … */
  scan_type: string;
  /** 'manual' | 'scheduled' | 'ci' */
  trigger_kind: string;
  /** 'completed' | 'running' | 'failed' | … */
  status: string;
  scanner_set: unknown;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  info_count: number;
  total_count: number;
  started_at: string;
  finished_at?: string | null;
  // Live progress telemetry (migration 0037).
  progress_pct?: number;
  phase?: string | null;
  current_activity?: string | null;
  tests_total?: number;
  tests_done?: number;
  // Runtime attack volume (migration 0045): real HTTP requests fired ("attacks
  // executed"), whether any contributing count was estimated, and the per-tool
  // breakdown { toolName: { count, estimated } }.
  attacks_executed?: number;
  attacks_estimated?: boolean;
  attacks_by_tool?: Record<string, { count: number; estimated: boolean }>;
}

/** Lightweight finding summary returned by /scans/diff. */
export interface ScanDiffFinding {
  id: string;
  title: string;
  severity: string;
  cve?: string | null;
}

/** new-vs-fixed delta since the latest scan. Mirrors `DiffResponse`. */
export interface ScanDiff {
  latest_scan_id?: string | null;
  since?: string | null;
  new: ScanDiffFinding[];
  fixed: ScanDiffFinding[];
  still_present_count: number;
}

/** Full detail of one finding within a single scan run. Mirrors
 *  `ScanFindingView` in routes/scans.rs (GET /scans/:id/findings) — carries
 *  the description + evidence the run drill-down needs. */
export interface ScanFindingDetail {
  id: string;
  title: string;
  severity: string;
  cve?: string | null;
  status: string;
  description: string;
  evidence?: string | null;
  target: string;
}

/** Auth block of a per-target scan config (opaque `auth` JSON on the row).
 *  Drives the deterministic DAST run's authenticated-scan behaviour. */
export interface ScanAuth {
  type: 'none' | 'header' | 'basic' | 'bearer' | 'form';
  /** Header mode: arbitrary request headers (name → value). */
  headers?: Record<string, string>;
  /** Basic / form modes. */
  username?: string;
  password?: string;
  /** Bearer mode. */
  token?: string;
  /** Form-login mode: where + which fields to POST credentials. */
  login_url?: string;
  username_field?: string;
  password_field?: string;
  /** Session keep-alive / recorded login (WS7, runner-enforced). A URL the
   *  runner re-hits to keep the session warm, a text/regex that indicates a
   *  live session, and an optional recorded login step sequence. */
  keep_alive_url?: string;
  session_check?: string;
  login_sequence?: string;
}

/** Scope block of a per-target scan config (opaque `scope` JSON on the row).
 *  Include/exclude URL globs that keep the run on-target. */
export interface ScanScope {
  include?: string[];
  exclude?: string[];
  /** OpenAPI/Swagger spec URL fed into API attacks (WS3). */
  openapi_url?: string;
}

/** Per-target authenticated-scan + scope config. Mirrors `ConfigView` in
 *  routes/scan_configs.rs (auth/scope are opaque JSON on the wire — typed
 *  here as the shapes the DAST page reads/writes). */
export interface ScanConfig {
  target_id: string;
  auth: ScanAuth;
  scope: ScanScope;
}

/** Cadence config for a target. Mirrors `ScheduleView` in scan_schedules.rs. */
export interface ScanSchedule {
  id: string;
  /** Solo target (NULL when application-scoped). Exactly one of target_id/application_id. */
  target_id?: string | null;
  /** Application this schedule fans out across (migration 0044). */
  application_id?: string | null;
  /** 'authed' (apply the target's scan-config auth) | 'unauthed' (anonymous). */
  auth_mode?: string;
  /** A value from the backend's SCAN_CADENCES enum (off / daily / weekly / …). */
  cadence: string;
  scan_type: string;
  enabled: boolean;
  last_run_at?: string | null;
  next_run_at?: string | null;
  /** Pinned scan policy (migration 0039). */
  policy_id?: string | null;
  /** Blackout window: "HH:MM:SS" local times in `timezone` (migration 0039). */
  window_start?: string | null;
  window_end?: string | null;
  timezone?: string | null;
}

/** A scheduled report-delivery subscription (migration 0041). Delivery is
 *  pending an external email integration. */
export interface ReportSubscription {
  id: string;
  application_id?: string | null;
  target_id?: string | null;
  recipients: string[];
  cadence: string;
  enabled: boolean;
  last_sent_at?: string | null;
  created_at: string;
  updated_at: string;
}

/** A CI API key (migration 0040). The plaintext `token` is only present in the
 *  mint response. */
export interface ApiKey {
  id: string;
  name: string;
  prefix: string;
  created_at: string;
  last_used_at?: string | null;
  revoked_at?: string | null;
  /** Only returned once, at mint. */
  token?: string;
}

/** A scan policy — a reusable attack-library subset (migration 0039). Built-in
 *  presets have id `builtin:*` and `builtin: true` (read-only). */
export interface ScanPolicy {
  id: string;
  builtin?: boolean;
  name: string;
  description?: string | null;
  /** Category prefixes (RECON, INJ, …). */
  categories: string[];
  /** Explicit test_ids. Empty categories + empty test_ids = full assessment. */
  test_ids: string[];
  created_at?: string;
  updated_at?: string;
}

/** A "deployed + reachable + vulnerable" correlation (Coverage Dashboard W4):
 *  a CVE-bearing image running on an internet-facing cloud workload. From
 *  GET /cloud/inventory/correlations (backend-rs/routes/cloud_inventory.rs). */
export interface CloudCorrelation {
  /** The underlying CVE finding (for "Prove this" / drill-in). */
  finding_id: string;
  cve: string | null;
  /** Severity enum value: critical / high / medium / low / info. */
  severity: string;
  /** 'true' / 'potentially' / 'false' — EXPLOITED vs detected-only in the graph. */
  exploitable: string | null;
  /** The vulnerable container image ref the workload runs. */
  image_ref: string;
  /** ARN of the reachable workload (ECS service / Lambda). */
  resource_arn: string;
  asset_name: string | null;
  /** ecs_service / lambda_function / … */
  resource_type: string;
  /** Internet-facing endpoint (LB DNS / function URL), when known. */
  endpoint: string | null;
  /** alb / nlb / function_url / public_ip / api_gateway. */
  exposed_via: string | null;
}

/** A persisted escalation / attack-path graph (W5) from an agent
 *  (cloud-analysis PMapper privesc / chain-analysis chains).
 *  GET /cloud/attack-paths. nodes/edges match the AttackPathGraph component. */
export interface PersistedAttackGraph {
  id: string;
  target_id: string | null;
  source: string;
  label: string | null;
  nodes: Array<{
    id: string;
    label: string;
    kind: string;
    layer: number;
    severity?: string;
    sub?: string;
  }>;
  edges: Array<{ from: string; to: string; exploited?: boolean }>;
}

// =============================================================================
// Attack-graph substrate (backend migration 0046 + /graph/*) — the persistent,
// accumulating node/edge union behind the interactive graph explorer (/graph).
// =============================================================================

/** A node/edge kind in the registry. Built-ins are global; orgs add custom
 *  kinds. `display` drives explorer + SVG styling straight from the registry. */
export interface GraphKind {
  kind: string;
  is_builtin: boolean;
  is_edge: boolean;
  is_goal: boolean;
  label: string;
  display: {
    fill?: string;
    stroke?: string;
    text?: string;
    icon?: string;
    layer?: number;
  } & Record<string, unknown>;
  schema: Record<string, unknown>;
}

/** A node from GET /graph/nodes (the accumulated union). `id` is the stable
 *  node key; `sources`/`assessments` accumulate across runs. */
export interface GraphSubstrateNode {
  id: string;
  kind: string;
  label: string;
  layer: number;
  severity: string | null;
  sub: string | null;
  /** Per-node crown-jewel override; null = inherit the kind's default. */
  is_goal: boolean | null;
  target_id: string | null;
  attrs: Record<string, unknown>;
  sources: string[];
  assessments: string[];
  last_seen_at: string;
}

/** An edge from GET /graph/edges. */
export interface GraphSubstrateEdge {
  from: string;
  to: string;
  kind: string;
  exploited: boolean;
  target_id: string | null;
  sources: string[];
  assessments: string[];
  last_seen_at: string;
}

/** One path returned by POST /graph/paths (path-enumeration mode). */
export interface GraphPath {
  start_key: string;
  /** Ordered node keys from start to goal. */
  nodes: string[];
  edges: Array<{ from: string; to: string; kind: string; exploited: boolean }>;
  depth: number;
}

/** One reachable goal returned by POST /graph/paths (reachable_only mode). */
export interface GraphReachable {
  goal_key: string;
  kind: string;
  reached_from: string[];
}

/** Request body for POST /graph/paths. */
export interface GraphPathsQuery {
  source_kind?: string;
  source_keys?: string[];
  goal_kind?: string;
  max_depth?: number;
  exploited_only?: boolean;
  reachable_only?: boolean;
  limit?: number;
}

/** Response from POST /graph/paths — `paths` OR `reachable` depending on mode. */
export interface GraphPathsResponse {
  paths?: GraphPath[];
  reachable?: GraphReachable[];
  truncated: boolean;
}

/** A post-exploitation foothold (GET /footholds). `node_key` links it to a graph
 *  node so the explorer's "paths from footholds" lens can mark where we landed. */
export interface Foothold {
  id: string;
  assessment_id: string;
  kind: string;
  target: string;
  grants: string[];
  how_acquired: string | null;
  /** Links to a graph node_key when the operator stamped one. */
  node_key: string | null;
  status: string;
  established_at: string;
  expires_at: string | null;
}

/** One cell of the Coverage Dashboard W3 heatmap: findings grouped by
 *  (category, surface). From GET /findings/coverage. */
export interface CoverageCell {
  /** category_from_source value: web_app / vuln_scan / infrastructure /
   *  code_security / exploitation / other. */
  category: string;
  /** web / cloud / identity. */
  surface: string;
  count: number;
  /** Worst severity present in this cell, or null if no findings. */
  worst_severity: string | null;
}

export interface CloudAuthProviderInfo {
  type: CloudAuthProvider;
  name: string;
  region?: string;
  user_pool_id?: string;
  client_id?: string;
  issuer?: string;
}

export interface CloudAuthProvidersResponse {
  providers: CloudAuthProviderInfo[];
  default: string;
}

export interface CloudLoginResponse {
  success: boolean;
  user: {
    email: string;
    name?: string;
  };
  expires_at?: string;
}

export interface CloudSyncResponse {
  success: boolean;
  synced_at: string;
  assessments_synced: number;
  findings_synced: number;
  reports_synced: number;
  total_synced: number;
}

// Multi-account: lightweight list-row representation
export interface CloudAccountSummary {
  id: string;
  name: string;
  api_url: string;
  auth_provider: CloudAuthProvider;
  is_active: boolean;
}

// Full account view (config + identity), returned by get_cloud_account.
// Shape: CloudConfig fields flattened into one object plus id/name/is_active.
export interface CloudAccountResponse extends CloudConfig {
  id: string;
  name: string;
  is_active: boolean;
}

// Input struct for add/update — mirrors CloudConfig plus a name.
export interface CloudAccountInput extends CloudConfig {
  name: string;
}

// =============================================================================
// INTEGRATIONS TYPES
// =============================================================================

export interface GitHubIntegration {
  enabled: boolean;
  personal_access_token?: string;
  username?: string;
}

export interface JiraIntegration {
  enabled: boolean;
  url?: string;
  email?: string;
  api_token?: string;
  project_key?: string;
}

export interface JiraProject {
  id: string;
  key: string;
  name: string;
  projectTypeKey: string;
  avatarUrl?: string;
}

export interface JiraBoard {
  id: number;
  name: string;
  type: string;
  projectKey: string;
}

export interface JiraIssueType {
  id: string;
  name: string;
  description: string;
  subtask: boolean;
  iconUrl?: string;
}

export interface JiraEpic {
  id: string;
  key: string;
  summary: string;
  status: string;
}

export interface JiraSearchResult {
  id: string;
  key: string;
  summary: string;
  issueType: string;
  status: string;
  priority?: string;
  assignee?: string;
}

export interface FindingContentOverride {
  title?: string;
  description?: string;
  evidence?: string;
  remediation?: string;
}

export interface CreateJiraTicketsRequest {
  finding_ids: string[];
  mode: 'individual' | 'combined';
  options: {
    projectKey: string;
    issueType?: string;
    epicKey?: string;
    priority?: string;
    labels?: string[];
    content_overrides?: Record<string, FindingContentOverride>;
  };
  title?: string;
}

export interface CreateJiraTicketsResult {
  status: string;
  total?: number;
  created?: number;
  failed?: number;
  ticket_key?: string;
  results?: Array<{ finding_id: string; status: string; ticket_key?: string; error?: string }>;
  error?: string;
}

export interface IntegrationsConfig {
  github?: GitHubIntegration;
  jira?: JiraIntegration;
}

// =============================================================================
// AI INSTRUCTIONS & ASSESSMENT COMMAND CENTER TYPES
// =============================================================================

/**
 * Escalation rules define when and how the AI should escalate findings
 */
export interface EscalationRule {
  condition: string;                // "CRITICAL finding discovered"
  action: 'alert' | 'pause' | 'continue';
  notify: string[];                 // Contacts to notify
}

/**
 * AI Instructions control how the AI behaves during an assessment
 */
export interface AIInstructions {
  // High-level direction
  missionStatement?: string;         // What are we trying to achieve?

  // System prompt for the AI
  systemPrompt?: string;             // Custom instructions for the AI

  // Focus and priorities
  primaryObjectives?: string[];      // Must achieve
  secondaryObjectives?: string[];    // Nice to have
  outOfScope?: string[];             // Explicitly skip
  focusAreas?: string[];             // Areas to emphasize (e.g., "authentication", "api security")

  // Behavioral guidance
  riskTolerance: 'conservative' | 'balanced' | 'aggressive';
  autonomyLevel: 'supervised' | 'autonomous' | 'full-auto';
  escalationRules?: EscalationRule[];

  // Communication preferences
  updateFrequency: 'realtime' | 'phase-end' | 'completion';
  reportingStyle: 'technical' | 'executive' | 'both';

  // Historical context to consider
  mustVerify?: string[];             // Finding IDs to regression test
  knownIssues?: string[];            // Issues to watch for
  previousContext?: string;          // Free-form context from past

  // Per-phase custom instructions
  phaseInstructions?: {
    recon?: string;
    auth?: string;
    vuln_scan?: string;
    web_app?: string;
    exploit?: string;
    report?: string;
  };

  // Template reference
  templateId?: string;
}

/**
 * Assessment Context provides strategic and historical context
 */
export interface AssessmentContext {
  // Strategic context
  businessJustification?: string;     // "Pre-release gate for payment service"
  complianceFrameworks?: string[];    // ["SOC2", "PCI-DSS"]
  stakeholders?: string[];            // ["CISO", "payment-team"]

  // Historical context (auto-populated)
  previousAssessments?: Assessment[];
  openFindings?: Finding[];
  remediatedFindings?: Finding[];

  // Success criteria
  releaseGate?: boolean;
  requiredOutcomes?: string[];        // ["No critical findings", "SQLi fixed"]

  // Rules of engagement
  testingHours?: string;              // "Business hours only"
  notificationThreshold?: Severity;   // "critical"
  notificationContacts?: string[];
  exploitationRules?: string;         // "Validate but don't persist"
}

/**
 * Mission Brief is the executive summary of an assessment plan
 */
export interface MissionBrief {
  // Header
  title: string;
  objective: string;

  // Targets
  targets: Array<{
    target: string;
    environment?: string;
    owner?: string;
    lastTested?: string;
    inScope: boolean;
  }>;

  // Scope
  includedEndpoints?: string[];
  excludedEndpoints?: string[];

  // Rules of engagement
  rulesOfEngagement: {
    riskProfile: 'conservative' | 'balanced' | 'aggressive';
    exploitationRules?: string;
    testingHours?: string;
    notifyOnCritical?: string[];
  };

  // Success criteria
  successCriteria: string[];

  // Deliverables
  deliverables: string[];

  // Regression tests
  regressionTests?: Array<{
    findingId: string;
    title: string;
    status: FindingStatus;
    lastTested?: string;
  }>;
}

/**
 * Execution Plan shows what the assessment will do.
 *
 * NOTE: the phase/step types here are the *planning* shapes (what the
 * assessment intends to run) and are distinct from the execution-overview
 * `ExecutionPhase` above (what actually ran). They were originally both named
 * `ExecutionPhase`, which collided once the execution-overview contract landed
 * — renamed to `ExecutionPlanPhase` / `ExecutionPlanStep` to disambiguate.
 */
export interface ExecutionPlan {
  phases: ExecutionPlanPhase[];
  estimatedDuration?: string;
  toolsUsed: string[];
}

export interface ExecutionPlanPhase {
  id: string;
  name: string;
  description: string;
  steps: ExecutionPlanStep[];
  dependsOn?: string[];
}

export interface ExecutionPlanStep {
  action: string;
  target?: string;
  tool?: string;
  notes?: string;
}

// =============================================================================
// SCAN SNAPSHOT TYPES
// =============================================================================

export interface ScanSnapshot {
  id: string;
  assessment_id: string;
  target: string;
  scanned_at: string;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  info_count: number;
  total_count: number;
}




// =============================================================================
// HELP RESOURCES (slash commands + agents reference)
// =============================================================================

export interface HelpCommand {
  name: string;          // filename stem — user types `/{name}`
  description: string;
  source_path: string;
}

export interface HelpAgent {
  name: string;
  description: string;
  source_path: string;
  team_only: boolean;    // true when frontmatter `user-invocable: false`
}

export interface HelpResources {
  commands: HelpCommand[];
  agents: HelpAgent[];
  project_root: string;
}
