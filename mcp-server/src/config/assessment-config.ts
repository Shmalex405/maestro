/**
 * Assessment Configuration
 *
 * TypeScript interfaces and YAML loader/validator for assessment configuration.
 * Supports both config file loading and runtime configuration.
 */

import * as fs from "fs";
import * as path from "path";
import * as yaml from "js-yaml";

// ==================== Interfaces ====================

/**
 * Browser login step for automated authentication
 */
export interface BrowserLoginStep {
  action: "navigate" | "fill" | "click" | "wait_for" | "screenshot" | "evaluate";
  /** Target URL (for navigate) */
  url?: string;
  /** CSS selector */
  selector?: string;
  /** Text to match (for click) */
  text?: string;
  /** Value to fill */
  value?: string;
  /** Wait state */
  state?: "visible" | "hidden" | "attached" | "detached";
  /** JavaScript to evaluate */
  script?: string;
  /** Timeout in ms */
  timeout?: number;
  /** Human-readable description of this step */
  description?: string;
}

/**
 * Authentication configuration
 */
export interface AuthConfig {
  /** Step-by-step browser login instructions */
  browser_login?: BrowserLoginStep[];
  /** Credentials reference from credentials.yml */
  credentials_ref?: string;
  /** Auth type hint */
  type?: "session" | "basic" | "bearer" | "api_key" | "oauth2" | "otp_email" | "none";
  /** Expected post-login indicator (CSS selector that appears after login) */
  success_indicator?: string;
  /** URL to verify auth state */
  verify_url?: string;
  /** Session expiry in minutes (for re-auth detection) */
  session_ttl_minutes?: number;
}

/**
 * Focus/scope configuration for the assessment
 */
export interface FocusConfig {
  /** Vulnerability types to include (e.g., ["sqli", "xss", "ssrf"]) */
  include_vuln_types?: string[];
  /** Vulnerability types to exclude */
  exclude_vuln_types?: string[];
  /** Priority endpoints to test first */
  priority_endpoints?: string[];
  /** Endpoints to skip */
  skip_endpoints?: string[];
}

/**
 * Browser configuration
 */
export interface BrowserConfig {
  /** Whether the target is a Single Page Application */
  is_spa?: boolean;
  /** Persist browser session across agents (default: true when auth is configured) */
  persist_session?: boolean;
  /** URL to open at start of browser session */
  start_url?: string;
  /** Additional browser launch args */
  extra_args?: string[];
}

/**
 * Phase override configuration
 */
export interface PhaseConfig {
  /** Override the default phase order */
  order?: string[];
  /** Phases to skip */
  skip?: string[];
  /** Phase-specific options */
  options?: Record<string, Record<string, any>>;
}

/**
 * Reporting configuration
 */
export interface ReportingConfig {
  /** Jira project key for ticket creation */
  jira_project?: string;
  /** Email recipients for report distribution */
  email_recipients?: string[];
  /** Report format */
  format?: "markdown" | "html" | "json";
  /** Upload to SharePoint */
  upload_sharepoint?: boolean;
  /** Minimum severity to include in report */
  min_severity?: "info" | "low" | "medium" | "high" | "critical";
}

/**
 * Full assessment configuration
 */
export interface AssessmentConfig {
  /** Assessment mode: interactive (pauses for guidance) or autonomous (best-effort) */
  mode: "interactive" | "autonomous";
  /** Target URLs, networks, domains */
  targets?: string[];
  /** Repository paths for code scanning */
  repo_paths?: string[];
  /** Authentication configuration */
  auth?: AuthConfig;
  /** Focus/scope for the assessment */
  focus?: FocusConfig;
  /** Browser configuration */
  browser?: BrowserConfig;
  /** Phase overrides */
  phases?: PhaseConfig;
  /** Reporting configuration */
  reporting?: ReportingConfig;
  /** Additional notes/instructions for the AI */
  notes?: string;
}

// ==================== Loader ====================

/**
 * Load assessment config from a YAML file
 */
export function loadAssessmentConfig(filePath?: string): AssessmentConfig | null {
  const configPath = filePath || getDefaultConfigPath();

  if (!fs.existsSync(configPath)) {
    console.log(`[assessment-config] No config file at ${configPath}`);
    return null;
  }

  try {
    const content = fs.readFileSync(configPath, "utf-8");
    const raw = yaml.load(content) as Record<string, any>;

    if (!raw) {
      console.warn("[assessment-config] Empty config file");
      return null;
    }

    const config = validateAndNormalize(raw);
    console.log(
      `[assessment-config] Loaded config: mode=${config.mode}, targets=${config.targets?.length || 0}, auth=${config.auth?.type || "none"}`
    );
    return config;
  } catch (error) {
    console.error(`[assessment-config] Failed to load config: ${error}`);
    return null;
  }
}

/**
 * Create an AssessmentConfig from runtime parameters (e.g., chat briefing)
 */
export function createAssessmentConfig(
  overrides: Partial<AssessmentConfig>
): AssessmentConfig {
  const defaults: AssessmentConfig = {
    mode: "interactive",
    browser: {
      persist_session: true,
    },
  };

  return validateAndNormalize({ ...defaults, ...overrides });
}

/**
 * Merge two configs (file config + runtime overrides)
 */
export function mergeAssessmentConfigs(
  base: AssessmentConfig,
  overrides: Partial<AssessmentConfig>
): AssessmentConfig {
  const merged: AssessmentConfig = {
    ...base,
    ...overrides,
    // Deep merge nested objects
    auth: overrides.auth ? { ...base.auth, ...overrides.auth } : base.auth,
    focus: overrides.focus ? { ...base.focus, ...overrides.focus } : base.focus,
    browser: overrides.browser
      ? { ...base.browser, ...overrides.browser }
      : base.browser,
    phases: overrides.phases
      ? { ...base.phases, ...overrides.phases }
      : base.phases,
    reporting: overrides.reporting
      ? { ...base.reporting, ...overrides.reporting }
      : base.reporting,
    // Merge arrays by override
    targets: overrides.targets || base.targets,
    repo_paths: overrides.repo_paths || base.repo_paths,
  };

  return validateAndNormalize(merged);
}

// ==================== Validation ====================

function validateAndNormalize(raw: Record<string, any>): AssessmentConfig {
  const config: AssessmentConfig = {
    mode: raw.mode === "autonomous" ? "autonomous" : "interactive",
    targets: normalizeStringArray(raw.targets),
    repo_paths: normalizeStringArray(raw.repo_paths),
    notes: raw.notes as string | undefined,
  };

  // Auth
  if (raw.auth) {
    config.auth = {
      browser_login: raw.auth.browser_login
        ? normalizeBrowserLoginSteps(raw.auth.browser_login)
        : undefined,
      credentials_ref: raw.auth.credentials_ref,
      type: raw.auth.type,
      success_indicator: raw.auth.success_indicator,
      verify_url: raw.auth.verify_url,
      session_ttl_minutes: raw.auth.session_ttl_minutes,
    };
  }

  // Focus
  if (raw.focus) {
    config.focus = {
      include_vuln_types: normalizeStringArray(raw.focus.include_vuln_types),
      exclude_vuln_types: normalizeStringArray(raw.focus.exclude_vuln_types),
      priority_endpoints: normalizeStringArray(raw.focus.priority_endpoints),
      skip_endpoints: normalizeStringArray(raw.focus.skip_endpoints),
    };
  }

  // Browser
  if (raw.browser) {
    config.browser = {
      is_spa: raw.browser.is_spa === true,
      persist_session: raw.browser.persist_session !== false, // default true
      start_url: raw.browser.start_url,
      extra_args: normalizeStringArray(raw.browser.extra_args),
    };
  } else {
    // Default browser config
    config.browser = {
      persist_session: !!config.auth?.browser_login,
    };
  }

  // Phases
  if (raw.phases) {
    config.phases = {
      order: normalizeStringArray(raw.phases.order),
      skip: normalizeStringArray(raw.phases.skip),
      options: raw.phases.options || {},
    };
  }

  // Reporting
  if (raw.reporting) {
    config.reporting = {
      jira_project: raw.reporting.jira_project,
      email_recipients: normalizeStringArray(raw.reporting.email_recipients),
      format: raw.reporting.format || "markdown",
      upload_sharepoint: raw.reporting.upload_sharepoint === true,
      min_severity: raw.reporting.min_severity || "low",
    };
  }

  return config;
}

function normalizeStringArray(value: any): string[] | undefined {
  if (!value) return undefined;
  if (Array.isArray(value)) return value.map(String);
  if (typeof value === "string") return [value];
  return undefined;
}

function normalizeBrowserLoginSteps(steps: any[]): BrowserLoginStep[] {
  return steps.map((step) => ({
    action: step.action,
    url: step.url,
    selector: step.selector,
    text: step.text,
    value: step.value,
    state: step.state,
    script: step.script,
    timeout: step.timeout,
    description: step.description,
  }));
}

function getDefaultConfigPath(): string {
  // Navigate from mcp-server/src/config to config/assessment.yml
  return path.join(__dirname, "../../../config/assessment.yml");
}
