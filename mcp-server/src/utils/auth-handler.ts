import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import * as yaml from "yaml";

export interface OtpConfig {
  initiate_url: string;
  initiate_method: string;
  initiate_body: Record<string, string>;
  username_field: string;
  username_value: string;
  verify_url: string;
  verify_method: string;
  verify_body: Record<string, string>;
  session_token_location: string;
  session_token_name: string;
  otp_timeout?: number;
}

export interface AppCredentials {
  name: string;
  environment: string;
  base_url: string;
  auth_type: "session" | "basic" | "bearer" | "api_key" | "oauth2" | "otp_email" | "none";
  /** Intended privilege level of the authenticated identity (admin |
   *  privileged | standard | readonly). Injected into the assessment as
   *  {AUTH_ROLE} so findings are calibrated to the role. Unset ⇒ no downgrade. */
  role?: string;
  credentials?: Record<string, string>;
  headers?: Record<string, string>;
  login_url?: string;
  login_method?: string;
  login_body?: Record<string, string>;
  session_token_location?: string;
  session_token_name?: string;
  interactive?: boolean;
  otp_config?: OtpConfig;
  oauth2?: {
    token_url: string;
    client_id: string;
    client_secret: string;
    scope: string;
    grant_type: string;
  };
}

// Callback type for OTP prompt
export type OtpPromptCallback = (appName: string, username: string) => Promise<string>;

export interface AuthConfig {
  applications: AppCredentials[];
  default_headers: Record<string, string>;
  test_accounts: Record<string, {
    username: string;
    password: string;
    role: string;
  }>;
}

let authConfig: AuthConfig | null = null;
const sessionCache: Map<string, { token: string; expires: number }> = new Map();

// Global OTP prompt callback - set this to enable interactive OTP
let otpPromptCallback: OtpPromptCallback | null = null;

/**
 * Set the callback function for OTP prompts
 * This should be called at startup to enable interactive OTP authentication
 */
export function setOtpPromptCallback(callback: OtpPromptCallback): void {
  otpPromptCallback = callback;
}

/**
 * Check if OTP prompting is available
 */
export function isOtpPromptAvailable(): boolean {
  return otpPromptCallback !== null;
}

/**
 * Path to the desktop-materialized merged credentials JSON. Tauri writes
 * this on sign-in and on every credentials update — it merges the cloud
 * `org_configs` shared metadata with the per-user OS-keychain secrets so
 * we don't need keychain access from inside the container.
 *
 * Override with MAESTRO_CREDENTIALS_PATH (used by docker.rs to point inside
 * `/mnt/host-home`).
 */
const CREDENTIALS_FILE_PATH =
  process.env.MAESTRO_CREDENTIALS_PATH ||
  path.join(os.homedir(), ".kali-mcp-pentest", "credentials-merged.json");

/**
 * Normalize the cloud/desktop CredentialsConfig (Record<appName, flat fields>)
 * into the MCP server's nested AuthConfig (applications: AppCredentials[]
 * with sub-objects for `credentials`, `oauth2`, `otp_config`).
 *
 * Field mapping by auth_type:
 *   - basic / session   → credentials.{username, password}
 *   - bearer            → credentials.token
 *   - api_key           → credentials.token + headers[header_name]
 *   - session also gets → login_url + login_body + session_token_name
 *   - oauth2            → oauth2.{token_url, client_id, client_secret, scope, grant_type}
 *   - otp_email         → otp_config.{initiate_url, verify_url, ...}
 */
function normalizeCloudCredentials(input: unknown): AuthConfig {
  const src = (input ?? {}) as Record<string, unknown>;
  const apps = (src.applications ?? {}) as Record<string, Record<string, unknown>>;

  const applications: AppCredentials[] = [];
  for (const [name, raw] of Object.entries(apps)) {
    const a = raw || {};
    const authType = (a.auth_type as AppCredentials["auth_type"]) || "none";
    const out: AppCredentials = {
      name: (a.name as string) || name,
      environment: (a.environment as string) || "production",
      base_url: (a.base_url as string) || "",
      auth_type: authType,
    };

    // Privilege level of this credential's identity — passes through verbatim
    // so the assessment can calibrate access-control findings to the role.
    if (typeof a.role === "string" && a.role.trim()) out.role = a.role.trim();

    // Username/password lives on credentials.{...} for basic/session.
    if (authType === "basic" || authType === "session") {
      out.credentials = {
        username: (a.username as string) || "",
        password: (a.password as string) || "",
      };
    }

    // Bearer / api_key share `token` under credentials; api_key also adds
    // a custom header so downstream code that reads `app.headers` works.
    if (authType === "bearer" || authType === "api_key") {
      out.credentials = { token: (a.token as string) || "" };
      const headerName = (a.header_name as string) || "Authorization";
      const value =
        authType === "bearer"
          ? `Bearer ${a.token || ""}`
          : (a.token as string) || "";
      out.headers = { [headerName]: value };
    }

    // Session login flow. The desktop UI only collects login_url + username +
    // password (not login_payload/token_field), so synthesize a sensible login
    // body from the credentials and let getSessionToken auto-detect the token
    // (configured field → common keys → JWT-by-shape in body/header/cookie) when
    // token_field is absent. Explicit login_payload/token_field still win.
    if (authType === "session") {
      const username = (a.username as string) || "";
      const password = (a.password as string) || "";
      out.credentials = { username, password };
      if (a.login_url) out.login_url = a.login_url as string;
      out.login_method = (a.login_method as string) || "POST";
      if (a.login_payload && typeof a.login_payload === "object") {
        out.login_body = a.login_payload as Record<string, string>;
      } else if (username || password) {
        out.login_body = { email: username, password };
      }
      out.session_token_location =
        (a.session_token_location as "cookie" | "header" | "body") || "body";
      if (a.token_field) out.session_token_name = a.token_field as string;
    }

    // OAuth2 client credentials.
    if (authType === "oauth2") {
      const scopes = Array.isArray(a.scopes)
        ? (a.scopes as string[]).join(" ")
        : "";
      out.oauth2 = {
        token_url: (a.token_url as string) || "",
        client_id: (a.client_id as string) || "",
        client_secret: (a.client_secret as string) || "",
        scope: scopes,
        grant_type: "client_credentials",
      };
    }

    // OTP email flow. Cloud shape only carries the URL + email; we fill
    // sensible defaults that match the existing local-YAML pattern.
    if (authType === "otp_email") {
      const email = (a.email as string) || "";
      out.otp_config = {
        initiate_url: (a.initiate_url as string) || "",
        initiate_method: "POST",
        initiate_body: { email },
        username_field: "email",
        username_value: email,
        verify_url: (a.verify_url as string) || "",
        verify_method: "POST",
        verify_body: { email, code: "{{OTP_CODE}}" },
        session_token_location: "body",
        session_token_name: (a.token_field as string) || "token",
      };
      out.interactive = true;
    }

    applications.push(out);
  }

  // Test accounts pass through verbatim — same shape on both sides.
  const testAccountsSrc = (src.test_accounts ?? {}) as Record<
    string,
    { username?: string; password?: string; role?: string }
  >;
  const test_accounts: AuthConfig["test_accounts"] = {};
  for (const [role, ta] of Object.entries(testAccountsSrc)) {
    test_accounts[role] = {
      username: ta?.username || "",
      password: ta?.password || "",
      role: ta?.role || role,
    };
  }

  return {
    applications,
    default_headers: {},
    test_accounts,
  };
}

/**
 * Read the desktop-materialized merged credentials file. Returns null if
 * the file is absent or malformed — the caller falls back to local YAML.
 */
function loadMaterializedCredentials(): AuthConfig | null {
  try {
    if (!fs.existsSync(CREDENTIALS_FILE_PATH)) return null;
    const raw = fs.readFileSync(CREDENTIALS_FILE_PATH, "utf-8");
    if (!raw.trim()) return null;
    return normalizeCloudCredentials(JSON.parse(raw));
  } catch (err) {
    console.warn(
      `[auth-handler] failed to read materialized credentials at ${CREDENTIALS_FILE_PATH}: ${err}`
    );
    return null;
  }
}

/**
 * Load credentials from local YAML — the offline path and the fallback
 * when no merged file has been written by the desktop yet.
 *
 * Priority order:
 *   1. `<credentials.yml>.local` next to CREDENTIALS_CONFIG_PATH — gitignored
 *      personal override so individual users keep real secrets out of the
 *      committed template.
 *   2. CREDENTIALS_CONFIG_PATH itself.
 */
function loadLocalCredentials(): AuthConfig {
  const configPath = process.env.CREDENTIALS_CONFIG_PATH || "../config/credentials.yml";
  const localPath = configPath.replace(/\.yml$/, ".local.yml");
  for (const candidate of [localPath, configPath]) {
    try {
      if (!fs.existsSync(candidate)) continue;
      let content = fs.readFileSync(candidate, "utf-8");
      content = content.replace(/\$\{(\w+)\}/g, (_, varName) => {
        return process.env[varName] || "";
      });
      return yaml.parse(content) as AuthConfig;
    } catch (error) {
      console.warn(`[auth-handler] failed to parse ${candidate}:`, error);
    }
  }
  console.warn("[auth-handler] no credentials file found, using empty config");
  return { applications: [], default_headers: {}, test_accounts: {} };
}

export async function loadAuthConfig(): Promise<AuthConfig> {
  const fromDesktop = loadMaterializedCredentials();
  authConfig = fromDesktop ?? loadLocalCredentials();
  return authConfig;
}

export async function getAuthConfig(): Promise<AuthConfig> {
  if (!authConfig) {
    return loadAuthConfig();
  }
  return authConfig;
}

export async function getAppCredentials(appName: string): Promise<AppCredentials | null> {
  const config = await getAuthConfig();
  return config.applications.find(app => app.name === appName) || null;
}

export async function getAuthHeaders(appName: string): Promise<Record<string, string>> {
  const app = await getAppCredentials(appName);
  const config = await getAuthConfig();
  
  if (!app) {
    return config.default_headers;
  }
  
  const headers: Record<string, string> = { ...config.default_headers };
  
  switch (app.auth_type) {
    case "basic":
      const basicAuth = Buffer.from(
        `${app.credentials?.username}:${app.credentials?.password}`
      ).toString("base64");
      headers["Authorization"] = `Basic ${basicAuth}`;
      break;
      
    case "bearer":
      headers["Authorization"] = `Bearer ${app.credentials?.token}`;
      break;
      
    case "api_key":
      if (app.headers) {
        Object.assign(headers, app.headers);
      }
      break;
      
    case "session":
      const session = await getSessionToken(app);
      if (session) {
        if (app.session_token_location === "header") {
          headers[app.session_token_name || "Authorization"] = session;
        }
        // Cookie handled separately
      }
      break;
      
    case "oauth2":
      const oauthToken = await getOAuth2Token(app);
      if (oauthToken) {
        headers["Authorization"] = `Bearer ${oauthToken}`;
      }
      break;

    case "otp_email":
      const otpSession = await getOtpSessionToken(app);
      if (otpSession) {
        if (app.otp_config?.session_token_location === "header") {
          headers[app.otp_config.session_token_name || "Authorization"] = otpSession;
        }
        // Cookie handled separately
      }
      break;
  }

  return headers;
}

/**
 * Force a FRESH authentication for an app and return the bearer token,
 * BYPASSING the session cache. Backs the `authenticate` MCP tool so DAST
 * agents can self-refresh on a 401 instead of relying on a static token that
 * dies at the (e.g. 15-min) JWT TTL — note getSessionToken caches for 1h, so
 * the cache itself can hand back an already-dead token, which is exactly the
 * 401 we recover from here. Resolves `appName` if given, else the single
 * non-"none" application in the credentials config.
 */
export async function refreshAppToken(
  appName?: string,
): Promise<
  { app: string; token: string; header_value: string; auth_type: string; role: string } | { error: string }
> {
  const config = await getAuthConfig();
  let app: AppCredentials | undefined = appName
    ? config.applications.find((a) => a.name === appName)
    : undefined;
  if (!app && !appName) {
    const candidates = config.applications.filter((a) => a.auth_type !== "none");
    if (candidates.length === 1) app = candidates[0];
    else
      return {
        error: `Pass app_name — ${candidates.length} apps in credentials config: ${candidates
          .map((a) => a.name)
          .join(", ")}`,
      };
  }
  if (!app) return { error: `No app named '${appName}' in credentials config` };

  // Clear cached tokens so we perform a real login, not return a stale one.
  sessionCache.delete(`session:${app.name}`);
  sessionCache.delete(`oauth2:${app.name}`);

  let token: string | null = null;
  if (app.auth_type === "session") token = await getSessionToken(app);
  else if (app.auth_type === "oauth2") token = await getOAuth2Token(app);
  else if (app.auth_type === "otp_email") token = await getOtpSessionToken(app);
  else if (app.auth_type === "bearer") token = app.credentials?.token || null;
  else
    return { error: `auth_type '${app.auth_type}' for ${app.name} cannot be auto-refreshed` };

  if (!token)
    return {
      error: `Re-authentication produced no token for ${app.name} — check the credentials config (login_url / login_body / session_token_location / session_token_name).`,
    };
  // Surface the credential's declared privilege so the assessment lead can fill
  // {AUTH_ROLE} deterministically from this same call. "unknown" ⇒ no downgrade.
  return {
    app: app.name,
    token,
    header_value: `Bearer ${token}`,
    auth_type: app.auth_type,
    role: app.role || "unknown",
  };
}

// A JWT is three base64url segments separated by dots, the first beginning "eyJ".
const JWT_RE = /eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/;

// Recursively search a parsed JSON value for the first JWT-shaped string. Lets
// session auth find the token even when the response field name is unknown.
function findJwtDeep(v: unknown): string | null {
  if (typeof v === "string") {
    const m = v.match(JWT_RE);
    return m ? m[0] : null;
  }
  if (Array.isArray(v)) {
    for (const x of v) {
      const f = findJwtDeep(x);
      if (f) return f;
    }
    return null;
  }
  if (v && typeof v === "object") {
    for (const x of Object.values(v)) {
      const f = findJwtDeep(x);
      if (f) return f;
    }
  }
  return null;
}

async function getSessionToken(app: AppCredentials): Promise<string | null> {
  const cacheKey = `session:${app.name}`;
  const cached = sessionCache.get(cacheKey);

  if (cached && cached.expires > Date.now()) {
    return cached.token;
  }

  // The desktop UI may supply only login_url + username/password (no explicit
  // login_body). Synthesize an {email,password} body from the credentials so a
  // session target configured through the UI still logs in.
  const loginBody =
    app.login_body ||
    (app.credentials?.username || app.credentials?.password
      ? { email: app.credentials?.username || "", password: app.credentials?.password || "" }
      : null);
  if (!app.login_url || !loginBody) {
    return null;
  }

  // Use login_url as-is when it's absolute. A session target's login often
  // lives on a concrete host (e.g. https://app.example.com/api/auth/login),
  // while base_url may be a wildcard scope domain (https://*.example.com) that
  // can't be a real request host — joining the two would break the URL. Only
  // prepend base_url for a relative path.
  const loginEndpoint = /^https?:\/\//i.test(app.login_url)
    ? app.login_url
    : `${app.base_url}${app.login_url}`;

  try {
    const response = await fetch(loginEndpoint, {
      method: app.login_method || "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(loginBody),
    });

    if (!response.ok) {
      console.error(`Login failed for ${app.name}: ${response.status}`);
      return null;
    }

    // Read the body once as text so we can handle a JSON object OR a raw token.
    const rawBody = await response.text();
    let parsed: unknown = null;
    try { parsed = JSON.parse(rawBody); } catch { /* non-JSON body */ }
    const cookies = response.headers.get("set-cookie") || "";

    // Best-effort, auto-detecting extraction: the UI rarely knows the exact
    // field/cookie name, so try the configured location/name first, then common
    // token keys, then any JWT-shaped value in the body, Authorization header,
    // or a Set-Cookie. Explicitly-configured names always win.
    let token: string | null = null;
    const loc = app.session_token_location || "body";

    if (loc === "cookie" && app.session_token_name) {
      const m = cookies.match(new RegExp(`${app.session_token_name}=([^;]+)`));
      if (m) token = m[1];
    }
    if (!token && parsed && typeof parsed === "object") {
      const obj = parsed as Record<string, unknown>;
      if (app.session_token_name && typeof obj[app.session_token_name] === "string") {
        token = obj[app.session_token_name] as string;
      }
      if (!token) {
        for (const k of ["access_token", "accessToken", "token", "jwt", "id_token", "idToken", "sessionToken", "session"]) {
          if (typeof obj[k] === "string") { token = obj[k] as string; break; }
        }
      }
      if (!token) token = findJwtDeep(parsed);
    }
    if (!token) {
      const fromText = rawBody.match(JWT_RE);
      if (fromText) token = fromText[0];
      else {
        const fromAuth = (response.headers.get("authorization") || "").match(JWT_RE);
        if (fromAuth) token = fromAuth[0];
        else {
          const fromCookie = cookies.match(JWT_RE);
          if (fromCookie) token = fromCookie[0];
        }
      }
    }

    if (token) {
      sessionCache.set(cacheKey, {
        token,
        expires: Date.now() + 3600000, // 1 hour
      });
    }

    return token;
  } catch (error) {
    console.error(`Session auth error for ${app.name}:`, error);
    return null;
  }
}

async function getOAuth2Token(app: AppCredentials): Promise<string | null> {
  if (!app.oauth2) return null;
  
  const cacheKey = `oauth2:${app.name}`;
  const cached = sessionCache.get(cacheKey);
  
  if (cached && cached.expires > Date.now()) {
    return cached.token;
  }
  
  try {
    const response = await fetch(app.oauth2.token_url, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: app.oauth2.grant_type,
        client_id: app.oauth2.client_id,
        client_secret: app.oauth2.client_secret,
        scope: app.oauth2.scope,
      }),
    });
    
    if (!response.ok) {
      console.error(`OAuth2 failed for ${app.name}: ${response.status}`);
      return null;
    }
    
    const data = await response.json() as { access_token: string; expires_in?: number };
    const token = data.access_token;
    const expiresIn = data.expires_in || 3600;
    
    sessionCache.set(cacheKey, {
      token,
      expires: Date.now() + (expiresIn * 1000) - 60000, // Refresh 1 min early
    });
    
    return token;
  } catch (error) {
    console.error(`OAuth2 error for ${app.name}:`, error);
    return null;
  }
}

export function clearSessionCache(): void {
  sessionCache.clear();
}

export async function getTestAccount(role: string): Promise<{ username: string; password: string } | null> {
  const config = await getAuthConfig();
  const account = config.test_accounts[role];

  if (!account) {
    return null;
  }

  return {
    username: account.username,
    password: account.password,
  };
}

/**
 * Get session token via OTP authentication
 * This is an interactive flow that prompts the user for the OTP code
 */
async function getOtpSessionToken(app: AppCredentials): Promise<string | null> {
  if (!app.otp_config) {
    console.error(`OTP config missing for ${app.name}`);
    return null;
  }

  const cacheKey = `otp_session:${app.name}`;
  const cached = sessionCache.get(cacheKey);

  if (cached && cached.expires > Date.now()) {
    return cached.token;
  }

  const otpConfig = app.otp_config;

  try {
    // Step 1: Initiate OTP (send the code to user's email/phone)
    console.log(`[OTP Auth] Initiating OTP for ${app.name}...`);

    const initiateResponse = await fetch(`${app.base_url}${otpConfig.initiate_url}`, {
      method: otpConfig.initiate_method || "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(otpConfig.initiate_body),
    });

    if (!initiateResponse.ok) {
      console.error(`[OTP Auth] Failed to initiate OTP for ${app.name}: ${initiateResponse.status}`);
      const errorText = await initiateResponse.text();
      console.error(`[OTP Auth] Error response: ${errorText}`);
      return null;
    }

    console.log(`[OTP Auth] OTP sent to ${otpConfig.username_value}`);

    // Step 2: Prompt user for OTP code
    if (!otpPromptCallback) {
      console.error(`[OTP Auth] No OTP prompt callback configured. Cannot get OTP interactively.`);
      console.error(`[OTP Auth] Set the callback using setOtpPromptCallback() or provide OTP via API.`);
      return null;
    }

    console.log(`[OTP Auth] Waiting for user to enter OTP code...`);
    const otpCode = await otpPromptCallback(app.name, otpConfig.username_value);

    if (!otpCode) {
      console.error(`[OTP Auth] No OTP code provided`);
      return null;
    }

    // Step 3: Verify OTP and get session token
    console.log(`[OTP Auth] Verifying OTP code...`);

    // Replace {{OTP_CODE}} placeholder in verify body
    const verifyBody: Record<string, string> = {};
    for (const [key, value] of Object.entries(otpConfig.verify_body)) {
      verifyBody[key] = value.replace("{{OTP_CODE}}", otpCode);
    }

    const verifyResponse = await fetch(`${app.base_url}${otpConfig.verify_url}`, {
      method: otpConfig.verify_method || "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(verifyBody),
    });

    if (!verifyResponse.ok) {
      console.error(`[OTP Auth] OTP verification failed for ${app.name}: ${verifyResponse.status}`);
      const errorText = await verifyResponse.text();
      console.error(`[OTP Auth] Error response: ${errorText}`);
      return null;
    }

    // Extract session token from response
    let token: string | null = null;

    if (otpConfig.session_token_location === "cookie") {
      const cookies = verifyResponse.headers.get("set-cookie");
      if (cookies) {
        const match = cookies.match(new RegExp(`${otpConfig.session_token_name}=([^;]+)`));
        if (match) {
          token = match[1];
        }
      }
    } else if (otpConfig.session_token_location === "body") {
      const body = await verifyResponse.json() as Record<string, string>;
      token = body[otpConfig.session_token_name || "token"];
    } else if (otpConfig.session_token_location === "header") {
      token = verifyResponse.headers.get(otpConfig.session_token_name || "Authorization");
    }

    if (token) {
      console.log(`[OTP Auth] Successfully authenticated with ${app.name}`);
      sessionCache.set(cacheKey, {
        token,
        expires: Date.now() + 3600000, // 1 hour default
      });
      return token;
    }

    console.error(`[OTP Auth] Could not extract session token from response`);
    return null;
  } catch (error) {
    console.error(`[OTP Auth] Error during OTP authentication for ${app.name}:`, error);
    return null;
  }
}

/**
 * Manually authenticate with OTP (for API/frontend use)
 * Returns session token if successful
 */
export async function authenticateWithOtp(
  appName: string,
  otpCode: string
): Promise<{ success: boolean; token?: string; error?: string }> {
  const app = await getAppCredentials(appName);

  if (!app) {
    return { success: false, error: `Application ${appName} not found` };
  }

  if (app.auth_type !== "otp_email" || !app.otp_config) {
    return { success: false, error: `Application ${appName} does not use OTP authentication` };
  }

  const otpConfig = app.otp_config;

  try {
    // Replace {{OTP_CODE}} placeholder in verify body
    const verifyBody: Record<string, string> = {};
    for (const [key, value] of Object.entries(otpConfig.verify_body)) {
      verifyBody[key] = value.replace("{{OTP_CODE}}", otpCode);
    }

    const verifyResponse = await fetch(`${app.base_url}${otpConfig.verify_url}`, {
      method: otpConfig.verify_method || "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(verifyBody),
    });

    if (!verifyResponse.ok) {
      const errorText = await verifyResponse.text();
      return { success: false, error: `OTP verification failed: ${errorText}` };
    }

    // Extract session token
    let token: string | null = null;

    if (otpConfig.session_token_location === "cookie") {
      const cookies = verifyResponse.headers.get("set-cookie");
      if (cookies) {
        const match = cookies.match(new RegExp(`${otpConfig.session_token_name}=([^;]+)`));
        if (match) {
          token = match[1];
        }
      }
    } else if (otpConfig.session_token_location === "body") {
      const body = await verifyResponse.json() as Record<string, string>;
      token = body[otpConfig.session_token_name || "token"];
    }

    if (token) {
      const cacheKey = `otp_session:${app.name}`;
      sessionCache.set(cacheKey, {
        token,
        expires: Date.now() + 3600000,
      });
      return { success: true, token };
    }

    return { success: false, error: "Could not extract session token from response" };
  } catch (error) {
    return { success: false, error: String(error) };
  }
}

/**
 * Initiate OTP flow (send OTP to user's email/phone)
 * Call this first, then call authenticateWithOtp with the received code
 */
export async function initiateOtpFlow(
  appName: string
): Promise<{ success: boolean; username?: string; error?: string }> {
  const app = await getAppCredentials(appName);

  if (!app) {
    return { success: false, error: `Application ${appName} not found` };
  }

  if (app.auth_type !== "otp_email" || !app.otp_config) {
    return { success: false, error: `Application ${appName} does not use OTP authentication` };
  }

  const otpConfig = app.otp_config;

  try {
    const initiateResponse = await fetch(`${app.base_url}${otpConfig.initiate_url}`, {
      method: otpConfig.initiate_method || "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(otpConfig.initiate_body),
    });

    if (!initiateResponse.ok) {
      const errorText = await initiateResponse.text();
      return { success: false, error: `Failed to initiate OTP: ${errorText}` };
    }

    return { success: true, username: otpConfig.username_value };
  } catch (error) {
    return { success: false, error: String(error) };
  }
}
