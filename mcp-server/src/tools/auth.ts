import { refreshAppToken, getAuthConfig } from "../utils/auth-handler";

/**
 * `authenticate` — lets an assessment agent obtain a FRESH bearer token by
 * performing a real server-side login (credentials never appear in the agent's
 * prompt). Agents call this when a request returns HTTP 401 mid-assessment: the
 * original token died at its JWT TTL (e.g. 15 min) while the chunk ran longer.
 * Re-login + retry beats the old "mark AUTH_EXPIRED → BLOCKED" behavior that
 * silently turned authenticated runs into unauthenticated ones.
 */
export const authTools = [
  {
    name: "authenticate",
    description:
      "Re-authenticate to the in-scope application and return a FRESH bearer token via a real server-side login (credentials stay server-side — never passed in). Use on HTTP 401 mid-assessment: call authenticate, update your Authorization header with the returned header_value, and retry the failed request. Also returns `role` — the credential's declared privilege (admin/privileged/standard/readonly, or 'unknown') — which the assessment lead uses to fill {AUTH_ROLE} for finding calibration. Returns {app, token, header_value: 'Bearer <token>', auth_type, role} or {error}.",
    inputSchema: {
      type: "object",
      properties: {
        app_name: {
          type: "string",
          description:
            "Application name from the credentials config. Optional — defaults to the single in-scope app when only one is configured.",
        },
      },
    },
  },
  {
    name: "get_auth_role",
    description:
      "Return the declared privilege level (role) of an in-scope application credential WITHOUT logging in — one of admin/privileged/standard/readonly, or 'unknown' if undeclared. The assessment lead calls this once during the auth phase to fill {AUTH_ROLE} for finding calibration. Works for ANY auth_type (including basic, where `authenticate` cannot refresh a token). Returns {app, role}.",
    inputSchema: {
      type: "object",
      properties: {
        app_name: {
          type: "string",
          description:
            "Application name from the credentials config. Optional — defaults to the single in-scope authenticated app.",
        },
      },
    },
  },
];

export const authHandlers: Record<string, (args: any) => Promise<string>> = {
  authenticate: async (args: any): Promise<string> => {
    const result = await refreshAppToken(args?.app_name);
    return JSON.stringify(result);
  },

  get_auth_role: async (args: any): Promise<string> => {
    const config = await getAuthConfig();
    // Fail-safe: no config / no apps ⇒ unknown (never throw, never downgrade).
    if (!config?.applications?.length) {
      return JSON.stringify({ app: args?.app_name ?? null, role: "unknown" });
    }
    let app = args?.app_name
      ? config.applications.find((a) => a.name === args.app_name)
      : undefined;
    if (!app && !args?.app_name) {
      const candidates = config.applications.filter((a) => a.auth_type !== "none");
      if (candidates.length === 1) app = candidates[0];
      else if (candidates.length > 1)
        return JSON.stringify({
          error: `Pass app_name — ${candidates.length} apps in credentials config: ${candidates
            .map((a) => a.name)
            .join(", ")}`,
        });
    }
    // No matching authenticated app ⇒ anonymous/undeclared ⇒ unknown (no downgrade).
    if (!app) return JSON.stringify({ app: args?.app_name ?? null, role: "unknown" });
    return JSON.stringify({ app: app.name, role: app.role || "unknown" });
  },
};
