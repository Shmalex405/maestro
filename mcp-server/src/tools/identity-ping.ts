import { executeInKali } from "../utils/docker-exec";

// =============================================================================
// IDENTITY — Ping Identity (PingOne / PingFederate) red-team MCP tool module.
//
// Authorized red-team tooling for Ping Identity infrastructure that customers
// explicitly authorize — same model as identity-entra.ts / identity-ad.ts.
//
// Mirrors the cloud-recon.ts / cloud-iam.ts / identity-ad.ts pattern exactly:
//   - `identityPingTools`    : MCP tool definitions (name, description, inputSchema)
//   - `identityPingHandlers` : Record<string, Function> shelling out via executeInKali
//
// CLOUD W1b LESSON (applied at design time): every handler runs a
// `command -v <tool>` preflight (INSTALLED / NOT INSTALLED) and uses `2>&1`
// (NOT `2>/dev/null`) so a packaging gap is never silently mistaken for an auth
// failure, and real tool errors surface in the output. Commands end with
// `2>&1 || echo "... FAILED"` and all interpolated values are shell-escaped.
//
// CONVENTIONS:
//   - EVERY tool's first required inputSchema arg is `tenant_id` (the PingOne
//     environment id or org domain) so the parent scope validator can pin it to
//     the in-scope Ping tenant (the identity analog of cloud `cloud_account_id`).
//   - Tool names carry a stable, unambiguous identity-Ping token for finding
//     categorization: enum_ping_*, abuse_ping_*, test_ping_*.
//
// SAFETY (.claude/agents/_preamble.md):
//   - NON-DESTRUCTIVE: enumerate, prove access, replay read-only. Never delete /
//     reset / create costly resources. Every state-changing op gates behind an
//     explicit `attempt_*: boolean` defaulting to FALSE.
//   - Auth probing is lockout-aware and fail-closed (no guessed thresholds).
//
// PingOne API surface used:
//   - Auth service:  https://auth.pingone.{tld}/{envId}/...  (OIDC / .well-known)
//   - Management API: https://api.pingone.{tld}/v1/environments/{envId}/...
//   where {tld} is com (NA), eu (EU), asia (AP), or ca (CA) by region.
// =============================================================================

// Shell-escape a value for safe single-quoted embedding in a bash command.
// Wraps in single quotes and escapes embedded single quotes via '\''.
function sq(value: string): string {
  return `'${String(value).replace(/'/g, `'\\''`)}'`;
}

// Build the standard tool-availability preflight line (cloud W1b lesson).
function preflight(tool: string, versionFlag = "--version"): string {
  return `command -v ${tool} >/dev/null 2>&1 && echo "${tool}: INSTALLED ($(${tool} ${versionFlag} 2>&1 | head -1))" || echo "${tool}: NOT INSTALLED"`;
}

// Map a PingOne region code to the API/auth domain TLD.
// NA -> com, EU -> eu, AP/ASIA -> asia, CA -> ca. Defaults to com (NA).
function regionTld(region?: string): string {
  switch ((region || "NA").toUpperCase()) {
    case "EU":
      return "eu";
    case "AP":
    case "ASIA":
      return "asia";
    case "CA":
      return "ca";
    case "NA":
    default:
      return "com";
  }
}

export const identityPingTools = [
  // ===========================================================================
  // RECON (deterministic)
  // ===========================================================================
  {
    name: "enum_ping_org",
    description:
      "[PING RECON — no auth] PingOne environment fingerprint: pulls the OIDC /.well-known/openid-configuration, the environment authorization/token/JWKS endpoints, and the SAML IdP metadata to identify the Ping deployment (PingOne vs PingFederate), supported flows, signing keys, and region. Unauthenticated.",
    inputSchema: {
      type: "object",
      properties: {
        tenant_id: {
          type: "string",
          description: "PingOne environment id or org domain for scope validation",
        },
        ping_env_id: {
          type: "string",
          description: "PingOne environment (env) GUID used to build the auth/.well-known URLs (defaults to tenant_id)",
        },
        ping_region: {
          type: "string",
          description: "PingOne region: NA / EU / AP / CA (selects api/auth domain TLD; default NA)",
          default: "NA",
        },
        base_url: {
          type: "string",
          description: "Optional explicit issuer/base URL for self-hosted PingFederate (e.g. https://sso.corp.com) — overrides the PingOne auth domain",
        },
      },
      required: ["tenant_id"],
    },
  },
  {
    name: "enum_ping_users",
    description:
      "[PING RECON — worker token OR auth-flow oracle] Enumerate PingOne users via the Management API (GET /v1/environments/{envId}/users, with a worker app token) or, when no token is supplied, via authentication-flow behavior differences (existing vs non-existing username responses). Read-only — no password attempts.",
    inputSchema: {
      type: "object",
      properties: {
        tenant_id: {
          type: "string",
          description: "PingOne environment id or org domain for scope validation",
        },
        ping_env_id: {
          type: "string",
          description: "PingOne environment GUID (defaults to tenant_id)",
        },
        ping_region: {
          type: "string",
          description: "PingOne region NA / EU / AP / CA (default NA)",
          default: "NA",
        },
        ping_worker_token: {
          type: "string",
          description: "PingOne worker-app access token for the Management API (brokered, short-lived). If present, enumerates via the users endpoint.",
        },
        userlist: {
          type: "array",
          items: { type: "string" },
          description: "Candidate usernames/emails to test for existence via auth-flow behavior when no worker token is supplied",
        },
        base_url: {
          type: "string",
          description: "Optional explicit auth base URL for self-hosted PingFederate",
        },
      },
      required: ["tenant_id"],
    },
  },

  // ===========================================================================
  // EXPLOITATION
  // ===========================================================================
  {
    name: "abuse_ping_oauth",
    description:
      "[PING EXPLOIT — needs WORKER TOKEN — non-destructive by default] OAuth application + consent / worker-app abuse analysis: enumerates PingOne OAuth/OIDC application registrations, their grant types, redirect URIs, and worker-app roles to find over-privileged or loosely-scoped apps (e.g. wildcard redirect URIs, implicit grant, client-credentials worker apps with admin roles). DEFAULT IS READ-ONLY (enumerate candidates). Registering/granting a new app is a WRITE op gated behind attempt_grant=true (defaults FALSE) and follows the user-confirm protocol (.claude/agents/_preamble.md).",
    inputSchema: {
      type: "object",
      properties: {
        tenant_id: {
          type: "string",
          description: "PingOne environment id or org domain for scope validation",
        },
        ping_env_id: {
          type: "string",
          description: "PingOne environment GUID (defaults to tenant_id)",
        },
        ping_region: {
          type: "string",
          description: "PingOne region NA / EU / AP / CA (default NA)",
          default: "NA",
        },
        ping_worker_token: {
          type: "string",
          description: "PingOne worker-app access token with application-read (or, for the write path, application-write) rights (brokered)",
        },
        app_name: {
          type: "string",
          description: "Display name for an injected OAuth app (write path only)",
          default: "maestro-consent-test",
        },
        scopes: {
          type: "array",
          items: { type: "string" },
          description: "OAuth/OIDC scopes to request for the injected app (write path only, e.g. ['openid','p1:read:user'])",
        },
        attempt_grant: {
          type: "boolean",
          description: "Actually register the OAuth app / consent grant (WRITE). Defaults FALSE = enumerate over-privileged app candidates only. Requires user-confirm.",
          default: false,
        },
        base_url: {
          type: "string",
          description: "Optional explicit Management API base URL for self-hosted PingFederate admin API",
        },
      },
      required: ["tenant_id"],
    },
  },
  {
    name: "test_ping_saml",
    description:
      "[PING EXPLOIT — non-destructive] SAML/OIDC response weakness analysis: pulls the IdP SAML metadata and OIDC JWKS, then analyzes signature posture for golden-SAML / token-forgery class issues (signed assertions vs signed responses, accepted signature algorithms, presence of a single long-lived signing key, XSW/unsigned-assertion acceptance indicators). Read-only analysis — submits a supplied response only to OBSERVE acceptance behavior, never forges a privileged identity unless attempt_forge=true (defaults FALSE).",
    inputSchema: {
      type: "object",
      properties: {
        tenant_id: {
          type: "string",
          description: "PingOne environment id or org domain for scope validation",
        },
        ping_env_id: {
          type: "string",
          description: "PingOne environment GUID (defaults to tenant_id)",
        },
        ping_region: {
          type: "string",
          description: "PingOne region NA / EU / AP / CA (default NA)",
          default: "NA",
        },
        saml_metadata_url: {
          type: "string",
          description: "Explicit SAML IdP metadata URL (overrides the derived PingOne metadata endpoint)",
        },
        sp_acs_url: {
          type: "string",
          description: "Service-provider ACS (Assertion Consumer Service) URL to observe response acceptance against (read-only probe)",
        },
        saml_response: {
          type: "string",
          description: "Optional base64 SAMLResponse to replay/observe acceptance behavior (read-only unless attempt_forge=true)",
        },
        attempt_forge: {
          type: "boolean",
          description: "Attempt a golden-SAML / signature-bypass forgery and submit it (WRITE/impactful). Defaults FALSE = analysis + observe only. Requires user-confirm.",
          default: false,
        },
        base_url: {
          type: "string",
          description: "Optional explicit base URL for self-hosted PingFederate",
        },
      },
      required: ["tenant_id"],
    },
  },
];

export const identityPingHandlers: Record<string, Function> = {
  // ===========================================================================
  // RECON
  // ===========================================================================
  enum_ping_org: async (args: {
    tenant_id: string;
    ping_env_id?: string;
    ping_region?: string;
    base_url?: string;
  }) => {
    const { tenant_id, ping_env_id, ping_region, base_url } = args;
    const envId = ping_env_id || tenant_id;
    const tld = regionTld(ping_region);
    const authBase = base_url
      ? base_url.replace(/\/$/, "")
      : `https://auth.pingone.${tld}/${envId}`;
    const oidcUrl = `${authBase}/as/.well-known/openid-configuration`;
    // PingFederate self-hosted serves OIDC at /.well-known/openid-configuration too.
    const altOidcUrl = `${authBase}/.well-known/openid-configuration`;
    const samlMetaUrl = `${authBase}/saml20/idp/metadata`;

    const commands: string[] = [
      `echo "=== PingOne / PingFederate Org Fingerprint (unauthenticated) ==="`,
      `echo "Tenant: ${sq(tenant_id)}"`,
      `echo "Env ID: ${sq(envId)}  Region: ${sq((ping_region || "NA").toUpperCase())}  Auth base: ${sq(authBase)}"`,
      `echo ""`,
      `echo "--- Tool availability ---"`,
      preflight("curl"),
      preflight("jq", "--version"),
      `echo ""`,
      `echo "--- OIDC .well-known/openid-configuration (PingOne /as) ---"`,
      `curl -sS ${sq(oidcUrl)} 2>&1 | (jq . 2>/dev/null || head -c 8000) || echo "PingOne OIDC config request FAILED (see stderr above)"`,
      `echo ""`,
      `echo "--- OIDC .well-known/openid-configuration (PingFederate root fallback) ---"`,
      `curl -sS ${sq(altOidcUrl)} 2>&1 | (jq . 2>/dev/null || head -c 8000) || echo "PingFederate root OIDC config request FAILED (see stderr above)"`,
      `echo ""`,
      `echo "--- Authorization / token / JWKS endpoints (from OIDC config) ---"`,
      `curl -sS ${sq(oidcUrl)} 2>&1 | jq -r '"authorization_endpoint=" + (.authorization_endpoint // "?"), "token_endpoint=" + (.token_endpoint // "?"), "jwks_uri=" + (.jwks_uri // "?"), "issuer=" + (.issuer // "?")' 2>&1 || echo "Could not extract endpoints (OIDC config may be unavailable)"`,
      `echo ""`,
      `echo "--- JWKS signing keys ---"`,
      `curl -sS "${authBase}/as/jwks" 2>&1 | (jq '.keys[] | {kid, kty, alg, use}' 2>/dev/null || head -c 4000) || echo "JWKS request FAILED (see stderr above)"`,
      `echo ""`,
      `echo "--- SAML IdP metadata ---"`,
      `curl -sS ${sq(samlMetaUrl)} 2>&1 | head -c 8000 || echo "SAML metadata request FAILED (see stderr above)"`,
      `echo ""`,
      `echo "=== PingOne / PingFederate Org Fingerprint Complete ==="`,
    ];

    return await executeInKali(commands.join(" && "));
  },

  enum_ping_users: async (args: {
    tenant_id: string;
    ping_env_id?: string;
    ping_region?: string;
    ping_worker_token?: string;
    userlist?: string[];
    base_url?: string;
  }) => {
    const { tenant_id, ping_env_id, ping_region, ping_worker_token, userlist = [], base_url } = args;
    const envId = ping_env_id || tenant_id;
    const tld = regionTld(ping_region);
    const apiBase = `https://api.pingone.${tld}/v1/environments/${envId}`;
    const authBase = base_url
      ? base_url.replace(/\/$/, "")
      : `https://auth.pingone.${tld}/${envId}`;

    const commands: string[] = [
      `echo "=== PingOne User Enumeration ==="`,
      `echo "Tenant: ${sq(tenant_id)}  Env ID: ${sq(envId)}  Region: ${sq((ping_region || "NA").toUpperCase())}"`,
      `echo "Mode: ${ping_worker_token ? "Management API (worker token)" : "auth-flow existence oracle"}  Candidates: ${userlist.length}"`,
      `echo ""`,
      `echo "--- Tool availability ---"`,
      preflight("curl"),
      preflight("jq", "--version"),
      `echo ""`,
    ];

    if (ping_worker_token) {
      const authHeader = `-H "Authorization: Bearer ${ping_worker_token}"`;
      commands.push(`echo "--- Management API user enumeration (GET /users) ---"`);
      commands.push(
        `curl -sS ${authHeader} "${apiBase}/users?limit=100" 2>&1 | (jq '._embedded.users[] | {id, username, email, enabled}' 2>/dev/null || head -c 30000) || echo "PingOne Management API users request FAILED (see stderr above; worker-token / role issue vs not-installed)"`
      );
      commands.push(`echo ""`);
      commands.push(`echo "--- Population summary ---"`);
      commands.push(
        `curl -sS ${authHeader} "${apiBase}/populations" 2>&1 | (jq '._embedded.populations[] | {id, name, userCount}' 2>/dev/null || head -c 8000) || echo "populations request FAILED (see stderr above)"`
      );
      commands.push(`echo ""`);
    } else {
      commands.push(`echo "--- Auth-flow existence oracle (no worker token; behavior-diff per candidate) ---"`);
      for (const u of userlist) {
        commands.push(`echo "Candidate: ${sq(u)}"`);
        // Read-only probe: observe the flow response for an existing vs non-existing username.
        commands.push(
          `curl -sS -o /dev/null -w 'http_status=%{http_code}\\n' "${authBase}/as/authorize?response_type=code&client_id=probe&login_hint=$(printf '%s' ${sq(u)} | jq -sRr @uri)" 2>&1 || echo "auth-flow probe for ${sq(u)} FAILED (see stderr above)"`
        );
      }
      if (userlist.length === 0) {
        commands.push(`echo "No userlist supplied and no worker token — nothing to enumerate."`);
      }
      commands.push(`echo ""`);
    }

    commands.push(`echo "=== PingOne User Enumeration Complete ==="`);

    return await executeInKali(commands.join(" && "));
  },

  // ===========================================================================
  // EXPLOITATION
  // ===========================================================================
  abuse_ping_oauth: async (args: {
    tenant_id: string;
    ping_env_id?: string;
    ping_region?: string;
    ping_worker_token?: string;
    app_name?: string;
    scopes?: string[];
    attempt_grant?: boolean;
    base_url?: string;
  }) => {
    const {
      tenant_id,
      ping_env_id,
      ping_region,
      ping_worker_token,
      app_name = "maestro-consent-test",
      scopes = [],
      attempt_grant = false,
      base_url,
    } = args;
    const envId = ping_env_id || tenant_id;
    const tld = regionTld(ping_region);
    const apiBase = base_url
      ? base_url.replace(/\/$/, "")
      : `https://api.pingone.${tld}/v1/environments/${envId}`;
    const authHeader = ping_worker_token ? `-H "Authorization: Bearer ${ping_worker_token}"` : "";

    const commands: string[] = [
      `echo "=== PingOne OAuth App / Worker-App Abuse Analysis ==="`,
      `echo "Tenant: ${sq(tenant_id)}  Env ID: ${sq(envId)}  Region: ${sq((ping_region || "NA").toUpperCase())}"`,
      `echo "App name (write path): ${sq(app_name)}  Scopes: ${sq(scopes.join(", ") || "(none)")}"`,
      `echo "Attempt grant (WRITE): ${attempt_grant}"`,
      `echo ""`,
      `echo "--- Tool availability ---"`,
      preflight("curl"),
      preflight("jq", "--version"),
      `echo ""`,
    ];

    // Always enumerate OAuth applications first (read-only).
    commands.push(`echo "--- OAuth/OIDC application registrations (read-only) ---"`);
    commands.push(
      `curl -sS ${authHeader} "${apiBase}/applications?limit=100" 2>&1 | (jq '._embedded.applications[] | {id, name, type, enabled, grantTypes: .grantTypes, redirectUris: .redirectUris, tokenEndpointAuthMethod}' 2>/dev/null || head -c 30000) || echo "applications enumeration FAILED (see stderr above; worker-token / role issue vs not-installed)"`
    );
    commands.push(`echo ""`);
    commands.push(`echo "--- Over-privileged worker-app roles (read-only) ---"`);
    commands.push(
      `curl -sS ${authHeader} "${apiBase}/roleAssignments" 2>&1 | (jq '._embedded.roleAssignments[] | {id, role: .role.id, scope: .scope.type}' 2>/dev/null || head -c 15000) || echo "roleAssignments enumeration FAILED (see stderr above)"`
    );
    commands.push(`echo ""`);

    if (!attempt_grant) {
      commands.push(
        `echo "WRITE GATED: no OAuth app registered. To inject an app / consent grant, set attempt_grant=true AND complete the user-confirm protocol (.claude/agents/_preamble.md). Enumerated over-privileged candidates above (wildcard redirect URIs, implicit grant, admin-roled worker apps)."`
      );
    } else {
      commands.push(`echo "--- WRITE (attempt_grant=true) — user-confirm MUST have run ---"`);
      const scopeList = scopes.length ? scopes : ["openid"];
      // PingOne OIDC app registration: POST /applications. Non-destructive intent
      // (a single test app), still gated because it is a real directory write.
      const body = JSON.stringify({
        name: app_name,
        enabled: true,
        type: "OPENID_CONNECT",
        protocol: "OPENID_CONNECT",
        grantTypes: ["AUTHORIZATION_CODE"],
        redirectUris: ["https://localhost/cb"],
        responseTypes: ["CODE"],
        tokenEndpointAuthMethod: "CLIENT_SECRET_BASIC",
        scopes: scopeList,
      });
      commands.push(
        `curl -sS -X POST ${authHeader} -H "Content-Type: application/json" -d ${sq(body)} "${apiBase}/applications" 2>&1 | (jq . 2>/dev/null || head -c 8000) || echo "OAuth app registration FAILED (see stderr above)"`
      );
    }

    commands.push(`echo ""`);
    commands.push(`echo "=== PingOne OAuth App Abuse Analysis Complete ==="`);

    return await executeInKali(commands.join(" && "));
  },

  test_ping_saml: async (args: {
    tenant_id: string;
    ping_env_id?: string;
    ping_region?: string;
    saml_metadata_url?: string;
    sp_acs_url?: string;
    saml_response?: string;
    attempt_forge?: boolean;
    base_url?: string;
  }) => {
    const {
      tenant_id,
      ping_env_id,
      ping_region,
      saml_metadata_url,
      sp_acs_url,
      saml_response,
      attempt_forge = false,
      base_url,
    } = args;
    const envId = ping_env_id || tenant_id;
    const tld = regionTld(ping_region);
    const authBase = base_url
      ? base_url.replace(/\/$/, "")
      : `https://auth.pingone.${tld}/${envId}`;
    const metaUrl = saml_metadata_url || `${authBase}/saml20/idp/metadata`;
    const jwksUrl = `${authBase}/as/jwks`;

    const commands: string[] = [
      `echo "=== PingOne / PingFederate SAML & OIDC Response Weakness Analysis ==="`,
      `echo "Tenant: ${sq(tenant_id)}  Env ID: ${sq(envId)}  Region: ${sq((ping_region || "NA").toUpperCase())}"`,
      `echo "Metadata URL: ${sq(metaUrl)}  SP ACS: ${sq(sp_acs_url || "(none)")}  attempt_forge: ${attempt_forge}"`,
      `echo ""`,
      `echo "--- Tool availability ---"`,
      preflight("curl"),
      preflight("xmllint", "--version"),
      preflight("jq", "--version"),
      `echo ""`,
      `echo "--- SAML IdP metadata ---"`,
      `curl -sS ${sq(metaUrl)} 2>&1 | (xmllint --format - 2>/dev/null | head -c 12000 || head -c 12000) || echo "SAML metadata request FAILED (see stderr above)"`,
      `echo ""`,
      `echo "--- Signing key / certificate posture (single long-lived key = golden-SAML risk) ---"`,
      `curl -sS ${sq(metaUrl)} 2>&1 | grep -oE '<ds:X509Certificate>[^<]+</ds:X509Certificate>' | wc -l | sed 's/^/X509Certificate count in metadata: /' 2>&1 || echo "could not count signing certs"`,
      `echo ""`,
      `echo "--- OIDC JWKS accepted signing algorithms ---"`,
      `curl -sS ${sq(jwksUrl)} 2>&1 | (jq '.keys[] | {kid, alg, kty, use}' 2>/dev/null || head -c 4000) || echo "JWKS request FAILED (see stderr above)"`,
      `echo ""`,
      `echo "NOTE: golden-SAML class = a single long-lived IdP signing key whose theft lets an attacker forge assertions for ANY user. Signed-response-only (assertion unsigned) enables XSW/assertion-wrapping. Verify the SP signs+validates the assertion, not just the response."`,
      `echo ""`,
    ];

    if (saml_response && sp_acs_url) {
      if (!attempt_forge) {
        commands.push(`echo "--- Observing SP acceptance of supplied SAMLResponse (read-only, unmodified) ---"`);
        commands.push(
          `curl -sS -o /dev/null -w 'http_status=%{http_code} redirect=%{redirect_url}\\n' -X POST ${sq(sp_acs_url)} --data-urlencode "SAMLResponse=${saml_response}" 2>&1 || echo "ACS observe probe FAILED (see stderr above)"`
        );
        commands.push(
          `echo "FORGE GATED: signature-bypass / golden-SAML forgery NOT attempted (attempt_forge=false). Set attempt_forge=true AND complete the user-confirm protocol to attempt an XSW / unsigned-assertion bypass."`
        );
      } else {
        commands.push(`echo "--- WRITE/impactful (attempt_forge=true) — user-confirm MUST have run ---"`);
        commands.push(`echo "Submitting modified SAMLResponse to test XSW / unsigned-assertion acceptance:"`);
        commands.push(
          `curl -sS -w '\\nhttp_status=%{http_code}\\n' -X POST ${sq(sp_acs_url)} --data-urlencode "SAMLResponse=${saml_response}" 2>&1 | head -c 8000 || echo "forged SAMLResponse submission FAILED (see stderr above)"`
        );
      }
      commands.push(`echo ""`);
    } else {
      commands.push(`echo "Supply both saml_response and sp_acs_url to observe SP acceptance behavior (metadata/JWKS analysis above runs without them)."`);
      commands.push(`echo ""`);
    }

    commands.push(`echo "=== PingOne / PingFederate SAML Analysis Complete ==="`);

    return await executeInKali(commands.join(" && "));
  },
};
