// Tool-execution provenance.
//
// Every security tool ultimately shells out through `executeInKali()`. That choke
// point historically returned a bare string and threw the exit code away, so a
// handler's `... || echo "failed"` soft-fail made an absent or broken tool look
// identical to a clean PASS. This module makes the execution auditable:
//
//   1. AsyncLocalStorage carries { tool_name, test_id, assessment_id } from the
//      tool-dispatch boundary down into executeInKali, so each shell call knows
//      which MCP tool / test triggered it without threading a parameter through
//      all 31 tool files.
//   2. recordToolExecution() persists the exit code + duration to local SQLite.
//   3. snapshotToolAvailability() independently probes whether each security
//      binary is actually installed (command -v + --version) — the only signal
//      that survives the soft-fail pattern.
//
// All writes are best-effort: provenance must NEVER throw into a live tool run.

import { AsyncLocalStorage } from "async_hooks";
import { getDatabase } from "./log-store";

export interface ToolContext {
  tool_name: string;
  test_id?: string;
  assessment_id?: string;
}

const als = new AsyncLocalStorage<ToolContext>();

/** Run `fn` with the given tool attribution context active for all nested awaits. */
export function runWithToolContext<T = any>(ctx: ToolContext, fn: () => T): T {
  // Default assessment_id from the env the orchestrator sets, so executions are
  // attributable even when the dispatcher didn't pass one explicitly.
  const resolved: ToolContext = {
    ...ctx,
    assessment_id: ctx.assessment_id || process.env.MAESTRO_ASSESSMENT_ID || undefined,
  };
  return als.run(resolved, fn);
}

/** The attribution context for the currently-executing tool, if any. */
export function currentToolContext(): ToolContext | undefined {
  return als.getStore();
}

export interface ExecProvenance {
  command: string;
  exitCode: number | null;
  /** true if the process executed (even with a non-zero exit); false if launch itself failed. */
  ran: boolean;
  durationMs: number;
  stderr?: string;
}

/**
 * Best-effort: strip env assignments / sudo / shell builtins and return the
 * basename of the first real binary in a command. Informational only — the gate
 * relies on the explicit TOOL_BINARIES registry, not this heuristic.
 */
export function extractBinary(command: string): string | undefined {
  const SKIP = new Set(["sudo", "command", "echo", "cd", "env", "time", "exec", "nohup", "if", "for", "while", "then", "do"]);
  const tokens = command.trim().split(/\s+/);
  for (const tok of tokens) {
    if (!tok || tok.includes("=") || tok.startsWith("-") || tok.startsWith("(") || tok.startsWith("{")) continue;
    if (SKIP.has(tok)) continue;
    const base = tok.split("/").pop() || tok;
    if (/^[A-Za-z0-9_.-]+$/.test(base)) return base;
    return undefined;
  }
  return undefined;
}

/** Persist one execution record. Swallows all errors — never breaks the tool run. */
export function recordToolExecution(prov: ExecProvenance): void {
  try {
    const db = getDatabase();
    if (!db) return;
    const ctx = als.getStore();
    db.prepare(
      `INSERT INTO tool_executions
         (assessment_id, tool_name, test_id, binary, command, exit_code, ran, duration_ms, stderr_excerpt, timestamp)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).run(
      ctx?.assessment_id || null,
      ctx?.tool_name || "unmapped",
      ctx?.test_id || null,
      extractBinary(prov.command) || null,
      prov.command.slice(0, 4000),
      prov.exitCode,
      prov.ran ? 1 : 0,
      Math.round(prov.durationMs),
      prov.stderr ? prov.stderr.slice(0, 2000) : null,
      new Date().toISOString()
    );
  } catch {
    /* provenance is advisory; never propagate */
  }
}

// ---------------------------------------------------------------------------
// MCP tool → underlying security binary(ies). Keyed by MCP tool name (the value
// of `tool:` in config/test-matrix.yml). Only the binaries whose silent absence
// is a real coverage risk need an entry; pure-API tools (analyze_jwt, test_cors,
// …) intentionally have none and are exempt from the binary-absence gate.
// Extend as new scanners are wired in.
// ---------------------------------------------------------------------------
// Each entry names the PRIMARY binary the tool can't work without — matching the
// binary names the handlers' own `command -v` preflights use, so the availability
// probe and the gate agree with the container. The gate forces a PASS/N_A to
// BLOCKED when that binary is absent. Tools with no entry are gate-exempt
// (pure-API: analyze_jwt, test_cors, test_idor, …).
export const TOOL_BINARIES: Record<string, string[]> = {
  // recon / infra
  scan_ports: ["nmap"],
  discover_hosts: ["nmap"],
  fingerprint_services: ["nmap"],
  enumerate_subdomains: ["subfinder"],
  scan_ssl_tls: ["sslscan"],
  scan_ssl_ciphers: ["sslscan"],
  check_certificate: ["openssl"],
  test_zone_transfer: ["dig"],
  check_dnssec: ["dig"],
  check_dns_records: ["dig"],
  // vuln scanning
  run_nuclei: ["nuclei"],
  run_nikto: ["nikto"],
  search_exploits: ["searchsploit"],
  // exploitation — these were gate-EXEMPT by omission, which meant the four
  // tools that do the actual attacking were the only ones the deterministic gate
  // could not see. A missing msfconsole/searchsploit made an exploitation test
  // look like clean coverage. execute_custom_exploit and execute_through_foothold
  // run a free-form command with no fixed binary, so they stay exempt from the
  // binary probe by design — the oracle layer (verify_finding) is what verifies
  // their claims, not this gate.
  run_metasploit: ["msfconsole"],
  validate_cve: ["nuclei"],
  // web / api
  run_sqlmap: ["sqlmap"],
  fuzz_endpoints: ["ffuf"],
  crawl_site: ["katana"],
  // SAST / code
  scan_semgrep: ["semgrep"],
  scan_bandit: ["bandit"],
  scan_njsscan: ["njsscan"],
  scan_secrets: ["gitleaks"],
  scan_dependencies: ["grype"],
  scan_iac: ["checkov"],
  scan_container_image: ["trivy"],
  // cloud
  run_prowler: ["prowler"],
  run_scoutsuite: ["scout"],
  audit_cloud_posture: ["prowler"],
  test_iam_privesc: ["pmapper"],
  // identity — Active Directory (binary names from identity-ad.ts preflights)
  enum_ad_domain: ["nxc"],
  enum_ad_kerberos_targets: ["nxc"],
  kerberoast: ["nxc"],
  asrep_roast: ["nxc"],
  password_spray_ad: ["nxc"],
  read_laps: ["nxc"],
  dcsync: ["secretsdump.py"],
  enum_adcs_templates: ["certipy"],
  exploit_adcs: ["certipy"],
  ntlm_relay: ["ntlmrelayx.py"],
  golden_ticket: ["ticketer.py"],
  abuse_delegation: ["rbcd.py"],
  abuse_ad_acl: ["dacledit.py"],
  // identity — Entra ID / M365 (binary names from identity-entra/m365 preflights)
  enum_entra_tenant: ["roadrecon"],
  enum_entra_directory: ["roadrecon"],
  enum_entra_users: ["roadrecon"],
  enum_oauth_apps: ["roadrecon"],
  password_spray_entra: ["o365spray"],
  forge_prt: ["roadtx"],
  replay_entra_token: ["roadtx"],
  access_mailbox: ["pwsh"],
  access_teams: ["pwsh"],
  search_sharepoint_onedrive: ["pwsh"],
  // AI / LLM — promptfoo is the PRIMARY backing tool. garak is opportunistic and
  // intentionally NOT listed so its absence doesn't hard-block (ai-surface-plan
  // §9). Until promptfoo is baked into the image, these AI tests correctly BLOCK —
  // the system working, not a regression. ai_fingerprint_target is curl-only recon
  // and stays gate-exempt (no entry), like the other pure-HTTP probes.
  ai_probe_injection: ["promptfoo"],
  ai_extract_system_prompt: ["promptfoo"],
  ai_test_info_disclosure: ["promptfoo"],
  ai_test_output_handling: ["promptfoo"],
  ai_test_excessive_agency: ["promptfoo"],
  ai_consumption_probe: ["promptfoo"],
  ai_test_rag_isolation: ["promptfoo"],
  ai_test_data_poisoning: ["promptfoo"],
  ai_test_mcp_server: ["promptfoo"],
  ai_test_model_extraction: ["promptfoo"],
};

/** Every distinct binary referenced by the registry. */
export function knownBinaries(): string[] {
  return Array.from(new Set(Object.values(TOOL_BINARIES).flat()));
}

/** Binaries backing a given MCP tool name (empty = pure-API tool, gate-exempt). */
export function binariesForTool(toolName: string): string[] {
  return TOOL_BINARIES[toolName] || [];
}

export interface AvailabilityRow {
  binary: string;
  installed: boolean;
  version: string | null;
}

/**
 * Probe each known security binary once and persist {installed, version}. Uses a
 * lazy require of docker-exec to avoid a module-load cycle (docker-exec imports
 * this module to record executions). Idempotent per (assessment_id, binary).
 */
export async function snapshotToolAvailability(assessmentId?: string): Promise<AvailabilityRow[]> {
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const { executeInKali } = require("../utils/docker-exec");
  const aid = assessmentId || process.env.MAESTRO_ASSESSMENT_ID || null;
  const rows: AvailabilityRow[] = [];

  for (const bin of knownBinaries()) {
    let installed = false;
    let version: string | null = null;
    try {
      // One round-trip: prints "INSTALLED <version>" or "MISSING".
      const probe = `command -v ${bin} >/dev/null 2>&1 && echo "INSTALLED $(${bin} --version 2>&1 | head -1)" || echo "MISSING"`;
      const out: string = (await executeInKali(probe)).trim();
      if (out.startsWith("INSTALLED")) {
        installed = true;
        version = out.replace(/^INSTALLED\s*/, "").trim() || null;
      }
    } catch {
      installed = false;
    }
    rows.push({ binary: bin, installed, version });
    try {
      const db = getDatabase();
      db?.prepare(
        `INSERT INTO tool_availability (assessment_id, binary, installed, version, checked_at)
         VALUES (?, ?, ?, ?, ?)
         ON CONFLICT(assessment_id, binary) DO UPDATE SET
           installed = excluded.installed, version = excluded.version, checked_at = excluded.checked_at`
      ).run(aid, bin, installed ? 1 : 0, version, new Date().toISOString());
    } catch {
      /* advisory */
    }
  }
  return rows;
}

// ---------------------------------------------------------------------------
// Read helpers for the gate (1.4) and the promote step (1.3).
// ---------------------------------------------------------------------------

export interface ToolExecSummary {
  tool_name: string;
  run_count: number;
  ok_count: number;
  fail_count: number;
  last_exit_code: number | null;
}

/** Per-MCP-tool execution rollup for an assessment. */
export function getExecutionSummary(assessmentId?: string): ToolExecSummary[] {
  try {
    const db = getDatabase();
    if (!db) return [];
    const aid = assessmentId || process.env.MAESTRO_ASSESSMENT_ID || null;
    return db
      .prepare(
        `SELECT tool_name,
                COUNT(*)                                    AS run_count,
                SUM(CASE WHEN exit_code = 0 AND ran = 1 THEN 1 ELSE 0 END) AS ok_count,
                SUM(CASE WHEN exit_code != 0 OR ran = 0 THEN 1 ELSE 0 END) AS fail_count,
                (SELECT exit_code FROM tool_executions e2
                   WHERE e2.tool_name = e1.tool_name
                     AND (e2.assessment_id IS ? OR e2.assessment_id = ?)
                   ORDER BY e2.id DESC LIMIT 1)            AS last_exit_code
           FROM tool_executions e1
          WHERE (assessment_id IS ? OR assessment_id = ?)
          GROUP BY tool_name`
      )
      .all(aid, aid, aid, aid) as ToolExecSummary[];
  } catch {
    return [];
  }
}

export interface ProvenancePromotionEntry {
  tool_name: string;
  binary: string | null;
  installed: boolean | null;
  version: string | null;
  run_count: number;
  ok_count: number;
  fail_count: number;
  last_exit_code: number | null;
}

/**
 * Join the per-tool execution summary with the binary-availability probe into the
 * flat shape the cloud `/assessments/:id/tool-executions` route ingests. One entry
 * per MCP tool that executed during the assessment.
 */
export function buildProvenancePromotion(assessmentId?: string): ProvenancePromotionEntry[] {
  const availByBin = new Map<string, AvailabilityRow>();
  for (const a of getAvailability(assessmentId)) availByBin.set(a.binary, a);
  return getExecutionSummary(assessmentId).map((e) => {
    const primary = binariesForTool(e.tool_name)[0] ?? null;
    const avail = primary ? availByBin.get(primary) : undefined;
    return {
      tool_name: e.tool_name,
      binary: primary,
      installed: avail ? avail.installed : null,
      version: avail ? avail.version : null,
      run_count: e.run_count,
      ok_count: e.ok_count,
      fail_count: e.fail_count,
      last_exit_code: e.last_exit_code ?? null,
    };
  });
}

/** Availability rows for an assessment (falls back to the latest probe of any run). */
export function getAvailability(assessmentId?: string): AvailabilityRow[] {
  try {
    const db = getDatabase();
    if (!db) return [];
    const aid = assessmentId || process.env.MAESTRO_ASSESSMENT_ID || null;
    const rows = db
      .prepare(
        `SELECT binary, installed, version FROM tool_availability
          WHERE (assessment_id IS ? OR assessment_id = ?)`
      )
      .all(aid, aid) as { binary: string; installed: number; version: string | null }[];
    return rows.map((r) => ({ binary: r.binary, installed: !!r.installed, version: r.version }));
  } catch {
    return [];
  }
}
