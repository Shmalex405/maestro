#!/usr/bin/env node
// analyze-trace.mjs — the deterministic LLM-assessment trace analyzer.
//
// Parses a Claude Code assessment transcript (main + every subagent) plus the
// per-agent checkpoint files and emits an ExecutionOverview (see
// execution-overview.schema.json). It measures what the orchestrated run ACTUALLY
// did — tool executions, real subagent fan-out, dead-ends, token burn — and, the
// differentiator, the claimed-vs-executed integrity check: a checkpoint marked
// PASS whose backing tool never appears as a tool_use anywhere in the trace.
//
// This is an ANALYZER, not a gate: it always exits 0 (gating lives in assert.mjs).
// It runs against the transcripts already on disk — no container, no API, $0:
//
//   node analyze-trace.mjs \
//     --transcript ~/.kali-mcp-pentest/claude-home/projects/<slug>/<uuid>.jsonl \
//     --checkpoints ./reports --out /tmp/trace-report.json
//
// Flags:
//   --transcript <jsonl|sessionDir>  main transcript file OR its session dir
//   --checkpoints <dir>              dir of {agent}-results.json (default <root>/reports)
//   --test-matrix <yml>              default <root>/config/test-matrix.yml
//   --provenance <json>              optional check_tool_provenance output (for provenanceBlocked)
//   --schema <json>                  default ./execution-overview.schema.json
//   --gap-minutes <n>                long-gap-without-finding threshold (default 10)
//   --out <json>                     write the ExecutionOverview here (else stdout only)

import fs from "node:fs";
import path from "node:path";
import readline from "node:readline";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, "..");

// --- arg parsing ------------------------------------------------------------
function parseArgs(argv) {
  const a = {};
  for (let i = 0; i < argv.length; i++) {
    const k = argv[i];
    if (k.startsWith("--")) a[k.slice(2)] = argv[i + 1]?.startsWith("--") || argv[i + 1] === undefined ? true : argv[++i];
  }
  return a;
}
const args = parseArgs(process.argv.slice(2));
const TRANSCRIPT = args.transcript;
const CHECKPOINTS = args.checkpoints || path.join(ROOT, "reports");
const MATRIX = args["test-matrix"] || path.join(ROOT, "config", "test-matrix.yml");
const PROVENANCE = args.provenance || null;
const SCHEMA_PATH = args.schema || path.join(HERE, "execution-overview.schema.json");
const GAP_MS = (Number(args["gap-minutes"]) || 10) * 60_000;
const OUT = typeof args.out === "string" ? args.out : null;

// --- helpers ----------------------------------------------------------------

/** Strip the `mcp__<server>__` prefix → bare tool name. Load-bearing: forgetting
 *  this makes EVERY matrix test look faked (no name ever matches the matrix). */
export function bareToolName(name) {
  const p = String(name).split("__");
  return p[0] === "mcp" && p.length >= 3 ? p.slice(2).join("__") : name;
}

/** Stable hash of a tool input object (sorted keys) for retry detection. */
function stableHash(obj) {
  const seen = new WeakSet();
  const norm = (v) => {
    if (v && typeof v === "object") {
      if (seen.has(v)) return null;
      seen.add(v);
      if (Array.isArray(v)) return v.map(norm);
      return Object.fromEntries(Object.keys(v).sort().map((k) => [k, norm(v[k])]));
    }
    return v;
  };
  try {
    return JSON.stringify(norm(obj));
  } catch {
    return "";
  }
}

// Fallback set of binary-backed scanner tool names — mirrors the keys of
// TOOL_BINARIES in mcp-server/src/logging/tool-provenance.ts. Used only when the
// built dist can't be imported. Keep roughly in sync; the dist is authoritative.
const FALLBACK_BINARY_TOOLS = new Set([
  "scan_ports", "discover_hosts", "fingerprint_services", "enumerate_subdomains",
  "scan_ssl_tls", "scan_ssl_ciphers", "check_certificate", "test_zone_transfer",
  "check_dnssec", "check_dns_records", "run_nuclei", "run_nikto", "search_exploits",
  "run_sqlmap", "fuzz_endpoints", "crawl_site", "scan_semgrep", "scan_bandit",
  "scan_njsscan", "scan_secrets", "scan_dependencies", "scan_iac", "scan_container_image",
  "run_prowler", "run_scoutsuite", "audit_cloud_posture", "test_iam_privesc",
  "enum_ad_domain", "enum_ad_kerberos_targets", "kerberoast", "asrep_roast",
  "password_spray_ad", "read_laps", "dcsync", "enum_adcs_templates", "exploit_adcs",
  "ntlm_relay", "golden_ticket", "abuse_delegation", "abuse_ad_acl",
  "enum_entra_tenant", "enum_entra_directory", "enum_entra_users", "enum_oauth_apps",
  "password_spray_entra", "forge_prt", "replay_entra_token", "access_mailbox",
  "access_teams", "search_sharepoint_onedrive",
]);

/** Resolve `binariesForTool` from the built mcp-server dist so the analyzer's
 *  "verifiable" universe is EXACTLY the gate's binary-backed universe. Falls back
 *  to the embedded name set if dist isn't built. Returns (name) => boolean. */
async function loadIsBinaryBacked() {
  for (const rel of ["mcp-server/dist/logging/tool-provenance.js"]) {
    try {
      const mod = await import(path.join(ROOT, rel));
      if (typeof mod.binariesForTool === "function") {
        return (name) => mod.binariesForTool(name).length > 0;
      }
    } catch {
      /* fall through */
    }
  }
  console.error("[analyze-trace] WARN: mcp-server dist not built — using embedded binary-tool set");
  return (name) => FALLBACK_BINARY_TOOLS.has(name);
}

/** Load { test_id -> bare tool } from test-matrix.yml. Mirrors loadTestToolMap
 *  in mcp-server/src/logging/provenance-gate.ts (recursive walk for objects with
 *  both test_id and tool). Resolves js-yaml from the mcp-server install. */
function loadTestToolMap() {
  let yaml = null;
  for (const base of ["mcp-server/package.json", "package.json"]) {
    try {
      yaml = createRequire(path.join(ROOT, base))("js-yaml");
      break;
    } catch {
      /* try next */
    }
  }
  if (!yaml) {
    console.error("[analyze-trace] WARN: js-yaml not resolvable — reconciliation disabled (no test→tool map)");
    return {};
  }
  let doc;
  try {
    doc = yaml.load(fs.readFileSync(MATRIX, "utf-8"));
  } catch (e) {
    console.error(`[analyze-trace] WARN: could not read ${MATRIX}: ${e.message}`);
    return {};
  }
  const map = {};
  const walk = (n) => {
    if (!n || typeof n !== "object") return;
    if (Array.isArray(n)) return n.forEach(walk);
    if (typeof n.test_id === "string" && typeof n.tool === "string") map[n.test_id] = n.tool;
    Object.values(n).forEach(walk);
  };
  walk(doc);
  return map;
}

// --- transcript discovery ---------------------------------------------------

/** Resolve { main, subagents:[{file, agentType}] } from a file or session dir. */
function discoverTranscripts(input) {
  let main, sessionDir;
  const st = fs.statSync(input);
  if (st.isDirectory()) {
    sessionDir = input.replace(/\/+$/, "");
    const sib = `${sessionDir}.jsonl`;
    if (fs.existsSync(sib)) main = sib;
    else {
      const inside = fs.readdirSync(sessionDir).filter((f) => f.endsWith(".jsonl"));
      if (inside.length) main = path.join(sessionDir, inside[0]);
    }
  } else {
    main = input;
    sessionDir = input.replace(/\.jsonl$/, "");
  }
  const subagents = [];
  const subRoot = path.join(sessionDir, "subagents");
  if (fs.existsSync(subRoot)) {
    const walkDir = (dir) => {
      for (const ent of fs.readdirSync(dir, { withFileTypes: true })) {
        const full = path.join(dir, ent.name);
        if (ent.isDirectory()) walkDir(full);
        else if (/^agent-.*\.jsonl$/.test(ent.name)) {
          const metaPath = full.replace(/\.jsonl$/, ".meta.json");
          let agentType = null;
          try {
            agentType = JSON.parse(fs.readFileSync(metaPath, "utf-8")).agentType;
          } catch {
            /* workflow-internal agents may lack a sibling meta */
          }
          if (!agentType) agentType = /\/workflows\//.test(full) ? "workflow" : "unknown";
          subagents.push({ file: full, agentType });
        }
      }
    };
    walkDir(subRoot);
  }
  return { main, sessionDir, subagents };
}

// --- per-file scan ----------------------------------------------------------

const NOISE_TYPES = new Set([
  "mode",
  "permission-mode",
  "file-history-snapshot",
  "attachment",
  "last-prompt",
  "queue-operation",
  "ai-title",
]);

async function scanFile(file) {
  const out = {
    turns: 0,
    tokens: { inputTokens: 0, outputTokens: 0, cacheCreationInputTokens: 0, cacheReadInputTokens: 0, totalTokens: 0 },
    calls: [], // {name(bare), inputHash, id, ts}
    results: new Map(), // tool_use_id -> is_error(bool)
    findingsCreated: 0,
    severities: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
    firstTs: null,
    lastTs: null,
    model: null,
    spawnToolUses: 0, // Agent + Workflow tool_use (cross-check only)
  };
  const rl = readline.createInterface({ input: fs.createReadStream(file), crlfDelay: Infinity });
  for await (const line of rl) {
    if (!line.trim()) continue;
    let ev;
    try {
      ev = JSON.parse(line);
    } catch {
      continue; // tolerate a truncated final line from a timed-out run
    }
    if (NOISE_TYPES.has(ev.type)) continue;
    if (ev.timestamp) {
      out.firstTs ??= ev.timestamp;
      out.lastTs = ev.timestamp;
    }
    if (ev.type === "assistant") out.turns++;
    if (ev.message?.model && !out.model) out.model = ev.message.model;
    const u = ev.message?.usage;
    if (u) {
      out.tokens.inputTokens += u.input_tokens || 0;
      out.tokens.outputTokens += u.output_tokens || 0;
      out.tokens.cacheCreationInputTokens += u.cache_creation_input_tokens || 0;
      out.tokens.cacheReadInputTokens += u.cache_read_input_tokens || 0;
    }
    const content = ev.message?.content;
    if (!Array.isArray(content)) continue;
    for (const b of content) {
      if (b.type === "tool_use") {
        const bare = bareToolName(b.name);
        if (b.name === "Agent" || b.name === "Workflow") out.spawnToolUses++;
        // TaskCreate/TaskUpdate are an internal tracker — not tool executions.
        if (b.name === "TaskCreate" || b.name === "TaskUpdate") continue;
        out.calls.push({ name: bare, inputHash: stableHash(b.input || {}), id: b.id, ts: ev.timestamp || null });
        if (bare === "create_finding") {
          out.findingsCreated++;
          const sev = String(b.input?.severity || "").toLowerCase();
          if (sev in out.severities) out.severities[sev]++;
        }
      } else if (b.type === "tool_result") {
        out.results.set(b.tool_use_id, !!b.is_error);
      }
    }
  }
  out.tokens.totalTokens =
    out.tokens.inputTokens + out.tokens.outputTokens + out.tokens.cacheCreationInputTokens + out.tokens.cacheReadInputTokens;
  return out;
}

// --- checkpoints ------------------------------------------------------------

function loadCheckpoints(dir) {
  const tests = []; // {test_id, status, agent}
  if (!fs.existsSync(dir)) return tests;
  for (const f of fs.readdirSync(dir).filter((f) => f.endsWith("-results.json"))) {
    let j;
    try {
      j = JSON.parse(fs.readFileSync(path.join(dir, f), "utf-8"));
    } catch {
      continue;
    }
    const agent = j.agent || f.replace(/-results\.json$/, "");
    for (const t of j.test_results || []) {
      if (t && typeof t.test_id === "string" && typeof t.status === "string") {
        tests.push({ test_id: t.test_id, status: t.status, agent });
      }
    }
  }
  return tests;
}

// --- minimal JSON-schema validator (no ajv dep) -----------------------------

export function validateSchema(schema, data, root = schema, pathStr = "") {
  const errs = [];
  const resolve = (node) => {
    if (node && node.$ref) {
      const ref = node.$ref.replace(/^#\//, "").split("/");
      let cur = root;
      for (const seg of ref) cur = cur?.[seg];
      return cur || {};
    }
    return node;
  };
  const s = resolve(schema);
  const typeOf = (v) => (v === null ? "null" : Array.isArray(v) ? "array" : typeof v);
  const matchType = (v, t) => {
    if (t === "integer") return Number.isInteger(v);
    if (t === "number") return typeof v === "number";
    if (t === "object") return v !== null && typeof v === "object" && !Array.isArray(v);
    return typeOf(v) === t;
  };
  if (s.const !== undefined && data !== s.const) errs.push(`${pathStr}: expected const ${JSON.stringify(s.const)}`);
  if (s.enum && !s.enum.includes(data)) errs.push(`${pathStr}: ${JSON.stringify(data)} not in enum`);
  if (s.type) {
    const types = Array.isArray(s.type) ? s.type : [s.type];
    if (!types.some((t) => matchType(data, t))) errs.push(`${pathStr || "root"}: expected ${types.join("|")}, got ${typeOf(data)}`);
  }
  if (s.type === "object" || (data && typeof data === "object" && !Array.isArray(data) && s.properties)) {
    for (const req of s.required || []) {
      if (data == null || !(req in data)) errs.push(`${pathStr}/${req}: required property missing`);
    }
    for (const [k, sub] of Object.entries(s.properties || {})) {
      if (data && k in data) errs.push(...validateSchema(sub, data[k], root, `${pathStr}/${k}`));
    }
  }
  if ((s.type === "array" || Array.isArray(data)) && s.items && Array.isArray(data)) {
    data.forEach((item, i) => errs.push(...validateSchema(s.items, item, root, `${pathStr}[${i}]`)));
  }
  return errs;
}

// --- main -------------------------------------------------------------------

async function main() {
  const { main: mainFile, subagents } = discoverTranscripts(TRANSCRIPT);
  if (!mainFile) {
    console.error(`[analyze-trace] no main transcript found for ${TRANSCRIPT}`);
    process.exit(2);
  }
  const toolMap = loadTestToolMap();
  const isBinaryBacked = await loadIsBinaryBacked();

  // scan every transcript (main + all subagents incl. workflow-internal)
  const mainScan = await scanFile(mainFile);
  const subScans = [];
  for (const sa of subagents) subScans.push({ ...sa, scan: await scanFile(sa.file) });
  const allScans = [mainScan, ...subScans.map((s) => s.scan)];

  // --- aggregate per-tool + retries/errors (across ALL transcripts) ---------
  const toolAgg = new Map(); // bare -> {calls, errors, retries, agents:Set}
  const groupKey = new Map(); // `${name} ${hash}` -> {count, errored}
  const calledTools = new Map(); // bare -> count
  const tally = (scan, agentLabel) => {
    for (const c of scan.calls) {
      calledTools.set(c.name, (calledTools.get(c.name) || 0) + 1);
      const errored = scan.results.get(c.id) === true;
      const t = toolAgg.get(c.name) || { calls: 0, errors: 0, retries: 0, agents: new Set() };
      t.calls++;
      if (errored) t.errors++;
      t.agents.add(agentLabel);
      toolAgg.set(c.name, t);
      const gk = `${c.name} ${c.inputHash}`;
      const g = groupKey.get(gk) || { name: c.name, count: 0, errored: false };
      g.count++;
      g.errored = g.errored || errored;
      groupKey.set(gk, g);
    }
  };
  tally(mainScan, "team-lead");
  for (const s of subScans) tally(s.scan, s.agentType);

  // retries: repeated identical-input calls in a group that had an error.
  // errored-never-retried: a group of size 1 that errored.
  const erroredNeverRetried = [];
  for (const g of groupKey.values()) {
    if (g.count > 1 && g.errored) {
      const t = toolAgg.get(g.name);
      if (t) t.retries += g.count - 1;
    }
    if (g.count === 1 && g.errored) erroredNeverRetried.push({ tool: g.name, testId: null });
  }

  // --- counts ---------------------------------------------------------------
  const toolExecutions = allScans.reduce((n, s) => n + s.calls.length, 0);
  const turns = allScans.reduce((n, s) => n + s.turns, 0);
  const findingsCreated = allScans.reduce((n, s) => n + s.findingsCreated, 0);
  const errors = [...toolAgg.values()].reduce((n, t) => n + t.errors, 0);
  const retries = [...toolAgg.values()].reduce((n, t) => n + t.retries, 0);
  const subagentSpawns = subagents.length;
  const distinctAgentTypes = new Set(subagents.map((s) => s.agentType).filter((a) => a && a !== "workflow" && a !== "unknown")).size;

  // --- tokens + duration (global across all transcripts) --------------------
  const tokens = { inputTokens: 0, outputTokens: 0, cacheCreationInputTokens: 0, cacheReadInputTokens: 0, totalTokens: 0 };
  let startTs = null, endTs = null;
  const sev = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  let model = mainScan.model;
  for (const s of allScans) {
    for (const k of Object.keys(tokens)) tokens[k] += s.tokens[k];
    if (s.firstTs && (!startTs || s.firstTs < startTs)) startTs = s.firstTs;
    if (s.lastTs && (!endTs || s.lastTs > endTs)) endTs = s.lastTs;
    for (const k of Object.keys(sev)) sev[k] += s.severities[k];
    model ||= s.model;
  }
  const wallMs = startTs && endTs ? new Date(endTs) - new Date(startTs) : null;

  // --- long gaps with no finding (main transcript timeline) -----------------
  const longGaps = [];
  const timeline = mainScan.calls.filter((c) => c.ts).map((c) => ({ ts: c.ts, isFinding: c.name === "create_finding" }));
  for (let i = 1; i < timeline.length; i++) {
    const gap = new Date(timeline[i].ts) - new Date(timeline[i - 1].ts);
    if (gap >= GAP_MS) {
      longGaps.push({ startTs: timeline[i - 1].ts, endTs: timeline[i].ts, gapMs: gap, toolCalls: 1 });
    }
  }

  // --- per-agent detail -----------------------------------------------------
  const agents = subScans.map((s) => {
    const out = s.scan.calls.length;
    const fc = s.scan.findingsCreated;
    const durMs = s.scan.firstTs && s.scan.lastTs ? new Date(s.scan.lastTs) - new Date(s.scan.firstTs) : null;
    return {
      agentType: s.agentType,
      transcript: s.file,
      turns: s.scan.turns,
      toolExecutions: out,
      findingsCreated: fc,
      tokens: s.scan.tokens,
      durationMs: durMs,
      tokensPerFinding: fc > 0 ? Math.round(s.scan.tokens.outputTokens / fc) : null,
    };
  });

  // --- checkpoints + reconciliation (the differentiator) --------------------
  const checks = loadCheckpoints(CHECKPOINTS);
  // Every agent that wrote a checkpoint FILE — independent of whether it carried
  // test_results (0-test agents like severity-calibrator/compliance/report-enrichment
  // still "ran"). This is the reliable "did agent X run" signal (mirrors the team
  // lead's pre-report manifest check); assert.mjs's agent-roster gate consumes it.
  const checkpointAgents = fs.existsSync(CHECKPOINTS)
    ? [...new Set(
        fs.readdirSync(CHECKPOINTS)
          .filter((f) => f.endsWith("-results.json"))
          .map((f) => f.replace(/-results\.json$/, "")),
      )].sort()
    : [];
  const rollup = { total: checks.length, pass: 0, fail: 0, n_a: 0, blocked: 0, skipped: 0, byStatus: {} };
  for (const t of checks) {
    rollup.byStatus[t.status] = (rollup.byStatus[t.status] || 0) + 1;
    if (t.status === "PASS") rollup.pass++;
    else if (t.status === "FAIL") rollup.fail++;
    else if (t.status === "N_A") rollup.n_a++;
    else if (t.status === "BLOCKED") rollup.blocked++;
    else if (t.status === "SKIPPED") rollup.skipped++;
  }
  // A test is TRACE-VERIFIABLE only when EVERY tool listed for it is a binary-
  // backed scanner — then "claimed PASS but no scanner ever appeared in the whole
  // multi-agent trace" is a high-confidence faking signal. Tests with any non-
  // scanner alternative (curl / browser / manual / agent / pure-API) can't be
  // disproven from tool_use names, so they are unverifiable (mirrors the gate,
  // which only enforces binary-backed tools). Split "/", "+", "," alternatives.
  const fakedPass = [];
  const unverifiable = [];
  for (const t of checks) {
    const raw = toolMap[t.test_id];
    const candidates = raw ? String(raw).split(/[/+,]/).map((s) => s.trim()).filter(Boolean) : [];
    const binBacked = candidates.filter(isBinaryBacked);
    if (candidates.length === 0 || binBacked.length !== candidates.length) {
      unverifiable.push({
        testId: t.test_id,
        reason: candidates.length === 0 ? "no backing tool in matrix (manual/judgment)" : `not trace-verifiable (non-scanner tool: ${raw})`,
      });
      continue;
    }
    if (t.status === "PASS") {
      const satisfied = binBacked.some((c) => (calledTools.get(c) || 0) > 0);
      if (!satisfied) {
        fakedPass.push({ testId: t.test_id, tool: binBacked.join(" / "), claimedStatus: "PASS", backingToolCalls: 0 });
      }
    }
  }
  let provenanceBlocked = [];
  if (PROVENANCE && fs.existsSync(PROVENANCE)) {
    try {
      const p = JSON.parse(fs.readFileSync(PROVENANCE, "utf-8"));
      provenanceBlocked = (p.changes || []).map((c) => c.test_id).filter(Boolean);
    } catch {
      /* optional */
    }
  }
  const consistent = fakedPass.length === 0;

  // --- success verdict ------------------------------------------------------
  const degenerateRun = subagentSpawns <= 1;
  const hardFailures = [];
  if (!consistent) hardFailures.push(`${fakedPass.length} faked PASS (claimed but backing tool never called): ${fakedPass.map((f) => f.testId).join(", ")}`);
  if (degenerateRun) hardFailures.push(`degenerate run: only ${subagentSpawns} subagent spawn(s) — orchestration did not fan out`);
  if (findingsCreated === 0) hardFailures.push("no findings created in the trace");
  const softWarnings = [];
  if (erroredNeverRetried.length) softWarnings.push(`${erroredNeverRetried.length} tool error(s) never retried`);
  if (longGaps.length) softWarnings.push(`${longGaps.length} long gap(s) (>${GAP_MS / 60000}m) with no finding`);
  let verdict = "unknown";
  if (hardFailures.length) verdict = degenerateRun ? "failed" : "partial";
  else if (rollup.blocked > 0) verdict = "blocked";
  else if (rollup.total > 0 && rollup.fail === 0) verdict = "complete";
  else if (rollup.total > 0) verdict = "partial";
  const ok = hardFailures.length === 0;

  const overview = {
    schemaVersion: 1,
    executionId: path.basename(mainFile, ".jsonl"),
    source: "harness-trace",
    generatedAt: new Date(endTs || startTs || Date.now()).toISOString(),
    model: model || null,
    success: {
      ok,
      verdict,
      summary: ok
        ? `${subagentSpawns} agents, ${toolExecutions} tool calls, ${findingsCreated} findings, integrity ${consistent ? "clean" : "BROKEN"}`
        : `execution issues: ${hardFailures.join("; ")}`,
      hardFailures,
      softWarnings,
      degenerateRun,
    },
    counts: {
      toolExecutions,
      distinctTools: toolAgg.size,
      subagentSpawns,
      distinctAgentTypes,
      turns,
      steps: turns + toolExecutions,
      findingsCreated,
      errors,
      retries,
    },
    testRollup: rollup,
    checkpointAgents,
    integrity: { consistent, fakedPass, provenanceBlocked, unverifiable },
    tools: [...toolAgg.entries()]
      .map(([name, t]) => ({ name, calls: t.calls, errors: t.errors, retries: t.retries, agentsUsing: [...t.agents] }))
      .sort((a, b) => b.calls - a.calls),
    agents,
    deadEnds: { degenerateRun, erroredToolsNeverRetried: erroredNeverRetried, longGapsNoFinding: longGaps },
    duration: { startTs, endTs, wallMs },
    tokens,
    costUsd: null,
    findingsBySeverity: sev,
    findingsTotal: findingsCreated,
  };

  // --- validate against the schema -----------------------------------------
  let schemaErrs = [];
  try {
    const schema = JSON.parse(fs.readFileSync(SCHEMA_PATH, "utf-8"));
    schemaErrs = validateSchema(schema, overview);
  } catch (e) {
    console.error(`[analyze-trace] WARN: could not load/validate schema: ${e.message}`);
  }

  if (OUT) fs.writeFileSync(OUT, JSON.stringify(overview, null, 2));

  // --- human summary --------------------------------------------------------
  console.log(`\n=== analyze-trace: ${overview.executionId} ===`);
  console.log(`  ${ok ? "✓" : "✗"} verdict=${verdict} ok=${ok}`);
  console.log(`  agents: ${subagentSpawns} spawn(s), ${distinctAgentTypes} distinct type(s)${degenerateRun ? "  ✗ DEGENERATE (no fan-out)" : ""}`);
  console.log(`  tools: ${toolExecutions} calls, ${toolAgg.size} distinct, ${errors} error(s), ${retries} retr(ies)`);
  console.log(`  findings: ${findingsCreated} (C${sev.critical}/H${sev.high}/M${sev.medium}/L${sev.low})`);
  console.log(`  coverage: ${rollup.total} tests (pass ${rollup.pass}, fail ${rollup.fail}, n_a ${rollup.n_a}, blocked ${rollup.blocked})`);
  console.log(`  checkpoints: ${checkpointAgents.length} agent file(s)${checkpointAgents.length ? " — " + checkpointAgents.join(", ") : ""}`);
  console.log(`  integrity: ${consistent ? "✓ consistent" : `✗ ${fakedPass.length} FAKED PASS`}${fakedPass.length ? " — " + fakedPass.map((f) => `${f.testId}(${f.tool})`).join(", ") : ""}`);
  console.log(`  ${unverifiable.length} unverifiable (no backing tool), ${provenanceBlocked.length} provenance-blocked`);
  console.log(`  tokens: ${tokens.totalTokens.toLocaleString()} total (out ${tokens.outputTokens.toLocaleString()})  wall: ${wallMs != null ? Math.round(wallMs / 60000) + "m" : "n/a"}`);
  if (schemaErrs.length) {
    console.log(`\n  ✗ SCHEMA VALIDATION FAILED (${schemaErrs.length}):`);
    for (const e of schemaErrs.slice(0, 20)) console.log(`     ${e}`);
  } else {
    console.log(`  ✓ schema valid`);
  }
  if (OUT) console.log(`\n  → wrote ${OUT}`);
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  if (!TRANSCRIPT || TRANSCRIPT === true) {
    console.error("usage: analyze-trace.mjs --transcript <jsonl|sessionDir> [--checkpoints dir] [--out file]");
    process.exit(2);
  }
  main().catch((e) => {
    console.error("[analyze-trace] fatal:", e);
    process.exit(2);
  });
}
