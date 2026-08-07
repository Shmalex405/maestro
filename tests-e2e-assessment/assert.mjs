#!/usr/bin/env node
// Harness assertions — what "the matrix ran and did its job" actually means.
//
// Modes:
//   node assert.mjs run      <result.json> <provenance.json> [creds.json]
//   node assert.mjs negative <provenance.json>
//   node assert.mjs oracles  <oracles.json>
//
// `run` proves: coverage completeness (no unexpected skips), the authenticated
// path executed (the upgraded auth tests actually ran), and the scan found real
// vulnerabilities in both engines.
// `negative` proves the gate works live: with nuclei removed, every nuclei-backed
// test is forced BLOCKED.
// `oracles` proves the verdict gate: real vulnerabilities earn a verdict, and —
// just as importantly — lazy recipes, mis-attributed findings and self-asserted
// verdicts are refused.
//
// Exit 0 = all assertions pass; non-zero = at least one failed (prints why).
// Correlation is intentionally NOT asserted here — it needs the cloud backend +
// promotion, and is already covered by backend-rs tests/correlation.rs. This
// harness owns the matrix + gate + ground-truth proof.

import { readFileSync } from "node:fs";

const HERE = new URL("./", import.meta.url).pathname;
const load = (p) => JSON.parse(readFileSync(p, "utf-8"));
const loadLocal = (n) => load(`${HERE}${n}`);

const failures = [];
const notes = [];
const ok = (msg) => notes.push(`  ✓ ${msg}`);
const fail = (msg) => failures.push(`  ✗ ${msg}`);

// ---------------------------------------------------------------------------
function assertRun(resultPath, provenancePath) {
  const result = load(resultPath);
  const prov = load(provenancePath);
  const spec = loadLocal("coverage-spec.json");
  const exp = loadLocal("expectations.json");

  const testResults = result.testResults || [];
  const findings = result.allFindings || [];
  const byId = new Map(testResults.map((t) => [t.testId, t]));

  // --- 1. Coverage completeness --------------------------------------------
  const VALID = new Set(["PASS", "FAIL", "N_A", "BLOCKED", "SKIPPED"]);
  const skippedOk = new Set(spec.skipped_ok);

  let withStatus = 0;
  for (const t of testResults) {
    if (VALID.has(t.status)) withStatus++;
    else fail(`test ${t.testId} has invalid status '${t.status}'`);
    if (t.status === "SKIPPED" && !skippedOk.has(t.testId)) {
      fail(`test ${t.testId} was SKIPPED but is not in skipped_ok — a tool/handler is missing or a test silently didn't run`);
    }
  }
  if (withStatus >= spec.min_total_with_status) ok(`coverage: ${withStatus} tests produced a status (≥ ${spec.min_total_with_status})`);
  else fail(`coverage: only ${withStatus} tests produced a status (< ${spec.min_total_with_status})`);

  const skippedCount = testResults.filter((t) => t.status === "SKIPPED").length;
  const unexpectedSkips = testResults.filter((t) => t.status === "SKIPPED" && !skippedOk.has(t.testId));
  if (unexpectedSkips.length === 0) ok(`no unexpected SKIPPED tests (${skippedCount} skipped, all in skipped_ok)`);

  // --- 2. Authenticated path executed (the auth-upgrade proof) -------------
  for (const id of spec.must_run_authed) {
    const t = byId.get(id);
    if (!t) fail(`must-run-authed test ${id} is MISSING from results — auth path did not reach it`);
    else if (t.status === "SKIPPED") fail(`must-run-authed test ${id} was SKIPPED — the bearer token did not unlock it (auth wiring broken)`);
    else ok(`authed test ${id} ran (status ${t.status})`);
  }

  // --- 3. Ground truth: it actually found vulnerabilities ------------------
  const hay = (f) => `${f.title || ""} ${f.description || ""} ${f.source || ""}`.toLowerCase();
  // Sources arrive prefixed (e.g. "sequential-pipeline/scan_semgrep"), so match by
  // substring against the underlying tool names rather than exact equality.
  const dastSrc = exp.dast_sources.map((s) => s.toLowerCase());
  const sastSrc = exp.sast_sources.map((s) => s.toLowerCase());
  const srcHit = (f, list) => list.some((s) => (f.source || "").toLowerCase().includes(s));
  const fromDast = findings.filter((f) => srcHit(f, dastSrc)).length;
  const fromSast = findings.filter((f) => srcHit(f, sastSrc)).length;

  const m = exp.minimums;
  if (findings.length >= m.total_findings) ok(`found ${findings.length} findings (≥ ${m.total_findings})`);
  else fail(`found only ${findings.length} findings (< ${m.total_findings}) — the scan produced almost nothing`);
  if (fromDast >= m.from_dast_source) ok(`DAST produced ${fromDast} finding(s)`);
  else if (m.from_dast_required) fail(`DAST produced ${fromDast} finding(s) (< ${m.from_dast_source}) — web scanners found nothing`);
  else notes.push(`  ⚠ DAST produced ${fromDast} finding(s) — KNOWN GAP (Tier 1.1): the deterministic engine's scanners RUN but their output isn't extracted into findings (nuclei text vs jsonl; whatweb shape has no extractFindings handler; test_cors nests results under raw_output; xsstrike is broken in the image). This is the SECONDARY/continuous engine, not the LLM-orchestrated product path.`);
  if (fromSast >= m.from_sast_source) ok(`SAST produced ${fromSast} finding(s)`);
  else fail(`SAST produced ${fromSast} finding(s) (< ${m.from_sast_source}) — code scanners found nothing (repo not scanned?)`);

  // must-find checklist (required = hard fail; else informational)
  const allExpect = [...(exp.unauth || []), ...(exp.authed || []), ...(exp.sast || [])];
  for (const e of allExpect) {
    let matched;
    if (e.match_any_source) {
      const srcs = e.match_any_source.map((s) => s.toLowerCase());
      matched = findings.some((f) => srcs.some((s) => (f.source || "").toLowerCase().includes(s)));
    } else {
      const needles = (e.match || []).map((s) => s.toLowerCase());
      matched = findings.some((f) => needles.every((n) => hay(f).includes(n)));
    }
    if (matched) ok(`must-find '${e.id}' — matched`);
    else if (e.required) fail(`required must-find '${e.id}' NOT matched — a known vuln went undetected (${e.note})`);
    else notes.push(`  ⚠ must-find '${e.id}' not matched (informational): ${e.note}`);
  }

  // --- 4. Provenance integrity (baseline: every backing tool was present) --
  if (!prov || !Array.isArray(prov.results)) {
    fail("check_tool_provenance returned no results array");
  } else if (prov.matrix_loaded === false) {
    fail(`provenance gate could NOT load the test matrix — it no-opped (every test → no tool). "0 blocked" is a FALSE green. ${prov.warning || ""}`);
  } else {
    // The gate is enforcing (matrix loaded). Every BLOCK must be expected (a known
    // image gap / gate-rule nuance); a BLOCK not in expected_blocked is a NEW
    // regression — a tool that used to work just stopped.
    const expected = new Set(spec.expected_blocked || []);
    const blocked = (prov.changes || []).map((c) => c.test_id);
    const unexpected = blocked.filter((id) => !expected.has(id));
    const missingExpected = [...expected].filter((id) => !blocked.includes(id));
    if (unexpected.length === 0) {
      ok(`provenance: matrix loaded + gate enforcing; ${blocked.length} block(s), all expected (${blocked.join(", ") || "none"})`);
      if (missingExpected.length) notes.push(`  ⚠ expected_blocked no longer blocking (tool may have been fixed — consider removing from the list): ${missingExpected.join(", ")}`);
    } else {
      fail(`provenance: ${unexpected.length} UNEXPECTED block(s) — a backing tool regressed: ${unexpected.join(", ")}`);
    }
  }
}

// ---------------------------------------------------------------------------
function assertNegative(provenancePath) {
  const prov = load(provenancePath);
  if (!prov || !Array.isArray(prov.results)) {
    fail("negative run: check_tool_provenance returned no results array");
    return;
  }
  // Tests whose backing binary is nuclei must now be BLOCKED (we removed nuclei).
  const nucleiTests = prov.results.filter((r) => (r.binaries || []).some((b) => b.binary === "nuclei"));
  if (nucleiTests.length === 0) {
    fail("negative run: no nuclei-backed tests found in provenance — cannot prove the gate (is run_nuclei mapped to the nuclei binary?)");
    return;
  }
  let allBlocked = true;
  for (const r of nucleiTests) {
    if (r.enforced_status === "BLOCKED" && /nuclei/i.test(r.reason || "")) {
      ok(`negative gate: ${r.test_id} → BLOCKED (${r.reason})`);
    } else {
      allBlocked = false;
      fail(`negative gate: ${r.test_id} should be BLOCKED with nuclei absent, but enforced_status=${r.enforced_status} reason=${r.reason || "none"}`);
    }
  }
  if (allBlocked) ok(`negative gate proven: all ${nucleiTests.length} nuclei-backed test(s) forced BLOCKED with nuclei removed`);
}

// ---------------------------------------------------------------------------
// `llm` proves the LLM-ORCHESTRATED product path (not the deterministic engine).
// Same ground-truth + provenance checks as `run` but loaded from expectations-llm
// (ranges, not exact floors), PLUS the trace-integrity gates that only a transcript
// exposes: no faked PASS (a scanner-backed test claimed PASS but its scanner never
// appeared in the whole multi-agent trace) and real fan-out (the team didn't
// collapse to a single-context run). Soft metrics are reported, not failed.
function assertLlm(resultPath, provenancePath, tracePath) {
  const result = load(resultPath);
  const prov = load(provenancePath);
  const trace = load(tracePath);
  const spec = loadLocal("coverage-spec.json");
  const exp = loadLocal("expectations-llm.json");

  const testResults = result.testResults || [];
  const findings = result.allFindings || [];
  const byId = new Map(testResults.map((t) => [t.testId, t]));

  // --- 1. coverage completeness (no unexpected SKIPPED) --------------------
  const VALID = new Set(["PASS", "FAIL", "N_A", "BLOCKED", "SKIPPED"]);
  const skippedOk = new Set(spec.skipped_ok);
  let withStatus = 0;
  for (const t of testResults) {
    if (VALID.has(t.status)) withStatus++;
    else fail(`test ${t.testId} has invalid status '${t.status}'`);
    if (t.status === "SKIPPED" && !skippedOk.has(t.testId)) fail(`test ${t.testId} was SKIPPED but is not in skipped_ok`);
  }
  if (withStatus >= spec.min_total_with_status) ok(`coverage: ${withStatus} tests produced a status (≥ ${spec.min_total_with_status})`);
  else fail(`coverage: only ${withStatus} tests produced a status (< ${spec.min_total_with_status})`);

  // --- 2. authenticated path executed -------------------------------------
  for (const id of spec.must_run_authed) {
    const t = byId.get(id);
    if (!t) notes.push(`  ⚠ must-run-authed test ${id} missing from checkpoints (LLM run may label it differently)`);
    else if (t.status === "SKIPPED") fail(`must-run-authed test ${id} was SKIPPED — the bearer token did not unlock it`);
    else ok(`authed test ${id} ran (status ${t.status})`);
  }

  // --- 3. ground truth: it actually found vulnerabilities -----------------
  const hay = (f) => `${f.title || ""} ${f.description || ""} ${f.source || ""}`.toLowerCase();
  const srcHit = (f, list) => list.some((s) => (f.source || "").toLowerCase().includes(s));
  const fromDast = findings.filter((f) => srcHit(f, exp.dast_sources.map((s) => s.toLowerCase()))).length;
  const fromSast = findings.filter((f) => srcHit(f, exp.sast_sources.map((s) => s.toLowerCase()))).length;
  const m = exp.minimums;
  if (findings.length >= m.total_findings) ok(`found ${findings.length} findings (≥ ${m.total_findings})`);
  else fail(`found only ${findings.length} findings (< ${m.total_findings}) — the LLM run produced almost nothing`);
  if (fromDast >= m.from_dast_source) ok(`DAST produced ${fromDast} finding(s)`);
  else if (m.from_dast_required) fail(`DAST produced ${fromDast} finding(s) (< ${m.from_dast_source})`);
  if (fromSast >= m.from_sast_source) ok(`SAST produced ${fromSast} finding(s)`);
  else fail(`SAST produced ${fromSast} finding(s) (< ${m.from_sast_source}) — repo not scanned?`);
  for (const e of [...(exp.unauth || []), ...(exp.authed || []), ...(exp.sast || [])]) {
    let matched;
    if (e.match_any_source) {
      const srcs = e.match_any_source.map((s) => s.toLowerCase());
      matched = findings.some((f) => srcs.some((s) => (f.source || "").toLowerCase().includes(s)));
    } else {
      const needles = (e.match || []).map((s) => s.toLowerCase());
      matched = findings.some((f) => needles.every((nd) => hay(f).includes(nd)));
    }
    if (matched) ok(`must-find '${e.id}' — matched`);
    else if (e.required) fail(`required must-find '${e.id}' NOT matched (${e.note})`);
    else notes.push(`  ⚠ must-find '${e.id}' not matched (informational): ${e.note}`);
  }

  // --- 4. provenance integrity (gate loaded + enforcing, no new blocks) ----
  if (!prov || !Array.isArray(prov.results)) fail("check_tool_provenance returned no results array");
  else if (prov.matrix_loaded === false) fail(`provenance gate could NOT load the test matrix — it no-opped. ${prov.warning || ""}`);
  else {
    const expected = new Set(spec.expected_blocked || []);
    const blocked = (prov.changes || []).map((c) => c.test_id);
    const unexpected = blocked.filter((id) => !expected.has(id));
    if (unexpected.length === 0) ok(`provenance: gate enforcing; ${blocked.length} block(s), all expected`);
    else fail(`provenance: ${unexpected.length} UNEXPECTED block(s) — a backing tool regressed: ${unexpected.join(", ")}`);
  }

  // --- 5. trace integrity (the differentiator) ----------------------------
  const integ = trace.integrity || {};
  const li = exp.llm_integrity || {};
  if (li.require_no_faked_pass) {
    if (integ.consistent === false) fail(`integrity: ${(integ.fakedPass || []).length} FAKED PASS (claimed but backing scanner never ran in the trace) — ${(integ.fakedPass || []).map((f) => `${f.testId}(${f.tool})`).join(", ")}`);
    else ok("integrity: no faked PASS — every scanner-backed PASS was actually invoked in the trace");
  }
  const degenerate = !!(trace.deadEnds?.degenerateRun ?? trace.success?.degenerateRun);
  const spawns = trace.counts?.subagentSpawns ?? 0;
  if (li.require_non_degenerate) {
    if (degenerate) fail(`orchestration DEGENERATE: only ${spawns} subagent spawn(s) — the agent team did not fan out (single-context run)`);
    else ok(`orchestration fanned out: ${spawns} subagent spawn(s)`);
  }
  if (li.require_min_subagents != null) {
    if (spawns >= li.require_min_subagents) ok(`subagent spawns ${spawns} ≥ ${li.require_min_subagents}`);
    else fail(`subagent spawns ${spawns} < required ${li.require_min_subagents}`);
  }

  // --- 5b. agent-team completeness (the "full check on the AGENTS") --------
  // checkpointAgents = every agent that wrote reports/{agent}-results.json (the
  // reliable "ran" signal). `require` members hard-fail when absent; the full
  // `expected` roster is reported ran/missing so a quietly-dropped agent is visible.
  const ag = exp.agents || {};
  const ranAgents = new Set(trace.checkpointAgents || []);
  const expectedRoster = ag.expected || [];
  if (expectedRoster.length) {
    const ranExp = expectedRoster.filter((a) => ranAgents.has(a));
    const missExp = expectedRoster.filter((a) => !ranAgents.has(a));
    notes.push(`  ${missExp.length ? "⚠" : "✓"} agent roster: ${ranExp.length}/${expectedRoster.length} expected agents ran${missExp.length ? ` — missing: ${missExp.join(", ")}` : ""}`);
  }
  const requireAgents = ag.require || [];
  if (requireAgents.length) {
    const missReq = requireAgents.filter((a) => !ranAgents.has(a));
    if (missReq.length === 0) ok(`agent team: all ${requireAgents.length} required agents ran (${requireAgents.join(", ")})`);
    else fail(`agent team: ${missReq.length} required agent(s) never ran (no checkpoint): ${missReq.join(", ")}`);
  }

  // --- 6. soft ranges (reported, never failed) ----------------------------
  const r = exp.ranges || {};
  const reportRange = (label, value, range) => {
    if (!range) return;
    const okMin = range.min == null || value >= range.min;
    notes.push(`  ${okMin ? "✓" : "⚠"} ${label}: ${value}${range.min != null ? ` (min ${range.min})` : ""}${range.soft_max != null && value > range.soft_max ? ` ⚠ above soft_max ${range.soft_max}` : ""}`);
  };
  reportRange("subagent spawns", spawns, r.subagent_spawns);
  reportRange("distinct tools", trace.counts?.distinctTools ?? 0, r.distinct_tools);
  reportRange("tool executions", trace.counts?.toolExecutions ?? 0, r.tool_executions);
  reportRange("findings total", trace.findingsTotal ?? findings.length, r.findings_total);
  if (trace.deadEnds?.erroredToolsNeverRetried?.length) notes.push(`  ⚠ ${trace.deadEnds.erroredToolsNeverRetried.length} tool error(s) never retried (dead-end signal)`);
  if (integ.provenanceBlocked?.length) notes.push(`  ⚠ ${integ.provenanceBlocked.length} test(s) provenance-blocked: ${integ.provenanceBlocked.join(", ")}`);
}


// ---------------------------------------------------------------------------
// `oracles` proves the VERDICT GATE (docs/oracle-verification-layer.md): that a
// finding's verdict is earned in code and cannot be talked into existence.
//
// Half these assertions are that an oracle REFUSED to verify something. That is
// the point — a layer that only ever confirms is not a check, and the failure
// mode it exists to prevent (a claim reaching a customer under a human
// signature) is invisible unless we test the refusals.
function assertOracles(oraclesPath) {
  const o = load(oraclesPath);

  // 1. The invariant at the tool boundary.
  const sc = o.selfCertification;
  if (!sc) {
    fail("oracles: no selfCertification probe in the results");
  } else {
    if (sc.verdict === "candidate") {
      ok("invariant: create_finding refused an asserted verdict, stored `candidate`");
    } else {
      fail(`invariant: create_finding stored verdict=${sc.verdict} — an agent asserted a verdict and it stuck`);
    }
    if ((sc.rejected_fields || []).includes("verdict")) {
      ok(`invariant: verdict fields reported back as rejected (${sc.rejected_fields.join(", ")})`);
    } else {
      fail("invariant: create_finding did not report the verdict field as rejected — the agent gets no signal it failed");
    }
  }

  // 2. Each oracle scenario.
  if (!Array.isArray(o.scenarios) || o.scenarios.length === 0) {
    fail("oracles: no scenarios ran");
    return;
  }
  for (const s of o.scenarios) {
    if (s.error) {
      fail(`oracle "${s.name}": tool call errored — ${s.error}`);
      continue;
    }
    if (s.created_verdict && s.created_verdict !== "candidate") {
      fail(`oracle "${s.name}": a fresh finding started at verdict=${s.created_verdict}, expected candidate`);
    }
    const wantV = s.expect.verdict;
    const wantR = s.expect.reason;
    const verdictOk = s.verdict === wantV;
    const reasonOk = wantR === undefined || s.reason === wantR;
    if (verdictOk && reasonOk) {
      ok(`oracle "${s.name}" → ${s.verdict}${s.reason ? ` (${s.reason})` : ""} ${s.replays || ""}`);
    } else {
      fail(
        `oracle "${s.name}": expected ${wantV}${wantR ? `/${wantR}` : ""}, got ${s.verdict}/${s.reason ?? "none"}` +
          (s.explanation ? ` — ${s.explanation}` : "")
      );
    }
  }

  // 3. Both halves must be represented, or the suite proves less than it claims.
  const verified = o.scenarios.filter((s) => s.verdict === "verified").length;
  const refused = o.scenarios.filter((s) => s.verdict === "refuted").length;
  if (verified === 0) fail("oracles: nothing verified — the layer may be refusing everything, which is not a working gate");
  if (refused === 0) fail("oracles: nothing refused — a gate that only confirms proves nothing about false claims");
  if (verified > 0 && refused > 0) {
    ok(`verdict gate proven both ways: ${verified} earned a verdict, ${refused} were refused`);
  }
}

// ---------------------------------------------------------------------------
const mode = process.argv[2];
if (mode === "run") {
  assertRun(process.argv[3], process.argv[4]);
} else if (mode === "negative") {
  assertNegative(process.argv[3]);
} else if (mode === "llm") {
  assertLlm(process.argv[3], process.argv[4], process.argv[5]);
} else if (mode === "oracles") {
  assertOracles(process.argv[3]);
} else {
  console.error("usage: assert.mjs run <result.json> <provenance.json> | negative <provenance.json> | oracles <oracles.json> | llm <result.json> <provenance.json> <trace-report.json>");
  process.exit(2);
}

console.log(`\n=== assert.mjs (${mode}) ===`);
for (const n of notes) console.log(n);
if (failures.length) {
  console.log("\nFAILURES:");
  for (const f of failures) console.log(f);
  console.log(`\n✗ ${failures.length} assertion(s) failed.`);
  process.exit(1);
}
console.log(`\n✓ all assertions passed.`);
