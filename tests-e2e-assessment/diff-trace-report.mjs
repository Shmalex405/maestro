#!/usr/bin/env node
// diff-trace-report.mjs — compare two ExecutionOverview trace reports.
//
//   node diff-trace-report.mjs <baseline.json> <current.json>
//
// Prints deltas and exits NON-ZERO only on a STRUCTURAL REGRESSION:
//   - a NEW faked-PASS that wasn't in the baseline (the run started faking),
//   - orchestration flipped degenerate (fan-out disappeared),
//   - findings dropped below the baseline floor (the run got dumber).
// Metric drift (tokens, tool counts) is a warning, never a failure — the LLM path
// is nondeterministic. Use against a committed trace-baseline.json once a real run
// is blessed, so each subsequent run is checked for "did it regress" not "is it
// byte-identical".

import fs from "node:fs";

const [, , basePath, curPath] = process.argv;
if (!basePath || !curPath) {
  console.error("usage: diff-trace-report.mjs <baseline.json> <current.json>");
  process.exit(2);
}
const base = JSON.parse(fs.readFileSync(basePath, "utf-8"));
const cur = JSON.parse(fs.readFileSync(curPath, "utf-8"));

const regressions = [];
const warnings = [];
const notes = [];

const n = (x) => (typeof x === "number" ? x : 0);
const delta = (label, b, c) => {
  const d = c - b;
  const arrow = d > 0 ? "▲" : d < 0 ? "▼" : "·";
  notes.push(`  ${arrow} ${label}: ${b} → ${c} (${d >= 0 ? "+" : ""}${d})`);
  return d;
};

// --- structural regressions -------------------------------------------------
const baseFaked = new Set((base.integrity?.fakedPass || []).map((f) => f.testId));
const newFaked = (cur.integrity?.fakedPass || []).filter((f) => !baseFaked.has(f.testId));
if (newFaked.length) regressions.push(`NEW faked PASS (not in baseline): ${newFaked.map((f) => `${f.testId}(${f.tool})`).join(", ")}`);

const baseDegen = !!(base.deadEnds?.degenerateRun ?? base.success?.degenerateRun);
const curDegen = !!(cur.deadEnds?.degenerateRun ?? cur.success?.degenerateRun);
if (curDegen && !baseDegen) regressions.push(`orchestration flipped DEGENERATE: subagentSpawns ${n(base.counts?.subagentSpawns)} → ${n(cur.counts?.subagentSpawns)}`);

const baseFindings = n(base.findingsTotal);
const curFindings = n(cur.findingsTotal);
if (curFindings < Math.floor(baseFindings * 0.5)) {
  regressions.push(`findings collapsed: ${baseFindings} → ${curFindings} (< 50% of baseline)`);
}

// --- metric drift (warn only) -----------------------------------------------
delta("findings", baseFindings, curFindings);
delta("subagent spawns", n(base.counts?.subagentSpawns), n(cur.counts?.subagentSpawns));
delta("distinct tools", n(base.counts?.distinctTools), n(cur.counts?.distinctTools));
delta("tool executions", n(base.counts?.toolExecutions), n(cur.counts?.toolExecutions));
const tokDelta = delta("total tokens", n(base.tokens?.totalTokens), n(cur.tokens?.totalTokens));
if (Math.abs(tokDelta) > n(base.tokens?.totalTokens) * 0.5) warnings.push(`token usage shifted >50% (${tokDelta >= 0 ? "+" : ""}${tokDelta})`);

const resolvedBaseFaked = [...baseFaked].filter((id) => !(cur.integrity?.fakedPass || []).some((f) => f.testId === id));
if (resolvedBaseFaked.length) notes.push(`  ✓ resolved faked PASS from baseline: ${resolvedBaseFaked.join(", ")}`);

// --- output -----------------------------------------------------------------
console.log(`\n=== diff-trace-report: ${base.executionId || "baseline"} → ${cur.executionId || "current"} ===`);
for (const ln of notes) console.log(ln);
if (warnings.length) {
  console.log("\nWARNINGS:");
  for (const w of warnings) console.log(`  ⚠ ${w}`);
}
if (regressions.length) {
  console.log("\nREGRESSIONS:");
  for (const r of regressions) console.log(`  ✗ ${r}`);
  console.log(`\n✗ ${regressions.length} structural regression(s).`);
  process.exit(1);
}
console.log("\n✓ no structural regressions.");
