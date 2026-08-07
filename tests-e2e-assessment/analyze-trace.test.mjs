// Unit tests for the trace analyzer's load-bearing pure functions.
// Run: node --test tests-e2e-assessment/analyze-trace.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { bareToolName, validateSchema } from "./analyze-trace.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, "..");
const schema = JSON.parse(fs.readFileSync(path.join(HERE, "execution-overview.schema.json"), "utf-8"));

// --- bareToolName: the single highest-risk bug (forgetting to strip the prefix
//     makes EVERY matrix test look faked) -------------------------------------
test("bareToolName strips the mcp__<server>__ prefix", () => {
  assert.equal(bareToolName("mcp__kali-pentest__scan_ports"), "scan_ports");
  assert.equal(bareToolName("mcp__kali-pentest__run_sqlmap"), "run_sqlmap");
});
test("bareToolName leaves non-MCP tool names untouched", () => {
  assert.equal(bareToolName("Bash"), "Bash");
  assert.equal(bareToolName("Read"), "Read");
  assert.equal(bareToolName("Agent"), "Agent");
});
test("bareToolName preserves a tool name that itself contains __", () => {
  assert.equal(bareToolName("mcp__srv__weird__tool"), "weird__tool");
});
test("bareToolName does not over-strip a bare name with no server segment", () => {
  // not the mcp__server__tool shape → returned as-is
  assert.equal(bareToolName("mcp__only"), "mcp__only");
});

// --- validateSchema: the no-ajv validator --------------------------------------
function minimalOverview() {
  const tok = { inputTokens: 0, outputTokens: 0, cacheCreationInputTokens: 0, cacheReadInputTokens: 0, totalTokens: 0 };
  return {
    schemaVersion: 1,
    executionId: "x",
    source: "harness-trace",
    generatedAt: "2026-06-10T00:00:00Z",
    success: { ok: true, summary: "ok", hardFailures: [], softWarnings: [] },
    counts: { toolExecutions: 0, distinctTools: 0, subagentSpawns: 0, distinctAgentTypes: 0, turns: 0, steps: 0, findingsCreated: 0, errors: 0, retries: 0 },
    testRollup: { total: 0, pass: 0, fail: 0, n_a: 0, blocked: 0, skipped: 0 },
    integrity: { consistent: true, fakedPass: [], provenanceBlocked: [], unverifiable: [] },
    duration: { startTs: null, endTs: null, wallMs: null },
    tokens: tok,
    findingsBySeverity: { critical: 0, high: 0, medium: 0, low: 0 },
    findingsTotal: 0,
  };
}

test("validateSchema accepts a minimal valid ExecutionOverview", () => {
  assert.deepEqual(validateSchema(schema, minimalOverview()), []);
});
test("validateSchema flags a missing required top-level block", () => {
  const o = minimalOverview();
  delete o.integrity;
  const errs = validateSchema(schema, o);
  assert.ok(errs.some((e) => e.includes("integrity")), errs.join("; "));
});
test("validateSchema flags a wrong const (schemaVersion)", () => {
  const o = minimalOverview();
  o.schemaVersion = 2;
  assert.ok(validateSchema(schema, o).some((e) => e.includes("const")));
});
test("validateSchema flags a bad enum (source)", () => {
  const o = minimalOverview();
  o.source = "nope";
  assert.ok(validateSchema(schema, o).some((e) => e.includes("enum")));
});
test("validateSchema flags a non-integer count", () => {
  const o = minimalOverview();
  o.counts.toolExecutions = "five";
  assert.ok(validateSchema(schema, o).some((e) => e.includes("toolExecutions")));
});

// --- parity: the TS mirrors must carry the same top-level blocks as the schema -
test("mcp-server TS mirror declares every required schema block", () => {
  const ts = fs.readFileSync(path.join(ROOT, "mcp-server/src/logging/execution-overview.ts"), "utf-8");
  for (const k of schema.required) assert.ok(ts.includes(k), `mcp-server type missing "${k}"`);
});
test("frontend TS mirror declares every required schema block (once it exists)", () => {
  const p = path.join(ROOT, "frontend/lib/types.ts");
  const txt = fs.readFileSync(p, "utf-8");
  if (!txt.includes("ExecutionOverview")) return; // mirror not added yet (Option A task)
  for (const k of schema.required) assert.ok(txt.includes(k), `frontend type missing "${k}"`);
});
