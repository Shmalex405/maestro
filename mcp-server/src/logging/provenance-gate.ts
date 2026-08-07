// The deterministic provenance gate.
//
// Turns recorded provenance into enforced test statuses. This is the "teeth" of
// P1: a test reported PASS/N_A whose backing tool was absent or never succeeded
// is forced to BLOCKED, deterministically, so a silently-missing scanner can no
// longer masquerade as clean coverage.
//
// The core (gateTestResults) is a PURE function over three inputs — the
// test→tool map, the binary availability snapshot, and the per-tool execution
// summary — so its decisions are reproducible and unit-testable. The MCP-tool
// wrapper that gathers those inputs lives in tools/qa-tools.ts.

import * as fs from "fs";
import * as path from "path";
import * as yaml from "js-yaml";
import {
  AvailabilityRow,
  ToolExecSummary,
  binariesForTool,
} from "./tool-provenance";

/** Locate config/test-matrix.yml across dev and in-container layouts. */
function findTestMatrix(): string | null {
  const candidates = [
    process.env.TEST_MATRIX_PATH,
    path.join(process.cwd(), "../config/test-matrix.yml"),
    path.join(__dirname, "../../../config/test-matrix.yml"),
    "/opt/pentest/config/test-matrix.yml",
  ].filter(Boolean) as string[];
  for (const c of candidates) {
    try {
      if (fs.existsSync(c)) return c;
    } catch {
      /* keep looking */
    }
  }
  return null;
}

/**
 * Build { test_id → MCP tool } by recursively walking test-matrix.yml. The file
 * nests categories → subcategories → arrays of test objects; any object that has
 * both `test_id` and `tool` is a leaf.
 */
export function loadTestToolMap(): Record<string, string> {
  const map: Record<string, string> = {};
  const file = findTestMatrix();
  if (!file) return map;
  let doc: unknown;
  try {
    doc = yaml.load(fs.readFileSync(file, "utf-8"));
  } catch {
    return map;
  }
  const walk = (node: unknown): void => {
    if (!node || typeof node !== "object") return;
    if (Array.isArray(node)) {
      node.forEach(walk);
      return;
    }
    const obj = node as Record<string, unknown>;
    if (typeof obj.test_id === "string" && typeof obj.tool === "string") {
      map[obj.test_id] = obj.tool;
    }
    Object.values(obj).forEach(walk);
  };
  walk(doc);
  return map;
}

export type TestStatus = "PASS" | "FAIL" | "BLOCKED" | "N_A" | string;

export interface TestResultInput {
  test_id: string;
  status: TestStatus;
  [k: string]: unknown;
}

export interface GateInputs {
  toolMap: Record<string, string>;
  availability: AvailabilityRow[];
  execSummary: ToolExecSummary[];
}

export interface EnforcedResult {
  test_id: string;
  tool: string | null;
  original_status: TestStatus;
  enforced_status: TestStatus;
  changed: boolean;
  reason: string | null;
  /** Non-enforcing caution (e.g. tool ran but always exited non-zero). Surfaced
   *  for review but does NOT change the status — exit codes are unreliable. */
  warning: string | null;
  run_count: number;
  ok_count: number;
  binaries: { binary: string; installed: boolean | null }[];
}

const ENFORCEABLE = new Set(["PASS", "N_A"]);

/**
 * PURE: given recorded provenance, return each test's enforced status.
 *
 * Rules (only PASS / N_A are ever downgraded; FAIL and BLOCKED are left alone):
 *   1. Backing binary explicitly absent (installed === false) → BLOCKED (reliable).
 *   2. Tool has known binaries, is installed, but was never invoked for a PASS → BLOCKED.
 *   3. Tool ran ≥1 time but never exited 0 → WARNING only (NOT blocked). Exit codes
 *      are an unreliable signal — many tools exit non-zero benignly (whatweb,
 *      fuzzers, grep-likes), so hard-blocking on them mis-flags working tools.
 * Tools with no known binary (pure-API: analyze_jwt, test_cors, …) and tests with
 * no matrix tool mapping are left untouched — there is nothing to verify.
 */
export function gateTestResults(results: TestResultInput[], inputs: GateInputs): EnforcedResult[] {
  const availByBin = new Map<string, boolean>();
  for (const a of inputs.availability) availByBin.set(a.binary, a.installed);
  const execByTool = new Map<string, ToolExecSummary>();
  for (const e of inputs.execSummary) execByTool.set(e.tool_name, e);

  return results.map((r) => {
    const tool = inputs.toolMap[r.test_id] || null;
    const binaries = tool ? binariesForTool(tool) : [];
    const exec = tool ? execByTool.get(tool) : undefined;
    const run_count = exec?.run_count ?? 0;
    const ok_count = exec?.ok_count ?? 0;
    const binStatus = binaries.map((b) => ({
      binary: b,
      installed: availByBin.has(b) ? (availByBin.get(b) as boolean) : null,
    }));

    let enforced: TestStatus = r.status;
    let reason: string | null = null;
    let warning: string | null = null;

    if (ENFORCEABLE.has(r.status) && tool) {
      const absent = binStatus.find((b) => b.installed === false);
      if (absent) {
        // Rule 1 — binary genuinely absent. Reliable → hard BLOCK.
        enforced = "BLOCKED";
        reason = `backing tool "${absent.binary}" not present in the container`;
      } else if (binaries.length > 0 && run_count === 0 && r.status === "PASS") {
        // Rule 2 — a scanner-backed test passed but its tool never ran. Hard BLOCK.
        enforced = "BLOCKED";
        reason = `backing tool "${tool}" was never invoked, so PASS is unverified`;
      } else if (run_count > 0 && ok_count === 0) {
        // Rule 3 — ran but always exited non-zero. Exit codes are unreliable, so
        // this is a caution, NOT an enforced block.
        warning = `backing tool "${tool}" ran ${run_count} time(s) and never exited 0 — verify it actually produced results (exit code alone is unreliable)`;
      }
    }

    return {
      test_id: r.test_id,
      tool,
      original_status: r.status,
      enforced_status: enforced,
      changed: enforced !== r.status,
      reason,
      warning,
      run_count,
      ok_count,
      binaries: binStatus,
    };
  });
}
