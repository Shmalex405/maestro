// Per-test execution + scope-decision capture (Option B).
//
// Companion to tool-provenance.ts. Where that module records WHICH security
// binary ran for each test, this module records the per-test PASS/FAIL/N_A/
// BLOCKED verdict each agent reported (imported from its reports/*-results.json
// checkpoint) and every scope decision validateToolScope made during the run.
//
// Both are captured local-first into the shared SQLite DB and promoted to the
// cloud at end-of-run by the `promote_execution_meta` MCP tool (Shape A) so the
// desktop "Assessment Execution Overview" can show, after a run, exactly which
// tests ran with what verdict and which targets were in/out of scope.
//
// All writes are best-effort: this capture must NEVER throw into a live run —
// it mirrors recordToolExecution's swallow-everything contract.

import * as fs from "fs";
import * as path from "path";
import { getDatabase } from "./log-store";
import {
  currentToolContext,
  getAvailability,
  getExecutionSummary,
} from "./tool-provenance";
import { gateTestResults, loadTestToolMap } from "./provenance-gate";

// ---------------------------------------------------------------------------
// Checkpoint import: reports/*-results.json → assessment_test_results
// ---------------------------------------------------------------------------

/** Locate the project reports/ directory across dev and in-container layouts. */
function findReportsDir(explicit?: string): string | null {
  const candidates = [
    explicit,
    process.env.MAESTRO_REPORTS_DIR,
    // CONFIG_PATH is set to <project>/config in the container — reports/ is its sibling.
    process.env.CONFIG_PATH ? path.join(process.env.CONFIG_PATH, "../reports") : undefined,
    path.join(process.cwd(), "reports"),
    path.join(process.cwd(), "../reports"),
    path.join(__dirname, "../../../reports"),
    "/mnt/host-home/Desktop/kali-mcp-pentest/reports",
  ].filter(Boolean) as string[];
  for (const c of candidates) {
    try {
      if (fs.existsSync(c) && fs.statSync(c).isDirectory()) return c;
    } catch {
      /* keep looking */
    }
  }
  return null;
}

interface CheckpointTestResult {
  test_id?: string;
  status?: string;
  finding_count?: number;
  notes?: string;
}

interface CheckpointFile {
  agent?: string;
  test_results?: CheckpointTestResult[];
}

interface FlatResult {
  agent: string;
  test_id: string;
  status: string;
  finding_count: number;
  notes: string | null;
}

/**
 * Glob reports/<agent>-results.json, flatten every test_result, run the flattened
 * set through the deterministic provenance gate so each row carries the enforced
 * verdict + reason, and UPSERT into assessment_test_results. Best-effort —
 * swallows all errors so it can never break a live run.
 *
 * @returns the number of rows upserted (0 on any failure / nothing to import).
 */
export function importTestResultsFromCheckpoints(
  assessmentId?: string,
  reportsDir?: string
): number {
  try {
    const db = getDatabase();
    if (!db) return 0;
    const aid =
      assessmentId || currentToolContext()?.assessment_id || process.env.MAESTRO_ASSESSMENT_ID || null;

    const dir = findReportsDir(reportsDir);
    if (!dir) return 0;

    let files: string[];
    try {
      files = fs.readdirSync(dir).filter((f) => f.endsWith("-results.json"));
    } catch {
      return 0;
    }

    const flat: FlatResult[] = [];
    for (const f of files) {
      try {
        const raw = fs.readFileSync(path.join(dir, f), "utf-8");
        const doc = JSON.parse(raw) as CheckpointFile;
        // Prefer the explicit `agent` field; fall back to the filename stem.
        const agent = doc.agent || f.replace(/-results\.json$/, "");
        for (const tr of doc.test_results || []) {
          if (!tr || typeof tr.test_id !== "string" || typeof tr.status !== "string") continue;
          flat.push({
            agent,
            test_id: tr.test_id,
            status: tr.status,
            finding_count: typeof tr.finding_count === "number" ? tr.finding_count : 0,
            notes: typeof tr.notes === "string" ? tr.notes : null,
          });
        }
      } catch {
        /* skip an unparseable checkpoint, keep importing the rest */
      }
    }
    if (flat.length === 0) return 0;

    // Run through the deterministic gate so `enforced` mirrors check_tool_provenance:
    // a PASS/N_A whose backing tool was absent/never ran becomes enforced=1 + reason.
    const enforcedByTest = new Map<string, { changed: boolean; reason: string | null }>();
    try {
      const enforced = gateTestResults(
        flat.map((r) => ({ test_id: r.test_id, status: r.status })),
        {
          toolMap: loadTestToolMap(),
          availability: getAvailability(aid || undefined),
          execSummary: getExecutionSummary(aid || undefined),
        }
      );
      for (const e of enforced) {
        // Last writer wins if the same test_id appears under two agents — fine,
        // the gate verdict is purely a function of test_id anyway.
        enforcedByTest.set(e.test_id, { changed: e.changed, reason: e.reason });
      }
    } catch {
      /* gate is advisory; on failure every row simply records enforced=0 */
    }

    const now = new Date().toISOString();
    const stmt = db.prepare(
      `INSERT INTO assessment_test_results
         (assessment_id, agent, test_id, status, enforced, enforced_reason, finding_count, notes, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(assessment_id, agent, test_id) DO UPDATE SET
         status = excluded.status,
         enforced = excluded.enforced,
         enforced_reason = excluded.enforced_reason,
         finding_count = excluded.finding_count,
         notes = excluded.notes`
    );
    let upserted = 0;
    for (const r of flat) {
      const gate = enforcedByTest.get(r.test_id);
      try {
        stmt.run(
          aid,
          r.agent,
          r.test_id,
          r.status,
          gate?.changed ? 1 : 0,
          gate?.changed ? gate.reason : null,
          r.finding_count,
          r.notes,
          now
        );
        upserted += 1;
      } catch {
        /* one bad row never aborts the import */
      }
    }
    return upserted;
  } catch {
    return 0;
  }
}

// ---------------------------------------------------------------------------
// Scope-decision capture: validateToolScope → scope_decisions
// ---------------------------------------------------------------------------

export interface ScopeDecisionInput {
  target: string;
  dimension?: string | null;
  in_scope: boolean;
  reason?: string | null;
  assessment_id?: string;
}

/**
 * Persist one scope decision. On conflict (same assessment+target+in_scope verdict)
 * bumps `attempts` and refreshes `last_seen`. Swallows all errors — never breaks
 * the tool run (mirrors recordToolExecution).
 */
export function recordScopeDecision(decision: ScopeDecisionInput): void {
  try {
    const db = getDatabase();
    if (!db) return;
    if (!decision || typeof decision.target !== "string" || !decision.target) return;
    const aid =
      decision.assessment_id ||
      currentToolContext()?.assessment_id ||
      process.env.MAESTRO_ASSESSMENT_ID ||
      null;
    db.prepare(
      `INSERT INTO scope_decisions
         (assessment_id, target, dimension, in_scope, reason, attempts, last_seen)
       VALUES (?, ?, ?, ?, ?, 1, ?)
       ON CONFLICT(assessment_id, target, in_scope) DO UPDATE SET
         attempts = attempts + 1,
         dimension = COALESCE(excluded.dimension, scope_decisions.dimension),
         reason = COALESCE(excluded.reason, scope_decisions.reason),
         last_seen = excluded.last_seen`
    ).run(
      aid,
      decision.target,
      decision.dimension ?? null,
      decision.in_scope ? 1 : 0,
      decision.reason ?? null,
      new Date().toISOString()
    );
  } catch {
    /* scope capture is advisory; never propagate */
  }
}

/**
 * Capture a scope decision straight off a validateToolScope call. Derives the
 * resolved target and (when determinable) the scope dimension from the tool's
 * args / the validator result, then records it. Best-effort and dimension-aware:
 *
 *   identity → tenant_id / identity_target_id   (also matched_target.id)
 *   cloud    → cloud_account_id
 *   k8s      → cluster_id
 *   network  → target / domain / cidr
 *
 * Local-only tools (no target) and tools with no resolvable target are skipped.
 * Wrapped so it can never affect the tool run. Mirrors the args extraction in
 * scope/tool-scope.ts so the two stay in agreement.
 */
export function captureScopeDecision(
  args: Record<string, unknown> | undefined,
  result: { valid: boolean; error?: string; matched_target?: any }
): void {
  try {
    const argObj = args ?? {};
    const identityTarget = (argObj.tenant_id || argObj.identity_target_id) as string | undefined;
    const cloudAccountId = argObj.cloud_account_id as string | undefined;
    const clusterId = argObj.cluster_id as string | undefined;
    const networkTarget = (argObj.target || argObj.domain || argObj.cidr) as string | undefined;

    let target: string | undefined;
    let dimension: string | null = null;
    if (identityTarget) {
      target = identityTarget;
      dimension = "identity";
    } else if (cloudAccountId) {
      target = cloudAccountId;
      dimension = "cloud";
    } else if (clusterId) {
      target = clusterId;
      dimension = "k8s";
    } else if (networkTarget) {
      target = networkTarget;
      dimension = "network";
    }
    if (!target) return; // no scoped target (local-only or non-targeted tool)

    recordScopeDecision({
      target,
      dimension,
      in_scope: result.valid,
      reason: result.valid ? null : result.error || null,
    });
  } catch {
    /* advisory; never propagate */
  }
}

// ---------------------------------------------------------------------------
// Read helpers (promotion-shaped) for promote_execution_meta + future readers.
// ---------------------------------------------------------------------------

export interface TestResultPromotionEntry {
  agent: string | null;
  test_id: string;
  status: string;
  enforced: boolean;
  enforced_reason: string | null;
  finding_count: number;
  notes: string | null;
}

/** Per-test results for an assessment, in the cloud-ingest shape, ordered by agent, test_id. */
export function getTestResults(assessmentId?: string): TestResultPromotionEntry[] {
  try {
    const db = getDatabase();
    if (!db) return [];
    const aid = assessmentId || process.env.MAESTRO_ASSESSMENT_ID || null;
    const rows = db
      .prepare(
        `SELECT agent, test_id, status, enforced, enforced_reason, finding_count, notes
           FROM assessment_test_results
          WHERE (assessment_id IS ? OR assessment_id = ?)
          ORDER BY agent ASC, test_id ASC`
      )
      .all(aid, aid) as {
      agent: string | null;
      test_id: string;
      status: string;
      enforced: number;
      enforced_reason: string | null;
      finding_count: number;
      notes: string | null;
    }[];
    return rows.map((r) => ({
      agent: r.agent,
      test_id: r.test_id,
      status: r.status,
      enforced: !!r.enforced,
      enforced_reason: r.enforced_reason,
      finding_count: r.finding_count,
      notes: r.notes,
    }));
  } catch {
    return [];
  }
}

export interface ScopeDecisionPromotionEntry {
  target: string;
  dimension: string | null;
  in_scope: boolean;
  reason: string | null;
  attempts: number;
}

/** Scope decisions for an assessment, in the cloud-ingest shape, ordered by target. */
export function getScopeDecisions(assessmentId?: string): ScopeDecisionPromotionEntry[] {
  try {
    const db = getDatabase();
    if (!db) return [];
    const aid = assessmentId || process.env.MAESTRO_ASSESSMENT_ID || null;
    const rows = db
      .prepare(
        `SELECT target, dimension, in_scope, reason, attempts
           FROM scope_decisions
          WHERE (assessment_id IS ? OR assessment_id = ?)
          ORDER BY target ASC, in_scope ASC`
      )
      .all(aid, aid) as {
      target: string;
      dimension: string | null;
      in_scope: number;
      reason: string | null;
      attempts: number;
    }[];
    return rows.map((r) => ({
      target: r.target,
      dimension: r.dimension,
      in_scope: !!r.in_scope,
      reason: r.reason,
      attempts: r.attempts,
    }));
  } catch {
    return [];
  }
}
