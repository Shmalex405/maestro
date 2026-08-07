// MCP tools for tool-execution provenance (P1).
//
//   check_tool_provenance   — the deterministic coverage gate (1.4)
//   promote_tool_provenance — push the per-assessment summary to the cloud (1.3,
//                             added alongside the cloud route)
//
// The heavy lifting lives in ../logging/tool-provenance.ts (capture + queries)
// and ../logging/provenance-gate.ts (the pure gate). These are just the MCP
// surface, registered in server.ts so report-writer / report-enrichment can call
// them.

import {
  snapshotToolAvailability,
  getAvailability,
  getExecutionSummary,
  buildProvenancePromotion,
} from "../logging/tool-provenance";
import {
  gateTestResults,
  loadTestToolMap,
  TestResultInput,
  EnforcedResult,
} from "../logging/provenance-gate";
import {
  importTestResultsFromCheckpoints,
  getTestResults,
  getScopeDecisions,
} from "../logging/test-results-store";
import { cloudRequest, hasCloudSession, CloudSessionError } from "../integrations/cloud-session";

export const provenanceTools = [
  {
    name: "check_tool_provenance",
    description:
      "Deterministic coverage gate. Given the assessment's test results, returns each test's ENFORCED status: any PASS/N_A whose backing security tool was absent from the container or never exited 0 is forced to BLOCKED with a reason. Probes binary availability on first call. report-writer / report-enrichment MUST call this and render enforced_status before PDF — it proves a test's tool actually ran, closing the silent-skip gap. FAIL/BLOCKED are never altered.",
    inputSchema: {
      type: "object",
      properties: {
        test_results: {
          type: "array",
          description: "The assessment's test results (from agent checkpoint JSON).",
          items: {
            type: "object",
            properties: {
              test_id: { type: "string", description: "e.g. RECON-01" },
              status: { type: "string", description: "PASS | FAIL | BLOCKED | N_A" },
            },
            required: ["test_id", "status"],
          },
        },
        assessment_id: {
          type: "string",
          description: "Optional; defaults to MAESTRO_ASSESSMENT_ID.",
        },
      },
      required: ["test_results"],
    },
  },
  {
    name: "promote_tool_provenance",
    description:
      "Promote this assessment's tool-execution provenance (per-tool run/ok/fail counts + binary availability + version) to the cloud backend so the desktop 'Tools' view can show, after the run, exactly which tools ran. Mirrors complete_assessment / promote_cloud_inventory (Shape A): local-first during the run, curated promotion at the end. No-op with ok:false if there is no active cloud session.",
    inputSchema: {
      type: "object",
      properties: {
        assessment_id: {
          type: "string",
          description: "Optional; defaults to MAESTRO_ASSESSMENT_ID.",
        },
      },
      required: [],
    },
  },
  {
    name: "promote_execution_meta",
    description:
      "Promote this assessment's EXECUTION OVERVIEW (Option B) to the cloud backend so the desktop 'Assessment Execution Overview' can show, after the run, every test's PASS/FAIL/N_A/BLOCKED verdict (with the provenance-gate enforced flag + reason) and every in/out-of-scope target decision. First imports the agents' reports/*-results.json checkpoints into the local store, runs them through the deterministic gate, then pushes both the per-test results and the scope decisions. Mirrors promote_tool_provenance (Shape A): local-first during the run, curated promotion at the end. No-op with ok:false if there is no active cloud session.",
    inputSchema: {
      type: "object",
      properties: {
        assessment_id: {
          type: "string",
          description: "Optional; defaults to MAESTRO_ASSESSMENT_ID.",
        },
      },
      required: [],
    },
  },
];

export const provenanceHandlers: Record<string, Function> = {
  check_tool_provenance: async (args: {
    test_results: TestResultInput[];
    assessment_id?: string;
  }): Promise<string> => {
    const assessmentId = args.assessment_id || process.env.MAESTRO_ASSESSMENT_ID || undefined;

    // Always re-probe availability — it's a sub-second `command -v` sweep, and
    // caching it by assessment_id goes stale if the binary set changes within a
    // session (e.g. a tool removed/repaired between two gate calls under the same
    // assessment id). Fresh is correct; the cost is negligible.
    const availability = await snapshotToolAvailability(assessmentId);

    // If the test-matrix can't be loaded, the gate has no test→tool map and would
    // silently no-op (mapping every test to "no backing tool" = nothing enforced).
    // Surface that loudly so a missing matrix can never read as clean coverage.
    const toolMap = loadTestToolMap();
    const matrixLoaded = Object.keys(toolMap).length > 0;

    const enforced: EnforcedResult[] = gateTestResults(args.test_results || [], {
      toolMap,
      availability,
      execSummary: getExecutionSummary(assessmentId),
    });

    const changes = enforced.filter((e) => e.changed);
    const warnings = enforced.filter((e) => e.warning);
    return JSON.stringify(
      {
        assessment_id: assessmentId || null,
        matrix_loaded: matrixLoaded,
        warning: matrixLoaded
          ? undefined
          : "test-matrix.yml not found — the gate could NOT map tests to tools and did NOT enforce. Set TEST_MATRIX_PATH or make config/test-matrix.yml readable by the MCP server.",
        total: enforced.length,
        blocked_by_provenance: changes.length,
        warnings_count: warnings.length,
        availability_probed: availability.length,
        changes,
        warnings: warnings.map((w) => ({ test_id: w.test_id, tool: w.tool, warning: w.warning })),
        results: enforced,
      },
      null,
      2
    );
  },

  promote_tool_provenance: async (args: { assessment_id?: string }): Promise<string> => {
    const assessmentId = args.assessment_id || process.env.MAESTRO_ASSESSMENT_ID || undefined;
    if (!assessmentId) {
      return JSON.stringify({
        ok: false,
        error: "No assessment_id (and MAESTRO_ASSESSMENT_ID unset) — nothing to promote.",
      });
    }
    if (!hasCloudSession()) {
      return JSON.stringify({
        ok: false,
        error:
          "No active cloud session — provenance captured locally but NOT promoted. " +
          "Sign in to Maestro to surface it in the dashboard Tools view.",
      });
    }

    // Probe availability if it hasn't been done yet this run, then build the summary.
    if (getAvailability(assessmentId).length === 0) {
      await snapshotToolAvailability(assessmentId);
    }
    const tools = buildProvenancePromotion(assessmentId);

    try {
      const resp = await cloudRequest<{ upserted: number }>(
        `/assessments/${assessmentId}/tool-executions`,
        { method: "POST", body: { tools } }
      );
      return JSON.stringify({ ok: true, promoted: resp.upserted, tools: tools.length }, null, 2);
    } catch (e) {
      const msg =
        e instanceof CloudSessionError
          ? `cloud request failed (${e.status}): ${e.message}`
          : e instanceof Error
            ? e.message
            : String(e);
      return JSON.stringify({ ok: false, error: msg });
    }
  },

  promote_execution_meta: async (args: { assessment_id?: string }): Promise<string> => {
    const assessmentId = args.assessment_id || process.env.MAESTRO_ASSESSMENT_ID || undefined;
    if (!assessmentId) {
      return JSON.stringify({
        ok: false,
        error: "No assessment_id (and MAESTRO_ASSESSMENT_ID unset) — nothing to promote.",
      });
    }

    // Import the agents' checkpoints into the local store FIRST so the per-test
    // table is populated (and gate-enforced) before we read it back for promotion.
    const imported = importTestResultsFromCheckpoints(assessmentId);

    if (!hasCloudSession()) {
      return JSON.stringify({
        ok: false,
        imported,
        error:
          "No active cloud session — execution overview captured locally but NOT promoted. " +
          "Sign in to Maestro to surface it in the dashboard.",
      });
    }

    const tests = getTestResults(assessmentId);
    const decisions = getScopeDecisions(assessmentId);

    try {
      const trResp = await cloudRequest<{ upserted: number }>(
        `/assessments/${assessmentId}/test-results`,
        { method: "POST", body: { tests } }
      );
      const sdResp = await cloudRequest<{ upserted: number }>(
        `/assessments/${assessmentId}/scope-decisions`,
        { method: "POST", body: { decisions } }
      );
      return JSON.stringify(
        {
          ok: true,
          imported,
          test_results_pushed: trResp.upserted,
          scope_decisions_pushed: sdResp.upserted,
        },
        null,
        2
      );
    } catch (e) {
      const msg =
        e instanceof CloudSessionError
          ? `cloud request failed (${e.status}): ${e.message}`
          : e instanceof Error
            ? e.message
            : String(e);
      return JSON.stringify({ ok: false, imported, error: msg });
    }
  },
};
