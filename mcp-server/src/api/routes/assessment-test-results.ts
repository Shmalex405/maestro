/**
 * Assessment Test-Results API Route
 *
 * GET /api/assessments/:id/test-results
 *
 * Returns the AUTHORITATIVE per-test outcomes (PASS / FAIL / BLOCKED / N_A) for
 * an assessment by reading each agent's checkpoint file
 * (reports/{agent}-results.json). This is the real verdict the assessment
 * recorded — distinct from the live SSE stream, which only carries tool-dispatch
 * status (started/ok/error). The Assessment View overlays these onto the plan so
 * the per-test grid reflects what actually happened, not just what got exercised.
 *
 * Checkpoint filenames are not assessment-scoped (they're overwritten each run),
 * so results are filtered by the `assessment_id` embedded in each file.
 */

import { Router, Request, Response } from "express";
import { promises as fs } from "fs";
import path from "path";

export const assessmentTestResultsRouter = Router();

// Mirrors the scope loader's "../config/scope.yml" convention: reports live at
// the project root, one level up from the mcp-server's working directory.
const REPORTS_DIR = process.env.REPORTS_DIR || "../reports";

interface CheckpointTest {
  test_id?: string;
  status?: string;
  finding_count?: number;
  notes?: string;
}

interface Checkpoint {
  agent?: string;
  assessment_id?: string;
  timestamp?: string;
  test_results?: CheckpointTest[];
}

export interface AuthoritativeTest {
  testId: string;
  status: string; // PASS | FAIL | BLOCKED | N_A (upper-cased; "" if absent)
  agent: string;
  findingCount: number;
  notes: string;
}

assessmentTestResultsRouter.get(
  "/:id/test-results",
  async (req: Request, res: Response) => {
    const { id } = req.params;
    try {
      let files: string[];
      try {
        files = (await fs.readdir(REPORTS_DIR)).filter((f) =>
          f.endsWith("-results.json")
        );
      } catch {
        // No reports dir yet (assessment hasn't produced checkpoints) — not an
        // error; the view just shows the neutral plan.
        return res.json({ assessmentId: id, tests: [], agents: [] });
      }

      const tests: AuthoritativeTest[] = [];
      const agents: Array<{ agent: string; timestamp: string | null; count: number }> = [];

      for (const file of files) {
        let cp: Checkpoint;
        try {
          cp = JSON.parse(
            await fs.readFile(path.join(REPORTS_DIR, file), "utf-8")
          ) as Checkpoint;
        } catch {
          continue; // skip unreadable/partial checkpoint
        }
        // Filter to this assessment. Checkpoints missing an id are included
        // (best-effort — the files on disk are the current run's).
        if (cp.assessment_id && cp.assessment_id !== id) continue;

        const agentName = cp.agent || file.replace(/-results\.json$/, "");
        const rs = Array.isArray(cp.test_results) ? cp.test_results : [];
        agents.push({ agent: agentName, timestamp: cp.timestamp ?? null, count: rs.length });
        for (const t of rs) {
          if (!t?.test_id) continue;
          tests.push({
            testId: t.test_id,
            status: String(t.status ?? "").toUpperCase(),
            agent: agentName,
            findingCount: t.finding_count ?? 0,
            notes: t.notes ?? "",
          });
        }
      }

      res.json({ assessmentId: id, tests, agents });
    } catch (error: any) {
      res.status(500).json({ error: error?.message || String(error) });
    }
  }
);
