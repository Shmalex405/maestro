/**
 * Assessment Plan API Route
 *
 * GET /api/assessment-plan
 *
 * Returns the scope-filtered assessment skeleton (phases → agents → test ids,
 * with parallelism + dependency edges) that the desktop "Assessment View"
 * renders as the react-flow phase/agent map. The frontend overlays live
 * ProgressEvents (from the SSE bus) on top of this static structure.
 *
 * Active scope dimensions are self-derived from the active scope.yml
 * (cloud / kubernetes / identity / ai). `post_exploitation` and `repo` are not
 * carried on the typed ScopeConfig (cloud normalization drops the former;
 * repo_paths is per-assessment), so the frontend augments them via `?dims=`.
 *
 * Query params:
 *   - dims=cloud,ai,repo,post_exploitation  → add dimensions to the derived set
 *   - inScopeOnly=1                         → drop out-of-scope agents/phases
 *                                             entirely (default: keep, flagged
 *                                             inScope:false so the UI can grey them)
 */

import { Router, Request, Response } from "express";
import { loadScopeConfig } from "../../scope/scope-config";
import { buildPlan, ScopeDimension } from "../../progress";

export const assessmentPlanRouter = Router();

const ALL_DIMS: ScopeDimension[] = [
  "cloud",
  "identity",
  "ai",
  "post_exploitation",
  "kubernetes",
  "repo",
];

async function deriveActiveDimensions(): Promise<ScopeDimension[]> {
  const dims = new Set<ScopeDimension>();
  try {
    const scope = await loadScopeConfig();
    if (scope.cloud_accounts?.length) dims.add("cloud");
    if (scope.kubernetes?.length) dims.add("kubernetes");
    if (scope.identity_targets?.length) dims.add("identity");
    if (scope.ai_targets?.length) dims.add("ai");
    // Treat post_exploitation as active only when configured non-empty (the
    // template default is `post_exploitation: {}`, which must NOT light up the
    // post-ex phases). The live overlay still activates them if a
    // post-exploit-operator actually spawns.
    const px = (scope as unknown as Record<string, unknown>).post_exploitation;
    if (px && typeof px === "object" && Object.keys(px).length > 0) {
      dims.add("post_exploitation");
    }
  } catch {
    // Unreadable scope → base (web/API/SAST) plan.
  }
  return [...dims];
}

assessmentPlanRouter.get("/", async (req: Request, res: Response) => {
  try {
    const inScopeOnly =
      req.query.inScopeOnly === "1" || req.query.inScopeOnly === "true";

    const derived = await deriveActiveDimensions();
    const extra = String(req.query.dims ?? "")
      .split(",")
      .map((s) => s.trim())
      .filter((s): s is ScopeDimension => (ALL_DIMS as string[]).includes(s));

    const dims = Array.from(new Set([...derived, ...extra]));
    res.json(buildPlan(dims, { inScopeOnly }));
  } catch (error: any) {
    res.status(500).json({ error: error?.message || String(error) });
  }
});
