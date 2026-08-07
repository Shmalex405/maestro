// Static assessment skeleton + tool→agent→phase attribution, derived entirely
// from config/team-assessment.yml (the authoritative orchestration source).
//
// Two consumers:
//   1. The chokepoint emitter resolves a tool call's test_id → {agent, phase}
//      via resolveAttribution() so each ProgressEvent is attributable with zero
//      inference (every test_id maps to exactly one agent, one phase).
//   2. The /api/assessment-plan endpoint returns buildPlan(activeDims) — the
//      scope-filtered DAG the desktop renders as the phase/agent map.
//
// Everything here is best-effort and never throws into the tool path: a missing
// or malformed yaml degrades to an empty plan / undefined attribution.

import fs from "fs";
import path from "path";
import yaml from "js-yaml";
import { AssessmentPlan, PlanAgent, PlanPhase, ScopeDimension } from "./types";

interface RawPhase {
  phase: string | number;
  name: string;
  agents?: string[];
  parallel?: boolean;
  blocked_by?: string[];
  applies_when?: string;
  description?: string;
}
interface RawAgent {
  description?: string;
  tests?: string[];
  checkpoint_file?: string | null;
  applies_when?: string;
}
interface RawTeam {
  phases?: RawPhase[];
  agents?: Record<string, RawAgent>;
}

let cachedTeam: RawTeam | null = null;
let cachedPath: string | null = null;

/**
 * Walk up from this module's directory looking for config/team-assessment.yml.
 * Robust to running from src (ts-node) or dist, and to nesting depth, so we
 * never hardcode a fragile "../../../config" relative path.
 */
function findConfigFile(): string | null {
  if (cachedPath && fs.existsSync(cachedPath)) return cachedPath;
  let dir = __dirname;
  for (let i = 0; i < 8; i++) {
    const candidate = path.join(dir, "config", "team-assessment.yml");
    if (fs.existsSync(candidate)) {
      cachedPath = candidate;
      return candidate;
    }
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return null;
}

export function loadTeamAssessment(): RawTeam {
  if (cachedTeam) return cachedTeam;
  const file = findConfigFile();
  if (!file) {
    cachedTeam = { phases: [], agents: {} };
    return cachedTeam;
  }
  try {
    cachedTeam =
      (yaml.load(fs.readFileSync(file, "utf8")) as RawTeam) ?? {
        phases: [],
        agents: {},
      };
  } catch {
    cachedTeam = { phases: [], agents: {} };
  }
  return cachedTeam;
}

/** Test hook — drop the parse cache (e.g. after the yaml changes on disk). */
export function _resetPlanCache(): void {
  cachedTeam = null;
  cachedPath = null;
  testIndex = null;
}

// applies_when in the yaml is freeform English ("cloud_accounts defined in
// scope.yml ..."). We map it to a scope dimension by keyword. Order matters
// only in that each applies_when names exactly one dimension in practice.
const DIMENSION_KEYWORDS: Array<[string, ScopeDimension]> = [
  ["cloud_accounts", "cloud"],
  ["identity_targets", "identity"],
  ["ai_targets", "ai"],
  ["post_exploitation", "post_exploitation"],
  ["kubernetes", "kubernetes"],
  ["repo_paths", "repo"],
];

function dimensionFromAppliesWhen(appliesWhen?: string): ScopeDimension | null {
  if (!appliesWhen) return null;
  for (const [kw, dim] of DIMENSION_KEYWORDS) {
    if (appliesWhen.includes(kw)) return dim;
  }
  return null;
}

const normPhase = (p: string | number): string => String(p);

// ---- test_id → {agent, phase} attribution index ----

let testIndex: Map<string, { agent: string; phase: string }> | null = null;

function buildTestIndex(): Map<string, { agent: string; phase: string }> {
  const team = loadTeamAssessment();
  const idx = new Map<string, { agent: string; phase: string }>();
  // First phase each agent appears in (chain-analysis appears twice, 3.5 & 4.5
  // — we attribute its tests to its first phase; the live overlay distinguishes
  // touches by event time, not by the static index).
  const agentPhase = new Map<string, string>();
  for (const ph of team.phases ?? []) {
    for (const a of ph.agents ?? []) {
      if (!agentPhase.has(a)) agentPhase.set(a, normPhase(ph.phase));
    }
  }
  for (const [name, agent] of Object.entries(team.agents ?? {})) {
    const phase = agentPhase.get(name) ?? "";
    for (const t of agent.tests ?? []) idx.set(t, { agent: name, phase });
  }
  return idx;
}

export function getTestIndex(): Map<string, { agent: string; phase: string }> {
  if (!testIndex) testIndex = buildTestIndex();
  return testIndex;
}

/**
 * Resolve a tool call's test_id to its owning agent + phase. Returns undefined
 * when test_id is absent or unknown — callers fall back to the active phase.
 */
export function resolveAttribution(
  testId?: string
): { agent: string; phase: string } | undefined {
  if (!testId) return undefined;
  return getTestIndex().get(testId);
}

/**
 * Build the scope-filtered assessment skeleton.
 *
 * @param activeDimensions dimensions present in the run's scope.yml
 * @param opts.inScopeOnly drop out-of-scope agents (and now-empty phases)
 *        entirely instead of returning them flagged inScope:false. Default
 *        false so the UI can show conditional agents greyed-out if it wants.
 */
export function buildPlan(
  activeDimensions: ScopeDimension[],
  opts?: { inScopeOnly?: boolean }
): AssessmentPlan {
  const inScopeOnly = opts?.inScopeOnly ?? false;
  const team = loadTeamAssessment();
  const active = new Set(activeDimensions);
  const phases: PlanPhase[] = [];
  let totalInScopeTests = 0;

  for (const ph of team.phases ?? []) {
    const phaseDim = dimensionFromAppliesWhen(ph.applies_when);
    const phaseInScope = !phaseDim || active.has(phaseDim);
    const agents: PlanAgent[] = [];

    for (const agentName of ph.agents ?? []) {
      const raw = (team.agents ?? {})[agentName] ?? {};
      // An agent's own applies_when wins; fall back to the phase's.
      const agentDim = dimensionFromAppliesWhen(raw.applies_when) ?? phaseDim;
      const inScope = phaseInScope && (!agentDim || active.has(agentDim));
      if (inScopeOnly && !inScope) continue;

      const tests = raw.tests ?? [];
      if (inScope) totalInScopeTests += tests.length;

      agents.push({
        name: agentName,
        description: raw.description ?? "",
        tests,
        testCount: tests.length,
        checkpointFile: raw.checkpoint_file ?? null,
        requiresDimension: agentDim,
        inScope,
      });
    }

    if (inScopeOnly && agents.length === 0) continue;

    phases.push({
      phase: normPhase(ph.phase),
      name: ph.name,
      parallel: ph.parallel ?? false,
      blockedBy: ph.blocked_by ?? [],
      description: ph.description,
      requiresDimension: phaseDim,
      agents,
    });
  }

  return { phases, activeDimensions, totalInScopeTests };
}
