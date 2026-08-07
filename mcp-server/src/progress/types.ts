// Live-assessment progress contract.
//
// These types are the wire format between the MCP server (which emits a
// ProgressEvent at the tool-dispatch chokepoint) and the desktop "Assessment
// View" (which renders the static plan skeleton and overlays live state). They
// are intentionally free of any runtime dependency so both the emission path
// and the plan/REST endpoints can share them.

export type ProgressStatus = "started" | "ok" | "error";

/**
 * One tool dispatch, projected into human terms. Emitted from the chokepoint
 * (`logCommand` site) in both server.ts (STDIO) and autonomous-runner.ts (HTTP).
 *
 * `agent` / `phase` are resolved from `testId` via the static team-assessment
 * index — see resolveAttribution(). When a tool call carries no test_id they
 * are left undefined and the UI attributes the event to the active phase.
 */
export interface ProgressEvent {
  assessmentId: string | null;
  /** ISO-8601 emit time. */
  ts: string;
  /** Bare tool name (mcp__server__ prefix already stripped). */
  tool: string;
  target?: string;
  testId?: string;
  /** Resolved from testId (team-assessment.yml). */
  agent?: string;
  /** Resolved from testId (team-assessment.yml), normalized to a string ("2a", "3.5"). */
  phase?: string;
  status: ProgressStatus;
  durationMs?: number;
  /** Fully-templated plain-English line for the ticker. No LLM. */
  narration: string;
}

/**
 * The scope dimensions that gate conditional agents/phases. Derived from each
 * agent/phase `applies_when` string in team-assessment.yml.
 */
export type ScopeDimension =
  | "cloud"
  | "identity"
  | "ai"
  | "post_exploitation"
  | "kubernetes"
  | "repo";

export interface PlanAgent {
  /** Agent id as it appears in team-assessment.yml (e.g. "web-security"). */
  name: string;
  description: string;
  /** Owned test ids. */
  tests: string[];
  testCount: number;
  /** The file this agent writes on completion, or null (report-writer/pdf-renderer). */
  checkpointFile: string | null;
  /** The scope dimension this agent requires, or null if always-on. */
  requiresDimension: ScopeDimension | null;
  /** True when this agent will actually run under the active scope. */
  inScope: boolean;
}

export interface PlanPhase {
  /** Normalized phase id as a string ("1", "2a", "3.5", "4.75"). */
  phase: string;
  name: string;
  /** Agents in this phase run concurrently when true. */
  parallel: boolean;
  /** Agent ids this phase waits on (dependency edges for the DAG). */
  blockedBy: string[];
  description?: string;
  /** Scope dimension gating the whole phase, or null. */
  requiresDimension: ScopeDimension | null;
  agents: PlanAgent[];
}

/**
 * The full assessment skeleton, scope-filtered. The frontend renders this as
 * the react-flow phase/agent map, then overlays live ProgressEvents on top.
 */
export interface AssessmentPlan {
  phases: PlanPhase[];
  activeDimensions: ScopeDimension[];
  /**
   * Header estimate only: the sum of test ids across in-scope agents. This is
   * an agent-level approximation for the map's "~N tests" label. The
   * AUTHORITATIVE per-run denominator is still derived from test-matrix.yml
   * `applies_when` at runtime (some tests are individually scope-gated within
   * an always-on agent, e.g. XVAL-12..15) — do not treat this as that count.
   */
  totalInScopeTests: number;
}
