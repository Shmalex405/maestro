// Frontend mirror of the MCP server's live-assessment progress contract
// (mcp-server/src/progress/types.ts). Kept in sync by hand — the two are small
// and stable. The Assessment View renders AssessmentPlan as the static skeleton
// and folds ProgressEvents into derived per-agent state.

export type ProgressStatus = 'started' | 'ok' | 'error';

export interface ProgressEvent {
  assessmentId: string | null;
  ts: string;
  tool: string;
  target?: string;
  testId?: string;
  agent?: string;
  phase?: string;
  status: ProgressStatus;
  durationMs?: number;
  narration: string;
}

export type ScopeDimension =
  | 'cloud'
  | 'identity'
  | 'ai'
  | 'post_exploitation'
  | 'kubernetes'
  | 'repo';

export interface PlanAgent {
  name: string;
  description: string;
  tests: string[];
  testCount: number;
  checkpointFile: string | null;
  requiresDimension: ScopeDimension | null;
  inScope: boolean;
}

export interface PlanPhase {
  phase: string;
  name: string;
  parallel: boolean;
  blockedBy: string[];
  description?: string;
  requiresDimension: ScopeDimension | null;
  agents: PlanAgent[];
}

export interface AssessmentPlan {
  phases: PlanPhase[];
  activeDimensions: ScopeDimension[];
  totalInScopeTests: number;
}

// ---- Derived UI state (computed from the event stream) ----

export type AgentRunStatus = 'pending' | 'active' | 'done' | 'error';

export interface AgentState {
  status: AgentRunStatus;
  /** Most recent narration line for this agent (drives the chip subtitle). */
  lastNarration?: string;
  lastTool?: string;
  toolCount: number;
  errorCount: number;
  lastTs?: string;
}

export interface TickerLine {
  id: string;
  ts: string;
  agent?: string;
  phase?: string;
  status: ProgressStatus;
  narration: string;
}
