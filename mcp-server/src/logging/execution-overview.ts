// The shared ExecutionOverview contract (TypeScript mirror).
//
// Two producers emit this exact shape:
//   - the harness trace analyzer (tests-e2e-assessment/analyze-trace.mjs), from
//     LLM transcripts — fills the integrity / dead-end / per-agent blocks that
//     only a transcript exposes;
//   - the production app (frontend/lib/hooks/use-assessment-execution.ts), from
//     the cloud DB — fills the `provenance` discriminator so the UI can label
//     "measured" vs "approximated".
//
// SOURCE OF TRUTH is tests-e2e-assessment/execution-overview.schema.json. This
// file and frontend/lib/types.ts both mirror it and MUST stay in lockstep — the
// parity test in tests-e2e-assessment/ asserts they match.

export const EXECUTION_OVERVIEW_SCHEMA_VERSION = 1 as const;

export interface TokenUsage {
  inputTokens: number;
  outputTokens: number;
  cacheCreationInputTokens: number;
  cacheReadInputTokens: number;
  totalTokens: number;
}

export type ExecutionVerdict =
  | "complete"
  | "partial"
  | "blocked"
  | "failed"
  | "unknown";

export interface ExecutionSuccess {
  ok: boolean;
  verdict?: ExecutionVerdict;
  summary: string;
  /** Gate-breaking reasons (empty = pass). */
  hardFailures: string[];
  /** Report-but-don't-fail cautions. */
  softWarnings: string[];
  /** subagentSpawns <= 1 — the orchestration never fanned out. */
  degenerateRun?: boolean;
}

export interface ExecutionCounts {
  toolExecutions: number;
  distinctTools: number;
  subagentSpawns: number;
  distinctAgentTypes: number;
  turns: number;
  steps: number;
  findingsCreated: number;
  errors: number;
  retries: number;
}

export interface ExecutionTargetScope {
  target: string;
  /** null = undetermined from this producer's evidence. */
  inScope?: boolean | null;
  dimension?: string | null;
  reason?: string | null;
  toolExecutions?: number;
}

export interface ExecutionTestRollup {
  total: number;
  pass: number;
  fail: number;
  n_a: number;
  blocked: number;
  skipped: number;
  byStatus?: Record<string, number>;
}

export interface FakedPass {
  testId: string;
  tool: string;
  claimedStatus: string;
  /** Backing-tool tool_use count found in the trace (0 = faked). */
  backingToolCalls: number;
}

export interface ExecutionIntegrity {
  /** fakedPass.length === 0 */
  consistent: boolean;
  /** Claimed PASS whose backing tool was never called in the transcript. */
  fakedPass: FakedPass[];
  /** test_ids the binary-level provenance gate forced BLOCKED. */
  provenanceBlocked: string[];
  /** Tests with no backing tool (pure-API / manual) — nothing to verify. */
  unverifiable: Array<{ testId: string; reason: string }>;
}

export interface ExecutionToolDetail {
  name: string;
  calls: number;
  errors: number;
  retries: number;
  agentsUsing?: string[];
}

export interface ExecutionAgentDetail {
  agentType: string;
  transcript?: string | null;
  turns: number;
  toolExecutions: number;
  findingsCreated: number;
  tokens: TokenUsage;
  durationMs?: number | null;
  tokensPerFinding?: number | null;
}

export interface ExecutionDeadEnds {
  degenerateRun: boolean;
  erroredToolsNeverRetried: Array<{ tool: string; testId?: string | null }>;
  longGapsNoFinding: Array<{
    startTs: string;
    endTs: string;
    gapMs: number;
    toolCalls?: number;
  }>;
}

export interface ExecutionDuration {
  startTs: string | null;
  endTs: string | null;
  wallMs: number | null;
}

export interface ExecutionFindingsBySeverity {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info?: number;
}

export interface ExecutionProvenance {
  test_results?: "db" | "derived" | "absent";
  scope?: "db" | "derived" | "absent";
  phases?: "db" | "derived" | "absent";
}

export interface ExecutionOverview {
  schemaVersion: typeof EXECUTION_OVERVIEW_SCHEMA_VERSION;
  executionId: string;
  source: "harness-trace" | "production";
  generatedAt: string;
  model?: string | null;

  success: ExecutionSuccess;
  counts: ExecutionCounts;
  targets?: ExecutionTargetScope[];
  testRollup: ExecutionTestRollup;
  integrity: ExecutionIntegrity;
  tools?: ExecutionToolDetail[];
  agents?: ExecutionAgentDetail[];
  deadEnds?: ExecutionDeadEnds;
  duration: ExecutionDuration;
  tokens: TokenUsage;
  costUsd?: number | null;
  findingsBySeverity: ExecutionFindingsBySeverity;
  findingsTotal: number;

  /** Production-only: how each block was sourced, so the UI can label it. */
  provenance?: ExecutionProvenance;
}

export function emptyTokenUsage(): TokenUsage {
  return {
    inputTokens: 0,
    outputTokens: 0,
    cacheCreationInputTokens: 0,
    cacheReadInputTokens: 0,
    totalTokens: 0,
  };
}

export function addTokenUsage(a: TokenUsage, b: TokenUsage): TokenUsage {
  return {
    inputTokens: a.inputTokens + b.inputTokens,
    outputTokens: a.outputTokens + b.outputTokens,
    cacheCreationInputTokens:
      a.cacheCreationInputTokens + b.cacheCreationInputTokens,
    cacheReadInputTokens: a.cacheReadInputTokens + b.cacheReadInputTokens,
    totalTokens: a.totalTokens + b.totalTokens,
  };
}
