'use client';

import { useMemo } from 'react';
import { useQueries } from '@tanstack/react-query';
import { api } from '@/lib/tauri-api';
import type {
  Assessment,
  AssessmentEvent,
  CacheStatsResponse,
  ExecutionOverview,
  ExecutionPhase,
  ExecutionTestResult,
  ExecutionVerdict,
  Finding,
  ScopeTargetDecision,
  TestOutcome,
  ToolExecution,
} from '@/lib/types';

/**
 * Loads everything the per-assessment execution overview needs in parallel and
 * folds it into a single `ExecutionOverview` (source: 'production').
 *
 * This is the in-app twin of the harness trace analyzer
 * (tests-e2e-assessment/analyze-trace.mjs): both emit the same shape, but this
 * one reads the cloud DB instead of LLM transcripts. The `provenance`
 * discriminator labels which Option-B blocks (test_results, scope) are
 * DB-sourced vs absent so the UI can render "measured" vs "not captured".
 *
 * Every underlying read degrades gracefully — listTestResults / listScopeDecisions
 * are graceful-404 (empty), getCacheStats returns null when no LLM activity was
 * recorded, listEvents is graceful-404. A run that never promoted per-test
 * coverage still produces a usable overview.
 */

// Stable empty fallbacks — shared across renders so `data ?? EMPTY` doesn't
// create a new array reference each render (which would churn useMemo deps).
const EMPTY_TOOLS: readonly ToolExecution[] = [];
const EMPTY_EVENTS: readonly AssessmentEvent[] = [];
const EMPTY_FINDINGS: readonly Finding[] = [];
const EMPTY_TESTS: readonly ExecutionTestResult[] = [];
const EMPTY_SCOPE: readonly ScopeTargetDecision[] = [];

interface UseAssessmentExecutionResult {
  overview: ExecutionOverview | null;
  assessment: Assessment | null;
  /** Phases derived once here so the summary tile count and the timeline agree. */
  phases: ExecutionPhase[];
  /** Raw per-test rows for the coverage matrix (grouped-by-agent there). */
  testResults: ExecutionTestResult[];
  /** Raw scope decisions for the in-scope / out-of-scope columns. */
  scopeDecisions: ScopeTargetDecision[];
  isLoading: boolean;
  isError: boolean;
  error: unknown;
}

/** Tools whose binary was absent — the case that silently passed pre-provenance. */
function toolAbsent(t: ToolExecution): boolean {
  return t.installed === false;
}

/** Tools that ran at least once but never exited 0. */
function toolFailing(t: ToolExecution): boolean {
  return t.run_count > 0 && t.ok_count === 0;
}

function deriveVerdict(
  assessment: Assessment | undefined,
  tests: ExecutionTestResult[],
  tools: ToolExecution[],
): ExecutionVerdict {
  const status = assessment?.status;
  if (status === 'failed' || status === 'cancelled') return 'failed';

  const anyAbsent = tools.some(toolAbsent);
  const anyBlocked = tests.some((t) => t.status === 'BLOCKED');

  // No per-test data: lean on assessment status + tool provenance.
  if (tests.length === 0) {
    if (anyBlocked || anyAbsent) return 'blocked';
    if (status === 'completed') return 'complete';
    return 'unknown';
  }

  const allGreen = tests.every((t) => t.status === 'PASS' || t.status === 'N_A');
  if (allGreen && !anyAbsent) return 'complete';
  if (anyBlocked || anyAbsent) {
    // Any clean PASS/N_A alongside the blocks → partial; otherwise blocked.
    const anyGreen = tests.some((t) => t.status === 'PASS' || t.status === 'N_A');
    return anyGreen ? 'partial' : 'blocked';
  }
  // Plain failures with no blocks/absences.
  if (tests.some((t) => t.status === 'FAIL')) return 'partial';
  return 'unknown';
}

/**
 * Bucket phase_change events into spans, counting intervening tool_call /
 * finding_detected events per span. Returns one ExecutionPhase per bucket.
 * If no phase_change events exist, falls back to grouping by the test-result
 * `agent` column (when present).
 */
export function derivePhases(
  events: AssessmentEvent[],
  tests: ExecutionTestResult[],
): ExecutionPhase[] {
  // Chronological order — the events endpoint may already be sorted, but be
  // defensive (string ISO timestamps sort lexically).
  const ordered = [...events].sort((a, b) =>
    (a.created_at || '').localeCompare(b.created_at || ''),
  );

  const phaseChanges = ordered.filter((e) => e.event_type === 'phase_change');

  if (phaseChanges.length > 0) {
    const phases: ExecutionPhase[] = [];
    for (let i = 0; i < phaseChanges.length; i++) {
      const start = phaseChanges[i];
      const next = phaseChanges[i + 1];
      const startTs = start.created_at;
      const endTs = next ? next.created_at : ordered[ordered.length - 1]?.created_at;

      // Phase name: prefer an explicit details.phase / details.name / target.
      const d = start.details || {};
      const name =
        (typeof d.phase === 'string' && d.phase) ||
        (typeof d.name === 'string' && d.name) ||
        (typeof d.agent === 'string' && d.agent) ||
        start.target ||
        `Phase ${i + 1}`;

      // Count tool_call / finding_detected events strictly within this span.
      let toolCalls = 0;
      let findings = 0;
      for (const e of ordered) {
        if (!e.created_at) continue;
        if (e.created_at < startTs) continue;
        if (endTs && e.created_at > endTs) continue;
        if (e === start) continue;
        if (e.event_type === 'tool_call') toolCalls++;
        else if (e.event_type === 'finding_detected') findings++;
      }

      phases.push({
        name,
        status: next ? 'completed' : undefined,
        started_at: startTs ?? null,
        ended_at: endTs ?? null,
        tool_call_count: toolCalls,
        finding_count: findings,
      });
    }
    return phases;
  }

  // Fallback: group test results by agent.
  const byAgent = new Map<string, { tests: number; findings: number }>();
  for (const t of tests) {
    const agent = t.agent || 'unknown';
    const cur = byAgent.get(agent) || { tests: 0, findings: 0 };
    cur.tests += 1;
    cur.findings += t.finding_count || 0;
    byAgent.set(agent, cur);
  }
  if (byAgent.size > 0) {
    return Array.from(byAgent.entries()).map(([name, agg]) => ({
      name,
      status: 'completed' as const,
      tool_call_count: undefined,
      finding_count: agg.findings,
    }));
  }

  return [];
}

export function useAssessmentExecution(
  assessmentId: string,
): UseAssessmentExecutionResult {
  const results = useQueries({
    queries: [
      {
        queryKey: ['assessment', assessmentId],
        queryFn: () => api.assessments.get(assessmentId),
        enabled: !!assessmentId,
      },
      {
        queryKey: ['assessment', assessmentId, 'tool-executions'],
        queryFn: () => api.assessments.listToolExecutions(assessmentId),
        enabled: !!assessmentId,
      },
      {
        queryKey: ['assessment', assessmentId, 'events'],
        queryFn: () => api.assessments.listEvents(assessmentId, { limit: 1000 }),
        enabled: !!assessmentId,
      },
      {
        queryKey: ['assessment', assessmentId, 'findings'],
        queryFn: () =>
          api.findings.list({ assessment_id: assessmentId, limit: 1000 }),
        enabled: !!assessmentId,
      },
      {
        queryKey: ['assessment', assessmentId, 'cache-stats'],
        queryFn: () => api.config.cloud.getCacheStats(assessmentId),
        enabled: !!assessmentId,
      },
      {
        queryKey: ['assessment', assessmentId, 'test-results'],
        queryFn: () => api.assessments.listTestResults(assessmentId),
        enabled: !!assessmentId,
      },
      {
        queryKey: ['assessment', assessmentId, 'scope-decisions'],
        queryFn: () => api.assessments.listScopeDecisions(assessmentId),
        enabled: !!assessmentId,
      },
    ],
  });

  const [
    assessmentQ,
    toolsQ,
    eventsQ,
    findingsQ,
    cacheQ,
    testsQ,
    scopeQ,
  ] = results;

  // The assessment fetch is the only hard dependency — a 404 there is a real
  // error. The Option-B blocks (tools/events/tests/scope/cache) all degrade to
  // empty, so we treat their failures as empty rather than blocking the view.
  const isLoading = assessmentQ.isLoading;
  const isError = assessmentQ.isError;

  // Use shared frozen empties for the undefined case so the fallback array
  // reference is stable across renders — otherwise `data ?? []` mints a fresh
  // `[]` every render and churns the downstream useMemo deps.
  const assessment = (assessmentQ.data as Assessment | undefined) ?? null;
  const tools = (toolsQ.data as ToolExecution[] | undefined) ?? (EMPTY_TOOLS as ToolExecution[]);
  const events = (eventsQ.data as AssessmentEvent[] | undefined) ?? (EMPTY_EVENTS as AssessmentEvent[]);
  const findings = (findingsQ.data?.data as Finding[] | undefined) ?? (EMPTY_FINDINGS as Finding[]);
  const cacheStats = (cacheQ.data as CacheStatsResponse | null | undefined) ?? null;
  const tests = (testsQ.data as ExecutionTestResult[] | undefined) ?? (EMPTY_TESTS as ExecutionTestResult[]);
  const scope = (scopeQ.data as ScopeTargetDecision[] | undefined) ?? (EMPTY_SCOPE as ScopeTargetDecision[]);

  const phases = useMemo<ExecutionPhase[]>(
    () => derivePhases(events, tests),
    [events, tests],
  );

  const overview = useMemo<ExecutionOverview | null>(() => {
    if (!assessment) return null;

    // ---- duration ----
    // Only computed for completed runs (both endpoints known) so this memo
    // stays pure — a still-running assessment renders as "running" rather than
    // a live-ticking clock (which would require reading Date.now() in render).
    const startTs = assessment.started_at || null;
    const endTs = assessment.completed_at || null;
    let wallMs: number | null = null;
    if (startTs && endTs) {
      const startMs = new Date(startTs).getTime();
      const endMs = new Date(endTs).getTime();
      if (Number.isFinite(startMs) && Number.isFinite(endMs) && endMs >= startMs) {
        wallMs = endMs - startMs;
      }
    }

    // ---- counts ----
    const toolExecutions = tools.reduce((acc, t) => acc + (t.run_count || 0), 0);
    const distinctTools = tools.length;
    const toolsAbsent = tools.filter(toolAbsent).length;
    const toolsFailing = tools.filter(toolFailing).length;
    const findingsCreated = events.filter(
      (e) => e.event_type === 'finding_detected',
    ).length;
    const errors = events.filter((e) => e.event_type === 'error').length;
    const toolCallEvents = events.filter((e) => e.event_type === 'tool_call').length;

    // ---- findings by severity (denormalized counts, findings[] fallback) ----
    const denormTotal =
      (assessment.critical_count || 0) +
      (assessment.high_count || 0) +
      (assessment.medium_count || 0) +
      (assessment.low_count || 0);
    const useDenorm = denormTotal > 0 || (assessment.findings_count ?? 0) > 0;
    const sev = useDenorm
      ? {
          critical: assessment.critical_count || 0,
          high: assessment.high_count || 0,
          medium: assessment.medium_count || 0,
          low: assessment.low_count || 0,
          info: 0,
        }
      : findings.reduce(
          (acc, f) => {
            if (f.severity === 'critical') acc.critical++;
            else if (f.severity === 'high') acc.high++;
            else if (f.severity === 'medium') acc.medium++;
            else if (f.severity === 'low') acc.low++;
            else acc.info++;
            return acc;
          },
          { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
        );
    const findingsTotal = useDenorm
      ? assessment.findings_count || denormTotal
      : sev.critical + sev.high + sev.medium + sev.low + (sev.info || 0);

    // ---- tokens / cost (cache stats) ----
    const tokens = cacheStats
      ? {
          inputTokens: cacheStats.input_tokens,
          outputTokens: cacheStats.output_tokens,
          cacheCreationInputTokens: cacheStats.cache_creation_input_tokens,
          cacheReadInputTokens: cacheStats.cache_read_input_tokens,
          totalTokens:
            cacheStats.input_tokens +
            cacheStats.output_tokens +
            cacheStats.cache_creation_input_tokens +
            cacheStats.cache_read_input_tokens,
        }
      : {
          inputTokens: 0,
          outputTokens: 0,
          cacheCreationInputTokens: 0,
          cacheReadInputTokens: 0,
          totalTokens: 0,
        };
    const costUsd = cacheStats ? cacheStats.cost_usd : null;

    // ---- test rollup ----
    const rollup = {
      total: tests.length,
      pass: 0,
      fail: 0,
      n_a: 0,
      blocked: 0,
      skipped: 0,
      byStatus: {} as Record<string, number>,
    };
    for (const t of tests) {
      const s: TestOutcome = t.status;
      rollup.byStatus[s] = (rollup.byStatus[s] || 0) + 1;
      if (s === 'PASS') rollup.pass++;
      else if (s === 'FAIL') rollup.fail++;
      else if (s === 'N_A') rollup.n_a++;
      else if (s === 'BLOCKED') rollup.blocked++;
    }

    // ---- targets ----
    const targets = scope.map((s) => ({
      target: s.target,
      inScope: s.in_scope,
      dimension: s.dimension ?? null,
      reason: s.reason ?? null,
      toolExecutions: undefined,
    }));

    // ---- verdict ----
    const verdict = deriveVerdict(assessment, tests, tools);
    const ok = verdict === 'complete' || verdict === 'partial';
    const hardFailures: string[] = [];
    if (verdict === 'failed' && assessment.error_message) {
      hardFailures.push(assessment.error_message);
    }
    const softWarnings: string[] = [];
    if (toolsAbsent > 0) {
      softWarnings.push(`${toolsAbsent} tool${toolsAbsent === 1 ? '' : 's'} absent from container`);
    }
    if (toolsFailing > 0) {
      softWarnings.push(`${toolsFailing} tool${toolsFailing === 1 ? '' : 's'} ran but never exited 0`);
    }
    const summary =
      verdict === 'complete'
        ? 'All recorded tests passed or were N/A with no absent tools.'
        : verdict === 'partial'
          ? 'Completed with blocked tests or absent tools.'
          : verdict === 'blocked'
            ? 'Coverage blocked — absent tools or blocked tests.'
            : verdict === 'failed'
              ? assessment.error_message || 'Assessment failed.'
              : 'Outcome could not be determined from recorded data.';

    // ---- provenance discriminator ----
    const provenance = {
      test_results: tests.length > 0 ? ('db' as const) : ('absent' as const),
      scope: scope.length > 0 ? ('db' as const) : ('absent' as const),
      phases: 'derived' as const,
    };

    // ---- integrity (harness-only differentiator; minimal for production) ----
    const provenanceBlocked = tests
      .filter((t) => t.enforced)
      .map((t) => t.test_id);

    const overview: ExecutionOverview = {
      schemaVersion: 1,
      executionId: assessment.id,
      source: 'production',
      generatedAt: new Date().toISOString(),
      model: cacheStats?.model ?? null,
      success: {
        ok,
        verdict,
        summary,
        hardFailures,
        softWarnings,
        degenerateRun: false,
      },
      counts: {
        toolExecutions,
        distinctTools,
        subagentSpawns: 0,
        distinctAgentTypes: 0,
        turns: 0,
        steps: toolCallEvents,
        findingsCreated,
        errors,
        retries: 0,
      },
      targets,
      testRollup: rollup,
      integrity: {
        consistent: true,
        fakedPass: [],
        provenanceBlocked,
        unverifiable: [],
      },
      duration: { startTs, endTs, wallMs },
      tokens,
      costUsd,
      findingsBySeverity: sev,
      findingsTotal,
      provenance,
    };
    return overview;
  }, [assessment, tools, events, findings, cacheStats, tests, scope]);

  return {
    overview,
    assessment,
    phases,
    testResults: tests,
    scopeDecisions: scope,
    isLoading,
    isError,
    error: assessmentQ.error,
  };
}
