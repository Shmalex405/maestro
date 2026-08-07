// Fetch AUTHORITATIVE per-test outcomes (PASS/FAIL/BLOCKED/N_A) for an
// assessment from the MCP server, which reads them from the agent checkpoint
// files (reports/{agent}-results.json). This is the real recorded verdict —
// distinct from the live SSE stream, which only carries tool-dispatch status
// (started/ok/error). The Assessment View overlays these onto the plan grid.

import { useQuery } from '@tanstack/react-query';

const MCP_BASE =
  process.env.NEXT_PUBLIC_DEPLOY_MODE === 'web'
    ? ''
    : process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3001';

export type TestOutcome = 'PASS' | 'FAIL' | 'BLOCKED' | 'N_A';

export interface AuthoritativeTest {
  testId: string;
  /** PASS | FAIL | BLOCKED | N_A (upper-cased; '' if the checkpoint omitted it). */
  status: string;
  agent: string;
  findingCount: number;
  notes: string;
}

interface TestResultsResponse {
  assessmentId: string;
  tests: AuthoritativeTest[];
  agents: Array<{ agent: string; timestamp: string | null; count: number }>;
}

/**
 * Returns a Map keyed by test id → its authoritative outcome. While the
 * assessment is running, pass `poll: true` so checkpoints written mid-run are
 * picked up. Empty map until the first checkpoint lands.
 */
export function useAssessmentTestResults(
  assessmentId: string | undefined,
  opts?: { enabled?: boolean; poll?: boolean },
) {
  return useQuery({
    queryKey: ['assessment-test-results', assessmentId],
    queryFn: async (): Promise<Map<string, AuthoritativeTest>> => {
      const res = await fetch(`${MCP_BASE}/api/assessments/${assessmentId}/test-results`);
      if (!res.ok) throw new Error(`test-results ${res.status}`);
      const data = (await res.json()) as TestResultsResponse;
      const m = new Map<string, AuthoritativeTest>();
      // Later agents can re-rate a shared test id (e.g. crossval-qa); last wins.
      for (const t of data.tests ?? []) m.set(t.testId, t);
      return m;
    },
    enabled: Boolean(assessmentId) && (opts?.enabled ?? true),
    refetchInterval: opts?.poll ? 5000 : false,
    staleTime: 3000,
  });
}
