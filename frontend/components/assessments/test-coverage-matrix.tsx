'use client';

import { useMemo } from 'react';
import { ListChecks, ShieldAlert } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { cn } from '@/lib/utils';
import type { ExecutionTestResult, TestOutcome } from '@/lib/types';

interface TestCoverageMatrixProps {
  testResults: ExecutionTestResult[];
  /** From overview.provenance.test_results — 'absent' renders a placeholder. */
  provenance?: 'db' | 'derived' | 'absent';
}

// Outcome → pill styling. Reuses the green/amber/red conventions from
// tool-provenance-panel.tsx and the badge-* status palette.
const OUTCOME_PILL: Record<TestOutcome, string> = {
  PASS: 'bg-green-500/10 text-green-600 dark:text-green-400 border-green-500/30',
  FAIL: 'bg-red-500/10 text-red-600 dark:text-red-400 border-red-500/30',
  N_A: 'bg-muted text-muted-foreground border-border',
  BLOCKED: 'bg-amber-500/10 text-amber-600 dark:text-amber-400 border-amber-500/30',
};

const OUTCOME_LABEL: Record<TestOutcome, string> = {
  PASS: 'PASS',
  FAIL: 'FAIL',
  N_A: 'N/A',
  BLOCKED: 'BLOCKED',
};

/**
 * Per-test coverage, grouped by agent. Each test renders a PASS/FAIL/N_A/BLOCKED
 * pill; an enforced-BLOCKED (a PASS/N_A the provenance gate forced to BLOCKED)
 * surfaces its enforced_reason. When per-test coverage wasn't captured for the
 * run (provenance === 'absent'), a labeled placeholder is shown instead.
 */
export function TestCoverageMatrix({ testResults, provenance }: TestCoverageMatrixProps) {
  const grouped = useMemo(() => {
    const map = new Map<string, ExecutionTestResult[]>();
    for (const t of testResults) {
      const agent = t.agent || 'unassigned';
      const arr = map.get(agent) || [];
      arr.push(t);
      map.set(agent, arr);
    }
    // Sort tests within each agent by test_id for stable ordering.
    for (const arr of map.values()) {
      arr.sort((a, b) => a.test_id.localeCompare(b.test_id));
    }
    return Array.from(map.entries()).sort((a, b) => a[0].localeCompare(b[0]));
  }, [testResults]);

  const header = (
    <CardHeader className="pb-3">
      <CardTitle className="text-base flex items-center gap-2">
        <ListChecks className="h-4 w-4" />
        Test coverage
        {testResults.length > 0 && (
          <span className="text-xs font-normal text-muted-foreground">
            · {testResults.length} test{testResults.length === 1 ? '' : 's'}
          </span>
        )}
      </CardTitle>
    </CardHeader>
  );

  if (provenance === 'absent' || testResults.length === 0) {
    return (
      <Card>
        {header}
        <CardContent>
          <div className="rounded-lg border border-dashed border-border p-4 text-sm text-muted-foreground">
            Per-test coverage not captured for this run.
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      {header}
      <CardContent className="space-y-4">
        {grouped.map(([agent, tests]) => (
          <div key={agent}>
            <div className="mb-2 flex items-center gap-2">
              <span className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                {agent}
              </span>
              <span className="text-[10px] text-muted-foreground tabular-nums">
                {tests.length}
              </span>
            </div>
            <div className="flex flex-wrap gap-1.5">
              {tests.map((t) => (
                <TestPill key={t.test_id} test={t} />
              ))}
            </div>
            {/* Surface the gate's reason for any enforced-BLOCKED in this group. */}
            {tests
              .filter((t) => t.enforced && t.enforced_reason)
              .map((t) => (
                <div
                  key={`${t.test_id}-reason`}
                  className="mt-1.5 flex items-start gap-1.5 text-[11px] text-amber-600 dark:text-amber-400"
                >
                  <ShieldAlert className="h-3 w-3 mt-0.5 shrink-0" />
                  <span>
                    <span className="font-mono">{t.test_id}</span>: {t.enforced_reason}
                  </span>
                </div>
              ))}
          </div>
        ))}
      </CardContent>
    </Card>
  );
}

function TestPill({ test }: { test: ExecutionTestResult }) {
  const pill = OUTCOME_PILL[test.status];
  const enforced = test.enforced;
  const title = enforced && test.enforced_reason
    ? `${test.test_id} — enforced BLOCKED: ${test.enforced_reason}`
    : test.test_id;

  return (
    <span
      title={title}
      className={cn(
        'inline-flex items-center gap-1 rounded-md border px-1.5 py-0.5 text-[10px] font-medium font-mono',
        pill,
      )}
    >
      {enforced && <ShieldAlert className="h-2.5 w-2.5" />}
      <span>{test.test_id}</span>
      <span className="opacity-70">{OUTCOME_LABEL[test.status]}</span>
    </span>
  );
}
