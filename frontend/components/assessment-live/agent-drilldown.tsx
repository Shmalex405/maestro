'use client';

// Drill-down for a selected agent: its plain-English status, live counters, the
// recent activity attributed to it, and its owned test ids. Per-test outcome
// prefers the authoritative verdict from the agent's checkpoint
// (reports/{agent}-results.json — PASS/FAIL/BLOCKED/N_A); until a checkpoint
// lands it falls back to the live SSE tool-status (started/ok/error).

import { motion } from 'framer-motion';
import { X } from 'lucide-react';
import { cn } from '@/lib/utils';
import { Badge } from '@/components/ui/badge';
import type {
  AgentState,
  PlanAgent,
  ProgressStatus,
  TickerLine,
} from '@/lib/assessment-progress/types';
import type { AuthoritativeTest } from '@/lib/assessment-progress/use-assessment-test-results';

const STATUS_BADGE: Record<string, string> = {
  pending: 'bg-muted text-muted-foreground',
  active: 'bg-cyan-500/20 text-cyan-300',
  done: 'bg-emerald-500/20 text-emerald-300',
  error: 'bg-amber-500/20 text-amber-300',
};

function effectiveStatus(state: AgentState | undefined): string {
  const s = state?.status ?? 'pending';
  if (s === 'active' && (state?.errorCount ?? 0) > 0) return 'error';
  return s;
}

const TEST_CHIP: Record<string, string> = {
  started: 'bg-cyan-500/20 text-cyan-300',
  ok: 'bg-emerald-500/20 text-emerald-300',
  error: 'bg-amber-500/20 text-amber-300',
};

// Authoritative checkpoint verdicts (outrank the live tool-status above).
const OUTCOME_CHIP: Record<string, string> = {
  PASS: 'bg-emerald-500/20 text-emerald-300',
  FAIL: 'bg-red-500/25 text-red-300',
  BLOCKED: 'bg-amber-500/20 text-amber-300',
  N_A: 'bg-muted text-muted-foreground',
};

export function AgentDrilldown({
  agent,
  state,
  lines,
  testStatus,
  authoritativeTests,
  onClose,
}: {
  agent: PlanAgent;
  state: AgentState | undefined;
  lines: TickerLine[];
  testStatus?: Map<string, ProgressStatus>;
  /** Authoritative per-test verdicts from checkpoints, keyed by test id. */
  authoritativeTests?: Map<string, AuthoritativeTest>;
  onClose: () => void;
}) {
  const status = effectiveStatus(state);
  const agentLines = [...lines].reverse().filter((l) => l.agent === agent.name);

  return (
    <motion.div
      initial={{ opacity: 0, x: 16 }}
      animate={{ opacity: 1, x: 0 }}
      exit={{ opacity: 0, x: 16 }}
      transition={{ duration: 0.2 }}
      className="flex flex-col h-full bg-card/95 backdrop-blur-sm border-l"
    >
      <div className="px-3 py-2.5 border-b flex items-start justify-between gap-2">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <span className="text-sm font-semibold text-foreground truncate">
              {agent.name}
            </span>
            <Badge className={cn('text-[10px] px-1.5 py-0 capitalize', STATUS_BADGE[status])}>
              {status}
            </Badge>
          </div>
          {agent.description && (
            <p className="text-[11px] text-muted-foreground mt-0.5 leading-snug">
              {agent.description}
            </p>
          )}
        </div>
        <button
          onClick={onClose}
          className="text-muted-foreground hover:text-foreground shrink-0"
        >
          <X className="h-4 w-4" />
        </button>
      </div>

      <div className="grid grid-cols-3 gap-px bg-border text-center">
        {[
          { label: 'Tools', value: state?.toolCount ?? 0 },
          { label: 'Errors', value: state?.errorCount ?? 0 },
          { label: 'Tests', value: agent.testCount },
        ].map((stat) => (
          <div key={stat.label} className="bg-card py-2">
            <div className="text-base font-semibold text-foreground tabular-nums">
              {stat.value}
            </div>
            <div className="text-[10px] text-muted-foreground uppercase tracking-wide">
              {stat.label}
            </div>
          </div>
        ))}
      </div>

      <div className="flex-1 overflow-y-auto">
        {/* Recent activity for this agent */}
        <div className="px-3 py-2">
          <div className="text-[10px] uppercase tracking-wide text-muted-foreground mb-1.5">
            Recent activity
          </div>
          {agentLines.length === 0 ? (
            <div className="text-[11px] text-muted-foreground">No activity yet.</div>
          ) : (
            <div className="space-y-1">
              {agentLines.slice(0, 12).map((l) => (
                <div key={l.id} className="text-[11px] text-foreground/90 leading-snug">
                  <span
                    className={cn(
                      'inline-block h-1.5 w-1.5 rounded-full mr-1.5 align-middle',
                      l.status === 'ok'
                        ? 'bg-emerald-500'
                        : l.status === 'error'
                        ? 'bg-amber-500'
                        : 'bg-cyan-400'
                    )}
                  />
                  {l.narration}
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Owned tests */}
        {agent.tests.length > 0 && (
          <div className="px-3 py-2 border-t">
            <div className="text-[10px] uppercase tracking-wide text-muted-foreground mb-1.5">
              Owned tests ({agent.tests.length})
            </div>
            <div className="flex flex-wrap gap-1">
              {agent.tests.map((t) => {
                const verdict = authoritativeTests?.get(t);
                const outcome = verdict?.status && OUTCOME_CHIP[verdict.status]
                  ? verdict.status
                  : undefined;
                const live = testStatus?.get(t);
                const chip = outcome
                  ? OUTCOME_CHIP[outcome]
                  : live
                  ? TEST_CHIP[live]
                  : 'bg-muted text-muted-foreground';
                const title = outcome
                  ? `${outcome}${verdict?.findingCount ? ` — ${verdict.findingCount} finding(s)` : ''}${verdict?.notes ? `: ${verdict.notes}` : ''}`
                  : live
                  ? `live: ${live}`
                  : 'not yet exercised';
                return (
                  <span
                    key={t}
                    className={cn('text-[10px] px-1.5 py-0.5 rounded tabular-nums', chip)}
                    title={title}
                  >
                    {t}
                  </span>
                );
              })}
            </div>
          </div>
        )}
      </div>
    </motion.div>
  );
}
