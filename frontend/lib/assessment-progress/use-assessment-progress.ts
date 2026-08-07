// Fold a ProgressFeed into the derived UI state the Assessment View renders:
// per-agent run status, the active phase, a rolling narration ticker, and a few
// counters. Pure event-stream reduction — works identically for the mock feed
// and the live SSE feed.
//
// Agent lifecycle is inferred from tool events alone (the feed carries no
// explicit "agent done" signal yet): an agent is `active` once it emits a tool
// event, and flips to `done` when the run advances to a later phase. Agents
// never seen stay `pending`. Phase progression is monotonic by plan order.

import { useEffect, useMemo, useRef, useState } from 'react';
import type { ProgressFeed } from './feed';
import type {
  AgentState,
  AssessmentPlan,
  ProgressEvent,
  ProgressStatus,
  TickerLine,
} from './types';

const TICKER_CAP = 80;

export interface AssessmentProgressState {
  agentState: Map<string, AgentState>;
  activePhase: string | undefined;
  ticker: TickerLine[];
  eventCount: number;
  lastEvent: ProgressEvent | undefined;
  /**
   * Live per-test outcome derived from tool events (testId → latest status).
   * This is a real-time proxy — the authoritative PASS/FAIL still comes from
   * the agent's checkpoint at completion. 'started' = running, 'ok' = exercised
   * cleanly, 'error' = a tool under that test errored.
   */
  testStatus: Map<string, ProgressStatus>;
}

export function useAssessmentProgress(
  plan: AssessmentPlan | null | undefined,
  feed: ProgressFeed | null | undefined
): AssessmentProgressState {
  const [agentState, setAgentState] = useState<Map<string, AgentState>>(
    () => new Map()
  );
  const [ticker, setTicker] = useState<TickerLine[]>([]);
  const [activePhase, setActivePhase] = useState<string | undefined>(undefined);
  const [eventCount, setEventCount] = useState(0);
  const [lastEvent, setLastEvent] = useState<ProgressEvent | undefined>();
  const [testStatus, setTestStatus] = useState<Map<string, ProgressStatus>>(
    () => new Map()
  );

  // Phase order index (monotonic progression). Recomputed when the plan loads.
  const phaseOrder = useMemo(() => {
    const m = new Map<string, number>();
    plan?.phases.forEach((p, i) => m.set(p.phase, i));
    return m;
  }, [plan]);

  // Agents grouped by phase — used to mark a phase's agents done on advance.
  const agentsByPhase = useMemo(() => {
    const m = new Map<string, string[]>();
    plan?.phases.forEach((p) =>
      m.set(
        p.phase,
        p.agents.map((a) => a.name)
      )
    );
    return m;
  }, [plan]);

  // Seed every in-scope agent as 'pending' when the plan (re)loads.
  useEffect(() => {
    if (!plan) return;
    const seeded = new Map<string, AgentState>();
    for (const phase of plan.phases) {
      for (const agent of phase.agents) {
        seeded.set(agent.name, {
          status: 'pending',
          toolCount: 0,
          errorCount: 0,
        });
      }
    }
    setAgentState(seeded);
    setActivePhase(undefined);
    setTicker([]);
    setEventCount(0);
    setLastEvent(undefined);
    setTestStatus(new Map());
  }, [plan]);

  const maxPhaseIdxRef = useRef(-1);
  const tickerSeqRef = useRef(0);

  useEffect(() => {
    if (!feed) return;
    maxPhaseIdxRef.current = -1;

    const unsub = feed.subscribe((e: ProgressEvent) => {
      setEventCount((n) => n + 1);
      setLastEvent(e);

      // Per-test live outcome (latest status wins; 'ok' shouldn't overwrite a
      // prior 'error' for the same test — an errored tool is the salient signal).
      if (e.testId) {
        setTestStatus((prev) => {
          const cur = prev.get(e.testId!);
          if (cur === 'error' && e.status === 'ok') return prev;
          const next = new Map(prev);
          next.set(e.testId!, e.status);
          return next;
        });
      }

      // Ticker line (always, attributed or not).
      setTicker((prev) => {
        const line: TickerLine = {
          id: `${e.ts}-${tickerSeqRef.current++}`,
          ts: e.ts,
          agent: e.agent,
          phase: e.phase,
          status: e.status,
          narration: e.narration,
        };
        const next = [...prev, line];
        return next.length > TICKER_CAP ? next.slice(-TICKER_CAP) : next;
      });

      // Phase progression: advance the active phase monotonically, marking the
      // agents of every earlier phase that were active as done.
      const evtIdx = e.phase != null ? phaseOrder.get(e.phase) : undefined;
      const advanced =
        evtIdx != null && evtIdx > maxPhaseIdxRef.current ? evtIdx : null;

      setAgentState((prev) => {
        const next = new Map(prev);

        if (advanced != null) {
          for (const [phaseId, idx] of phaseOrder) {
            if (idx < advanced) {
              for (const name of agentsByPhase.get(phaseId) ?? []) {
                const s = next.get(name);
                if (s && s.status === 'active') {
                  next.set(name, { ...s, status: 'done' });
                }
              }
            }
          }
        }

        // Update the emitting agent (when attributable).
        if (e.agent) {
          const cur =
            next.get(e.agent) ??
            ({ status: 'pending', toolCount: 0, errorCount: 0 } as AgentState);
          next.set(e.agent, {
            ...cur,
            status: cur.status === 'done' ? 'done' : 'active',
            lastNarration: e.narration,
            lastTool: e.tool,
            lastTs: e.ts,
            toolCount: e.status === 'started' ? cur.toolCount + 1 : cur.toolCount,
            errorCount:
              e.status === 'error' ? cur.errorCount + 1 : cur.errorCount,
          });
        }

        return next;
      });

      if (advanced != null && e.phase) {
        maxPhaseIdxRef.current = advanced;
        setActivePhase(e.phase);
      } else if (e.phase && maxPhaseIdxRef.current < 0) {
        // First attributed event before any advance recorded.
        const idx = phaseOrder.get(e.phase);
        if (idx != null) {
          maxPhaseIdxRef.current = idx;
          setActivePhase(e.phase);
        }
      }
    });

    return unsub;
  }, [feed, phaseOrder, agentsByPhase]);

  return { agentState, activePhase, ticker, eventCount, lastEvent, testStatus };
}
