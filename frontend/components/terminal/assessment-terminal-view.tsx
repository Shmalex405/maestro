'use client';

import { useState, useCallback, useEffect, useRef, useMemo } from 'react';
import { useRouter } from 'next/navigation';
import { useQueryClient } from '@tanstack/react-query';
import { useTerminalStore } from '@/lib/stores/terminal-store';
import { useSettingsStore } from '@/lib/stores/settings-store';
import { useParsedOutputStore } from '@/lib/stores/parsed-output-store';
import { useLiveAssessmentsStore } from '@/lib/stores/live-assessments-store';
import { useTerminalParser } from '@/lib/hooks/use-terminal-parser';
import { useAssessmentSync } from '@/lib/hooks/use-assessment-sync';
import { useEventPersistence } from '@/lib/hooks/use-event-persistence';
import { api } from '@/lib/tauri-api';
import { isCodexEnabled } from '@/lib/codex-enabled';
import { TerminalView } from './terminal-view';
import { TranscriptView } from './transcript-view';
import { CodexTerminalView } from './codex-terminal-view';
import { AssessmentLiveView } from '@/components/assessment-live/assessment-live-view';
import { useAssessmentPlan } from '@/lib/assessment-progress/use-assessment-plan';
import { createLiveFeed } from '@/lib/assessment-progress/feed';
import { UnifiedInputBar } from './unified-input-bar';
import { AssessmentPromptBar } from './assessment-prompt-bar';
import { AssessmentHeaderBar } from './assessment-header-bar';
import { AssessmentDetailSidebar } from './assessment-detail-sidebar';
import { Badge } from '@/components/ui/badge';
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from '@/components/ui/popover';
import {
  Bot,
  Sparkles,
  AlertTriangle,
  AlertOctagon,
  AlertCircle,
  Info,
  PanelRight,
  TerminalSquare,
  ChevronDown,
  ChevronUp,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { toast } from 'sonner';
import type { Assessment } from '@/lib/types';

interface AssessmentTerminalViewProps {
  /** null = new assessment, string = existing assessment */
  assessmentId: string | null;
  assessment: Assessment | null;
  onAssessmentCreated: (assessment: Assessment) => void;
  onAssessmentStatusChanged: () => void;
}

type ViewMode = 'codex' | 'terminal';

export function AssessmentTerminalView({
  assessmentId,
  assessment,
  onAssessmentCreated,
  onAssessmentStatusChanged,
}: AssessmentTerminalViewProps) {
  const router = useRouter();
  const queryClient = useQueryClient();
  const [viewMode, setViewMode] = useState<ViewMode>('terminal');
  const [showDetails, setShowDetails] = useState(false);
  // The structured Assessment View is the default while a run is live; the raw
  // Claude Code terminal is one caret-click away (and stays tmux-attached the
  // whole time, so expanding it is instant). See terminalExpanded below.
  const [terminalExpanded, setTerminalExpanded] = useState(false);
  const [activeSessionKey, setActiveSessionKey] = useState<string | null>(null);
  const [sessionMode, setSessionMode] = useState<'loading' | 'live' | 'reattach' | 'transcript'>('loading');
  // Whether a read-only transcript can be turned back into a live session:
  //   'resumable' — Claude's .jsonl is still in the container → reload it.
  //   'lost'      — had a session but the file is gone (e.g. claude-home was
  //                 reset / container fully rebuilt) → only a fresh start is
  //                 possible; resuming would open an empty prompt.
  //   'none'      — assessment never had a pinned session id.
  //   'unknown'   — still checking, or not in transcript mode.
  const [resumeContext, setResumeContext] = useState<'unknown' | 'resumable' | 'lost' | 'none'>('unknown');
  const tmuxPath = useSettingsStore((s) => s.tmuxPath);

  // Session key: use assessmentId if viewing one, otherwise a default key for the always-on terminal
  const sessionKey = assessmentId || activeSessionKey || '__new__';

  // Determine session mode: live terminal, reattach to running tmux, or read-only transcript.
  // Sessions can come from either brain — Claude uses `assess-<id>`, Codex uses
  // `codex-assess-<id>` — so we probe both prefixes. Whichever responds first
  // is enough to flip into reattach mode; the assessment-terminal-view's
  // tab-switch logic shows whichever PTY pane the user picks.
  useEffect(() => {
    async function determineSessionMode() {
      if (!assessmentId) {
        setSessionMode('live');
        return;
      }

      // Check if either brain has a running tmux session to reattach to.
      // checkAssessmentSessionLive on the Tauri side already handles both
      // prefixes (terminal.rs), so one call covers both.
      const sessionAlive = await api.terminal
        .checkAssessmentSessionLive(assessmentId)
        .catch(() => false);
      if (sessionAlive) {
        setSessionMode('reattach');
        return;
      }

      // Check assessment status from props
      if (assessment?.status === 'completed' || assessment?.status === 'failed') {
        setSessionMode('transcript');
      } else {
        setSessionMode('live');
      }
    }
    determineSessionMode();
  }, [assessmentId, assessment?.status, tmuxPath]);

  // While showing a read-only transcript, decide whether Resume can actually
  // restore the conversation. A completed assessment carries a pinned session
  // id, but `claude --resume <id>` only reloads context if that session's
  // .jsonl still exists in the container. After a full container rebuild (or a
  // claude-home reset) the file can be gone — resuming would silently open an
  // empty prompt that looks like lost work. We probe the file's existence so
  // the UI can offer a clearly-labeled fresh start in that case instead.
  useEffect(() => {
    let cancelled = false;
    async function computeResumeContext() {
      if (sessionMode !== 'transcript' || !assessmentId) {
        setResumeContext('unknown');
        return;
      }
      const storedId = (assessment?.options as { claude_session_id?: string } | null | undefined)
        ?.claude_session_id;
      if (!storedId) {
        setResumeContext('none');
        return;
      }
      const resumable = await api.terminal
        .checkClaudeSessionResumable(storedId)
        .catch(() => false);
      if (!cancelled) setResumeContext(resumable ? 'resumable' : 'lost');
    }
    computeResumeContext();
    return () => {
      cancelled = true;
    };
  }, [sessionMode, assessmentId, assessment?.options]);

  // One-shot toast when we land on a reattach. Surfaces what's already
  // true — sessions stay alive across screen navigation and app restarts —
  // so users don't wonder why the pane is opening into an existing prompt
  // instead of a fresh banner. Fires once per assessment-id transition.
  const reattachToastFiredRef = useRef<string | null>(null);
  useEffect(() => {
    if (
      sessionMode === 'reattach' &&
      assessmentId &&
      reattachToastFiredRef.current !== assessmentId
    ) {
      reattachToastFiredRef.current = assessmentId;
      toast.info('Resuming live session…', {
        description: "Reconnecting to the running CLI inside the Kali container.",
        duration: 4000,
      });
    }
  }, [sessionMode, assessmentId]);

  // Reconcile tmux sessions with DB on mount (one-time)
  const reconcileRef = useRef(false);
  useEffect(() => {
    if (reconcileRef.current) return;
    reconcileRef.current = true;
    (async () => {
      try {
        const tmuxSessions = await api.terminal.listTmuxSessions();
        for (const tmux of tmuxSessions) {
          const id = tmux.name.replace('assess-', '');
          try {
            const a = await api.assessments.get(id);
            if (a && a.status !== 'running') {
              await api.assessments.update(id, { status: 'running' });
            }
          } catch { /* assessment not found, ignore */ }
        }
      } catch { /* tmux not available, ignore */ }
    })();
  }, []);

  // Parser hook — feeds PTY data into structured blocks
  const { feedData } = useTerminalParser(sessionKey);

  // Finding counts from parsed output — read raw blocks to avoid new-object-per-render
  const parsedBlocks = useParsedOutputStore((s) => s.sessions.get(sessionKey));
  const findingsBySeverity = useMemo(() => {
    const blocks = parsedBlocks || [];
    const findings = blocks.filter((b) => b.type === 'finding_detected');
    const counts: Record<string, number> = {};
    for (const f of findings) {
      const severity = (f.metadata as { severity?: string })?.severity || 'info';
      counts[severity] = (counts[severity] || 0) + 1;
    }
    return counts;
  }, [parsedBlocks]);
  const totalFindings = Object.values(findingsBySeverity).reduce((a, b) => a + b, 0);

  // Session state from terminal store
  const session = useTerminalStore((s) => s.sessions.get(sessionKey));

  // Poll assessment data while active
  useAssessmentSync(assessmentId);

  // Persist notable terminal blocks (tool calls, tool results, findings) to
  // the cloud assessment_events table so the activity feed timeline is
  // durable across reloads and other clients.
  useEventPersistence(assessmentId, sessionKey);

  // Auto-spawn removed (Shape A): assessments are only created via the
  // explicit "New Assessment" modal in app/assessments/page.tsx. The
  // terminal view never creates an assessment row on its own — it
  // requires a non-null assessmentId. This guarantees we don't run
  // assessments the user didn't explicitly start, and keeps the live
  // popup limited to runs the user actually kicked off.

  // When new findings are detected, invalidate assessment queries so sidebar updates
  const prevFindingCountRef = useRef(totalFindings);
  useEffect(() => {
    if (totalFindings > prevFindingCountRef.current) {
      prevFindingCountRef.current = totalFindings;
      queryClient.invalidateQueries({ queryKey: ['assessments'] });
      queryClient.invalidateQueries({ queryKey: ['findings-stats'] });
      if (assessmentId) {
        queryClient.invalidateQueries({ queryKey: ['findings', assessmentId] });
      }
    }
  }, [totalFindings, assessmentId, queryClient]);

  // Wire the live-assessments popup. Register on mount with a current
  // assessmentId, stream the parser's severity breakdown into the store
  // on every change, and tear down when the assessment moves out of
  // 'running'. The popup itself is mounted at the root layout so the
  // counts stay visible if the user navigates away from /assessments.
  const registerLive = useLiveAssessmentsStore((s) => s.register);
  const setLiveCounts = useLiveAssessmentsStore((s) => s.setCounts);
  const setLiveName = useLiveAssessmentsStore((s) => s.setName);
  const setLiveStatus = useLiveAssessmentsStore((s) => s.setStatus);
  const unregisterLive = useLiveAssessmentsStore((s) => s.unregister);

  useEffect(() => {
    if (!assessmentId) return;
    registerLive(assessmentId, assessment?.name ?? 'Assessment');
    return () => {
      // Don't unregister on unmount alone — the user navigating away
      // shouldn't kill the popup card. Cleanup happens via status change
      // (see the status effect below).
    };
  }, [assessmentId, registerLive, assessment?.name]);

  useEffect(() => {
    if (!assessmentId) return;
    if (assessment?.name) setLiveName(assessmentId, assessment.name);
  }, [assessmentId, assessment?.name, setLiveName]);

  useEffect(() => {
    if (!assessmentId) return;
    setLiveCounts(assessmentId, {
      critical: findingsBySeverity.critical || 0,
      high: findingsBySeverity.high || 0,
      medium: findingsBySeverity.medium || 0,
      low: findingsBySeverity.low || 0,
      info: findingsBySeverity.info || 0,
    });
  }, [assessmentId, findingsBySeverity, setLiveCounts]);

  useEffect(() => {
    if (!assessmentId) return;
    const status = assessment?.status;
    if (status === 'completed' || status === 'failed') {
      setLiveStatus(assessmentId, status);
      // Keep the card visible briefly so the user sees final counts,
      // then drop it. Master collapsed users won't see this — fine.
      const t = setTimeout(() => unregisterLive(assessmentId), 8000);
      return () => clearTimeout(t);
    }
    if (status === 'running') {
      setLiveStatus(assessmentId, 'running');
    }
  }, [assessmentId, assessment?.status, setLiveStatus, unregisterLive]);

  // Handle new assessment creation from prompt bar
  const handlePromptBarAssessmentCreated = useCallback((newAssessment: Assessment, _prompt: string) => {
    setActiveSessionKey(newAssessment.id);
    onAssessmentCreated(newAssessment);
  }, [onAssessmentCreated]);

  // Handle PTY data — forward to parser
  const handlePtyData = useCallback((data: string) => {
    feedData(data);
  }, [feedData]);

  const handleSessionStarted = useCallback(() => {
    // Session started, terminal is running
  }, []);

  const handleAssessmentStatusChanged = useCallback(() => {
    queryClient.invalidateQueries({ queryKey: ['assessments'] });
    onAssessmentStatusChanged();
  }, [queryClient, onAssessmentStatusChanged]);

  const handleViewReport = useCallback(() => {
    if (assessmentId) {
      router.push(`/reports?assessment_id=${assessmentId}`);
    }
  }, [assessmentId, router]);

  const effectiveAssessmentId = assessmentId || activeSessionKey || undefined;
  const hasActiveAssessment = !!effectiveAssessmentId;
  const isAssessmentRunning = assessment?.status === 'running';

  // The structured Assessment View is the default while a run is live or
  // reattached — not for completed/transcript runs (no live event stream to
  // animate). The raw terminal collapses behind a caret but stays mounted.
  const structuredApplicable =
    hasActiveAssessment && (sessionMode === 'live' || sessionMode === 'reattach');
  const structuredVisible = structuredApplicable && !terminalExpanded;

  // Scope-filtered plan skeleton + the live SSE progress feed for the view.
  const { data: assessmentPlan } = useAssessmentPlan({
    inScopeOnly: true,
    enabled: structuredApplicable,
  });
  const liveFeed = useMemo(
    () =>
      structuredApplicable && effectiveAssessmentId
        ? createLiveFeed(effectiveAssessmentId)
        : null,
    [structuredApplicable, effectiveAssessmentId]
  );

  return (
    <div className="flex flex-col h-full">
      {/* Assessment Header Bar — only when an assessment exists */}
      {hasActiveAssessment && (
        <AssessmentHeaderBar
          assessment={assessment}
          onViewReport={assessment?.status === 'completed' ? handleViewReport : undefined}
        />
      )}

      {/* Prompt Bar — always visible, disabled when assessment is running */}
      <AssessmentPromptBar
        sessionKey={sessionKey}
        onAssessmentCreated={handlePromptBarAssessmentCreated}
        disabled={isAssessmentRunning}
      />

      {/* View Toggle Bar + Finding Badges + Details.
          The two tabs map to the two "brains": Claude runs the Anthropic
          Claude Code CLI, Codex runs the OpenAI Codex CLI. Both drive the
          same MCP tools — only the LLM differs. */}
      <div className="flex items-center justify-between px-4 py-2 border-b bg-background/95 backdrop-blur-sm">
        <div className="flex items-center gap-1 bg-muted/50 rounded-lg p-0.5">
          <button
            onClick={() => {
              if (viewMode !== 'terminal') {
                setViewMode('terminal');
                api.terminal.recordBrainSelected('claude', effectiveAssessmentId).catch(() => {});
              }
            }}
            className={cn(
              'flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium transition-colors',
              viewMode === 'terminal'
                ? 'bg-background text-foreground shadow-sm'
                : 'text-muted-foreground hover:text-foreground'
            )}
          >
            <Sparkles className="h-3.5 w-3.5" />
            Claude
          </button>
          {isCodexEnabled() && (
            <button
              onClick={() => {
                if (viewMode !== 'codex') {
                  setViewMode('codex');
                  api.terminal.recordBrainSelected('codex', effectiveAssessmentId).catch(() => {});
                }
              }}
              className={cn(
                'flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium transition-colors',
                viewMode === 'codex'
                  ? 'bg-background text-foreground shadow-sm'
                  : 'text-muted-foreground hover:text-foreground'
              )}
            >
              <Bot className="h-3.5 w-3.5" />
              Codex
            </button>
          )}
        </div>

        <div className="flex items-center gap-2">
          {/* Caret: reveal / hide the raw Claude Code session. The structured
              Assessment View is the default; the terminal stays mounted (and
              tmux-attached) behind this toggle so expanding is instant. */}
          {structuredApplicable && (
            <button
              onClick={() => setTerminalExpanded((v) => !v)}
              className={cn(
                'flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium transition-colors border',
                terminalExpanded
                  ? 'bg-background text-foreground border-border shadow-sm'
                  : 'text-muted-foreground hover:text-foreground border-transparent hover:border-border'
              )}
              title={
                terminalExpanded
                  ? 'Back to the assessment view'
                  : 'Show the raw Claude Code session'
              }
            >
              <TerminalSquare className="h-3.5 w-3.5" />
              {terminalExpanded ? 'Hide terminal' : 'Terminal'}
              {terminalExpanded ? (
                <ChevronDown className="h-3 w-3" />
              ) : (
                <ChevronUp className="h-3 w-3" />
              )}
            </button>
          )}

          {/* Real-time finding badges */}
          {totalFindings > 0 && (
            <div className="flex items-center gap-1.5">
              {findingsBySeverity.critical > 0 && (
                <Badge className="bg-red-500 text-white text-[10px] px-1.5 py-0 gap-0.5">
                  <AlertOctagon className="h-2.5 w-2.5" />
                  {findingsBySeverity.critical}
                </Badge>
              )}
              {findingsBySeverity.high > 0 && (
                <Badge className="bg-orange-500 text-white text-[10px] px-1.5 py-0 gap-0.5">
                  <AlertTriangle className="h-2.5 w-2.5" />
                  {findingsBySeverity.high}
                </Badge>
              )}
              {findingsBySeverity.medium > 0 && (
                <Badge className="bg-yellow-500 text-white text-[10px] px-1.5 py-0 gap-0.5">
                  <AlertCircle className="h-2.5 w-2.5" />
                  {findingsBySeverity.medium}
                </Badge>
              )}
              {(findingsBySeverity.low || 0) + (findingsBySeverity.info || 0) > 0 && (
                <Badge variant="outline" className="text-[10px] px-1.5 py-0 gap-0.5 text-muted-foreground">
                  <Info className="h-2.5 w-2.5" />
                  {(findingsBySeverity.low || 0) + (findingsBySeverity.info || 0)}
                </Badge>
              )}
            </div>
          )}

          {/* Details popover toggle */}
          {hasActiveAssessment && (
            <Popover open={showDetails} onOpenChange={setShowDetails}>
              <PopoverTrigger asChild>
                <button
                  className={cn(
                    'flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium transition-colors border',
                    showDetails
                      ? 'bg-background text-foreground border-border shadow-sm'
                      : 'text-muted-foreground hover:text-foreground border-transparent hover:border-border'
                  )}
                >
                  <PanelRight className="h-3.5 w-3.5" />
                  Details
                </button>
              </PopoverTrigger>
              <PopoverContent align="end" sideOffset={4} className="w-72 p-0">
                <AssessmentDetailSidebar
                  assessment={assessment}
                  findingsBySeverity={findingsBySeverity}
                  onViewReport={assessment?.status === 'completed' ? handleViewReport : undefined}
                />
              </PopoverContent>
            </Popover>
          )}
        </div>
      </div>

      {/* Main content area — full width, no sidebar */}
      <div className="flex-1 min-h-0 relative overflow-hidden">
        {/* Terminal view (Claude Code) — always mounted to keep PTY alive,
            hidden when not active so the tmux session keeps running. */}
        <div className={cn(
          'absolute inset-0 flex flex-col',
          viewMode === 'terminal' && !structuredVisible ? '' : 'pointer-events-none opacity-0'
        )}>
          {sessionMode === 'transcript' && effectiveAssessmentId ? (
            <TranscriptView
              assessmentId={effectiveAssessmentId}
              // 'resumable' → Claude's conversation file is present, reload it.
              // 'lost'      → had a session but the file is gone (container
              //               rebuilt / claude-home reset) → fresh start only.
              // 'none'      → no pinned session id (pre-v0.1.39 runs) → no
              //               button; transcript stays read-only.
              resumeContext={resumeContext}
              onResume={async (fresh) => {
                if (!effectiveAssessmentId) return;
                try {
                  if (fresh) {
                    // Prior conversation is unrecoverable — drop the stale
                    // session id so terminal-view generates a new
                    // `--session-id` instead of `--resume`-ing a file that no
                    // longer exists (which would just open an empty prompt).
                    const opts = {
                      ...((assessment?.options as Record<string, unknown> | null | undefined) || {}),
                    };
                    delete (opts as { claude_session_id?: string }).claude_session_id;
                    await api.assessments.updateOptions(effectiveAssessmentId, opts);
                  }
                  // Flip status back to running. determineSessionMode picks
                  // this up on the next tick, switches sessionMode to 'live',
                  // and terminal-view spawns claude — `--resume <uuid>` when
                  // the file is present (context reloads exactly where it left
                  // off), or a fresh `--session-id` after a fresh start.
                  await api.assessments.update(effectiveAssessmentId, { status: 'running' });
                  queryClient.invalidateQueries({ queryKey: ['assessment', effectiveAssessmentId] });
                  queryClient.invalidateQueries({ queryKey: ['assessments'] });
                  onAssessmentStatusChanged();
                } catch (err) {
                  console.error('[assessment-terminal-view] resume failed:', err);
                }
              }}
            />
          ) : (
            <TerminalView
              // key forces a full remount when the user switches between
              // conversations in the sidebar. Without it, the same
              // TerminalView instance re-renders with a new assessmentId
              // prop but its internal refs (terminalRef, xterm DOM) are
              // shared — xterm.js mounts the new terminal on top of the
              // old one's DOM and the user sees stale content. The
              // remount disposes the old xterm cleanly; tmux survives in
              // the container (v0.1.60 detached pattern), so reattach to
              // the same conversation later still picks up where it
              // left off.
              key={`claude-${effectiveAssessmentId || '__new__'}`}
              assessmentId={effectiveAssessmentId}
              assessment={assessment}
              onSessionStarted={handleSessionStarted}
              onAssessmentStatusChanged={handleAssessmentStatusChanged}
              onPtyData={handlePtyData}
              tmuxPath={tmuxPath}
            />
          )}
        </div>

        {/* Codex view (OpenAI Codex CLI) — parallel of Terminal, separate
            tmux session prefix (codex-assess-<id>) so the two brains'
            sessions don't collide. Hidden unless NEXT_PUBLIC_CODEX_ENABLED;
            not mounted at all when disabled (the Codex tab is gone too). */}
        {isCodexEnabled() && (
          <div className={cn(
            'absolute inset-0 flex flex-col',
            viewMode === 'codex' && !structuredVisible ? '' : 'pointer-events-none opacity-0'
          )}>
            <CodexTerminalView
              // Same rationale as the Claude pane — key-on-assessmentId
              // forces a clean remount per conversation switch.
              key={`codex-${effectiveAssessmentId || '__new__'}`}
              assessmentId={effectiveAssessmentId}
              assessment={assessment}
              onSessionStarted={handleSessionStarted}
              onAssessmentStatusChanged={handleAssessmentStatusChanged}
              onPtyData={handlePtyData}
              tmuxPath={tmuxPath}
            />
          </div>
        )}

        {/* Structured Assessment View — the default while a run is live. Kept
            mounted (when applicable) on top of the terminal panes so its SSE
            connection + accumulated agent state survive peeking the terminal;
            visibility is opacity-toggled, never unmounted. */}
        {structuredApplicable && (
          <div className={cn(
            'absolute inset-0 bg-background',
            structuredVisible ? '' : 'pointer-events-none opacity-0'
          )}>
            {assessmentPlan ? (
              <AssessmentLiveView
                plan={assessmentPlan}
                feed={liveFeed}
                findingsBySeverity={findingsBySeverity}
                assessmentId={assessmentId ?? undefined}
              />
            ) : (
              <div className="flex items-center justify-center h-full text-sm text-muted-foreground">
                Loading assessment plan…
              </div>
            )}
          </div>
        )}
      </div>

      {/* Unified input bar — used by the deprecated Structured view; both
          terminal panes now have their own xterm input, so this is hidden. */}
      <UnifiedInputBar
        sessionKey={sessionKey}
        visible={false}
      />
    </div>
  );
}
