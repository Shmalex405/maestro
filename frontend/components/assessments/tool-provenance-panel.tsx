'use client';

import { useEffect, useState } from 'react';
import { Wrench, AlertCircle, CheckCircle2, XCircle } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Skeleton } from '@/components/ui/skeleton';
import { cn } from '@/lib/utils';
import { api } from '@/lib/tauri-api';
import type { ToolExecution } from '@/lib/types';

interface ToolProvenancePanelProps {
  assessmentId: string;
  /** Poll interval in ms. Default 30s; set 0 to disable. */
  refreshIntervalMs?: number;
}

/**
 * Per-assessment tool-execution provenance.
 *
 * Lists every security tool that ran during the assessment with proof it
 * actually executed: the independent binary-availability probe (installed?
 * version), the run/ok/fail counts, and the last exit code. A tool whose binary
 * was absent — the case that silently passed before P1 — is flagged in red so
 * "tested and clean" can't be confused with "tool never ran".
 *
 * Reads the promoted cloud summary (POST at complete_assessment), so it persists
 * after the run and works from any machine. The live "running now" feed is the
 * separate activity feed; this is the durable record.
 */
export function ToolProvenancePanel({ assessmentId, refreshIntervalMs = 30_000 }: ToolProvenancePanelProps) {
  const [tools, setTools] = useState<ToolExecution[] | null | undefined>(undefined);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    let timer: ReturnType<typeof setInterval> | null = null;

    const fetchTools = async () => {
      try {
        const result = await api.assessments.listToolExecutions(assessmentId);
        if (cancelled) return;
        setTools(result);
        setError(null);
      } catch (e) {
        if (cancelled) return;
        const msg = typeof e === 'string' ? e : (e as Error)?.message ?? String(e);
        // "not authenticated"/"not enabled" is the expected empty state, not an error.
        if (msg.toLowerCase().includes('not authenticated') || msg.toLowerCase().includes('not enabled')) {
          setTools(null);
          setError(null);
        } else {
          setError(msg);
        }
      }
    };

    fetchTools();
    if (refreshIntervalMs > 0) timer = setInterval(fetchTools, refreshIntervalMs);
    return () => {
      cancelled = true;
      if (timer) clearInterval(timer);
    };
  }, [assessmentId, refreshIntervalMs]);

  const header = (
    <CardHeader className="pb-3">
      <CardTitle className="text-base flex items-center gap-2">
        <Wrench className="h-4 w-4" />
        Tools that ran
      </CardTitle>
    </CardHeader>
  );

  if (tools === undefined) {
    return (
      <Card>
        {header}
        <CardContent>
          <div className="space-y-2">
            {[0, 1, 2].map((i) => (
              <Skeleton key={i} className="h-4 w-full" />
            ))}
          </div>
        </CardContent>
      </Card>
    );
  }

  if (error) {
    return (
      <Card>
        {header}
        <CardContent>
          <div className="flex items-center gap-2 text-sm text-muted-foreground">
            <AlertCircle className="h-4 w-4" />
            <span>Couldn&apos;t load tool provenance: {error}</span>
          </div>
        </CardContent>
      </Card>
    );
  }

  if (tools === null || tools.length === 0) {
    return (
      <Card>
        {header}
        <CardContent>
          <div className="text-sm text-muted-foreground">
            No tool provenance recorded yet — promoted when the assessment completes.
          </div>
        </CardContent>
      </Card>
    );
  }

  const absent = tools.filter((t) => t.installed === false).length;
  const failing = tools.filter((t) => t.run_count > 0 && t.ok_count === 0).length;

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="text-base flex items-center gap-2">
          <Wrench className="h-4 w-4" />
          Tools that ran
          <span className="text-xs font-normal text-muted-foreground">
            · {tools.length}
            {absent > 0 && <span className="text-red-600 dark:text-red-400"> · {absent} absent</span>}
            {failing > 0 && <span className="text-amber-600 dark:text-amber-400"> · {failing} failing</span>}
          </span>
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="space-y-1.5">
          {tools.map((t) => (
            <ToolRow key={t.tool_name} tool={t} />
          ))}
        </div>
      </CardContent>
    </Card>
  );
}

function ToolRow({ tool }: { tool: ToolExecution }) {
  // A tool is "verified" when its binary is present (or unknown/pure-API) AND at
  // least one invocation exited 0. Absent binary is the headline failure.
  const absent = tool.installed === false;
  const ran = tool.run_count > 0;
  const ok = ran && tool.ok_count > 0;

  const status = absent ? 'absent' : !ran ? 'unrun' : ok ? 'ok' : 'failed';
  const statusMeta = {
    ok: { label: 'OK', cls: 'text-green-600 dark:text-green-400', Icon: CheckCircle2 },
    failed: { label: 'FAILED', cls: 'text-amber-600 dark:text-amber-400', Icon: XCircle },
    absent: { label: 'ABSENT', cls: 'text-red-600 dark:text-red-400', Icon: XCircle },
    unrun: { label: 'NOT RUN', cls: 'text-muted-foreground', Icon: AlertCircle },
  }[status];
  const { Icon } = statusMeta;

  return (
    <div className="flex items-center justify-between gap-2">
      <div className="flex items-center gap-1.5 min-w-0">
        <Icon className={cn('h-3 w-3 shrink-0', statusMeta.cls)} />
        <span className="text-xs font-mono truncate" title={tool.binary ?? tool.tool_name}>
          {tool.tool_name}
          {tool.binary && tool.binary !== tool.tool_name && (
            <span className="text-muted-foreground"> ({tool.binary})</span>
          )}
        </span>
      </div>
      <div className="flex items-center gap-1.5 shrink-0">
        {tool.version && (
          <span className="text-[10px] text-muted-foreground truncate max-w-[90px]" title={tool.version}>
            {tool.version}
          </span>
        )}
        <Badge variant="outline" className="text-[10px] px-1.5 py-0 font-mono">
          {tool.ok_count}/{tool.run_count}
        </Badge>
        <span className={cn('text-[10px] font-medium uppercase tracking-wide', statusMeta.cls)}>
          {statusMeta.label}
        </span>
      </div>
    </div>
  );
}
