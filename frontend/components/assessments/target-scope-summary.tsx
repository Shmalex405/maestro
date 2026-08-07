'use client';

import { useMemo } from 'react';
import { Target as TargetIcon, ShieldCheck, ShieldX } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { cn } from '@/lib/utils';
import type { ScopeTargetDecision } from '@/lib/types';

interface TargetScopeSummaryProps {
  scopeDecisions: ScopeTargetDecision[];
  /** From overview.provenance.scope — 'absent' renders a placeholder. */
  provenance?: 'db' | 'derived' | 'absent';
}

/**
 * Two-column in-scope vs out-of-scope summary built from the scope-validation
 * decisions recorded at tool-dispatch time. Out-of-scope rows surface the
 * rejection reason. When scope decisions weren't captured (provenance ===
 * 'absent'), a labeled placeholder is shown.
 */
export function TargetScopeSummary({ scopeDecisions, provenance }: TargetScopeSummaryProps) {
  const { inScope, outOfScope } = useMemo(() => {
    const inS: ScopeTargetDecision[] = [];
    const outS: ScopeTargetDecision[] = [];
    for (const d of scopeDecisions) {
      (d.in_scope ? inS : outS).push(d);
    }
    inS.sort((a, b) => a.target.localeCompare(b.target));
    outS.sort((a, b) => a.target.localeCompare(b.target));
    return { inScope: inS, outOfScope: outS };
  }, [scopeDecisions]);

  const header = (
    <CardHeader className="pb-3">
      <CardTitle className="text-base flex items-center gap-2">
        <TargetIcon className="h-4 w-4" />
        Target scope
        {scopeDecisions.length > 0 && (
          <span className="text-xs font-normal text-muted-foreground">
            · {inScope.length} in · {outOfScope.length} out
          </span>
        )}
      </CardTitle>
    </CardHeader>
  );

  if (provenance === 'absent' || scopeDecisions.length === 0) {
    return (
      <Card>
        {header}
        <CardContent>
          <div className="rounded-lg border border-dashed border-border p-4 text-sm text-muted-foreground">
            Scope decisions not captured for this run.
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      {header}
      <CardContent>
        <div className="grid gap-4 md:grid-cols-2">
          <ScopeColumn
            title="In scope"
            tone="in"
            icon={<ShieldCheck className="h-4 w-4 text-green-600 dark:text-green-400" />}
            decisions={inScope}
          />
          <ScopeColumn
            title="Out of scope"
            tone="out"
            icon={<ShieldX className="h-4 w-4 text-red-600 dark:text-red-400" />}
            decisions={outOfScope}
          />
        </div>
      </CardContent>
    </Card>
  );
}

function ScopeColumn({
  title,
  tone,
  icon,
  decisions,
}: {
  title: string;
  tone: 'in' | 'out';
  icon: React.ReactNode;
  decisions: ScopeTargetDecision[];
}) {
  return (
    <div>
      <div className="mb-2 flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
        {icon}
        {title}
        <span className="tabular-nums">({decisions.length})</span>
      </div>
      {decisions.length === 0 ? (
        <p className="text-xs text-muted-foreground/70">None</p>
      ) : (
        <ul className="space-y-1.5">
          {decisions.map((d, i) => (
            <li
              key={`${d.target}-${i}`}
              className={cn(
                'rounded-md border px-2 py-1.5',
                tone === 'in' ? 'border-green-500/20 bg-green-500/5' : 'border-red-500/20 bg-red-500/5',
              )}
            >
              <div className="flex items-center justify-between gap-2">
                <span className="text-xs font-mono truncate" title={d.target}>
                  {d.target}
                </span>
                <div className="flex items-center gap-1 shrink-0">
                  {d.dimension && (
                    <Badge variant="outline" className="text-[9px] px-1 py-0 uppercase">
                      {d.dimension}
                    </Badge>
                  )}
                  {d.attempts != null && d.attempts > 0 && (
                    <span className="text-[10px] text-muted-foreground tabular-nums" title="dispatch attempts">
                      {d.attempts}×
                    </span>
                  )}
                </div>
              </div>
              {d.reason && (
                <p className="mt-0.5 text-[11px] text-muted-foreground">{d.reason}</p>
              )}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
