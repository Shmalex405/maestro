'use client';

import { useEffect, useState } from 'react';
import { History, ShieldCheck, RefreshCw, AlertTriangle } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Skeleton } from '@/components/ui/skeleton';
import { api } from '@/lib/tauri-api';
import type { BaselineResponse } from '@/lib/types';

interface BaselineReusePanelProps {
  /**
   * The canonical target_id for which to fetch the baseline. Resolved
   * upstream by the team-lead Phase 1.5 step (Rust util ::canonicalize +
   * fingerprint) or via the targets API.
   */
  targetId: string;
  /**
   * Optional override of the per-org `baseline_max_age_days`. Useful for
   * a "show stale findings too" toggle. Defaults to whatever the
   * server-side org_settings row holds.
   */
  maxAgeDays?: number;
}

/**
 * Surfaces the baseline-aware caching state to the user before / during
 * an assessment of a target that's been assessed before. The panel
 * answers three questions at a glance:
 *
 *   1. How many findings from prior runs are eligible for cache reuse?
 *   2. Will this run skip the cache entirely (Nth-run forced revalidation)?
 *   3. When is the next forced revalidation due?
 *
 * The panel doesn't trigger the cache itself — that's the team lead's
 * job at Phase 1.5. It's purely a visibility surface so the user
 * understands what's happening when crossval-qa later reports "12
 * findings validated from baseline."
 */
export function BaselineReusePanel({ targetId, maxAgeDays }: BaselineReusePanelProps) {
  const [data, setData] = useState<BaselineResponse | null | undefined>(undefined);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    const fetchBaseline = async () => {
      try {
        const result = await api.config.cloud.getBaselineFindings(targetId, maxAgeDays);
        if (cancelled) return;
        setData(result);
        setError(null);
      } catch (e) {
        if (cancelled) return;
        const msg = typeof e === 'string' ? e : (e as Error)?.message ?? String(e);
        // Auth / disabled-cloud = empty state, not an error.
        if (
          msg.toLowerCase().includes('not authenticated') ||
          msg.toLowerCase().includes('not enabled')
        ) {
          setData(null);
          setError(null);
        } else {
          setError(msg);
        }
      }
    };
    fetchBaseline();
    return () => {
      cancelled = true;
    };
  }, [targetId, maxAgeDays]);

  if (data === undefined) {
    return (
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base flex items-center gap-2">
            <History className="h-4 w-4" />
            Baseline reuse
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-2">
            <Skeleton className="h-3 w-32" />
            <Skeleton className="h-6 w-24" />
          </div>
        </CardContent>
      </Card>
    );
  }

  if (error) {
    return (
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base flex items-center gap-2">
            <History className="h-4 w-4" />
            Baseline reuse
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex items-center gap-2 text-sm text-muted-foreground">
            <AlertTriangle className="h-4 w-4" />
            <span>Couldn&apos;t load baseline: {error}</span>
          </div>
        </CardContent>
      </Card>
    );
  }

  // Cloud disabled or no baseline yet.
  if (data === null) {
    return (
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base flex items-center gap-2">
            <History className="h-4 w-4" />
            Baseline reuse
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="text-sm text-muted-foreground">
            First assessment of this target — no baseline to reuse.
          </div>
        </CardContent>
      </Card>
    );
  }

  const total = data.baseline.length;
  const highSev = data.baseline.filter(
    (f) =>
      (f.calibrated_severity ?? f.severity).toLowerCase() === 'critical' ||
      (f.calibrated_severity ?? f.severity).toLowerCase() === 'high',
  ).length;
  const willRevalidate = data.force_full_revalidation
    ? total
    : highSev; // High/Critical always re-validate; others MAY be cached
  const eligibleForReuse = data.force_full_revalidation ? 0 : total - highSev;
  const nextForced = data.full_revalidation_interval
    ? Math.max(
        0,
        data.full_revalidation_interval - data.assessments_since_last_full_revalidation,
      )
    : null;

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="text-base flex items-center gap-2">
          <History className="h-4 w-4" />
          Baseline reuse
          {!data.caching_enabled && (
            <span className="text-xs font-normal text-amber-600 dark:text-amber-400">
              · cache disabled
            </span>
          )}
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="grid grid-cols-2 gap-4 sm:grid-cols-3">
          <Metric
            icon={<ShieldCheck className="h-3.5 w-3.5" />}
            label="Reusable"
            value={eligibleForReuse.toString()}
            sublabel={
              eligibleForReuse > 0
                ? 'crossval-qa may skip these'
                : 'forced full re-validation'
            }
            tone={eligibleForReuse > 0 ? 'good' : 'warn'}
          />
          <Metric
            icon={<RefreshCw className="h-3.5 w-3.5" />}
            label="Re-validate"
            value={willRevalidate.toString()}
            sublabel={
              data.force_full_revalidation
                ? 'every finding — Nth-run pass'
                : `${highSev} critical/high · always`
            }
          />
          <Metric
            label="Next forced run"
            value={
              nextForced === null
                ? 'off'
                : nextForced === 0
                  ? 'this run'
                  : `in ${nextForced}`
            }
            sublabel={
              data.full_revalidation_interval
                ? `every ${data.full_revalidation_interval} runs`
                : 'cadence disabled'
            }
            tone={nextForced === 0 ? 'warn' : undefined}
          />
        </div>

        {data.force_full_revalidation && (
          <div className="mt-3 flex items-start gap-2 rounded-md border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-xs">
            <AlertTriangle className="h-4 w-4 shrink-0 text-amber-600 dark:text-amber-400" />
            <div>
              <div className="font-medium">Forced full re-validation this run</div>
              <div className="text-muted-foreground">
                {!data.caching_enabled
                  ? 'Caching is disabled for this org.'
                  : `${data.assessments_since_last_full_revalidation} assessments since last forced pass.`}{' '}
                Every baseline finding will be actively re-tested. This is by design — it&apos;s
                the safety net that keeps the cache trustworthy long-term.
              </div>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

interface MetricProps {
  icon?: React.ReactNode;
  label: string;
  value: string;
  sublabel?: string;
  tone?: 'good' | 'warn';
}

function Metric({ icon, label, value, sublabel, tone }: MetricProps) {
  const valueClass =
    tone === 'good'
      ? 'text-green-600 dark:text-green-400'
      : tone === 'warn'
        ? 'text-amber-600 dark:text-amber-400'
        : '';

  return (
    <div className="space-y-1">
      <div className="flex items-center gap-1 text-xs text-muted-foreground">
        {icon}
        <span>{label}</span>
      </div>
      <div className={`text-lg font-semibold tabular-nums ${valueClass}`}>{value}</div>
      {sublabel && <div className="text-[11px] text-muted-foreground">{sublabel}</div>}
    </div>
  );
}
