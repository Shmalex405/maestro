'use client';

import { useEffect, useState } from 'react';
import { Zap, TrendingDown, Database, Sparkles, AlertCircle } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Skeleton } from '@/components/ui/skeleton';
import { api } from '@/lib/tauri-api';
import type { CacheStatsResponse } from '@/lib/types';

interface CostPanelProps {
  assessmentId: string;
  /**
   * Poll interval in ms. Default 30s — cache stats are updated by the
   * orchestrator as it streams, but a slow refresh is enough for the
   * display. Set to 0 to disable polling (one-shot fetch).
   */
  refreshIntervalMs?: number;
}

/**
 * Per-assessment LLM cost + cache hit telemetry panel.
 *
 * Renders four headline numbers:
 *   1. Total cost (this run, post-cache pricing)
 *   2. Cache hit % (how much input came from cache)
 *   3. $ saved by caching (counterfactual: cost if no caching)
 *   4. Request count + ttl flavor breakdown
 *
 * Shows an empty state when no cache_stats row exists yet (no LLM
 * activity recorded against this assessment, or cloud not authenticated).
 *
 * Phase 0 of the caching plan (docs/caching-plan-2026-05-22.md). The
 * underlying data is populated by `record_cache_stats` calls (currently
 * driven from the desktop orchestrator; cross-account proxy ingest is
 * a future iteration — see the design memo for the pipeline plan).
 */
export function CostPanel({ assessmentId, refreshIntervalMs = 30_000 }: CostPanelProps) {
  const [stats, setStats] = useState<CacheStatsResponse | null | undefined>(undefined);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    let timer: ReturnType<typeof setInterval> | null = null;

    const fetchStats = async () => {
      try {
        const result = await api.config.cloud.getCacheStats(assessmentId);
        if (cancelled) return;
        setStats(result);
        setError(null);
      } catch (e) {
        if (cancelled) return;
        // Don't surface "not authenticated" as a noisy error — that's the
        // expected empty state. Only show genuine fetch failures.
        const msg = typeof e === 'string' ? e : (e as Error)?.message ?? String(e);
        if (msg.toLowerCase().includes('not authenticated') || msg.toLowerCase().includes('not enabled')) {
          setStats(null);
          setError(null);
        } else {
          setError(msg);
        }
      }
    };

    fetchStats();
    if (refreshIntervalMs > 0) {
      timer = setInterval(fetchStats, refreshIntervalMs);
    }
    return () => {
      cancelled = true;
      if (timer) clearInterval(timer);
    };
  }, [assessmentId, refreshIntervalMs]);

  // Initial loading state — stats is `undefined` until first fetch resolves.
  if (stats === undefined) {
    return (
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base flex items-center gap-2">
            <Zap className="h-4 w-4" />
            LLM cost &amp; cache
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
            {[0, 1, 2, 3].map((i) => (
              <div key={i} className="space-y-2">
                <Skeleton className="h-3 w-20" />
                <Skeleton className="h-6 w-16" />
              </div>
            ))}
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
            <Zap className="h-4 w-4" />
            LLM cost &amp; cache
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex items-center gap-2 text-sm text-muted-foreground">
            <AlertCircle className="h-4 w-4" />
            <span>Couldn&apos;t load cache stats: {error}</span>
          </div>
        </CardContent>
      </Card>
    );
  }

  // No stats row exists yet for this assessment. This is normal during
  // recon / before the orchestrator's first LLM call lands telemetry,
  // and also when cloud isn't authenticated.
  if (stats === null) {
    return (
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base flex items-center gap-2">
            <Zap className="h-4 w-4" />
            LLM cost &amp; cache
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="text-sm text-muted-foreground">
            No LLM activity recorded yet for this assessment.
          </div>
        </CardContent>
      </Card>
    );
  }

  const cacheHit = stats.cache_hit_pct.toFixed(1);
  const cost = formatUsd(stats.cost_usd);
  const savings = formatUsd(stats.savings_usd);
  const noBetaPct =
    stats.request_count > 0
      ? (stats.requests_without_cache_beta / stats.request_count) * 100
      : 0;

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="text-base flex items-center gap-2">
          <Zap className="h-4 w-4" />
          LLM cost &amp; cache
          {stats.model && (
            <span className="text-xs font-normal text-muted-foreground">
              · {stats.model}
            </span>
          )}
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
          <Metric
            icon={<Sparkles className="h-3.5 w-3.5" />}
            label="This run"
            value={cost}
            sublabel={`${stats.request_count.toLocaleString()} request${stats.request_count === 1 ? '' : 's'}`}
          />
          <Metric
            icon={<Database className="h-3.5 w-3.5" />}
            label="Cache hit"
            value={`${cacheHit}%`}
            sublabel={`${stats.cache_read_input_tokens.toLocaleString()} cached input tokens`}
            tone={parseFloat(cacheHit) >= 50 ? 'good' : parseFloat(cacheHit) >= 20 ? 'ok' : 'low'}
          />
          <Metric
            icon={<TrendingDown className="h-3.5 w-3.5" />}
            label="Saved by cache"
            value={savings}
            sublabel={`vs ${formatUsd(stats.cost_usd_without_cache)} uncached`}
            tone="good"
          />
          <Metric
            label="Tokens"
            value={`${formatTokens(stats.input_tokens + stats.cache_read_input_tokens + stats.cache_creation_input_tokens)} in / ${formatTokens(stats.output_tokens)} out`}
            sublabel={
              noBetaPct > 50
                ? `${noBetaPct.toFixed(0)}% requests missing cache header`
                : `${stats.requests_with_extended_ttl} request${stats.requests_with_extended_ttl === 1 ? '' : 's'} at 1h TTL`
            }
            tone={noBetaPct > 50 ? 'warn' : undefined}
          />
        </div>
      </CardContent>
    </Card>
  );
}

interface MetricProps {
  icon?: React.ReactNode;
  label: string;
  value: string;
  sublabel?: string;
  tone?: 'good' | 'ok' | 'low' | 'warn';
}

function Metric({ icon, label, value, sublabel, tone }: MetricProps) {
  const valueClass =
    tone === 'good'
      ? 'text-green-600 dark:text-green-400'
      : tone === 'warn'
        ? 'text-amber-600 dark:text-amber-400'
        : tone === 'low'
          ? 'text-muted-foreground'
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

function formatUsd(n: number): string {
  if (n < 0.01 && n > 0) return '<$0.01';
  if (n < 1) return `$${n.toFixed(3)}`;
  if (n < 100) return `$${n.toFixed(2)}`;
  return `$${Math.round(n).toLocaleString()}`;
}

function formatTokens(n: number): string {
  if (n < 1_000) return n.toString();
  if (n < 1_000_000) return `${(n / 1_000).toFixed(1)}K`;
  return `${(n / 1_000_000).toFixed(1)}M`;
}
