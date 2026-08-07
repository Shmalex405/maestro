'use client';

import { useQuery } from '@tanstack/react-query';
import { api } from '@/lib/tauri-api';
import { inferCloudFromFinding } from '@/lib/finding-cloud-inference';
import type { FindingCategory, Severity } from '@/lib/types';

// 'all' | a single FindingCategory | a comma-separated union of categories for
// a surface lens (e.g. 'cloud,infrastructure' for Cloud / Infra — the backend
// unions their source-pattern sets).
export type TrendCategoryFilter = 'all' | FindingCategory | (string & {});

export interface TrendBucket {
  date: string;
  iso: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  total: number;
}

export interface FindingsTrend {
  buckets: TrendBucket[];
  perSeverity: Record<Severity, number[]>;
  totalSeries: number[];
}

const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

function isoDay(d: Date): string {
  const y = d.getUTCFullYear();
  const m = String(d.getUTCMonth() + 1).padStart(2, '0');
  const day = String(d.getUTCDate()).padStart(2, '0');
  return `${y}-${m}-${day}`;
}

function buildEmptyBuckets(days: number): TrendBucket[] {
  const out: TrendBucket[] = [];
  const today = new Date();
  today.setUTCHours(0, 0, 0, 0);
  for (let i = days - 1; i >= 0; i--) {
    const d = new Date(today);
    d.setUTCDate(d.getUTCDate() - i);
    out.push({
      date: isoDay(d),
      iso: d.toISOString(),
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
      total: 0,
    });
  }
  return out;
}

/**
 * Returns the per-day count of findings observed in the last `days` window,
 * broken out by severity. Buckets are dense (one entry per day, zero-filled).
 *
 * Bucketing key: `last_seen_at ?? updated_at ?? created_at`. The cloud
 * backend dedups findings by fingerprint (v0.1.54+) — same vuln → same row,
 * `last_seen_at` refreshes each scan but `created_at` stays at first
 * discovery. Bucketing by `created_at` would show "no recent findings" for
 * an org that's actively rediscovering long-standing vulns. `last_seen_at`
 * reflects scan activity, which matches what a dashboard user expects.
 *
 * No `date_from` is passed: the backend filters that against `created_at`
 * server-side, which combined with dedup hides everything older than the
 * window. We pull the full page and filter client-side instead. Fine while
 * orgs have <few thousand findings; swap for a server-side aggregate if
 * that ever changes.
 */
export function useFindingsTrend(
  days = 30,
  categoryFilter: TrendCategoryFilter = 'all',
) {
  return useQuery<FindingsTrend>({
    queryKey: ['findings-trend', days, categoryFilter],
    queryFn: async () => {
      const buckets = buildEmptyBuckets(days);
      const byDate = new Map(buckets.map((b) => [b.date, b]));
      const firstBucketDate = buckets[0]?.date;

      // Server-side category filter when applicable. The legacy 'cloud'
      // standalone filter isn't a persisted column — fetch unfiltered and
      // narrow client-side. A comma-separated union (e.g. 'cloud,infrastructure')
      // passes straight through; the backend's category_clause unions it.
      const apiCategory: string | undefined =
        categoryFilter === 'all' || categoryFilter === 'cloud'
          ? undefined
          : categoryFilter;

      const res = await api.findings.list({
        limit: 1000,
        category: apiCategory,
      });

      const rows = (res.data || []).filter((f) => {
        if (categoryFilter === 'cloud') {
          return !!inferCloudFromFinding(f).provider;
        }
        return true;
      });

      for (const f of rows) {
        // Prefer most-recent activity; fall back to first discovery for
        // findings written before dedup (last_seen_at may be null on those).
        const when = f.last_seen_at || f.updated_at || f.created_at;
        if (!when) continue;
        const d = new Date(when);
        if (Number.isNaN(d.getTime())) continue;
        const key = isoDay(d);
        // Drop anything outside the window; the listing is unfiltered.
        if (!firstBucketDate || key < firstBucketDate) continue;
        const bucket = byDate.get(key);
        if (!bucket) continue;
        const sev = f.severity as Severity;
        if (sev in bucket) {
          (bucket as unknown as Record<Severity, number>)[sev] += 1;
          bucket.total += 1;
        }
      }

      const perSeverity = SEVERITIES.reduce((acc, sev) => {
        acc[sev] = buckets.map((b) => b[sev] as number);
        return acc;
      }, {} as Record<Severity, number[]>);

      return {
        buckets,
        perSeverity,
        totalSeries: buckets.map((b) => b.total),
      };
    },
    staleTime: 60_000,
  });
}
