'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import {
  ArrowLeft,
  Zap,
  RefreshCw,
  Database,
  ShieldAlert,
  Save,
  Loader2,
  AlertCircle,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import { Separator } from '@/components/ui/separator';
import { toast } from 'sonner';
import { api } from '@/lib/tauri-api';
import type {
  OrgCacheSettings,
  OrgCacheSettingsUpdate,
  DriftAlertsSummary,
} from '@/lib/types';

/**
 * Per-org cache configuration page.
 *
 * Surfaces the master kill switch + revalidation cadence + TTL knobs
 * defined in `backend-rs/migrations/0019_org_settings.sql`. Also shows
 * a 30-day drift alert summary so the operator can see whether the
 * cache is behaving (or whether the auto-disable threshold is close to
 * breaching).
 *
 * Phase 6 of the caching plan.
 */
export default function CacheSettingsPage() {
  const router = useRouter();
  const [settings, setSettings] = useState<OrgCacheSettings | null>(null);
  const [drift, setDrift] = useState<DriftAlertsSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [dirty, setDirty] = useState(false);

  // Loading the two endpoints in parallel — neither blocks the other,
  // and drift summary is purely informational so a failure there
  // shouldn't prevent the page from rendering.
  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      setLoading(true);
      try {
        const [s, d] = await Promise.allSettled([
          api.config.cloud.getOrgSettings(),
          api.config.cloud.getDriftAlertsSummary(),
        ]);
        if (cancelled) return;
        if (s.status === 'fulfilled') {
          setSettings(s.value);
          setError(null);
        } else {
          setError(
            typeof s.reason === 'string'
              ? s.reason
              : (s.reason as Error)?.message ?? String(s.reason),
          );
        }
        if (d.status === 'fulfilled') setDrift(d.value);
        // Drift fetch failure is silent — the section just won't render.
      } finally {
        if (!cancelled) setLoading(false);
      }
    };
    load();
    return () => {
      cancelled = true;
    };
  }, []);

  const update = (patch: OrgCacheSettingsUpdate) => {
    if (!settings) return;
    setSettings({ ...settings, ...patch });
    setDirty(true);
  };

  const save = async () => {
    if (!settings) return;
    setSaving(true);
    try {
      const updated = await api.config.cloud.updateOrgSettings({
        caching_enabled: settings.caching_enabled,
        full_revalidation_interval: settings.full_revalidation_interval,
        sast_cache_ttl_days: settings.sast_cache_ttl_days,
        recon_cache_ttl_days: settings.recon_cache_ttl_days,
        baseline_max_age_days: settings.baseline_max_age_days,
        drift_alert_threshold: settings.drift_alert_threshold,
      });
      setSettings(updated);
      setDirty(false);
      toast.success('Cache settings saved');
    } catch (e) {
      const msg = typeof e === 'string' ? e : (e as Error)?.message ?? String(e);
      toast.error('Save failed', { description: msg });
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="container mx-auto max-w-3xl py-8 px-4 space-y-6">
      <div className="flex items-center gap-3">
        <Button variant="ghost" size="sm" onClick={() => router.back()}>
          <ArrowLeft className="h-4 w-4 mr-1" />
          Back
        </Button>
        <h1 className="text-2xl font-semibold">Cache settings</h1>
      </div>

      <p className="text-sm text-muted-foreground">
        Controls how aggressively Maestro reuses prior assessment results to
        speed up repeat runs of the same target. The defaults are conservative
        — every Nth assessment forces a full re-validation, and any code
        change in a finding&apos;s file invalidates that finding&apos;s cache entry
        regardless of these settings.
      </p>

      {error && (
        <Card className="border-destructive">
          <CardContent className="pt-6">
            <div className="flex items-center gap-2 text-sm text-destructive">
              <AlertCircle className="h-4 w-4" />
              {error}
            </div>
          </CardContent>
        </Card>
      )}

      {loading || !settings ? (
        <Card>
          <CardContent className="py-12">
            <div className="flex items-center justify-center gap-2 text-sm text-muted-foreground">
              <Loader2 className="h-4 w-4 animate-spin" />
              Loading…
            </div>
          </CardContent>
        </Card>
      ) : (
        <>
          {/* Master kill switch */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-base">
                <Zap className="h-4 w-4" />
                Caching master switch
              </CardTitle>
              <CardDescription>
                Disable to force every assessment to run as if no prior results
                existed. Cost panel still computes counterfactual savings.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="flex items-center justify-between">
                <Label htmlFor="caching-enabled" className="cursor-pointer">
                  Cross-assessment caching {settings.caching_enabled ? 'enabled' : 'disabled'}
                </Label>
                <Switch
                  id="caching-enabled"
                  checked={settings.caching_enabled}
                  onCheckedChange={(v) => update({ caching_enabled: v })}
                />
              </div>
            </CardContent>
          </Card>

          {/* Cadence */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-base">
                <RefreshCw className="h-4 w-4" />
                Revalidation cadence
              </CardTitle>
              <CardDescription>
                Every Nth assessment of a target ignores the cache and re-tests
                every baseline finding. Catches silent drift. Set to 0 to
                disable forced revalidation (TTLs + per-severity rules still
                apply).
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <NumberField
                id="full-rev-interval"
                label="Full re-validation interval (assessments)"
                value={settings.full_revalidation_interval}
                min={0}
                max={50}
                onChange={(v) => update({ full_revalidation_interval: v })}
                hint="Default: 4 — every 4th run is a clean pass"
              />
              <NumberField
                id="baseline-max-age"
                label="Baseline max age (days)"
                value={settings.baseline_max_age_days}
                min={1}
                max={365}
                onChange={(v) => update({ baseline_max_age_days: v })}
                hint="Findings older than this are excluded from baseline reuse. Default: 30"
              />
            </CardContent>
          </Card>

          {/* TTLs */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-base">
                <Database className="h-4 w-4" />
                Cache TTLs
              </CardTitle>
              <CardDescription>
                How long scanner outputs stay cached. After expiry, the next
                run does a full scan regardless of whether the cache key
                matches.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <NumberField
                id="sast-ttl"
                label="SAST cache TTL (days)"
                value={settings.sast_cache_ttl_days}
                min={1}
                max={180}
                onChange={(v) => update({ sast_cache_ttl_days: v })}
                hint="Semgrep / Bandit / gitleaks etc. Default: 30"
              />
              <NumberField
                id="recon-ttl"
                label="Recon cache TTL (days)"
                value={settings.recon_cache_ttl_days}
                min={1}
                max={30}
                onChange={(v) => update({ recon_cache_ttl_days: v })}
                hint="nmap / subdomain / TLS scans. Default: 7 (recon ages faster)"
              />
            </CardContent>
          </Card>

          {/* Safety net */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-base">
                <ShieldAlert className="h-4 w-4" />
                Drift detection
              </CardTitle>
              <CardDescription>
                When a baseline-trusted finding fails to reproduce in a forced
                re-validation, that&apos;s a drift event. Too many in 30 days and
                the auto-disable circuit flips this org&apos;s caching off until
                a human reviews.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <NumberField
                id="drift-threshold"
                label="Auto-disable threshold (alerts / 30 days)"
                value={settings.drift_alert_threshold}
                min={1}
                max={100}
                onChange={(v) => update({ drift_alert_threshold: v })}
                hint="Default: 3 — strict enough to catch real problems, lenient enough to ignore noise"
              />
              <Separator />
              {drift ? (
                <div className="space-y-1 text-sm">
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Drift events (last 30 days)</span>
                    <span
                      className={`font-mono ${
                        drift.threshold_breached
                          ? 'text-red-600 dark:text-red-400 font-semibold'
                          : ''
                      }`}
                    >
                      {drift.alerts_30d} / {drift.threshold}
                      {drift.threshold_breached && ' ⚠ threshold breached'}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Unacknowledged</span>
                    <span className="font-mono">{drift.unacknowledged}</span>
                  </div>
                </div>
              ) : (
                <div className="text-xs text-muted-foreground">
                  No drift summary available.
                </div>
              )}
            </CardContent>
          </Card>

          {/* Save bar */}
          <div className="sticky bottom-0 -mx-4 border-t bg-background/95 backdrop-blur px-4 py-3 flex justify-end gap-2">
            <Button
              variant="outline"
              onClick={() => router.back()}
              disabled={saving}
            >
              Cancel
            </Button>
            <Button onClick={save} disabled={!dirty || saving}>
              {saving ? (
                <Loader2 className="h-4 w-4 mr-2 animate-spin" />
              ) : (
                <Save className="h-4 w-4 mr-2" />
              )}
              {dirty ? 'Save changes' : 'Saved'}
            </Button>
          </div>
        </>
      )}
    </div>
  );
}

interface NumberFieldProps {
  id: string;
  label: string;
  value: number;
  min: number;
  max: number;
  onChange: (v: number) => void;
  hint?: string;
}

function NumberField({ id, label, value, min, max, onChange, hint }: NumberFieldProps) {
  return (
    <div className="space-y-1.5">
      <Label htmlFor={id}>{label}</Label>
      <Input
        id={id}
        type="number"
        min={min}
        max={max}
        value={value}
        onChange={(e) => {
          const parsed = parseInt(e.target.value, 10);
          if (!Number.isNaN(parsed)) onChange(Math.max(min, Math.min(max, parsed)));
        }}
        className="w-32 tabular-nums"
      />
      {hint && <div className="text-xs text-muted-foreground">{hint}</div>}
    </div>
  );
}
