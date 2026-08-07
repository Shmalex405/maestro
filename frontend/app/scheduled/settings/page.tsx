'use client';

// Scheduled DAST → Settings. SLA thresholds + AI auto-escalate (org-level) and
// per-target auth + scope (opens the shared ScanConfigDialog via the provider).

import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { toast } from 'sonner';
import { Settings2, Globe, Clock, Sparkles, Bell, KeyRound, Copy, Trash2, Plus } from 'lucide-react';
import { Skeleton } from '@/components/ui/skeleton';
import { Card, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Switch } from '@/components/ui/switch';
import { Checkbox } from '@/components/ui/checkbox';
import { api } from '@/lib/tauri-api';
import { TargetTypeIcon } from '@/components/scheduled/dast-shared';
import { useScheduledDast } from '@/components/scheduled/dast-context';

const SLA_SEVERITIES = ['critical', 'high', 'medium', 'low'] as const;

function SlaAndEscalateCards() {
  const queryClient = useQueryClient();
  const { data, isLoading } = useQuery({
    queryKey: ['dast-settings'],
    queryFn: () => api.dastSettings.get(),
  });

  // Local editable state, hydrated once from the loaded settings.
  const [sla, setSla] = useState<Record<string, number>>({});
  const [enabled, setEnabled] = useState(false);
  const [sevs, setSevs] = useState<Set<string>>(new Set());
  const [webhook, setWebhook] = useState('');
  const [hydrated, setHydrated] = useState(false);
  if (data && !hydrated) {
    setSla({
      critical: data.sla_critical_days ?? 7,
      high: data.sla_high_days ?? 14,
      medium: data.sla_medium_days ?? 30,
      low: data.sla_low_days ?? 90,
    });
    setEnabled(Boolean(data.dast_auto_escalate_enabled));
    setSevs(new Set((data.dast_auto_escalate_severities ?? 'critical,high').split(',').map((s) => s.trim()).filter(Boolean)));
    setWebhook(data.dast_webhook_url ?? '');
    setHydrated(true);
  }

  const save = useMutation({
    mutationFn: (body: Parameters<typeof api.dastSettings.update>[0]) => api.dastSettings.update(body),
    onSuccess: () => {
      toast.success('Settings saved.');
      queryClient.invalidateQueries({ queryKey: ['dast-settings'] });
    },
    onError: (e) => toast.error(`Couldn't save: ${e instanceof Error ? e.message : String(e)}`),
  });

  return (
    <>
      {/* SLA thresholds */}
      <Card className="glass-card">
        <CardContent className="p-0">
          <div className="border-b border-border/40 px-4 py-3">
            <p className="flex items-center gap-2 text-sm font-semibold">
              <Clock className="h-4 w-4 text-primary/70" /> Remediation SLA
            </p>
            <p className="mt-0.5 text-xs text-muted-foreground">
              Days-to-remediate per severity. Drives the SLA / aging badges + breach highlighting on
              the Vulnerabilities workbench.
            </p>
          </div>
          <div className="flex flex-wrap items-end gap-4 p-4">
            {SLA_SEVERITIES.map((sev) => (
              <div key={sev} className="space-y-1.5">
                <label className="text-[10px] font-semibold uppercase tracking-wide text-muted-foreground capitalize">{sev}</label>
                <div className="flex items-center gap-1">
                  <Input
                    type="number"
                    min={1}
                    value={sla[sev] ?? ''}
                    onChange={(e) => setSla((p) => ({ ...p, [sev]: Number(e.target.value) }))}
                    className="h-8 w-[88px] text-sm"
                    disabled={isLoading}
                  />
                  <span className="text-xs text-muted-foreground">days</span>
                </div>
              </div>
            ))}
            <Button
              size="sm"
              className="h-8"
              disabled={save.isPending || isLoading}
              onClick={() =>
                save.mutate({
                  sla_critical_days: sla.critical,
                  sla_high_days: sla.high,
                  sla_medium_days: sla.medium,
                  sla_low_days: sla.low,
                })
              }
            >
              Save SLA
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* AI auto-escalate */}
      <Card className="glass-card">
        <CardContent className="p-0">
          <div className="flex items-center justify-between border-b border-border/40 px-4 py-3">
            <div>
              <p className="flex items-center gap-2 text-sm font-semibold">
                <Sparkles className="h-4 w-4 text-primary/70" /> AI auto-escalate
              </p>
              <p className="mt-0.5 max-w-lg text-xs text-muted-foreground">
                When a scheduled scan surfaces a NEW candidate in the selected severities, auto-create
                a (not-started) &quot;Prove it&quot; run. Cost-safe — you start it from the escalation
                queue; nothing runs unattended.
              </p>
            </div>
            <Switch
              checked={enabled}
              disabled={isLoading || save.isPending}
              onCheckedChange={(v) => {
                setEnabled(v);
                save.mutate({ dast_auto_escalate_enabled: v });
              }}
            />
          </div>
          <div className="flex flex-wrap items-center gap-4 p-4">
            <span className="text-xs font-medium text-muted-foreground">Escalate severities:</span>
            {SLA_SEVERITIES.map((sev) => (
              <label key={sev} className="flex items-center gap-1.5 text-sm capitalize">
                <Checkbox
                  checked={sevs.has(sev)}
                  disabled={!enabled}
                  onCheckedChange={() => {
                    const next = new Set(sevs);
                    if (next.has(sev)) next.delete(sev);
                    else next.add(sev);
                    setSevs(next);
                    save.mutate({ dast_auto_escalate_severities: Array.from(next).join(',') });
                  }}
                />
                {sev}
              </label>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Notifications */}
      <Card className="glass-card">
        <CardContent className="p-0">
          <div className="border-b border-border/40 px-4 py-3">
            <p className="flex items-center gap-2 text-sm font-semibold">
              <Bell className="h-4 w-4 text-primary/70" /> Notifications
            </p>
            <p className="mt-0.5 max-w-lg text-xs text-muted-foreground">
              Outbound webhook posted on a new Critical/High DAST finding. Slack-compatible
              (incoming-webhook URL); any endpoint accepting <code className="text-[11px]">{'{ "text": "…" }'}</code> works.
            </p>
          </div>
          <div className="flex items-center gap-2 p-4">
            <Input
              value={webhook}
              onChange={(e) => setWebhook(e.target.value)}
              placeholder="https://hooks.slack.com/services/…"
              className="h-8 max-w-lg text-sm font-mono"
              disabled={isLoading}
            />
            <Button
              size="sm"
              className="h-8"
              disabled={save.isPending || isLoading}
              onClick={() => save.mutate({ dast_webhook_url: webhook.trim() })}
            >
              Save
            </Button>
          </div>
        </CardContent>
      </Card>
    </>
  );
}

function ApiTokensCard() {
  const queryClient = useQueryClient();
  const { data: keys, isLoading } = useQuery({
    queryKey: ['api-keys'],
    queryFn: () => api.apiKeys.list(),
  });
  const [name, setName] = useState('');
  const [minted, setMinted] = useState<string | null>(null);

  const mint = useMutation({
    mutationFn: (n: string) => api.apiKeys.mint(n),
    onSuccess: (k) => {
      setMinted(k.token ?? null);
      setName('');
      queryClient.invalidateQueries({ queryKey: ['api-keys'] });
    },
    onError: (e) => toast.error(`Couldn't mint token: ${e instanceof Error ? e.message : String(e)}`),
  });
  const revoke = useMutation({
    mutationFn: (id: string) => api.apiKeys.revoke(id),
    onSuccess: () => {
      toast.success('Token revoked.');
      queryClient.invalidateQueries({ queryKey: ['api-keys'] });
    },
    onError: (e) => toast.error(`Couldn't revoke: ${e instanceof Error ? e.message : String(e)}`),
  });

  const active = (keys ?? []).filter((k) => !k.revoked_at);

  return (
    <Card className="glass-card">
      <CardContent className="p-0">
        <div className="border-b border-border/40 px-4 py-3">
          <p className="flex items-center gap-2 text-sm font-semibold">
            <KeyRound className="h-4 w-4 text-primary/70" /> CI API tokens
          </p>
          <p className="mt-0.5 max-w-lg text-xs text-muted-foreground">
            Trigger DAST scans from CI/CD. Use the token as a bearer against{' '}
            <code className="text-[11px]">POST /scans/trigger</code> with a target_id (+ optional policy_id).
          </p>
        </div>

        {minted && (
          <div className="m-4 rounded-lg border border-emerald-500/30 bg-emerald-500/10 p-3">
            <p className="text-xs font-medium text-emerald-400">New token — copy it now, it won&apos;t be shown again:</p>
            <div className="mt-1.5 flex items-center gap-2">
              <code className="flex-1 truncate rounded bg-black/40 px-2 py-1 font-mono text-[11px]">{minted}</code>
              <Button size="sm" variant="outline" className="h-7" onClick={() => { navigator.clipboard?.writeText(minted); toast.success('Copied.'); }}>
                <Copy className="h-3.5 w-3.5" />
              </Button>
              <Button size="sm" variant="ghost" className="h-7 text-xs" onClick={() => setMinted(null)}>Done</Button>
            </div>
          </div>
        )}

        <div className="flex items-center gap-2 p-4">
          <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="Token name (e.g. github-actions)" className="h-8 max-w-xs text-sm" />
          <Button size="sm" className="h-8" disabled={!name.trim() || mint.isPending} onClick={() => mint.mutate(name.trim())}>
            <Plus className="mr-1.5 h-3.5 w-3.5" /> Mint token
          </Button>
        </div>

        <div className="px-4 pb-4">
          {isLoading ? (
            <Skeleton className="h-10 w-full" />
          ) : active.length === 0 ? (
            <p className="text-xs text-muted-foreground/60">No active tokens.</p>
          ) : (
            <div className="divide-y divide-border/40 rounded-lg border border-border/40">
              {active.map((k) => (
                <div key={k.id} className="flex items-center gap-3 px-3 py-2">
                  <KeyRound className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />
                  <div className="min-w-0 flex-1">
                    <p className="truncate text-sm font-medium">{k.name}</p>
                    <p className="font-mono text-[10px] text-muted-foreground">dast_{k.prefix}…{k.last_used_at ? ' · used' : ' · never used'}</p>
                  </div>
                  <Button variant="ghost" size="sm" className="h-7 w-7 p-0 text-muted-foreground hover:text-red-400" onClick={() => revoke.mutate(k.id)}>
                    <Trash2 className="h-3.5 w-3.5" />
                  </Button>
                </div>
              ))}
            </div>
          )}
          <pre className="mt-3 overflow-x-auto rounded-md bg-black/40 p-2.5 font-mono text-[10px] text-muted-foreground/90">{`curl -X POST "$MAESTRO_API/scans/trigger" \\
  -H "Authorization: Bearer dast_…" \\
  -H "Content-Type: application/json" \\
  -d '{"target_id":"<id>"}'`}</pre>
        </div>
      </CardContent>
    </Card>
  );
}

export default function ScheduledSettingsPage() {
  const { targets, scheduledIds, dastTargetOptions, openConfig } = useScheduledDast();
  const byId = new Map(targets.map((t) => [t.id, t]));

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-xl font-bold tracking-tight">Settings</h1>
        <p className="mt-0.5 text-sm text-muted-foreground">
          SLA, AI auto-escalation, and per-target authentication + scope for DAST runs.
        </p>
      </div>

      <SlaAndEscalateCards />

      <ApiTokensCard />

      <Card className="glass-card">
        <CardContent className="p-0">
          <div className="border-b border-border/40 px-4 py-3">
            <p className="flex items-center gap-2 text-sm font-semibold">
              <Settings2 className="h-4 w-4 text-primary/70" /> Per-target scan config
            </p>
            <p className="mt-0.5 text-xs text-muted-foreground">
              Auth (header / basic / bearer / form login) + include/exclude scope so scans reach
              behind login and stay in bounds.
            </p>
          </div>

          {dastTargetOptions.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 text-center">
              <div className="mb-3 rounded-xl bg-muted/50 p-3">
                <Globe className="h-7 w-7 text-muted-foreground/50" />
              </div>
              <p className="text-sm font-medium text-muted-foreground">No DAST-eligible targets</p>
              <p className="mt-1 max-w-md text-xs text-muted-foreground/70">
                Add a reachable web / host target in Config → Scope to configure its DAST auth and scope.
              </p>
            </div>
          ) : (
            <div className="divide-y divide-border/40">
              {dastTargetOptions.map((opt) => {
                const t = byId.get(opt.value);
                return (
                  <div key={opt.value} className="flex items-center gap-3 px-4 py-3">
                    <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-primary/8">
                      <TargetTypeIcon targetType={t?.target_type ?? 'host'} className="h-4 w-4 text-primary/80" />
                    </div>
                    <div className="min-w-0 flex-1">
                      <p className="truncate text-sm font-medium">{opt.label}</p>
                      <p className="text-[10px] capitalize text-muted-foreground">
                        {(t?.target_type ?? 'host').replace('_', ' ')}
                        {scheduledIds.has(opt.value) ? ' · scheduled' : ''}
                      </p>
                    </div>
                    <Button variant="outline" size="sm" className="h-8" onClick={() => openConfig(opt.value)}>
                      <Settings2 className="mr-1.5 h-3.5 w-3.5" /> Configure
                    </Button>
                  </div>
                );
              })}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
