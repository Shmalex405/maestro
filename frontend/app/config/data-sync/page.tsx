'use client';

// Data & Sync — where the deployment mode lives.
//
// Two modes (see lib/deployment-mode.ts):
//   Local — findings/assessments/reports in the local SQLite DB. No backend, no
//           sign-in, nothing to provision. Single operator.
//   Team  — a Postgres backend the operator deployed (deploy/terraform/
//           maestro-self-host). Multiple users share one view.
//
// An open-core build defaults to LOCAL with no config file and no first-run
// question, so most users never come here. This page exists for the upgrade
// path: paste the terraform output and switch to team.
//
// Deliberately a paste field rather than four inputs. `terraform output -raw
// desktop_self_host_json` emits exactly the config shape, and hand-transcribing
// a pool ID / client ID / region / URL is the step people get wrong.

import { useEffect, useState } from 'react';
import { PageHeader } from '@/components/layout/page-header';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Textarea } from '@/components/ui/textarea';
import { invoke } from '@tauri-apps/api/core';
import { isTauri } from '@/lib/tauri-api';
import {
  getDataMode,
  setDataMode,
  type DataMode,
  type TeamOnlyFeature,
} from '@/lib/deployment-mode';
import {
  HardDrive,
  Cloud,
  Check,
  AlertTriangle,
  Loader2,
  ArrowRight,
} from 'lucide-react';

/** Capabilities that need the team backend, with the copy shown on this page.
 *  Mirrors TEAM_ONLY_REASON in deployment-mode.ts but phrased as a feature list
 *  rather than an error. */
const TEAM_ONLY: { feature: TeamOnlyFeature; label: string }[] = [
  { feature: 'attack-graph', label: 'Attack-graph explorer' },
  { feature: 'post-exploitation', label: 'Post-exploitation footholds' },
  { feature: 'scheduled-dast', label: 'Scheduled DAST' },
  { feature: 'user-management', label: 'Users and roles' },
  { feature: 'cross-assessment-cache', label: 'Cross-assessment caching' },
];

const SHARED = [
  'Run assessments across all five surfaces',
  'Findings, triage, evidence, severity calibration',
  'Reports and PDF rendering',
  'Projects, imports, scan history',
  'Oracle verification',
];

export default function DataSyncPage() {
  const [mode, setMode] = useState<DataMode>('cloud');
  const [pasted, setPasted] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [saved, setSaved] = useState(false);

  // Read once on mount rather than during render — getDataMode touches
  // localStorage, which is absent during the static-export prerender.
  useEffect(() => setMode(getDataMode()), []);

  const isLocal = mode === 'local';

  async function switchToLocal() {
    setBusy(true);
    setError('');
    setSaved(false);
    try {
      await invoke('set_local_mode');
      setDataMode('local');
      setMode('local');
      setSaved(true);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  async function switchToTeam() {
    setBusy(true);
    setError('');
    setSaved(false);
    try {
      // The Rust side validates and reports missing fields by name, so a
      // truncated paste gets a useful message instead of a generic failure.
      await invoke('set_deployment_config', { config_json: pasted });
      setDataMode('cloud');
      setMode('cloud');
      setSaved(true);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-5">
      <PageHeader
        title="Data & Sync"
        description="Where this install stores findings, assessments and reports."
      />

      {!isTauri() && (
        <Card className="border-amber-500/30 bg-amber-500/5">
          <CardContent className="flex gap-3 py-4 text-sm">
            <AlertTriangle className="h-4 w-4 shrink-0 text-amber-400" />
            <span className="text-muted-foreground">
              Running outside the desktop app, so the mode can be previewed but not
              changed — switching writes a config file through the Tauri backend.
            </span>
          </CardContent>
        </Card>
      )}

      {/* ── Current mode ─────────────────────────────────────────────────── */}
      <div className="grid gap-4 md:grid-cols-2">
        <Card className={isLocal ? 'border-primary/60 bg-primary/5' : ''}>
          <CardHeader>
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <HardDrive className="h-4 w-4 text-muted-foreground" />
                <CardTitle className="text-base">Local</CardTitle>
              </div>
              {isLocal ? (
                <Badge className="gap-1">
                  <Check className="h-3 w-3" /> Active
                </Badge>
              ) : (
                <Badge variant="outline">Available</Badge>
              )}
            </div>
            <CardDescription>
              Everything on this machine, in a local SQLite database. No backend,
              no sign-in, nothing to provision. Single operator.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <p className="text-xs text-muted-foreground">
              Stored at <code className="text-[11px]">~/.pentest/data/pentest.db</code>
            </p>
            {!isLocal && (
              <Button
                size="sm"
                variant="outline"
                disabled={busy || !isTauri()}
                onClick={switchToLocal}
              >
                {busy ? <Loader2 className="mr-2 h-3 w-3 animate-spin" /> : null}
                Switch to local
              </Button>
            )}
          </CardContent>
        </Card>

        <Card className={!isLocal ? 'border-primary/60 bg-primary/5' : ''}>
          <CardHeader>
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Cloud className="h-4 w-4 text-muted-foreground" />
                <CardTitle className="text-base">Team</CardTitle>
              </div>
              {!isLocal ? (
                <Badge className="gap-1">
                  <Check className="h-3 w-3" /> Active
                </Badge>
              ) : (
                <Badge variant="outline">Available</Badge>
              )}
            </div>
            <CardDescription>
              A Postgres backend you deploy into your own AWS account. Users sign
              in against your Cognito pool and share one view of the data.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <p className="text-xs text-muted-foreground">
              Deploy with <code className="text-[11px]">deploy/terraform/maestro-self-host</code>
            </p>
          </CardContent>
        </Card>
      </div>

      {/* ── Switching data stores is not a migration ──────────────────────── */}
      <Card className="border-amber-500/30 bg-amber-500/5">
        <CardContent className="flex gap-3 py-4 text-sm">
          <AlertTriangle className="h-4 w-4 shrink-0 text-amber-400" />
          <div className="space-y-1 text-muted-foreground">
            <p className="font-medium text-foreground">
              Switching modes does not move your data.
            </p>
            <p>
              Local and team findings live in different stores. Nothing is deleted
              when you switch, but the other store&apos;s findings will not be
              visible until you switch back. Decide before you accumulate work you
              care about.
            </p>
          </div>
        </CardContent>
      </Card>

      {/* ── Connect a team backend ───────────────────────────────────────── */}
      {isLocal && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Connect a team backend</CardTitle>
            <CardDescription>
              Run this against your deployment and paste the whole output:
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <pre className="overflow-x-auto rounded-md bg-muted/40 px-3 py-2 text-[11px]">
{`cd deploy/terraform/maestro-self-host
terraform output -raw desktop_self_host_json`}
            </pre>
            <Textarea
              value={pasted}
              onChange={(e) => setPasted(e.target.value)}
              placeholder='{ "mode": "team", "backendUrl": "https://...", "cognitoUserPoolId": "...", ... }'
              className="min-h-[130px] font-mono text-xs"
              spellCheck={false}
            />
            <div className="flex items-center gap-3">
              <Button
                size="sm"
                disabled={busy || !pasted.trim() || !isTauri()}
                onClick={switchToTeam}
              >
                {busy ? <Loader2 className="mr-2 h-3 w-3 animate-spin" /> : null}
                Connect and switch
                <ArrowRight className="ml-2 h-3 w-3" />
              </Button>
              <span className="text-xs text-muted-foreground">
                Restart the app after switching.
              </span>
            </div>
          </CardContent>
        </Card>
      )}

      {saved && (
        <Card className="border-emerald-500/30 bg-emerald-500/5">
          <CardContent className="flex gap-3 py-4 text-sm">
            <Check className="h-4 w-4 shrink-0 text-emerald-400" />
            <span className="text-muted-foreground">
              Saved. Restart Maestro for the change to take effect.
            </span>
          </CardContent>
        </Card>
      )}

      {error && (
        <Card className="border-destructive/40 bg-destructive/5">
          <CardContent className="flex gap-3 py-4 text-sm">
            <AlertTriangle className="h-4 w-4 shrink-0 text-destructive" />
            <span className="whitespace-pre-wrap text-muted-foreground">{error}</span>
          </CardContent>
        </Card>
      )}

      {/* ── What differs ─────────────────────────────────────────────────── */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">What each mode gives you</CardTitle>
          <CardDescription>
            Local is a smaller product, not a degraded one — the assessment engine
            is identical.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div>
            <p className="mb-2 text-xs font-medium uppercase tracking-wide text-muted-foreground">
              Both modes
            </p>
            <ul className="space-y-1">
              {SHARED.map((f) => (
                <li key={f} className="flex items-center gap-2 text-sm">
                  <Check className="h-3.5 w-3.5 text-emerald-400" />
                  <span className="text-muted-foreground">{f}</span>
                </li>
              ))}
            </ul>
          </div>
          <div>
            <p className="mb-2 text-xs font-medium uppercase tracking-wide text-muted-foreground">
              Team only
            </p>
            <ul className="space-y-1">
              {TEAM_ONLY.map(({ feature, label }) => (
                <li key={feature} className="flex items-center gap-2 text-sm">
                  <Cloud className="h-3.5 w-3.5 text-muted-foreground" />
                  <span className="text-muted-foreground">{label}</span>
                </li>
              ))}
            </ul>
            <p className="mt-2 text-xs text-muted-foreground">
              These rely on Postgres-native schema the local database has no
              equivalent for — the attack graph in particular on a recursive-CTE
              pathfinder.
            </p>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
