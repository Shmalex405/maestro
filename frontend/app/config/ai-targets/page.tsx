'use client';

// =============================================================================
// Config → AI Targets (/config/ai-targets)
//
// CRUD for `scope.yml` `ai_targets[]` — the customer-owned AI/LLM systems the AI
// red-team agents are authorized to assess (see docs/ai-surface-plan.md). Mirrors
// the Identity Targets / Cloud Accounts config pages: load scope, list targets in
// a table, add/edit in a dialog, structurally validate (validate_ai_target) before
// persisting, then merge back into scope and save. Fail-closed: no entry, no AI
// testing.
//
// The endpoint MUST also resolve into an in-scope domains/networks entry — the
// mcp-server AI scope validator enforces that at assessment time; this page only
// does structural validation (required fields per kind).
// =============================================================================

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { api } from '@/lib/tauri-api';
import type { AiTargetValidationResult } from '@/lib/tauri-api';
import type { AiTarget, ScopeConfig } from '@/lib/types';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import { Textarea } from '@/components/ui/textarea';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from '@/components/ui/alert-dialog';
import {
  ArrowLeft,
  Plus,
  Trash2,
  Bot,
  Shield,
  Save,
  CheckCircle2,
  XCircle,
  Loader2,
  Pencil,
} from 'lucide-react';
import { toast } from 'sonner';

type AiKind = AiTarget['kind'];

const KINDS: { value: AiKind; label: string }[] = [
  { value: 'chat_app', label: 'chat_app — chatbot wrapping a model' },
  { value: 'agent', label: 'agent — LLM with tools / function-calling' },
  { value: 'rag_app', label: 'rag_app — retrieval-augmented app' },
  { value: 'model_api', label: 'model_api — raw completion/chat endpoint' },
  { value: 'mcp_server', label: 'mcp_server — an MCP server itself' },
];

const PROVIDERS = ['custom', 'openai', 'anthropic', 'azure_openai', 'bedrock', 'vertex'];
const AUTH_METHODS = ['bearer', 'api_key', 'session', 'none'];

// Request-shape presets — the endpoint's body is customer-declared (no default).
// {{PROMPT}} is where the user message goes. The preset prefills both fields; the
// customer edits to match their real endpoint. See
// docs/user-guide/ai-targets/request-shapes.md.
const REQUEST_PRESETS: Record<string, { request_template: string; response_path: string }> = {
  openai: {
    request_template:
      '{"model":"gpt-4o","messages":[{"role":"user","content":"{{PROMPT}}"}]}',
    response_path: 'choices.0.message.content',
  },
  anthropic: {
    request_template:
      '{"model":"claude-sonnet-4-6","max_tokens":1024,"messages":[{"role":"user","content":"{{PROMPT}}"}]}',
    response_path: 'content.0.text',
  },
  custom: {
    request_template: '{"input":"{{PROMPT}}"}',
    response_path: 'output',
  },
};

function emptyTarget(): AiTarget {
  return {
    id: '',
    kind: 'chat_app',
    provider: 'custom',
    endpoint: '',
    model: '',
    auth_method: 'bearer',
    credential_ref: '',
    request_template: REQUEST_PRESETS.openai.request_template,
    response_path: REQUEST_PRESETS.openai.response_path,
    declared_tools: [],
    exclusions: [],
    trials: 10,
    cross_kind_probe: true,
    notes: '',
  };
}

export default function AiTargetsPage() {
  const router = useRouter();
  const [scope, setScope] = useState<ScopeConfig | null>(null);
  const [targets, setTargets] = useState<AiTarget[]>([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);

  const [dialogOpen, setDialogOpen] = useState(false);
  const [editIndex, setEditIndex] = useState<number | null>(null);
  const [draft, setDraft] = useState<AiTarget>(emptyTarget());
  const [validating, setValidating] = useState(false);
  const [validation, setValidation] = useState<AiTargetValidationResult | null>(null);
  // Config → Credentials application names + their base_url, for the "reuse app
  // login" picker and its host-based auto-suggest.
  const [appCreds, setAppCreds] = useState<{ name: string; base_url?: string }[]>([]);

  useEffect(() => {
    (async () => {
      try {
        const config = await api.config.scope.get();
        setScope(config);
        setTargets(config.ai_targets ?? []);
      } catch (e) {
        toast.error(`Failed to load scope: ${e}`);
      } finally {
        setLoading(false);
      }
      try {
        const creds = await api.config.credentials.get();
        setAppCreds(
          Object.entries(creds.applications ?? {}).map(([name, a]) => ({
            name,
            base_url: a?.base_url,
          })),
        );
      } catch {
        /* credentials are optional; the static-token fallback still works */
      }
    })();
  }, []);

  // Suggest the app credential whose base_url host matches the AI endpoint host.
  function suggestedAppCred(endpoint?: string): string | undefined {
    if (!endpoint) return undefined;
    let host: string;
    try {
      host = new URL(endpoint).host;
    } catch {
      return undefined;
    }
    const bareHost = host.replace(/^api\./, '');
    const match = appCreds.find((c) => {
      if (!c.base_url) return false;
      const b = c.base_url.replace(/^https?:\/\//, '').replace(/^\*\./, '').replace(/\/.*$/, '');
      return host === b || host.endsWith('.' + b) || bareHost === b || host.includes(b);
    });
    return match?.name;
  }

  function openAdd() {
    setDraft(emptyTarget());
    setEditIndex(null);
    setValidation(null);
    setDialogOpen(true);
  }

  function openEdit(i: number) {
    setDraft({ ...targets[i], declared_tools: targets[i].declared_tools ?? [] });
    setEditIndex(i);
    setValidation(null);
    setDialogOpen(true);
  }

  function setField<K extends keyof AiTarget>(key: K, value: AiTarget[K]) {
    setDraft((d) => ({ ...d, [key]: value }));
    setValidation(null);
  }

  async function runValidate(): Promise<boolean> {
    setValidating(true);
    try {
      const res = await api.config.scope.validateAiTarget(draft);
      setValidation(res);
      if (!res.ok) toast.error(res.error || 'Validation failed');
      return res.ok;
    } catch (e) {
      const res = { ok: false, identity: '', details: '', error: String(e) };
      setValidation(res);
      toast.error(String(e));
      return false;
    } finally {
      setValidating(false);
    }
  }

  async function persist(next: AiTarget[]) {
    if (!scope) return;
    setSaving(true);
    try {
      const updated: ScopeConfig = { ...scope, ai_targets: next };
      await api.config.scope.update(updated);
      setScope(updated);
      setTargets(next);
      toast.success('AI targets saved');
    } catch (e) {
      toast.error(`Save failed: ${e}`);
    } finally {
      setSaving(false);
    }
  }

  async function saveDraft() {
    if (!draft.id.trim()) {
      toast.error('id is required');
      return;
    }
    // Structural validation gates the save (mirrors the identity/cloud dialogs).
    const ok = await runValidate();
    if (!ok) return;
    const next = [...targets];
    if (editIndex === null) next.push(draft);
    else next[editIndex] = draft;
    await persist(next);
    setDialogOpen(false);
  }

  async function remove(i: number) {
    const next = targets.filter((_, idx) => idx !== i);
    await persist(next);
  }

  const showTools = draft.kind === 'agent' || draft.kind === 'mcp_server';

  return (
    <div className="max-w-[1100px] mx-auto p-6 space-y-5">
      {/* Header */}
      <div className="flex items-center gap-3">
        <Button variant="ghost" size="icon" onClick={() => router.push('/config')}>
          <ArrowLeft className="h-5 w-5" />
        </Button>
        <div className="p-2 rounded-lg bg-violet-600 text-white">
          <Bot className="h-5 w-5" />
        </div>
        <div className="flex-1">
          <h1 className="text-2xl font-bold tracking-tight">AI Targets</h1>
          <p className="text-sm text-muted-foreground">
            Customer-owned AI/LLM systems authorized for red teaming. Fail-closed — no entry, no AI
            testing. Run with <span className="font-mono">/assess-ai</span>.
          </p>
        </div>
        <Button onClick={openAdd} className="gap-1.5">
          <Plus className="h-4 w-4" /> Add AI target
        </Button>
      </div>

      <Card className="glass-card">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <Shield className="h-4 w-4" /> AI Safety Mandate
          </CardTitle>
          <CardDescription>
            Consumption is probe-only, excessive agency is capability-not-execution (the captured
            tool call is the proof — no real side effects), no persistent poisoning, and only the
            customer&apos;s own systems — never the upstream model provider. Each target&apos;s{' '}
            <span className="font-mono">endpoint</span> must also be in an in-scope{' '}
            <span className="font-mono">domains</span>/<span className="font-mono">networks</span>{' '}
            entry.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {loading ? (
            <div className="flex items-center gap-2 text-sm text-muted-foreground">
              <Loader2 className="h-4 w-4 animate-spin" /> Loading scope…
            </div>
          ) : targets.length === 0 ? (
            <div className="text-sm text-muted-foreground py-6 text-center">
              No AI targets configured. Click <span className="font-medium">Add AI target</span> to
              authorize one.
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>ID</TableHead>
                  <TableHead>Kind</TableHead>
                  <TableHead>Endpoint</TableHead>
                  <TableHead>Model</TableHead>
                  <TableHead>Auth</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {targets.map((t, i) => (
                  <TableRow key={t.id || i}>
                    <TableCell className="font-medium">{t.id}</TableCell>
                    <TableCell>
                      <Badge variant="secondary">{t.kind}</Badge>
                    </TableCell>
                    <TableCell className="font-mono text-xs max-w-[260px] truncate">
                      {t.endpoint || t.base_url || '—'}
                    </TableCell>
                    <TableCell className="text-xs">{t.model || '—'}</TableCell>
                    <TableCell className="text-xs">{t.auth_method}</TableCell>
                    <TableCell className="text-right">
                      <Button variant="ghost" size="icon" onClick={() => openEdit(i)}>
                        <Pencil className="h-4 w-4" />
                      </Button>
                      <AlertDialog>
                        <AlertDialogTrigger asChild>
                          <Button variant="ghost" size="icon" disabled={saving} aria-label={`Remove target ${t.id}`}>
                            <Trash2 className="h-4 w-4 text-destructive" />
                          </Button>
                        </AlertDialogTrigger>
                        <AlertDialogContent>
                          <AlertDialogHeader>
                            <AlertDialogTitle>Remove target &quot;{t.id}&quot;?</AlertDialogTitle>
                            <AlertDialogDescription>
                              This removes the AI target from the assessment scope. This takes effect immediately.
                            </AlertDialogDescription>
                          </AlertDialogHeader>
                          <AlertDialogFooter>
                            <AlertDialogCancel>Cancel</AlertDialogCancel>
                            <AlertDialogAction onClick={() => remove(i)}>Remove</AlertDialogAction>
                          </AlertDialogFooter>
                        </AlertDialogContent>
                      </AlertDialog>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {/* Add / Edit dialog */}
      <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
        <DialogContent className="max-w-lg max-h-[85vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>{editIndex === null ? 'Add AI target' : 'Edit AI target'}</DialogTitle>
            <DialogDescription>
              Structural validation runs on save. A live endpoint probe runs at assessment time.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-3">
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1.5">
                <Label>ID</Label>
                <Input
                  value={draft.id}
                  onChange={(e) => setField('id', e.target.value)}
                  placeholder="support-bot"
                />
              </div>
              <div className="space-y-1.5">
                <Label>Kind</Label>
                <Select value={draft.kind} onValueChange={(v) => setField('kind', v as AiKind)}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {KINDS.map((k) => (
                      <SelectItem key={k.value} value={k.value}>
                        {k.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>

            <div className="space-y-1.5">
              <Label>Endpoint (must be in scope domains/networks)</Label>
              <Input
                value={draft.endpoint ?? ''}
                onChange={(e) => setField('endpoint', e.target.value)}
                placeholder="https://app.staging.example.com/api/chat"
              />
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1.5">
                <Label>Provider</Label>
                <Select value={draft.provider} onValueChange={(v) => setField('provider', v)}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {PROVIDERS.map((p) => (
                      <SelectItem key={p} value={p}>
                        {p}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-1.5">
                <Label>Model (claimed)</Label>
                <Input
                  value={draft.model ?? ''}
                  onChange={(e) => setField('model', e.target.value)}
                  placeholder="gpt-4o"
                />
              </div>
            </div>

            <div className="space-y-1.5">
              <Label>App credential (reuse a login — recommended)</Label>
              <Select
                value={draft.app_credential || 'none'}
                onValueChange={(v) => setField('app_credential', v === 'none' ? undefined : v)}
              >
                <SelectTrigger>
                  <SelectValue placeholder="None — use a static token below" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="none">None — use a static token below</SelectItem>
                  {appCreds.map((c) => (
                    <SelectItem key={c.name} value={c.name}>
                      {c.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <p className="text-muted-foreground text-xs">
                Reuse a Config → Credentials app&apos;s login so the assessment mints a fresh token each
                run (shared with the web/API assessment) — no static token that expires mid-run.
                {(() => {
                  const s = suggestedAppCred(draft.endpoint);
                  return s && draft.app_credential !== s ? (
                    <>
                      {' '}Suggested for this host:{' '}
                      <button
                        type="button"
                        className="text-primary underline"
                        onClick={() => setField('app_credential', s)}
                      >
                        {s}
                      </button>
                      .
                    </>
                  ) : null;
                })()}
              </p>
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1.5">
                <Label>Auth method</Label>
                <Select value={draft.auth_method} onValueChange={(v) => setField('auth_method', v)}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {AUTH_METHODS.map((a) => (
                      <SelectItem key={a} value={a}>
                        {a}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-1.5">
                <Label>{draft.app_credential ? 'Credential ref (fallback)' : 'Credential ref'}</Label>
                <Input
                  value={draft.credential_ref ?? ''}
                  onChange={(e) => setField('credential_ref', e.target.value)}
                  placeholder={draft.app_credential ? 'unused — app credential set' : 'support-bot-key'}
                  disabled={draft.auth_method === 'none' || !!draft.app_credential}
                />
              </div>
            </div>

            {/* Request shape — customer-declared; no default is assumed. */}
            <div className="space-y-1.5 rounded-md border p-2.5">
              <div className="flex items-center justify-between">
                <Label>Request shape</Label>
                <div className="flex gap-1">
                  {Object.keys(REQUEST_PRESETS).map((p) => (
                    <Button
                      key={p}
                      type="button"
                      variant="outline"
                      size="sm"
                      className="h-6 px-2 text-[11px]"
                      onClick={() => {
                        setField('request_template', REQUEST_PRESETS[p].request_template);
                        setField('response_path', REQUEST_PRESETS[p].response_path);
                      }}
                    >
                      {p}
                    </Button>
                  ))}
                </div>
              </div>
              <p className="text-[11px] text-muted-foreground">
                The endpoint&apos;s JSON request body — <span className="font-mono">{'{{PROMPT}}'}</span> is
                where the user message goes. Required (no default). Pick a preset and edit to match
                your endpoint.
              </p>
              <Textarea
                value={draft.request_template ?? ''}
                onChange={(e) => setField('request_template', e.target.value)}
                placeholder={REQUEST_PRESETS.openai.request_template}
                rows={3}
                className="font-mono text-xs"
              />
              <Input
                value={draft.response_path ?? ''}
                onChange={(e) => setField('response_path', e.target.value)}
                placeholder="response_path — where the reply lives, e.g. choices.0.message.content (optional)"
                className="font-mono text-xs"
              />
            </div>

            {showTools && (
              <div className="space-y-1.5">
                <Label>Declared tools (comma-separated — the excessive-agency blast radius)</Label>
                <Input
                  value={(draft.declared_tools ?? []).join(', ')}
                  onChange={(e) =>
                    setField(
                      'declared_tools',
                      e.target.value
                        .split(',')
                        .map((s) => s.trim())
                        .filter(Boolean),
                    )
                  }
                  placeholder="search_kb, send_email, create_ticket"
                />
              </div>
            )}

            <button
              type="button"
              role="checkbox"
              aria-checked={draft.cross_kind_probe !== false}
              aria-label="Cross-kind capability probing"
              onClick={() => setField('cross_kind_probe', draft.cross_kind_probe === false ? true : false)}
              className="flex w-full items-start gap-2 rounded-md border p-2.5 text-left text-sm hover:bg-muted/50"
            >
              <span
                aria-hidden="true"
                className={`mt-0.5 h-3.5 w-3.5 rounded-sm border shrink-0 ${
                  draft.cross_kind_probe !== false ? 'bg-primary border-primary' : 'border-muted-foreground/40'
                }`}
              />
              <span>
                <span className="font-medium">Cross-kind capability probing</span>
                <span className="block text-xs text-muted-foreground">
                  Probe the target&apos;s true nature beyond the declared kind (AI-RECON-05) — e.g. a
                  chatbot that will actually tool-call. Detected capabilities expand the test set; an
                  undeclared one is a finding. Default on.
                </span>
              </span>
            </button>

            <div className="space-y-1.5">
              <Label>Notes</Label>
              <Textarea
                value={draft.notes ?? ''}
                onChange={(e) => setField('notes', e.target.value)}
                placeholder="Staging support chatbot — authorized for full AI red team"
                rows={2}
              />
            </div>

            {validation && (
              <div
                className={`flex items-start gap-2 rounded-md p-2.5 text-xs ${
                  validation.ok
                    ? 'bg-green-500/10 text-green-600 dark:text-green-400'
                    : 'bg-destructive/10 text-destructive'
                }`}
              >
                {validation.ok ? (
                  <CheckCircle2 className="h-4 w-4 shrink-0" />
                ) : (
                  <XCircle className="h-4 w-4 shrink-0" />
                )}
                <span>{validation.ok ? validation.identity : validation.error}</span>
              </div>
            )}
          </div>

          <DialogFooter>
            <Button variant="outline" onClick={() => runValidate()} disabled={validating}>
              {validating ? <Loader2 className="h-4 w-4 animate-spin" /> : 'Validate'}
            </Button>
            <Button onClick={saveDraft} disabled={saving || validating} className="gap-1.5">
              <Save className="h-4 w-4" /> Save
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
