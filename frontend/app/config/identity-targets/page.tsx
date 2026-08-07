'use client';

import { useState, useEffect, useRef } from 'react';
import { useRouter } from 'next/navigation';
import { api } from '@/lib/tauri-api';
import type { IdentityTargetValidationResult } from '@/lib/tauri-api';
import type {
  CredentialsConfig,
  IdentityCredentialEntry,
  IdentityTarget,
  ScopeConfig,
} from '@/lib/types';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
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
  DialogTrigger,
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
  Fingerprint,
  Shield,
  Save,
  CheckCircle2,
  XCircle,
  Loader2,
  Pencil,
  PlugZap,
} from 'lucide-react';
import { toast } from 'sonner';

type IdentityKind = IdentityTarget['kind'];

/**
 * Reasonable default auth method per IDP kind — picked the moment the
 * provider dropdown changes so the conditional field block always has a
 * valid method to render against.
 */
const DEFAULT_AUTH_METHOD: Record<IdentityKind, string> = {
  active_directory: 'domain_creds',
  entra_id: 'service_principal',
  m365: 'service_principal',
  okta: 'api_token',
  google_workspace: 'service_account',
  ping: 'oauth',
};

const kindColors: Record<IdentityKind, string> = {
  active_directory: 'bg-slate-600',
  entra_id: 'bg-blue-600',
  m365: 'bg-orange-600',
  okta: 'bg-indigo-600',
  google_workspace: 'bg-red-600',
  ping: 'bg-emerald-600',
};

const kindLabels: Record<IdentityKind, string> = {
  active_directory: 'Active Directory',
  entra_id: 'Entra ID',
  m365: 'Microsoft 365',
  okta: 'Okta',
  google_workspace: 'Google Workspace',
  ping: 'Ping',
};

// Auth-method options offered per kind. The first entry is the default.
const AUTH_METHODS: Record<IdentityKind, { value: string; label: string }[]> = {
  active_directory: [
    { value: 'domain_creds', label: 'Domain credentials (user + password)' },
    { value: 'none', label: 'No credentials (unauthenticated recon)' },
  ],
  entra_id: [
    { value: 'service_principal', label: 'Service Principal (app registration)' },
    { value: 'none', label: 'No credentials (unauthenticated recon)' },
  ],
  m365: [
    { value: 'service_principal', label: 'Service Principal (app registration)' },
    { value: 'none', label: 'No credentials (unauthenticated recon)' },
  ],
  okta: [{ value: 'api_token', label: 'API token' }],
  google_workspace: [{ value: 'service_account', label: 'Service Account (domain-wide delegation)' }],
  ping: [{ value: 'oauth', label: 'OAuth (PingOne/PingFederate)' }],
};

/**
 * Edit-form working state. Carries the IdentityTarget fields plus the
 * transient, never-persisted-inline secret inputs (token, SA-key JSON,
 * AD/service-principal username+password). On save these are pushed to
 * credentials.yml `identity_credentials` and the target keeps only refs.
 */
type IdentityForm = Partial<IdentityTarget> & {
  // Transient secret inputs (cleared on save; never stored on the target).
  _token?: string;
  _saKeyJson?: string;
  _username?: string;
  _password?: string;
  // Service-principal app id (Entra/M365). Not part of IdentityTarget —
  // it pairs with the client secret to mint the probe token; only the
  // resulting credential_ref is persisted on the target.
  client_id?: string;
  // True while editing an entry that already has a stored secret — drives
  // the "•••• stored — re-enter to replace" placeholder so we don't show
  // the secret back and don't clobber it on a no-op edit.
  _hasStoredSecret?: boolean;
};

function emptyForm(kind: IdentityKind = 'google_workspace'): IdentityForm {
  return {
    kind,
    provider: kind,
    auth_method: DEFAULT_AUTH_METHOD[kind],
    exclusions: [],
    notes: '',
  };
}

export default function IdentityTargetsPage() {
  const router = useRouter();
  const [targets, setTargets] = useState<IdentityTarget[]>([]);
  const [dialogOpen, setDialogOpen] = useState(false);
  // Non-null while editing an existing target (its id).
  const [editingId, setEditingId] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  // Hold the full scope so save round-trips networks/domains/exclusions/
  // cloud_accounts/kubernetes along with the identity changes.
  const [scope, setScope] = useState<ScopeConfig | null>(null);

  const [form, setForm] = useState<IdentityForm>(emptyForm());

  // Load scope on mount, populate targets from it.
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const config = await api.config.scope.get();
        if (cancelled) return;
        setScope(config);
        setTargets(config.identity_targets ?? []);
      } catch (err) {
        if (cancelled) return;
        console.error('[identity-targets] failed to load scope', err);
        toast.error('Failed to load identity targets');
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  // Credential-probe state. Gates the Add/Save submit on a successful
  // verify. Auto-resets to idle whenever a credential-affecting field
  // changes — see the useEffect below.
  type ProbeState =
    | { kind: 'idle' }
    | { kind: 'checking' }
    | { kind: 'success'; result: IdentityTargetValidationResult }
    | { kind: 'failure'; result: IdentityTargetValidationResult };
  const [probeState, setProbeState] = useState<ProbeState>({ kind: 'idle' });
  const probeRequestId = useRef(0);

  // Auto-reset probe state whenever any credential-affecting field
  // changes. Identifier metadata (display_name, notes, exclusions) is
  // intentionally NOT here — those don't change what the probe tests.
  useEffect(() => {
    probeRequestId.current += 1;
    setProbeState((s) => (s.kind === 'idle' ? s : { kind: 'idle' }));
  }, [
    form.kind,
    form.auth_method,
    form.tenant_id,
    form.domain,
    form.base_url,
    form.delegated_subject,
    form._token,
    form._saKeyJson,
    form._username,
    form._password,
  ]);

  // Per-row connection verify for already-saved targets.
  const [verifyingId, setVerifyingId] = useState<string | null>(null);

  const handleVerifyRow = async (target: IdentityTarget) => {
    setVerifyingId(target.id);
    try {
      const result = await api.config.scope.validateIdentityTarget(target);
      if (result.ok) {
        toast.success(`Connected: ${result.identity}`, {
          description: result.details || undefined,
        });
      } else {
        toast.error(`Verification failed: ${result.error}`);
      }
    } catch (e) {
      toast.error(`Verify failed: ${e instanceof Error ? e.message : String(e)}`);
    } finally {
      setVerifyingId(null);
    }
  };

  const resetForm = () => {
    setForm(emptyForm());
    setProbeState({ kind: 'idle' });
    setEditingId(null);
  };

  // Open the dialog pre-filled with an existing target for editing.
  // Stored secrets are NOT shown back — _hasStoredSecret drives a
  // "stored — re-enter to replace" placeholder instead.
  const openEdit = (target: IdentityTarget) => {
    const hasStoredSecret = !!(target.credential_ref || target.sa_key_ref);
    setForm({
      ...target,
      _hasStoredSecret: hasStoredSecret,
    });
    setEditingId(target.id);
    setProbeState({ kind: 'idle' });
    setDialogOpen(true);
  };

  /**
   * Field-level validation per (kind, auth_method). Returns null when the
   * form is good to submit, or a user-facing string describing what's
   * missing. When editing a target with a stored secret, a re-entered
   * secret is optional (the existing ref is kept).
   */
  const validationError = (f: IdentityForm): string | null => {
    if (!f.id?.trim()) return 'Target ID is required';
    if (!f.kind) return 'Provider is required';
    const secretOptional = !!f._hasStoredSecret;
    if (f.kind === 'google_workspace') {
      if (!f.tenant_id?.trim()) return 'Primary domain / customer ID is required';
      if (!f.delegated_subject?.trim()) return 'Delegated admin email is required';
      if (!secretOptional && !f._saKeyJson?.trim()) return 'Service Account key JSON is required';
    } else if (f.kind === 'okta') {
      if (!f.base_url?.trim()) return 'Okta org URL is required';
      if (!secretOptional && !f._token?.trim()) return 'API token is required';
    } else if (f.kind === 'ping') {
      if (!f.base_url?.trim()) return 'PingOne/PingFederate base URL is required';
      if (!f.tenant_id?.trim()) return 'Environment ID is required';
      if (!secretOptional && !f._token?.trim()) return 'API token is required';
    } else if (f.kind === 'entra_id' || f.kind === 'm365') {
      if (!f.tenant_id?.trim()) return 'Tenant ID / primary domain is required';
      if (f.auth_method === 'service_principal') {
        if (!f.client_id?.trim()) return 'Client ID is required';
        if (!secretOptional && !f._token?.trim()) return 'Client secret is required';
      }
    } else if (f.kind === 'active_directory') {
      if (!f.domain?.trim()) return 'AD domain FQDN is required';
      if (f.auth_method === 'domain_creds') {
        if (!f._username?.trim()) return 'Username is required';
        if (!secretOptional && !f._password?.trim()) return 'Password is required';
      }
    }
    return null;
  };

  /**
   * Build an IdentityTarget candidate from the current form for the probe.
   * Inline secrets are attached transiently so the backend probe can test
   * them; they are NOT what gets persisted on the scope entry (refs are).
   */
  const buildProbeCandidate = (f: IdentityForm): IdentityTarget => {
    const kind = (f.kind ?? 'google_workspace') as IdentityKind;
    const base: IdentityTarget = {
      id: f.id?.trim() || '',
      kind,
      provider: kind,
      display_name: f.display_name?.trim() || undefined,
      tenant_id: f.tenant_id?.trim() || undefined,
      domain: f.domain?.trim() || undefined,
      base_url: f.base_url?.trim() || undefined,
      auth_method: f.auth_method || DEFAULT_AUTH_METHOD[kind],
      // Probe-time only: stash the raw secret in credential_ref so the
      // backend can authenticate without a round-trip to the cred store.
      // The persisted entry replaces this with the real ref on save.
      credential_ref: f._token?.trim() || f._password?.trim() || undefined,
      sa_key_ref: f._saKeyJson?.trim() || undefined,
      delegated_subject: f.delegated_subject?.trim() || undefined,
      exclusions: f.exclusions || [],
      lockout_threshold: f.lockout_threshold,
      notes: f.notes || '',
    };
    // client_id / username aren't part of IdentityTarget — attach them for
    // the probe only (the backend reads them when minting a test token).
    return {
      ...base,
      client_id: f.client_id?.trim() || undefined,
      username: f._username?.trim() || undefined,
    } as IdentityTarget;
  };

  const handleVerifyConnection = async () => {
    const err = validationError(form);
    if (err) {
      toast.error(err);
      return;
    }
    const myReq = ++probeRequestId.current;
    setProbeState({ kind: 'checking' });
    try {
      const candidate = buildProbeCandidate(form);
      const result = await api.config.scope.validateIdentityTarget(candidate);
      // Ignore a stale return if a newer probe / credential edit superseded
      // this one.
      if (myReq !== probeRequestId.current) return;
      setProbeState(result.ok ? { kind: 'success', result } : { kind: 'failure', result });
    } catch (e) {
      if (myReq !== probeRequestId.current) return;
      setProbeState({
        kind: 'failure',
        result: {
          ok: false,
          identity: '',
          details: '',
          error: e instanceof Error ? e.message : String(e),
        },
      });
    }
  };

  /**
   * Persist the entered secrets into credentials.yml `identity_credentials`
   * (load-modify-write so applications/test_accounts are preserved) and
   * return the refs to set on the scope entry. SA keys go to a container
   * file via the Rust command; tokens are stored inline.
   */
  const persistCredentials = async (
    f: IdentityForm,
  ): Promise<{ credential_ref?: string; sa_key_ref?: string }> => {
    const kind = (f.kind ?? 'google_workspace') as IdentityKind;
    const id = f.id!.trim();

    const newEntries: Record<string, IdentityCredentialEntry> = {};
    let credential_ref: string | undefined = f.credential_ref;
    let sa_key_ref: string | undefined = f.sa_key_ref;

    if (kind === 'google_workspace' && f._saKeyJson?.trim()) {
      const ref = `${id}-sa`;
      // The Rust command writes the key into the Kali container and hands
      // back the file PATH — the secret itself never lands in the store.
      const path = await api.config.identity.saveSaKey(ref, f._saKeyJson.trim());
      newEntries[ref] = { kind: 'sa_json', path };
      sa_key_ref = ref;
    }

    // Token-style secrets (okta / ping / entra client secret / AD password).
    const token = f._token?.trim() || f._password?.trim();
    if (token) {
      const ref = `${id}-cred`;
      const credKind =
        kind === 'okta'
          ? 'okta_token'
          : kind === 'ping'
            ? 'ping_oauth'
            : 'api_token';
      newEntries[ref] = { kind: credKind, value: token };
      credential_ref = ref;
    }

    if (Object.keys(newEntries).length > 0) {
      // Load-modify-write — preserve applications/test_accounts and any
      // other identity_credentials already present.
      const creds: CredentialsConfig = await api.config.credentials.get();
      const next: CredentialsConfig = {
        ...creds,
        identity_credentials: {
          ...(creds.identity_credentials ?? {}),
          ...newEntries,
        },
      };
      await api.config.credentials.update(next);
    }

    return { credential_ref, sa_key_ref };
  };

  // Persist the given identity targets into the full scope immediately, so an
  // add/edit/delete can't be silently lost by navigating away before the batch
  // "Save Configuration" click. The Save button remains as an explicit re-save.
  const persistTargets = async (nextTargets: typeof targets) => {
    const next: ScopeConfig = {
      ...(scope ?? {
        networks: [],
        domains: [],
        exclusions: [],
        cloud_accounts: [],
        kubernetes: [],
      }),
      identity_targets: nextTargets,
    };
    const saved = await api.config.scope.update(next);
    setScope(saved);
    setTargets(nextTargets);
  };

  const handleDeleteTarget = async (id: string) => {
    try {
      await persistTargets(targets.filter((t) => t.id !== id));
      toast.success(`Removed target: ${id}`);
    } catch (e) {
      console.error('[identity-targets] delete failed', e);
      toast.error(`Delete failed: ${e instanceof Error ? e.message : String(e)}`);
    }
  };

  const handleSubmit = async () => {
    const err = validationError(form);
    if (err) {
      toast.error(err);
      return;
    }
    // Gate the save on a successful probe so we don't persist a credential
    // that doesn't resolve.
    if (probeState.kind !== 'success') {
      toast.error('Verify connection first — the credential must pass the probe before saving.');
      return;
    }
    setSaving(true);
    try {
      const { credential_ref, sa_key_ref } = await persistCredentials(form);
      const kind = (form.kind ?? 'google_workspace') as IdentityKind;
      const target: IdentityTarget = {
        id: form.id!.trim(),
        kind,
        // provider is set EQUAL to kind — the backend validator reads it.
        provider: kind,
        display_name: form.display_name?.trim() || undefined,
        tenant_id: form.tenant_id?.trim() || undefined,
        domain: form.domain?.trim() || undefined,
        base_url: form.base_url?.trim() || undefined,
        auth_method: form.auth_method || DEFAULT_AUTH_METHOD[kind],
        credential_ref,
        sa_key_ref,
        delegated_subject: form.delegated_subject?.trim() || undefined,
        exclusions: form.exclusions || [],
        lockout_threshold: form.lockout_threshold,
        notes: form.notes || '',
      };
      const isEdit = Boolean(editingId);
      const nextTargets = isEdit
        ? targets.map((t) => (t.id === editingId ? target : t))
        : [...targets, target];
      await persistTargets(nextTargets);
      toast.success(
        isEdit
          ? `Updated ${kindLabels[kind]} target: ${target.id}`
          : `Added ${kindLabels[kind]} target: ${target.id}`,
      );
      setDialogOpen(false);
      resetForm();
    } catch (e) {
      toast.error(`Save failed: ${e instanceof Error ? e.message : String(e)}`);
    } finally {
      setSaving(false);
    }
  };

  const handleSaveScope = async () => {
    setSaving(true);
    try {
      // Merge identity changes into the full scope so save preserves
      // networks/domains/exclusions/cloud_accounts/kubernetes.
      const next: ScopeConfig = {
        ...(scope ?? {
          networks: [],
          domains: [],
          exclusions: [],
          cloud_accounts: [],
          kubernetes: [],
        }),
        identity_targets: targets,
      };
      const saved = await api.config.scope.update(next);
      setScope(saved);
      toast.success('Identity targets configuration saved');
    } catch (err) {
      console.error('[identity-targets] save failed', err);
      toast.error('Failed to save identity targets');
    } finally {
      setSaving(false);
    }
  };

  const currentKind = (form.kind ?? 'google_workspace') as IdentityKind;
  const storedPlaceholder = '•••• stored — re-enter to replace';

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center gap-4">
        <Button variant="ghost" size="icon" onClick={() => router.push('/config')}>
          <ArrowLeft className="h-5 w-5" />
        </Button>
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Identity Targets</h1>
          <p className="text-sm text-muted-foreground">
            Configure IDPs (Entra, M365, Okta, Google Workspace, Ping, AD) for identity red team testing
          </p>
        </div>
      </div>

      {/* Info Banner */}
      <Card className="border-blue-500/30 bg-blue-500/5">
        <CardContent className="py-4">
          <div className="flex items-start gap-3">
            <Shield className="h-5 w-5 text-blue-500 flex-shrink-0 mt-0.5" />
            <div className="text-sm">
              <p className="font-medium text-blue-400">Identity Red Team Testing</p>
              <p className="text-muted-foreground mt-1">
                Configure identity providers authorized for security testing. Maestro enumerates
                users, roles, and policies, maps privilege-escalation paths, and attempts
                non-destructive exploitation. The Lockout Mandate is enforced — accounts you list
                under exclusions are never touched.
              </p>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Identity Targets */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <Fingerprint className="h-5 w-5 text-primary" />
              <div>
                <CardTitle>Identity Targets</CardTitle>
                <CardDescription>Identity providers in scope for red team testing</CardDescription>
              </div>
            </div>
            <Dialog
              open={dialogOpen}
              onOpenChange={(o) => {
                setDialogOpen(o);
                if (!o) resetForm();
              }}
            >
              <DialogTrigger asChild>
                <Button size="sm" onClick={() => resetForm()}>
                  <Plus className="h-4 w-4 mr-2" />
                  Add Target
                </Button>
              </DialogTrigger>
              <DialogContent className="max-w-lg max-h-[85vh] overflow-y-auto">
                <DialogHeader>
                  <DialogTitle>{editingId ? 'Edit Identity Target' : 'Add Identity Target'}</DialogTitle>
                  <DialogDescription>
                    {editingId
                      ? 'Update this target, then re-verify the connection before saving.'
                      : 'Add an identity provider authorized for testing'}
                  </DialogDescription>
                </DialogHeader>
                <div className="space-y-4">
                  <div className="space-y-2">
                    <Label>Provider</Label>
                    <Select
                      value={currentKind}
                      onValueChange={(v) => {
                        const kind = v as IdentityKind;
                        // Changing provider invalidates every kind-specific
                        // field: clear them so stale Okta token doesn't ride
                        // into a Google Workspace config.
                        setForm({
                          ...emptyForm(kind),
                          id: form.id,
                          display_name: form.display_name,
                          notes: form.notes,
                          exclusions: form.exclusions,
                          lockout_threshold: form.lockout_threshold,
                        });
                      }}
                    >
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="entra_id">Microsoft Entra ID</SelectItem>
                        <SelectItem value="m365">Microsoft 365</SelectItem>
                        <SelectItem value="okta">Okta</SelectItem>
                        <SelectItem value="google_workspace">Google Workspace</SelectItem>
                        <SelectItem value="ping">Ping (PingOne / PingFederate)</SelectItem>
                        <SelectItem value="active_directory">Active Directory</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>

                  <div className="space-y-2">
                    <Label>Target ID (unique identifier)</Label>
                    <Input
                      value={form.id || ''}
                      onChange={(e) => setForm({ ...form, id: e.target.value })}
                      placeholder="e.g., gws-groovy, okta-corp"
                      disabled={!!editingId}
                    />
                  </div>

                  <div className="space-y-2">
                    <Label>Display Name (optional)</Label>
                    <Input
                      value={form.display_name || ''}
                      onChange={(e) => setForm({ ...form, display_name: e.target.value })}
                      placeholder="e.g., Groovy Google Workspace"
                    />
                  </div>

                  <div className="space-y-2">
                    <Label>Authentication Method</Label>
                    <Select
                      value={form.auth_method}
                      onValueChange={(v) =>
                        setForm({
                          ...form,
                          auth_method: v,
                          // Switching method drops the per-method secrets.
                          _token: undefined,
                          _password: undefined,
                          _username: undefined,
                          client_id: undefined,
                          _hasStoredSecret: false,
                        })
                      }
                    >
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        {AUTH_METHODS[currentKind].map((m) => (
                          <SelectItem key={m.value} value={m.value}>
                            {m.label}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>

                  {/* ---- Google Workspace ---- */}
                  {currentKind === 'google_workspace' && (
                    <>
                      <div className="space-y-2">
                        <Label>Primary domain / customer ID</Label>
                        <Input
                          value={form.tenant_id || ''}
                          onChange={(e) => setForm({ ...form, tenant_id: e.target.value })}
                          placeholder="groovysec.com or C0xxxxxxx"
                        />
                      </div>
                      <div className="space-y-2">
                        <Label>Delegated admin email</Label>
                        <Input
                          value={form.delegated_subject || ''}
                          onChange={(e) => setForm({ ...form, delegated_subject: e.target.value })}
                          placeholder="admin@groovysec.com"
                        />
                        <p className="text-xs text-muted-foreground">
                          The admin principal the service account impersonates via domain-wide delegation.
                        </p>
                      </div>
                      <div className="space-y-2">
                        <Label>Service Account key (JSON)</Label>
                        <textarea
                          rows={6}
                          value={form._saKeyJson || ''}
                          onChange={(e) => setForm({ ...form, _saKeyJson: e.target.value })}
                          placeholder={
                            form._hasStoredSecret
                              ? storedPlaceholder
                              : '{\n  "type": "service_account",\n  "project_id": "...",\n  ...\n}'
                          }
                          className="flex w-full rounded-md border border-input bg-background px-3 py-2 text-sm font-mono ring-offset-background placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2"
                          autoComplete="off"
                          spellCheck={false}
                        />
                        <p className="text-xs text-muted-foreground">
                          Paste the full service-account key JSON. Stored in the Kali container, referenced by path — never inline in scope.yml.
                        </p>
                      </div>
                    </>
                  )}

                  {/* ---- Okta ---- */}
                  {currentKind === 'okta' && (
                    <>
                      <div className="space-y-2">
                        <Label>Okta org URL</Label>
                        <Input
                          value={form.base_url || ''}
                          onChange={(e) => setForm({ ...form, base_url: e.target.value })}
                          placeholder="https://corp.okta.com"
                        />
                      </div>
                      <div className="space-y-2">
                        <Label>API token</Label>
                        <Input
                          type="password"
                          value={form._token || ''}
                          onChange={(e) => setForm({ ...form, _token: e.target.value })}
                          placeholder={form._hasStoredSecret ? storedPlaceholder : '00aBc...'}
                          autoComplete="off"
                        />
                      </div>
                    </>
                  )}

                  {/* ---- Ping ---- */}
                  {currentKind === 'ping' && (
                    <>
                      <div className="space-y-2">
                        <Label>PingOne/PingFederate base URL</Label>
                        <Input
                          value={form.base_url || ''}
                          onChange={(e) => setForm({ ...form, base_url: e.target.value })}
                          placeholder="https://auth.pingone.com"
                        />
                      </div>
                      <div className="space-y-2">
                        <Label>Environment ID</Label>
                        <Input
                          value={form.tenant_id || ''}
                          onChange={(e) => setForm({ ...form, tenant_id: e.target.value })}
                          placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
                        />
                      </div>
                      <div className="space-y-2">
                        <Label>API token</Label>
                        <Input
                          type="password"
                          value={form._token || ''}
                          onChange={(e) => setForm({ ...form, _token: e.target.value })}
                          placeholder={form._hasStoredSecret ? storedPlaceholder : ''}
                          autoComplete="off"
                        />
                      </div>
                    </>
                  )}

                  {/* ---- Entra ID / M365 ---- */}
                  {(currentKind === 'entra_id' || currentKind === 'm365') && (
                    <>
                      <div className="space-y-2">
                        <Label>Tenant ID / primary domain</Label>
                        <Input
                          value={form.tenant_id || ''}
                          onChange={(e) => setForm({ ...form, tenant_id: e.target.value })}
                          placeholder="contoso.onmicrosoft.com or tenant GUID"
                        />
                      </div>
                      {form.auth_method === 'service_principal' && (
                        <>
                          <div className="space-y-2">
                            <Label>Client ID (App Registration)</Label>
                            <Input
                              value={form.client_id || ''}
                              onChange={(e) => setForm({ ...form, client_id: e.target.value })}
                              placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
                              autoComplete="off"
                            />
                          </div>
                          <div className="space-y-2">
                            <Label>Client Secret</Label>
                            <Input
                              type="password"
                              value={form._token || ''}
                              onChange={(e) => setForm({ ...form, _token: e.target.value })}
                              placeholder={form._hasStoredSecret ? storedPlaceholder : ''}
                              autoComplete="off"
                            />
                          </div>
                        </>
                      )}
                      {form.auth_method === 'none' && (
                        <p className="text-xs text-muted-foreground">
                          Unauthenticated recon only — no service principal configured. Tenant
                          metadata and user enumeration via open endpoints.
                        </p>
                      )}
                    </>
                  )}

                  {/* ---- Active Directory ---- */}
                  {currentKind === 'active_directory' && (
                    <>
                      <div className="space-y-2">
                        <Label>AD domain FQDN</Label>
                        <Input
                          value={form.domain || ''}
                          onChange={(e) => setForm({ ...form, domain: e.target.value })}
                          placeholder="corp.example.com"
                        />
                      </div>
                      {form.auth_method === 'domain_creds' && (
                        <>
                          <div className="space-y-2">
                            <Label>Username</Label>
                            <Input
                              value={form._username || ''}
                              onChange={(e) => setForm({ ...form, _username: e.target.value })}
                              placeholder="CORP\\svc-audit"
                              autoComplete="off"
                            />
                          </div>
                          <div className="space-y-2">
                            <Label>Password</Label>
                            <Input
                              type="password"
                              value={form._password || ''}
                              onChange={(e) => setForm({ ...form, _password: e.target.value })}
                              placeholder={form._hasStoredSecret ? storedPlaceholder : ''}
                              autoComplete="off"
                            />
                          </div>
                        </>
                      )}
                      {form.auth_method === 'none' && (
                        <p className="text-xs text-muted-foreground">
                          Unauthenticated enumeration only — anonymous LDAP / null session probes.
                        </p>
                      )}
                    </>
                  )}

                  {/* ---- Lockout Mandate (exclusions) ---- */}
                  <div className="space-y-2">
                    <Label>Never test these accounts (break-glass / executives)</Label>
                    <textarea
                      rows={3}
                      value={(form.exclusions || []).join('\n')}
                      onChange={(e) =>
                        setForm({
                          ...form,
                          exclusions: e.target.value
                            .split('\n')
                            .map((s) => s.trim())
                            .filter(Boolean),
                        })
                      }
                      placeholder={'ceo@example.com\nbreakglass-admin@example.com'}
                      className="flex w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2"
                      spellCheck={false}
                    />
                    <p className="text-xs text-muted-foreground">
                      Lockout Mandate — one account per line. These are excluded from every
                      identity test, password spray, and lockout-bearing operation.
                    </p>
                  </div>

                  <div className="space-y-2">
                    <Label>Lockout threshold (optional)</Label>
                    <Input
                      type="number"
                      value={form.lockout_threshold ?? ''}
                      onChange={(e) =>
                        setForm({
                          ...form,
                          lockout_threshold: e.target.value ? Number(e.target.value) : undefined,
                        })
                      }
                      placeholder="e.g., 5"
                    />
                    <p className="text-xs text-muted-foreground">
                      Max failed attempts before a spray backs off, to stay under the directory&apos;s
                      lockout policy.
                    </p>
                  </div>

                  <div className="space-y-2">
                    <Label>Notes</Label>
                    <Input
                      value={form.notes || ''}
                      onChange={(e) => setForm({ ...form, notes: e.target.value })}
                      placeholder="e.g., Staging tenant — authorized for full identity red team"
                    />
                  </div>

                  {/* Verify connection — gates the save below on success. */}
                  <div className="space-y-2">
                    <div className="flex items-center justify-between gap-2">
                      <Label>Connection</Label>
                      <Button
                        type="button"
                        size="sm"
                        variant="outline"
                        onClick={handleVerifyConnection}
                        disabled={probeState.kind === 'checking'}
                      >
                        {probeState.kind === 'checking' ? (
                          <>
                            <Loader2 className="h-3.5 w-3.5 mr-1.5 animate-spin" />
                            Verifying…
                          </>
                        ) : (
                          <>
                            <PlugZap className="h-3.5 w-3.5 mr-1.5" />
                            Verify connection
                          </>
                        )}
                      </Button>
                    </div>
                    {probeState.kind === 'idle' && (
                      <p className="text-xs text-muted-foreground">
                        Maestro runs a read-only test call against the IDP inside the Kali container
                        to confirm this credential resolves. The save button stays disabled until the
                        test passes.
                      </p>
                    )}
                    {probeState.kind === 'success' && (
                      <div className="rounded-md border border-emerald-500/40 bg-emerald-500/10 px-3 py-2 text-xs text-emerald-300 space-y-0.5">
                        <div className="flex items-center gap-1.5 font-medium">
                          <CheckCircle2 className="h-3.5 w-3.5" />
                          Credential verified
                        </div>
                        <div className="font-mono break-all">{probeState.result.identity}</div>
                        {probeState.result.details && (
                          <div className="text-emerald-300/80">{probeState.result.details}</div>
                        )}
                      </div>
                    )}
                    {probeState.kind === 'failure' && (
                      <div className="rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2 text-xs text-destructive space-y-0.5">
                        <div className="flex items-center gap-1.5 font-medium">
                          <XCircle className="h-3.5 w-3.5" />
                          Verification failed
                        </div>
                        <div className="whitespace-pre-wrap break-words">{probeState.result.error}</div>
                      </div>
                    )}
                  </div>
                </div>
                <DialogFooter>
                  <Button variant="outline" onClick={() => setDialogOpen(false)}>
                    Cancel
                  </Button>
                  <Button
                    onClick={handleSubmit}
                    disabled={probeState.kind !== 'success' || saving}
                    title={
                      probeState.kind === 'success'
                        ? undefined
                        : 'Run "Verify connection" first — credentials must pass the probe before saving.'
                    }
                  >
                    {editingId ? 'Save Changes' : 'Add Target'}
                  </Button>
                </DialogFooter>
              </DialogContent>
            </Dialog>
          </div>
        </CardHeader>
        <CardContent>
          {targets.length === 0 ? (
            <div className="text-center py-8 text-muted-foreground">
              <Fingerprint className="h-12 w-12 mx-auto mb-3 opacity-30" />
              <p className="font-medium">No identity targets configured</p>
              <p className="text-sm mt-1">
                Add an IDP (Entra, M365, Okta, Google Workspace, Ping, AD) to enable identity red team testing
              </p>
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>ID</TableHead>
                  <TableHead>Provider</TableHead>
                  <TableHead>Tenant / Org</TableHead>
                  <TableHead>Auth</TableHead>
                  <TableHead>Exclusions</TableHead>
                  <TableHead className="w-10"></TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {targets.map((target) => (
                  <TableRow key={target.id}>
                    <TableCell className="font-mono text-sm">{target.id}</TableCell>
                    <TableCell>
                      <Badge className={`${kindColors[target.kind]} text-white`}>
                        {kindLabels[target.kind]}
                      </Badge>
                    </TableCell>
                    <TableCell className="font-mono text-sm">
                      {target.tenant_id || target.domain || target.base_url || '-'}
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline">{target.auth_method}</Badge>
                    </TableCell>
                    <TableCell>
                      <span className="text-sm text-muted-foreground">
                        {target.exclusions.length > 0
                          ? `${target.exclusions.length} protected`
                          : 'None'}
                      </span>
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center justify-end gap-1">
                        <Button
                          variant="ghost"
                          size="icon"
                          title="Edit target"
                          onClick={() => openEdit(target)}
                        >
                          <Pencil className="h-4 w-4 text-muted-foreground" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon"
                          title="Verify connection"
                          onClick={() => handleVerifyRow(target)}
                          disabled={verifyingId === target.id}
                        >
                          {verifyingId === target.id ? (
                            <Loader2 className="h-4 w-4 animate-spin" />
                          ) : (
                            <PlugZap className="h-4 w-4 text-muted-foreground" />
                          )}
                        </Button>
                        <AlertDialog>
                          <AlertDialogTrigger asChild>
                            <Button variant="ghost" size="icon" aria-label={`Remove target ${target.id}`}>
                              <Trash2 className="h-4 w-4 text-red-500" />
                            </Button>
                          </AlertDialogTrigger>
                          <AlertDialogContent>
                            <AlertDialogHeader>
                              <AlertDialogTitle>Remove target &quot;{target.id}&quot;?</AlertDialogTitle>
                              <AlertDialogDescription>
                                This removes the {kindLabels[target.kind]} target from the assessment scope. This takes effect immediately.
                              </AlertDialogDescription>
                            </AlertDialogHeader>
                            <AlertDialogFooter>
                              <AlertDialogCancel>Cancel</AlertDialogCancel>
                              <AlertDialogAction onClick={() => handleDeleteTarget(target.id)}>Remove</AlertDialogAction>
                            </AlertDialogFooter>
                          </AlertDialogContent>
                        </AlertDialog>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {/* Save Button */}
      <div className="flex justify-end">
        <Button onClick={handleSaveScope} disabled={saving || loading}>
          <Save className="h-4 w-4 mr-2" />
          {saving ? 'Saving…' : 'Save Configuration'}
        </Button>
      </div>
    </div>
  );
}
