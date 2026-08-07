'use client';

import { useState, useEffect, useRef } from 'react';
import { useRouter } from 'next/navigation';
import { api } from '@/lib/tauri-api';
import type {
  AwsSourceCredentialsBlob,
  AwsSourceEntry,
  AwsSourcesLibrary,
  CloudAccountValidationResult,
} from '@/lib/tauri-api';
import type { CloudAccountScope, K8sClusterScope, ScopeConfig } from '@/lib/types';
import { SetupCredentialsWizard } from '@/components/cloud-accounts/setup-credentials-wizard';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import { Switch } from '@/components/ui/switch';
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
  Cloud,
  Server,
  Shield,
  AlertTriangle,
  Save,
  Key,
  Container,
  CheckCircle2,
  XCircle,
  Loader2,
  Pencil,
  PlugZap,
} from 'lucide-react';
import { toast } from 'sonner';

// Use the canonical scope types so round-trips preserve fields the UI
// doesn't render (role_arn, client_secret, service_account_key, etc.)
type CloudAccount = CloudAccountScope;
type K8sCluster = K8sClusterScope;

/**
 * Reasonable default auth method per provider — picked up the moment the
 * user changes the provider dropdown so the conditional field block has
 * something valid to render against (no flicker of a stale method).
 */
const DEFAULT_AUTH_METHOD: Record<'aws' | 'azure' | 'gcp', string> = {
  aws: 'profile',
  azure: 'cli',
  gcp: 'adc',
};

const providerColors: Record<string, string> = {
  aws: 'bg-orange-500',
  azure: 'bg-blue-500',
  gcp: 'bg-red-500',
};

const providerLabels: Record<string, string> = {
  aws: 'AWS',
  azure: 'Azure',
  gcp: 'GCP',
};

export default function CloudAccountsPage() {
  const router = useRouter();
  const [accounts, setAccounts] = useState<CloudAccount[]>([]);
  const [clusters, setClusters] = useState<K8sCluster[]>([]);
  const [accountDialogOpen, setAccountDialogOpen] = useState(false);
  // Non-null while editing an existing account (its id). Drives the
  // dialog title/button copy and makes the submit replace-in-place rather
  // than append.
  const [editingId, setEditingId] = useState<string | null>(null);
  const [clusterDialogOpen, setClusterDialogOpen] = useState(false);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  // Hold the full scope so save round-trips networks/domains/exclusions
  // along with the cloud changes — without this, save would drop them.
  const [scope, setScope] = useState<ScopeConfig | null>(null);

  // Load scope on mount, populate accounts + clusters from it.
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const config = await api.config.scope.get();
        if (cancelled) return;
        setScope(config);
        setAccounts(config.cloud_accounts ?? []);
        setClusters(config.kubernetes ?? []);
      } catch (err) {
        if (cancelled) return;
        console.error('[cloud-accounts] failed to load scope', err);
        toast.error('Failed to load cloud accounts');
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  // New account form. `regions` and `services_in_scope` are intentionally [] —
  // an assessment's scope is the cloud account you pick plus the read-only role
  // it assumes, NOT a hardcoded region. Regions/services are chosen (and default
  // to "All") per-assessment in the New Assessment wizard; a live credential
  // probe derives what the credential actually grants. (Regions used to default
  // to a hardcoded ['us-east-1'], which mis-scoped any deployment in another
  // region and triggered a spurious "outside configured regions" warning.)
  const [newAccount, setNewAccount] = useState<Partial<CloudAccount>>({
    provider: 'aws',
    regions: [],
    auth_method: 'profile',
    services_in_scope: [],
    exclusions: [],
    notes: '',
  });

  // New cluster form
  const [newCluster, setNewCluster] = useState<Partial<K8sCluster>>({
    provider: '',
    auth_method: 'kubeconfig',
    namespaces_in_scope: [],
    namespaces_excluded: ['kube-system', 'kube-public'],
    notes: '',
  });

  // Credential-probe state for the Add Cloud Account flow. Gates the
  // Add Account submit on a successful verify. Auto-resets to 'idle'
  // whenever a credential-affecting field changes — see the useEffect
  // below — so a stale 'success' can't let a different credential slip
  // through the form.
  type ProbeState =
    | { kind: 'idle' }
    | { kind: 'checking' }
    | { kind: 'success'; result: CloudAccountValidationResult }
    | { kind: 'failure'; result: CloudAccountValidationResult };
  const [probeState, setProbeState] = useState<ProbeState>({ kind: 'idle' });
  // Monotonic request id — increments on every probe-invalidating event
  // (verify click, credential edit). The async probe handler captures
  // the id at call time and bails on return if the counter has moved
  // on, so a fast-typing user can't get a late response from an old
  // probe overwriting a fresh state.
  const probeRequestId = useRef(0);

  // Auto-reset probe state whenever any credential-affecting field
  // changes. Includes provider/auth_method (which switch the entire
  // field block) plus every per-method credential field. Identifier
  // metadata (account_id, project_id, notes) is intentionally NOT here
  // — those don't change what the probe is testing.
  useEffect(() => {
    probeRequestId.current += 1;
    setProbeState((s) => (s.kind === 'idle' ? s : { kind: 'idle' }));
  }, [
    newAccount.provider,
    newAccount.auth_method,
    newAccount.subscription_id,
    newAccount.aws_profile,
    newAccount.access_key_id,
    newAccount.secret_access_key,
    newAccount.role_arn,
    newAccount.external_id,
    newAccount.tenant_id,
    newAccount.client_id,
    newAccount.client_secret,
    newAccount.service_account_key,
  ]);

  // Per-row connection verify for already-saved accounts. Runs the same
  // credential probe the Add dialog uses, but against a persisted account
  // so accounts like Groovy-Prod aren't stranded with no way to (re)check
  // they resolve. Tracks the in-flight account id for the spinner.
  const [verifyingId, setVerifyingId] = useState<string | null>(null);

  // In-app SSO re-auth popup. Set when a verify/probe returns
  // needs_reauth (SSO session expired, silent refresh impossible). Runs
  // the device-code wizard, updates the source's token in place, then
  // re-runs whatever triggered it.
  const [reauth, setReauth] = useState<{ id: string; name: string; retry: () => void } | null>(
    null,
  );

  const triggerReauth = async (retry: () => void) => {
    try {
      const lib = await api.config.scope.listAwsSources();
      const def = lib.sources.find((s) => s.id === lib.default_id) ?? lib.sources[0];
      if (!def) {
        toast.error('No source credential to re-authenticate. Add one first.');
        return;
      }
      setReauth({ id: def.id, name: def.name, retry });
    } catch (e) {
      toast.error(`Could not start re-auth: ${e instanceof Error ? e.message : String(e)}`);
    }
  };

  const handleVerifyRow = async (account: CloudAccount) => {
    setVerifyingId(account.id);
    try {
      const result = await api.config.scope.validateAccountCredential(account);
      if (result.ok) {
        toast.success(`Connected: ${result.identity}`, {
          description: result.details || undefined,
        });
      } else if (result.needs_reauth) {
        // SSO session expired beyond silent refresh — pop in-app sign-in,
        // then re-verify this same account.
        await triggerReauth(() => handleVerifyRow(account));
      } else {
        // The "no source identity to assume FROM" case has a dedicated,
        // actionable message pointing at the Source Credentials card —
        // everything else is a real error in the account config.
        const missingSource = /Unable to locate credentials|aws configure|no credentials/i.test(
          result.error,
        );
        toast.error(
          missingSource
            ? 'No source credentials. Set up "Source Credentials" above, then retry.'
            : `Verification failed: ${result.error}`,
        );
      }
    } catch (e) {
      toast.error(`Verify failed: ${e instanceof Error ? e.message : String(e)}`);
    } finally {
      setVerifyingId(null);
    }
  };

  const resetAccountForm = () => {
    setNewAccount({
      provider: 'aws',
      regions: [],
      auth_method: DEFAULT_AUTH_METHOD.aws,
      services_in_scope: [],
      exclusions: [],
      notes: '',
    });
    setProbeState({ kind: 'idle' });
    setEditingId(null);
  };

  // Open the dialog pre-filled with an existing account for editing.
  // Re-verification is still required (the probe gates submit), so a
  // changed credential can't be saved without proving it resolves.
  const openEditAccount = (account: CloudAccount) => {
    setNewAccount({ ...account });
    setEditingId(account.id);
    setProbeState({ kind: 'idle' });
    setAccountDialogOpen(true);
  };

  /**
   * Run the save-time credential probe. Sends the in-progress account
   * to the backend, which dispatches to the right cloud CLI inside the
   * Kali container. Result drives the verify card UI + the Add Account
   * button's enabled state.
   */
  const handleVerifyConnection = async () => {
    // Re-use the same field-level validator so we don't fire a probe
    // that's guaranteed to fail because the user hasn't filled in
    // every required field yet.
    const err = accountValidationError(newAccount);
    if (err) {
      toast.error(err);
      return;
    }
    // Capture the request id at call time; the useEffect on credential
    // changes increments this, so we can detect a stale return.
    const myReq = ++probeRequestId.current;
    setProbeState({ kind: 'checking' });
    try {
      // Build the same shape the backend persists. external_id,
      // services_in_scope, etc. are non-essential for the probe but
      // we send the full object so the Rust side has everything it
      // needs without an extra mapping step.
      const candidate = {
        id: newAccount.id || '',
        provider: newAccount.provider as 'aws' | 'azure' | 'gcp',
        account_id: newAccount.account_id,
        subscription_id: newAccount.subscription_id,
        tenant_id: newAccount.tenant_id,
        project_id: newAccount.project_id,
        regions: newAccount.regions || [],
        auth_method:
          newAccount.auth_method ||
          DEFAULT_AUTH_METHOD[newAccount.provider as 'aws' | 'azure' | 'gcp'],
        role_arn: newAccount.role_arn,
        external_id: newAccount.external_id,
        aws_profile: newAccount.aws_profile,
        access_key_id: newAccount.access_key_id,
        secret_access_key: newAccount.secret_access_key,
        client_id: newAccount.client_id,
        client_secret: newAccount.client_secret,
        service_account_key: newAccount.service_account_key,
        services_in_scope: [],
        exclusions: newAccount.exclusions || [],
        notes: newAccount.notes || '',
      };
      const result = await api.config.scope.validateAccountCredential(candidate);
      // Ignore the result if a newer probe / credential edit has
      // superseded this one — protects against a slow probe returning
      // after the user typed into a credential field.
      if (myReq !== probeRequestId.current) return;
      setProbeState(
        result.ok
          ? { kind: 'success', result }
          : { kind: 'failure', result },
      );
      // Expired SSO beyond silent refresh → pop in-app sign-in, then re-probe.
      if (!result.ok && result.needs_reauth) {
        await triggerReauth(() => handleVerifyConnection());
      }
    } catch (e) {
      if (myReq !== probeRequestId.current) return;
      // Hard failure (container not running, Tauri command errored).
      // The Rust side normally catches these and returns a graceful
      // {ok: false, error: …}; this catch is the last resort.
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
   * Field-level validation per (provider, auth_method). Returns null when
   * the form is good to submit, or a user-facing string describing what's
   * missing. Keeping this in one place avoids drift between the disabled
   * state on the submit button and the error toast.
   */
  const accountValidationError = (a: Partial<CloudAccount>): string | null => {
    if (!a.id?.trim()) return 'Account ID is required';
    if (!a.provider) return 'Provider is required';
    if (a.provider === 'aws') {
      if (a.auth_method === 'profile' && !a.aws_profile?.trim()) {
        return 'AWS CLI profile name is required';
      }
      if (a.auth_method === 'access_key') {
        if (!a.access_key_id?.trim()) return 'Access Key ID is required';
        if (!a.secret_access_key?.trim()) return 'Secret Access Key is required';
      }
      if (a.auth_method === 'role' && !a.role_arn?.trim()) {
        return 'Role ARN is required';
      }
    } else if (a.provider === 'azure') {
      if (a.auth_method === 'service_principal') {
        if (!a.tenant_id?.trim()) return 'Tenant ID is required';
        if (!a.client_id?.trim()) return 'Client ID is required';
        if (!a.client_secret?.trim()) return 'Client Secret is required';
      }
    } else if (a.provider === 'gcp') {
      if (a.auth_method === 'service_account' && !a.service_account_key?.trim()) {
        return 'Service Account JSON is required';
      }
    }
    return null;
  };

  // Persist the given accounts + clusters into the full scope immediately, so an
  // add/edit/delete can't be silently lost by navigating away before the batch
  // "Save Configuration" click (matches the AI-targets editor). The Save button
  // remains as an explicit re-save. Throws on failure so callers can toast.
  const persistCloud = async (nextAccounts: typeof accounts, nextClusters: typeof clusters) => {
    const next: ScopeConfig = {
      ...(scope ?? {
        networks: [],
        domains: [],
        exclusions: [],
        cloud_accounts: [],
        kubernetes: [],
      }),
      cloud_accounts: nextAccounts,
      kubernetes: nextClusters,
    };
    const saved = await api.config.scope.update(next);
    setScope(saved);
    setAccounts(nextAccounts);
    setClusters(nextClusters);
  };

  const handleAddAccount = async () => {
    const err = accountValidationError(newAccount);
    if (err) {
      toast.error(err);
      return;
    }
    // Gate the save on a successful probe so we don't persist a
    // credential that doesn't resolve. The button's `disabled` state
    // is the primary defense; this is the safety net if the click
    // somehow lands during a state transition.
    if (probeState.kind !== 'success') {
      toast.error('Verify connection first — the credential must pass the probe before saving.');
      return;
    }
    const account: CloudAccount = {
      id: newAccount.id!,
      provider: newAccount.provider as 'aws' | 'azure' | 'gcp',
      account_id: newAccount.account_id,
      subscription_id: newAccount.subscription_id,
      tenant_id: newAccount.tenant_id,
      project_id: newAccount.project_id,
      regions: newAccount.regions || [],
      auth_method: newAccount.auth_method || DEFAULT_AUTH_METHOD[newAccount.provider as 'aws' | 'azure' | 'gcp'],
      role_arn: newAccount.role_arn,
      external_id: newAccount.external_id,
      aws_profile: newAccount.aws_profile,
      access_key_id: newAccount.access_key_id,
      secret_access_key: newAccount.secret_access_key,
      client_id: newAccount.client_id,
      client_secret: newAccount.client_secret,
      service_account_key: newAccount.service_account_key,
      // Scope discovery happens at probe time (see follow-up PR);
      // persist as empty until then so storage shape stays valid.
      services_in_scope: [],
      exclusions: newAccount.exclusions || [],
      notes: newAccount.notes || '',
    };
    const isEdit = Boolean(editingId);
    const nextAccounts = isEdit
      ? accounts.map((a) => (a.id === editingId ? account : a))
      : [...accounts, account];
    try {
      await persistCloud(nextAccounts, clusters);
    } catch (e) {
      console.error('[cloud-accounts] save failed', e);
      toast.error('Failed to save — the change was not persisted.');
      return;
    }
    toast.success(
      isEdit
        ? `Updated ${providerLabels[account.provider]} account: ${account.id}`
        : `Added ${providerLabels[account.provider]} account: ${account.id}`,
    );
    setAccountDialogOpen(false);
    resetAccountForm();
  };

  const handleDeleteAccount = async (id: string) => {
    const nextAccounts = accounts.filter((a) => a.id !== id);
    try {
      await persistCloud(nextAccounts, clusters);
    } catch (e) {
      console.error('[cloud-accounts] delete failed', e);
      toast.error('Failed to delete — the change was not persisted.');
      return;
    }
    toast.success(`Removed account: ${id}`);
  };

  const handleDeleteCluster = async (id: string) => {
    const nextClusters = clusters.filter((c) => c.id !== id);
    try {
      await persistCloud(accounts, nextClusters);
    } catch (e) {
      console.error('[cloud-accounts] delete failed', e);
      toast.error('Failed to delete — the change was not persisted.');
      return;
    }
    toast.success(`Removed K8s cluster: ${id}`);
  };

  const handleAddCluster = async () => {
    if (!newCluster.id || !newCluster.cluster) {
      toast.error('Please fill in all required fields');
      return;
    }
    const cluster: K8sCluster = {
      id: newCluster.id!,
      cluster: newCluster.cluster!,
      provider: newCluster.provider || '',
      auth_method: newCluster.auth_method || 'kubeconfig',
      kubeconfig_path: newCluster.kubeconfig_path,
      api_server: newCluster.api_server,
      token: newCluster.token,
      namespaces_in_scope: newCluster.namespaces_in_scope || [],
      namespaces_excluded: newCluster.namespaces_excluded || [],
      notes: newCluster.notes || '',
    };
    try {
      await persistCloud(accounts, [...clusters, cluster]);
    } catch (e) {
      console.error('[cloud-accounts] save failed', e);
      toast.error('Failed to save — the change was not persisted.');
      return;
    }
    setClusterDialogOpen(false);
    setNewCluster({ provider: '', auth_method: 'kubeconfig', namespaces_in_scope: [], namespaces_excluded: ['kube-system', 'kube-public'], notes: '' });
    toast.success(`Added K8s cluster: ${cluster.id}`);
  };

  const handleSave = async () => {
    setSaving(true);
    try {
      // Merge cloud changes into the full scope so save preserves
      // networks/domains/exclusions/apps that this page doesn't manage.
      const next: ScopeConfig = {
        ...(scope ?? {
          networks: [],
          domains: [],
          exclusions: [],
          cloud_accounts: [],
          kubernetes: [],
        }),
        cloud_accounts: accounts,
        kubernetes: clusters,
      };
      const saved = await api.config.scope.update(next);
      setScope(saved);
      toast.success('Cloud accounts configuration saved');
    } catch (err) {
      console.error('[cloud-accounts] save failed', err);
      toast.error('Failed to save cloud accounts');
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center gap-4">
        <Button variant="ghost" size="icon" onClick={() => router.push('/config')}>
          <ArrowLeft className="h-5 w-5" />
        </Button>
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Cloud Accounts</h1>
          <p className="text-sm text-muted-foreground">
            Configure AWS, Azure, and GCP accounts for cloud red team testing
          </p>
        </div>
      </div>

      {/* Info Banner */}
      <Card className="border-blue-500/30 bg-blue-500/5">
        <CardContent className="py-4">
          <div className="flex items-start gap-3">
            <Shield className="h-5 w-5 text-blue-500 flex-shrink-0 mt-0.5" />
            <div className="text-sm">
              <p className="font-medium text-blue-400">Cloud Red Team Testing</p>
              <p className="text-muted-foreground mt-1">
                Configure cloud accounts and Kubernetes clusters authorized for security testing.
                Maestro will enumerate resources, analyze IAM policies, test for privilege escalation,
                and attempt exploitation — all non-destructive. Each account is scoped to specific
                regions and services.
              </p>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Source credentials — the identity Maestro assumes target roles FROM */}
      <SourceCredentialsCard />

      {/* Cloud Accounts */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <Cloud className="h-5 w-5 text-primary" />
              <div>
                <CardTitle>Cloud Accounts</CardTitle>
                <CardDescription>AWS, Azure, and GCP accounts in scope</CardDescription>
              </div>
            </div>
            <Dialog
              open={accountDialogOpen}
              onOpenChange={(o) => {
                setAccountDialogOpen(o);
                if (!o) resetAccountForm();
              }}
            >
              <DialogTrigger asChild>
                <Button size="sm" onClick={() => resetAccountForm()}>
                  <Plus className="h-4 w-4 mr-2" />
                  Add Account
                </Button>
              </DialogTrigger>
              <DialogContent className="max-w-lg">
                <DialogHeader>
                  <DialogTitle>{editingId ? 'Edit Cloud Account' : 'Add Cloud Account'}</DialogTitle>
                  <DialogDescription>
                    {editingId
                      ? 'Update this account, then re-verify the connection before saving.'
                      : 'Add a cloud account authorized for testing'}
                  </DialogDescription>
                </DialogHeader>
                <div className="space-y-4">
                  <div className="space-y-2">
                    <Label>Provider</Label>
                    <Select
                      value={newAccount.provider}
                      onValueChange={(v) => {
                        const provider = v as 'aws' | 'azure' | 'gcp';
                        // Changing provider invalidates every auth-specific
                        // field: clear them all so a stale AWS access key
                        // doesn't ride along into an Azure config. Pick the
                        // provider's default auth method so the conditional
                        // block always has a sensible target.
                        setNewAccount({
                          ...newAccount,
                          provider,
                          auth_method: DEFAULT_AUTH_METHOD[provider],
                          role_arn: undefined,
                          external_id: undefined,
                          aws_profile: undefined,
                          access_key_id: undefined,
                          secret_access_key: undefined,
                          tenant_id: undefined,
                          client_id: undefined,
                          client_secret: undefined,
                          service_account_key: undefined,
                        });
                      }}
                    >
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="aws">Amazon Web Services (AWS)</SelectItem>
                        <SelectItem value="azure">Microsoft Azure</SelectItem>
                        <SelectItem value="gcp">Google Cloud Platform (GCP)</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="space-y-2">
                    <Label>Account ID (unique identifier for this account)</Label>
                    <Input
                      value={newAccount.id || ''}
                      onChange={(e) => setNewAccount({ ...newAccount, id: e.target.value })}
                      placeholder="e.g., aws-staging, azure-dev"
                    />
                  </div>
                  {newAccount.provider === 'aws' && (
                    <div className="space-y-2">
                      <Label>AWS Account Number</Label>
                      <Input
                        value={newAccount.account_id || ''}
                        onChange={(e) => setNewAccount({ ...newAccount, account_id: e.target.value })}
                        placeholder="123456789012"
                      />
                    </div>
                  )}
                  {newAccount.provider === 'azure' && (
                    <div className="space-y-2">
                      <Label>Subscription ID</Label>
                      <Input
                        value={newAccount.subscription_id || ''}
                        onChange={(e) => setNewAccount({ ...newAccount, subscription_id: e.target.value })}
                        placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
                      />
                    </div>
                  )}
                  {newAccount.provider === 'gcp' && (
                    <div className="space-y-2">
                      <Label>Project ID</Label>
                      <Input
                        value={newAccount.project_id || ''}
                        onChange={(e) => setNewAccount({ ...newAccount, project_id: e.target.value })}
                        placeholder="my-project-staging"
                      />
                    </div>
                  )}
                  <div className="space-y-2">
                    <Label>Authentication Method</Label>
                    <Select
                      value={newAccount.auth_method}
                      onValueChange={(v) =>
                        // Switching auth method drops every per-method
                        // field — leaving a stale role_arn around when
                        // the user moves to "profile" would silently
                        // ride into storage.
                        setNewAccount({
                          ...newAccount,
                          auth_method: v,
                          role_arn: undefined,
                          external_id: undefined,
                          aws_profile: undefined,
                          access_key_id: undefined,
                          secret_access_key: undefined,
                          tenant_id: undefined,
                          client_id: undefined,
                          client_secret: undefined,
                          service_account_key: undefined,
                        })
                      }
                    >
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        {newAccount.provider === 'aws' && (
                          <>
                            <SelectItem value="profile">AWS CLI Profile</SelectItem>
                            <SelectItem value="access_key">Access Key (Key ID + Secret)</SelectItem>
                            <SelectItem value="role">Assume Role (IAM Role ARN)</SelectItem>
                          </>
                        )}
                        {newAccount.provider === 'azure' && (
                          <>
                            <SelectItem value="cli">Azure CLI (az login)</SelectItem>
                            <SelectItem value="service_principal">Service Principal</SelectItem>
                            <SelectItem value="managed_identity">Managed Identity</SelectItem>
                          </>
                        )}
                        {newAccount.provider === 'gcp' && (
                          <>
                            <SelectItem value="adc">Application Default Credentials</SelectItem>
                            <SelectItem value="service_account">Service Account Key</SelectItem>
                          </>
                        )}
                      </SelectContent>
                    </Select>
                  </div>

                  {/* Auth-method-specific credential fields. Each block
                      only renders when its (provider, auth_method) pair
                      is active; switching provider or method clears the
                      underlying state above so nothing stale ships. */}
                  {newAccount.provider === 'aws' && newAccount.auth_method === 'profile' && (
                    <div className="space-y-2">
                      <Label>AWS Profile Name</Label>
                      <Input
                        value={newAccount.aws_profile || ''}
                        onChange={(e) => setNewAccount({ ...newAccount, aws_profile: e.target.value })}
                        placeholder="default"
                      />
                      <p className="text-xs text-muted-foreground">
                        Name of a profile from <code>~/.aws/credentials</code>. Maestro will set <code>AWS_PROFILE</code> when running tools.
                      </p>
                    </div>
                  )}
                  {newAccount.provider === 'aws' && newAccount.auth_method === 'access_key' && (
                    <>
                      <div className="space-y-2">
                        <Label>Access Key ID</Label>
                        <Input
                          value={newAccount.access_key_id || ''}
                          onChange={(e) => setNewAccount({ ...newAccount, access_key_id: e.target.value })}
                          placeholder="AKIAIOSFODNN7EXAMPLE"
                          autoComplete="off"
                        />
                      </div>
                      <div className="space-y-2">
                        <Label>Secret Access Key</Label>
                        <Input
                          type="password"
                          value={newAccount.secret_access_key || ''}
                          onChange={(e) => setNewAccount({ ...newAccount, secret_access_key: e.target.value })}
                          placeholder="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
                          autoComplete="off"
                        />
                      </div>
                    </>
                  )}
                  {newAccount.provider === 'aws' && newAccount.auth_method === 'role' && (
                    <>
                      <div className="space-y-2">
                        <Label>Role ARN</Label>
                        <Input
                          value={newAccount.role_arn || ''}
                          onChange={(e) => setNewAccount({ ...newAccount, role_arn: e.target.value })}
                          placeholder="arn:aws:iam::123456789012:role/SecurityAudit"
                        />
                      </div>
                      <div className="space-y-2">
                        <Label>External ID (optional)</Label>
                        <Input
                          value={newAccount.external_id || ''}
                          onChange={(e) => setNewAccount({ ...newAccount, external_id: e.target.value })}
                          placeholder="shared secret expected by the role's trust policy"
                        />
                      </div>
                    </>
                  )}
                  {newAccount.provider === 'azure' && newAccount.auth_method === 'service_principal' && (
                    <>
                      <div className="space-y-2">
                        <Label>Tenant ID</Label>
                        <Input
                          value={newAccount.tenant_id || ''}
                          onChange={(e) => setNewAccount({ ...newAccount, tenant_id: e.target.value })}
                          placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
                        />
                      </div>
                      <div className="space-y-2">
                        <Label>Client ID (App Registration)</Label>
                        <Input
                          value={newAccount.client_id || ''}
                          onChange={(e) => setNewAccount({ ...newAccount, client_id: e.target.value })}
                          placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
                          autoComplete="off"
                        />
                      </div>
                      <div className="space-y-2">
                        <Label>Client Secret</Label>
                        <Input
                          type="password"
                          value={newAccount.client_secret || ''}
                          onChange={(e) => setNewAccount({ ...newAccount, client_secret: e.target.value })}
                          autoComplete="off"
                        />
                      </div>
                    </>
                  )}
                  {newAccount.provider === 'azure' && newAccount.auth_method === 'managed_identity' && (
                    <p className="text-xs text-muted-foreground">
                      Managed Identity uses the VM/App Service&apos;s assigned identity — no credentials needed here.
                    </p>
                  )}
                  {newAccount.provider === 'azure' && newAccount.auth_method === 'cli' && (
                    <p className="text-xs text-muted-foreground">
                      Uses your <code>az login</code> session. Run <code>az login</code> in the Kali container before launching an assessment.
                    </p>
                  )}
                  {newAccount.provider === 'gcp' && newAccount.auth_method === 'service_account' && (
                    <div className="space-y-2">
                      <Label>Service Account JSON</Label>
                      <textarea
                        rows={6}
                        value={newAccount.service_account_key || ''}
                        onChange={(e) => setNewAccount({ ...newAccount, service_account_key: e.target.value })}
                        placeholder={'{\n  "type": "service_account",\n  "project_id": "...",\n  ...\n}'}
                        className="flex w-full rounded-md border border-input bg-background px-3 py-2 text-sm font-mono ring-offset-background placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2"
                        autoComplete="off"
                        spellCheck={false}
                      />
                      <p className="text-xs text-muted-foreground">
                        Paste the full contents of the service-account key JSON file.
                      </p>
                    </div>
                  )}
                  {newAccount.provider === 'gcp' && newAccount.auth_method === 'adc' && (
                    <p className="text-xs text-muted-foreground">
                      Uses Application Default Credentials. Run <code>gcloud auth application-default login</code> in the Kali container before launching an assessment.
                    </p>
                  )}

                  <div className="space-y-2">
                    <Label>Notes</Label>
                    <Input
                      value={newAccount.notes || ''}
                      onChange={(e) => setNewAccount({ ...newAccount, notes: e.target.value })}
                      placeholder="e.g., Staging environment — authorized for full red team"
                    />
                  </div>

                  {/* Verify connection — runs a save-time credential
                      probe via the Kali container. The state machine
                      lives in `probeState`; UI shows the resolved
                      identity on success, the trimmed CLI error on
                      failure. Saving the account is gated below on
                      probeState.kind === 'success'. */}
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
                        Maestro will run a read-only test call (e.g. <code>sts:GetCallerIdentity</code> for AWS) inside the Kali container to confirm this credential resolves. The Add Account button stays disabled until the test passes.
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
                    {probeState.kind === 'failure' && (() => {
                      // Detect the specific failure mode where the probe
                      // succeeded mechanically but couldn't find any AWS
                      // credentials to assume FROM. That's the wizard's
                      // moment — anything else is a real error the user
                      // needs to fix in the form.
                      const isAwsRole =
                        newAccount.provider === 'aws' && newAccount.auth_method === 'role';
                      const looksLikeMissingCreds = /Unable to locate credentials|aws configure|no credentials/i.test(
                        probeState.result.error,
                      );
                      if (isAwsRole && looksLikeMissingCreds) {
                        return (
                          <SetupCredentialsWizard
                            targetRoleArn={newAccount.role_arn || ''}
                            onCompleted={() => {
                              // Re-fire the probe — the wizard wrote
                              // source credentials to the keyring, so
                              // the next AssumeRole exec should now
                              // succeed and flip us into the green card.
                              handleVerifyConnection();
                            }}
                            onCancel={() => setProbeState({ kind: 'idle' })}
                          />
                        );
                      }
                      return (
                        <div className="rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2 text-xs text-destructive space-y-0.5">
                          <div className="flex items-center gap-1.5 font-medium">
                            <XCircle className="h-3.5 w-3.5" />
                            Verification failed
                          </div>
                          <div className="whitespace-pre-wrap break-words">{probeState.result.error}</div>
                        </div>
                      );
                    })()}
                  </div>
                </div>
                <DialogFooter>
                  <Button variant="outline" onClick={() => setAccountDialogOpen(false)}>Cancel</Button>
                  <Button
                    onClick={handleAddAccount}
                    disabled={probeState.kind !== 'success'}
                    title={
                      probeState.kind === 'success'
                        ? undefined
                        : 'Run "Verify connection" first — credentials must pass the probe before saving.'
                    }
                  >
                    {editingId ? 'Save Changes' : 'Add Account'}
                  </Button>
                </DialogFooter>
              </DialogContent>
            </Dialog>
          </div>
        </CardHeader>
        <CardContent>
          {accounts.length === 0 ? (
            <div className="text-center py-8 text-muted-foreground">
              <Cloud className="h-12 w-12 mx-auto mb-3 opacity-30" />
              <p className="font-medium">No cloud accounts configured</p>
              <p className="text-sm mt-1">Add AWS, Azure, or GCP accounts to enable cloud security testing</p>
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>ID</TableHead>
                  <TableHead>Provider</TableHead>
                  <TableHead>Account</TableHead>
                  <TableHead>Auth</TableHead>
                  <TableHead>Scope</TableHead>
                  <TableHead className="w-10"></TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {accounts.map((account) => (
                  <TableRow key={account.id}>
                    <TableCell className="font-mono text-sm">{account.id}</TableCell>
                    <TableCell>
                      <Badge className={`${providerColors[account.provider]} text-white`}>
                        {providerLabels[account.provider]}
                      </Badge>
                    </TableCell>
                    <TableCell className="font-mono text-sm">
                      {account.account_id || account.subscription_id || account.project_id || '-'}
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline">{account.auth_method}</Badge>
                    </TableCell>
                    <TableCell>
                      <span className="text-sm text-muted-foreground">
                        {account.services_in_scope.length > 0
                          ? `${account.services_in_scope.length} services`
                          : 'Auto-discover'}
                      </span>
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center justify-end gap-1">
                        <Button
                          variant="ghost"
                          size="icon"
                          title="Edit account"
                          onClick={() => openEditAccount(account)}
                        >
                          <Pencil className="h-4 w-4 text-muted-foreground" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon"
                          title="Verify connection"
                          onClick={() => handleVerifyRow(account)}
                          disabled={verifyingId === account.id}
                        >
                          {verifyingId === account.id ? (
                            <Loader2 className="h-4 w-4 animate-spin" />
                          ) : (
                            <PlugZap className="h-4 w-4 text-muted-foreground" />
                          )}
                        </Button>
                        <AlertDialog>
                          <AlertDialogTrigger asChild>
                            <Button variant="ghost" size="icon" aria-label={`Remove account ${account.id}`}>
                              <Trash2 className="h-4 w-4 text-red-500" />
                            </Button>
                          </AlertDialogTrigger>
                          <AlertDialogContent>
                            <AlertDialogHeader>
                              <AlertDialogTitle>Remove account &quot;{account.id}&quot;?</AlertDialogTitle>
                              <AlertDialogDescription>
                                This removes the {providerLabels[account.provider]} account from the assessment scope. This takes effect immediately.
                              </AlertDialogDescription>
                            </AlertDialogHeader>
                            <AlertDialogFooter>
                              <AlertDialogCancel>Cancel</AlertDialogCancel>
                              <AlertDialogAction onClick={() => handleDeleteAccount(account.id)}>Remove</AlertDialogAction>
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

      {/* Kubernetes Clusters */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <Container className="h-5 w-5 text-blue-500" />
              <div>
                <CardTitle>Kubernetes Clusters</CardTitle>
                <CardDescription>K8s clusters in scope for red team testing</CardDescription>
              </div>
            </div>
            <Dialog open={clusterDialogOpen} onOpenChange={setClusterDialogOpen}>
              <DialogTrigger asChild>
                <Button size="sm" variant="outline">
                  <Plus className="h-4 w-4 mr-2" />
                  Add Cluster
                </Button>
              </DialogTrigger>
              <DialogContent>
                <DialogHeader>
                  <DialogTitle>Add Kubernetes Cluster</DialogTitle>
                  <DialogDescription>Add a K8s cluster authorized for testing</DialogDescription>
                </DialogHeader>
                <div className="space-y-4">
                  <div className="space-y-2">
                    <Label>Cluster ID (unique)</Label>
                    <Input
                      value={newCluster.id || ''}
                      onChange={(e) => setNewCluster({ ...newCluster, id: e.target.value })}
                      placeholder="e.g., eks-staging"
                    />
                  </div>
                  <div className="space-y-2">
                    <Label>Cluster Name</Label>
                    <Input
                      value={newCluster.cluster || ''}
                      onChange={(e) => setNewCluster({ ...newCluster, cluster: e.target.value })}
                      placeholder="e.g., staging-cluster"
                    />
                  </div>
                  <div className="space-y-2">
                    <Label>Cloud Provider (optional)</Label>
                    <Select
                      value={newCluster.provider || ''}
                      onValueChange={(v) => setNewCluster({ ...newCluster, provider: v })}
                    >
                      <SelectTrigger>
                        <SelectValue placeholder="Select provider" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="aws">AWS (EKS)</SelectItem>
                        <SelectItem value="azure">Azure (AKS)</SelectItem>
                        <SelectItem value="gcp">GCP (GKE)</SelectItem>
                        <SelectItem value="on-prem">On-Premise</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="space-y-2">
                    <Label>Authentication Method</Label>
                    <Select
                      value={newCluster.auth_method || 'kubeconfig'}
                      onValueChange={(v) =>
                        // Switching method invalidates the credential
                        // fields below — clear them so a stale kubeconfig
                        // doesn't tag along into an in-cluster config.
                        setNewCluster({
                          ...newCluster,
                          auth_method: v,
                          kubeconfig_path: undefined,
                          api_server: undefined,
                          token: undefined,
                        })
                      }
                    >
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="kubeconfig">Kubeconfig file</SelectItem>
                        <SelectItem value="in_cluster">In-cluster (service account)</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  {newCluster.auth_method === 'kubeconfig' && (
                    <div className="space-y-2">
                      <Label>Kubeconfig Path</Label>
                      <Input
                        value={newCluster.kubeconfig_path || ''}
                        onChange={(e) =>
                          setNewCluster({ ...newCluster, kubeconfig_path: e.target.value })
                        }
                        placeholder="~/.kube/config"
                      />
                      <p className="text-xs text-muted-foreground">
                        Path to the kubeconfig file Maestro should load. Defaults to <code>~/.kube/config</code> if empty.
                      </p>
                    </div>
                  )}
                  {newCluster.auth_method === 'in_cluster' && (
                    <p className="text-xs text-muted-foreground">
                      Uses the pod&apos;s mounted service-account token. Only works when Maestro itself runs inside the target cluster.
                    </p>
                  )}
                  <div className="space-y-2">
                    <Label>Namespaces in Scope (comma-separated)</Label>
                    <Input
                      value={(newCluster.namespaces_in_scope || []).join(', ')}
                      onChange={(e) => setNewCluster({
                        ...newCluster,
                        namespaces_in_scope: e.target.value.split(',').map((s) => s.trim()).filter(Boolean),
                      })}
                      placeholder="app, api, backend"
                    />
                  </div>
                  <div className="space-y-2">
                    <Label>Namespaces Excluded (comma-separated)</Label>
                    <Input
                      value={(newCluster.namespaces_excluded || []).join(', ')}
                      onChange={(e) => setNewCluster({
                        ...newCluster,
                        namespaces_excluded: e.target.value.split(',').map((s) => s.trim()).filter(Boolean),
                      })}
                      placeholder="kube-system, kube-public"
                    />
                  </div>
                </div>
                <DialogFooter>
                  <Button variant="outline" onClick={() => setClusterDialogOpen(false)}>Cancel</Button>
                  <Button onClick={handleAddCluster}>Add Cluster</Button>
                </DialogFooter>
              </DialogContent>
            </Dialog>
          </div>
        </CardHeader>
        <CardContent>
          {clusters.length === 0 ? (
            <div className="text-center py-8 text-muted-foreground">
              <Container className="h-12 w-12 mx-auto mb-3 opacity-30" />
              <p className="font-medium">No Kubernetes clusters configured</p>
              <p className="text-sm mt-1">Add clusters to enable K8s RBAC, secrets, and escape testing</p>
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>ID</TableHead>
                  <TableHead>Cluster</TableHead>
                  <TableHead>Provider</TableHead>
                  <TableHead>Namespaces</TableHead>
                  <TableHead className="w-10"></TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {clusters.map((cluster) => (
                  <TableRow key={cluster.id}>
                    <TableCell className="font-mono text-sm">{cluster.id}</TableCell>
                    <TableCell>{cluster.cluster}</TableCell>
                    <TableCell>
                      {cluster.provider ? (
                        <Badge variant="outline">{cluster.provider.toUpperCase()}</Badge>
                      ) : (
                        <span className="text-muted-foreground">-</span>
                      )}
                    </TableCell>
                    <TableCell>
                      <span className="text-sm text-muted-foreground">
                        {cluster.namespaces_in_scope.length} in scope
                      </span>
                    </TableCell>
                    <TableCell>
                      <AlertDialog>
                        <AlertDialogTrigger asChild>
                          <Button variant="ghost" size="icon" aria-label={`Remove cluster ${cluster.id}`}>
                            <Trash2 className="h-4 w-4 text-red-500" />
                          </Button>
                        </AlertDialogTrigger>
                        <AlertDialogContent>
                          <AlertDialogHeader>
                            <AlertDialogTitle>Remove cluster &quot;{cluster.id}&quot;?</AlertDialogTitle>
                            <AlertDialogDescription>
                              This removes the Kubernetes cluster from the assessment scope. This takes effect immediately.
                            </AlertDialogDescription>
                          </AlertDialogHeader>
                          <AlertDialogFooter>
                            <AlertDialogCancel>Cancel</AlertDialogCancel>
                            <AlertDialogAction onClick={() => handleDeleteCluster(cluster.id)}>Remove</AlertDialogAction>
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

      {/* Save Button */}
      <div className="flex justify-end">
        <Button onClick={handleSave} disabled={saving || loading}>
          <Save className="h-4 w-4 mr-2" />
          {saving ? 'Saving…' : 'Save Configuration'}
        </Button>
      </div>

      {/* In-app SSO re-auth popup (fires when a verify needs sign-in) */}
      <Dialog open={!!reauth} onOpenChange={(o) => (o ? undefined : setReauth(null))}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle>Re-authenticate AWS SSO</DialogTitle>
            <DialogDescription>
              Your AWS SSO session for{' '}
              <span className="font-mono">{reauth?.name}</span> expired and couldn&apos;t be
              refreshed. Sign in again — the new token is saved in place and the connection retries
              automatically.
            </DialogDescription>
          </DialogHeader>
          {reauth && (
            <SetupCredentialsWizard
              targetRoleArn=""
              persist={async (blob) => {
                await api.config.scope.updateAwsSource(reauth.id, reauth.name, blob);
              }}
              onCompleted={() => {
                const retry = reauth.retry;
                setReauth(null);
                toast.success('Re-authenticated');
                retry();
              }}
              onCancel={() => setReauth(null)}
            />
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}

/**
 * Source-credentials library. The AWS identities Maestro assumes target
 * roles FROM. A deployment can hold several (different targets assumed
 * from different identities) and mark one default; the new-assessment
 * wizard pre-selects the default and lets the user override per run.
 *
 * Backed by the `aws_sources` keyring blob via the list/add/delete/
 * set-default helpers on api.config.scope. A legacy single `aws_source`
 * blob is migrated into the library on first load.
 */
function describeSource(s: AwsSourceEntry): {
  method: string;
  identity: string;
  sub: string;
  expired: boolean;
} {
  if (s.kind === 'sso') {
    const expired = s.sso.expires_at * 1000 <= Date.now();
    const when = new Date(s.sso.expires_at * 1000).toLocaleString();
    return {
      method: 'AWS SSO',
      identity: `${s.sso.source_account_id} / ${s.sso.source_role_name}`,
      sub: expired ? `Session expired ${when} — re-authenticate` : `Valid until ${when}`,
      expired,
    };
  }
  if (s.kind === 'access_keys') {
    return {
      method: 'Access keys',
      identity: s.access_keys.access_key_id,
      sub: 'Long-term IAM user keys (cached in your OS keychain)',
      expired: false,
    };
  }
  return {
    method: 'CLI profile',
    identity: s.profile.name,
    sub: 'Resolved from ~/.aws at assume time',
    expired: false,
  };
}

function SourceCredentialsCard() {
  const [lib, setLib] = useState<AwsSourcesLibrary>({ default_id: null, sources: [] });
  const [loading, setLoading] = useState(true);
  const [addOpen, setAddOpen] = useState(false);
  const [newName, setNewName] = useState('');
  const [busyId, setBusyId] = useState<string | null>(null);

  const reload = async () => {
    setLoading(true);
    try {
      setLib(await api.config.scope.listAwsSources());
    } catch (e) {
      console.error('[source-creds] load failed', e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void reload();
  }, []);

  const handleSetDefault = async (id: string) => {
    setBusyId(id);
    try {
      await api.config.scope.setDefaultAwsSource(id);
      await reload();
      toast.success('Default source updated');
    } catch (e) {
      toast.error(`Failed: ${e instanceof Error ? e.message : String(e)}`);
    } finally {
      setBusyId(null);
    }
  };

  const handleDelete = async (id: string) => {
    setBusyId(id);
    try {
      await api.config.scope.deleteAwsSource(id);
      await reload();
      toast.success('Source removed');
    } catch (e) {
      toast.error(`Failed: ${e instanceof Error ? e.message : String(e)}`);
    } finally {
      setBusyId(null);
    }
  };

  const closeAdd = () => {
    setAddOpen(false);
    setNewName('');
  };

  // Edit an existing source in place (rename + fix the underlying value).
  // SSO sessions can only be renamed here — changing the signed-in
  // identity means re-adding. Profile/access-key values are editable.
  const [editing, setEditing] = useState<AwsSourceEntry | null>(null);
  const [editName, setEditName] = useState('');
  const [editProfile, setEditProfile] = useState('');
  const [editKeyId, setEditKeyId] = useState('');
  const [editSecret, setEditSecret] = useState('');
  const [savingEdit, setSavingEdit] = useState(false);

  const openEdit = (s: AwsSourceEntry) => {
    setEditing(s);
    setEditName(s.name);
    setEditProfile(s.kind === 'profile' ? s.profile.name : '');
    setEditKeyId(s.kind === 'access_keys' ? s.access_keys.access_key_id : '');
    setEditSecret(s.kind === 'access_keys' ? s.access_keys.secret_access_key : '');
  };

  const saveEdit = async () => {
    if (!editing) return;
    setSavingEdit(true);
    try {
      let blob: AwsSourceCredentialsBlob;
      if (editing.kind === 'profile') {
        blob = { kind: 'profile', profile: { name: editProfile.trim() } };
      } else if (editing.kind === 'access_keys') {
        blob = {
          kind: 'access_keys',
          access_keys: {
            access_key_id: editKeyId.trim(),
            secret_access_key: editSecret.trim(),
          },
        };
      } else {
        blob = { kind: 'sso', sso: editing.sso };
      }
      await api.config.scope.updateAwsSource(
        editing.id,
        editName.trim() || 'Unnamed source',
        blob,
      );
      setEditing(null);
      await reload();
      toast.success('Source updated');
    } catch (e) {
      toast.error(`Failed: ${e instanceof Error ? e.message : String(e)}`);
    } finally {
      setSavingEdit(false);
    }
  };

  return (
    <Card className="border-amber-500/30 bg-amber-500/5">
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <Key className="h-5 w-5 text-amber-500" />
            <div>
              <CardTitle className="text-base">Source Credentials</CardTitle>
              <CardDescription>
                AWS identities Maestro assumes target roles <span className="font-medium">from</span>.
                Add several, mark a default, and override per assessment.
              </CardDescription>
            </div>
          </div>
          <Dialog open={addOpen} onOpenChange={(o) => (o ? setAddOpen(true) : closeAdd())}>
            <DialogTrigger asChild>
              <Button size="sm">
                <Plus className="h-4 w-4 mr-2" />
                Add source
              </Button>
            </DialogTrigger>
            <DialogContent className="max-w-lg">
              <DialogHeader>
                <DialogTitle>Add source credential</DialogTitle>
                <DialogDescription>
                  Name it, then choose how Maestro signs in before assuming a target role. Cached to
                  your OS keychain.
                </DialogDescription>
              </DialogHeader>
              <div className="space-y-4">
                <div className="space-y-2">
                  <Label>Name</Label>
                  <Input
                    placeholder="e.g. Groovy (whiteout-us SSO)"
                    value={newName}
                    onChange={(e) => setNewName(e.target.value)}
                  />
                </div>
                <SetupCredentialsWizard
                  targetRoleArn=""
                  persist={async (blob) => {
                    await api.config.scope.addAwsSource(newName.trim() || 'Unnamed source', blob);
                  }}
                  onCompleted={() => {
                    closeAdd();
                    void reload();
                  }}
                  onCancel={closeAdd}
                />
              </div>
            </DialogContent>
          </Dialog>
        </div>
      </CardHeader>
      <CardContent className="pt-0">
        {loading ? (
          <p className="text-sm text-muted-foreground">Loading…</p>
        ) : lib.sources.length === 0 ? (
          <p className="text-sm text-muted-foreground">
            No source credentials configured. Add one (SSO sign-in, access keys, or a named AWS CLI
            profile) so Maestro has an identity to assume your target roles from.
          </p>
        ) : (
          <div className="space-y-2">
            {lib.sources.map((s) => {
              const d = describeSource(s);
              const isDefault = lib.default_id === s.id;
              return (
                <div
                  key={s.id}
                  className="flex items-center justify-between gap-3 rounded-md border border-border/60 px-3 py-2"
                >
                  <div className="flex items-center gap-2 text-sm min-w-0">
                    {d.expired ? (
                      <AlertTriangle className="h-4 w-4 text-amber-500 flex-shrink-0" />
                    ) : (
                      <CheckCircle2 className="h-4 w-4 text-emerald-500 flex-shrink-0" />
                    )}
                    <div className="min-w-0">
                      <div className="font-medium flex items-center gap-2">
                        <span className="truncate">{s.name}</span>
                        {isDefault && (
                          <Badge variant="secondary" className="text-xs">
                            Default
                          </Badge>
                        )}
                      </div>
                      <div className="text-xs text-muted-foreground truncate">
                        {d.method}: <span className="font-mono">{d.identity}</span> · {d.sub}
                      </div>
                    </div>
                  </div>
                  <div className="flex items-center gap-1 flex-shrink-0">
                    {!isDefault && (
                      <Button
                        variant="ghost"
                        size="sm"
                        disabled={busyId === s.id}
                        onClick={() => handleSetDefault(s.id)}
                      >
                        Make default
                      </Button>
                    )}
                    <Button
                      variant="ghost"
                      size="icon"
                      title="Edit source"
                      onClick={() => openEdit(s)}
                    >
                      <Pencil className="h-4 w-4 text-muted-foreground" />
                    </Button>
                    <Button
                      variant="ghost"
                      size="icon"
                      title="Remove source"
                      disabled={busyId === s.id}
                      onClick={() => handleDelete(s.id)}
                      className="text-red-500 hover:text-red-500"
                    >
                      <Trash2 className="h-4 w-4" />
                    </Button>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </CardContent>

      {/* Edit source dialog */}
      <Dialog open={!!editing} onOpenChange={(o) => (o ? undefined : setEditing(null))}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle>Edit source credential</DialogTitle>
            <DialogDescription>
              {editing && editing.kind === 'sso'
                ? 'Rename this SSO source. To change the signed-in identity, remove it and add a new one.'
                : 'Update this source, then re-verify on a cloud account afterward.'}
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="space-y-2">
              <Label>Name</Label>
              <Input value={editName} onChange={(e) => setEditName(e.target.value)} />
            </div>
            {editing && editing.kind === 'profile' && (
              <div className="space-y-2">
                <Label>AWS CLI profile</Label>
                <Input
                  value={editProfile}
                  onChange={(e) => setEditProfile(e.target.value)}
                  placeholder="whiteout-us"
                />
                <p className="text-xs text-muted-foreground">
                  Case-sensitive — must exactly match a profile in your <span className="font-mono">~/.aws/config</span>.
                </p>
              </div>
            )}
            {editing && editing.kind === 'access_keys' && (
              <>
                <div className="space-y-2">
                  <Label>Access Key ID</Label>
                  <Input value={editKeyId} onChange={(e) => setEditKeyId(e.target.value)} />
                </div>
                <div className="space-y-2">
                  <Label>Secret Access Key</Label>
                  <Input
                    type="password"
                    value={editSecret}
                    onChange={(e) => setEditSecret(e.target.value)}
                  />
                </div>
              </>
            )}
            {editing && editing.kind === 'sso' && (
              <p className="text-xs text-muted-foreground">
                SSO session:{' '}
                <span className="font-mono">
                  {editing.sso.source_account_id} / {editing.sso.source_role_name}
                </span>
              </p>
            )}
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setEditing(null)}>
              Cancel
            </Button>
            <Button onClick={saveEdit} disabled={savingEdit}>
              {savingEdit ? 'Saving…' : 'Save'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </Card>
  );
}
