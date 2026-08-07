'use client';

/**
 * Project editor dialog — create OR edit a project plus its OWN scope.
 *
 * Reused by the Projects list page ("New Project") and the per-project
 * detail page ("Edit"). The scope editor mirrors the inline add/table/
 * delete pattern from /config/scope for networks/domains/repos/exclusions,
 * and adds two multi-select blocks for cloud accounts + identity targets
 * (REFERENCED by id from the org's existing config — never re-entered, so
 * no credential material lives on a project).
 */

import { useEffect, useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { api } from '@/lib/tauri-api';
import {
  EMPTY_PROJECT_SCOPE,
  type Project,
  type ProjectScope,
  type ProjectStatus,
} from '@/lib/types';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Badge } from '@/components/ui/badge';
import { Checkbox } from '@/components/ui/checkbox';
import { ScrollArea } from '@/components/ui/scroll-area';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import {
  Plus,
  Trash2,
  Network,
  Globe,
  FolderGit2,
  Cloud,
  KeyRound,
  ShieldAlert,
  Loader2,
} from 'lucide-react';

// Provider / kind label maps — mirror the config pages so the multi-selects
// read identically to /config/cloud-accounts and /config/identity-targets.
const providerLabels: Record<string, string> = {
  aws: 'AWS',
  azure: 'Azure',
  gcp: 'GCP',
};

const identityKindLabels: Record<string, string> = {
  active_directory: 'Active Directory',
  entra_id: 'Entra ID',
  m365: 'Microsoft 365',
  okta: 'Okta',
  google_workspace: 'Google Workspace',
  ping: 'Ping',
};

export interface ProjectEditorDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** Undefined → create mode. Provided → edit mode (pre-fills the form). */
  project?: Project | null;
  /** Called with the assembled name/description/status/scope on Save.
   *  Parent owns the mutation (create vs update). */
  onSubmit: (data: {
    name: string;
    description?: string;
    status: ProjectStatus;
    scope: ProjectScope;
  }) => void;
  /** True while the parent's create/update mutation is in flight. */
  isSaving?: boolean;
}

export function ProjectEditorDialog({
  open,
  onOpenChange,
  project,
  onSubmit,
  isSaving,
}: ProjectEditorDialogProps) {
  const isEdit = !!project;

  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [status, setStatus] = useState<ProjectStatus>('active');
  const [scope, setScope] = useState<ProjectScope>(EMPTY_PROJECT_SCOPE);

  // Inline-add form state for the four list sections.
  const [newNetwork, setNewNetwork] = useState({ cidr: '', environment: 'staging', notes: '' });
  const [newDomain, setNewDomain] = useState({ pattern: '', environment: 'staging' });
  const [newRepo, setNewRepo] = useState('');
  const [newExclusion, setNewExclusion] = useState({ pattern: '', reason: '' });

  // Reset the form whenever the dialog opens (or the target project changes).
  useEffect(() => {
    if (!open) return;
    setName(project?.name ?? '');
    setDescription(project?.description ?? '');
    setStatus(project?.status ?? 'active');
    setScope({
      ...EMPTY_PROJECT_SCOPE,
      ...(project?.scope ?? {}),
      networks: project?.scope?.networks ?? [],
      domains: project?.scope?.domains ?? [],
      repos: project?.scope?.repos ?? [],
      cloud_account_ids: project?.scope?.cloud_account_ids ?? [],
      identity_target_ids: project?.scope?.identity_target_ids ?? [],
      exclusions: project?.scope?.exclusions ?? [],
    });
    setNewNetwork({ cidr: '', environment: 'staging', notes: '' });
    setNewDomain({ pattern: '', environment: 'staging' });
    setNewRepo('');
    setNewExclusion({ pattern: '', reason: '' });
  }, [open, project]);

  // Org's existing cloud accounts + identity targets — referenced (not
  // re-entered) by the two multi-selects. Both come off the global scope
  // config, where each carries a stable id + a human-readable label.
  const { data: orgScope, isLoading: loadingOrgScope } = useQuery({
    queryKey: ['scope'],
    queryFn: () => api.config.scope.get(),
    enabled: open,
  });

  const cloudAccounts = useMemo(
    () => orgScope?.cloud_accounts ?? [],
    [orgScope],
  );
  const identityTargets = useMemo(
    () => orgScope?.identity_targets ?? [],
    [orgScope],
  );

  // --- list section mutators (immutable updates on scope) ---
  const addNetwork = () => {
    if (!newNetwork.cidr.trim()) return;
    setScope((s) => ({ ...s, networks: [...s.networks, { ...newNetwork }] }));
    setNewNetwork({ cidr: '', environment: 'staging', notes: '' });
  };
  const removeNetwork = (i: number) =>
    setScope((s) => ({ ...s, networks: s.networks.filter((_, idx) => idx !== i) }));

  const addDomain = () => {
    if (!newDomain.pattern.trim()) return;
    setScope((s) => ({ ...s, domains: [...s.domains, { ...newDomain }] }));
    setNewDomain({ pattern: '', environment: 'staging' });
  };
  const removeDomain = (i: number) =>
    setScope((s) => ({ ...s, domains: s.domains.filter((_, idx) => idx !== i) }));

  const addRepo = () => {
    const v = newRepo.trim();
    if (!v || scope.repos.includes(v)) return;
    setScope((s) => ({ ...s, repos: [...s.repos, v] }));
    setNewRepo('');
  };
  const removeRepo = (i: number) =>
    setScope((s) => ({ ...s, repos: s.repos.filter((_, idx) => idx !== i) }));

  const addExclusion = () => {
    if (!newExclusion.pattern.trim()) return;
    setScope((s) => ({ ...s, exclusions: [...s.exclusions, { ...newExclusion }] }));
    setNewExclusion({ pattern: '', reason: '' });
  };
  const removeExclusion = (i: number) =>
    setScope((s) => ({ ...s, exclusions: s.exclusions.filter((_, idx) => idx !== i) }));

  const toggleCloudAccount = (id: string) =>
    setScope((s) => ({
      ...s,
      cloud_account_ids: s.cloud_account_ids.includes(id)
        ? s.cloud_account_ids.filter((x) => x !== id)
        : [...s.cloud_account_ids, id],
    }));

  const toggleIdentityTarget = (id: string) =>
    setScope((s) => ({
      ...s,
      identity_target_ids: s.identity_target_ids.includes(id)
        ? s.identity_target_ids.filter((x) => x !== id)
        : [...s.identity_target_ids, id],
    }));

  const handleSave = () => {
    if (!name.trim()) return;
    onSubmit({
      name: name.trim(),
      description: description.trim() || undefined,
      status,
      scope,
    });
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl max-h-[90vh] flex flex-col">
        <DialogHeader>
          <DialogTitle>{isEdit ? 'Edit Project' : 'New Project'}</DialogTitle>
          <DialogDescription>
            {isEdit
              ? 'Update the project details and its scope.'
              : 'Create a project to group scope and findings together.'}
          </DialogDescription>
        </DialogHeader>

        <ScrollArea className="flex-1 -mx-6 px-6">
          <div className="space-y-6 py-2">
            {/* Details */}
            <div className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="project-name">Name</Label>
                <Input
                  id="project-name"
                  placeholder="e.g., Acme Q3 External"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="project-description">Description (optional)</Label>
                <Textarea
                  id="project-description"
                  placeholder="What this project covers"
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  rows={2}
                />
              </div>
              <div className="space-y-2">
                <Label>Status</Label>
                <Select value={status} onValueChange={(v) => setStatus(v as ProjectStatus)}>
                  <SelectTrigger className="w-[200px]">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="active">Active</SelectItem>
                    <SelectItem value="archived">Archived</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>

            <div className="h-px bg-border" />

            {/* Scope header */}
            <div>
              <h3 className="text-sm font-semibold">Scope</h3>
              <p className="text-xs text-muted-foreground">
                Targets and references this project covers.
              </p>
            </div>

            {/* Networks */}
            <ScopeSection
              icon={<Network className="h-4 w-4" />}
              title="Networks"
              count={scope.networks.length}
            >
              <div className="flex flex-wrap items-end gap-2">
                <div className="flex-1 min-w-[180px] space-y-1">
                  <Label className="text-xs">CIDR Range</Label>
                  <Input
                    placeholder="192.168.100.0/24"
                    value={newNetwork.cidr}
                    onChange={(e) => setNewNetwork({ ...newNetwork, cidr: e.target.value })}
                    onKeyDown={(e) => e.key === 'Enter' && (e.preventDefault(), addNetwork())}
                  />
                </div>
                <div className="space-y-1">
                  <Label className="text-xs">Environment</Label>
                  <Select
                    value={newNetwork.environment}
                    onValueChange={(v) => setNewNetwork({ ...newNetwork, environment: v })}
                  >
                    <SelectTrigger className="w-[130px]">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="development">Development</SelectItem>
                      <SelectItem value="staging">Staging</SelectItem>
                      <SelectItem value="production">Production</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <Button type="button" variant="secondary" onClick={addNetwork} disabled={!newNetwork.cidr.trim()}>
                  <Plus className="h-4 w-4" />
                </Button>
              </div>
              {scope.networks.length > 0 && (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>CIDR</TableHead>
                      <TableHead>Environment</TableHead>
                      <TableHead className="w-[60px]" />
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {scope.networks.map((n, i) => (
                      <TableRow key={i}>
                        <TableCell className="font-mono text-xs">{n.cidr}</TableCell>
                        <TableCell>
                          <Badge variant="outline">{n.environment}</Badge>
                        </TableCell>
                        <TableCell>
                          <Button variant="ghost" size="sm" className="text-destructive" onClick={() => removeNetwork(i)}>
                            <Trash2 className="h-4 w-4" />
                          </Button>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </ScopeSection>

            {/* Domains */}
            <ScopeSection
              icon={<Globe className="h-4 w-4" />}
              title="Domains"
              count={scope.domains.length}
            >
              <div className="flex flex-wrap items-end gap-2">
                <div className="flex-1 min-w-[180px] space-y-1">
                  <Label className="text-xs">Domain Pattern</Label>
                  <Input
                    placeholder="*.staging.example.com"
                    value={newDomain.pattern}
                    onChange={(e) => setNewDomain({ ...newDomain, pattern: e.target.value })}
                    onKeyDown={(e) => e.key === 'Enter' && (e.preventDefault(), addDomain())}
                  />
                </div>
                <div className="space-y-1">
                  <Label className="text-xs">Environment</Label>
                  <Select
                    value={newDomain.environment}
                    onValueChange={(v) => setNewDomain({ ...newDomain, environment: v })}
                  >
                    <SelectTrigger className="w-[130px]">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="development">Development</SelectItem>
                      <SelectItem value="staging">Staging</SelectItem>
                      <SelectItem value="production">Production</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <Button type="button" variant="secondary" onClick={addDomain} disabled={!newDomain.pattern.trim()}>
                  <Plus className="h-4 w-4" />
                </Button>
              </div>
              {scope.domains.length > 0 && (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Pattern</TableHead>
                      <TableHead>Environment</TableHead>
                      <TableHead className="w-[60px]" />
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {scope.domains.map((d, i) => (
                      <TableRow key={i}>
                        <TableCell className="font-mono text-xs">{d.pattern}</TableCell>
                        <TableCell>
                          <Badge variant="outline">{d.environment}</Badge>
                        </TableCell>
                        <TableCell>
                          <Button variant="ghost" size="sm" className="text-destructive" onClick={() => removeDomain(i)}>
                            <Trash2 className="h-4 w-4" />
                          </Button>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </ScopeSection>

            {/* Repos */}
            <ScopeSection
              icon={<FolderGit2 className="h-4 w-4" />}
              title="Repositories"
              count={scope.repos.length}
            >
              <div className="flex items-end gap-2">
                <div className="flex-1 space-y-1">
                  <Label className="text-xs">Repo path or git URL</Label>
                  <Input
                    placeholder="~/projects/api or https://github.com/org/repo"
                    value={newRepo}
                    onChange={(e) => setNewRepo(e.target.value)}
                    onKeyDown={(e) => e.key === 'Enter' && (e.preventDefault(), addRepo())}
                  />
                </div>
                <Button type="button" variant="secondary" onClick={addRepo} disabled={!newRepo.trim()}>
                  <Plus className="h-4 w-4" />
                </Button>
              </div>
              {scope.repos.length > 0 && (
                <div className="space-y-1">
                  {scope.repos.map((r, i) => (
                    <div
                      key={i}
                      className="flex items-center justify-between rounded-md border border-border bg-muted/30 px-3 py-1.5"
                    >
                      <span className="font-mono text-xs truncate">{r}</span>
                      <Button variant="ghost" size="sm" className="text-destructive h-7" onClick={() => removeRepo(i)}>
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    </div>
                  ))}
                </div>
              )}
            </ScopeSection>

            {/* Cloud accounts (multi-select from org config) */}
            <ScopeSection
              icon={<Cloud className="h-4 w-4" />}
              title="Cloud Accounts"
              count={scope.cloud_account_ids.length}
            >
              {loadingOrgScope ? (
                <div className="flex items-center gap-2 text-xs text-muted-foreground">
                  <Loader2 className="h-3.5 w-3.5 animate-spin" /> Loading cloud accounts…
                </div>
              ) : cloudAccounts.length === 0 ? (
                <p className="text-xs text-muted-foreground">
                  No cloud accounts configured. Add them under Config → Cloud Accounts.
                </p>
              ) : (
                <div className="space-y-1.5">
                  {cloudAccounts.map((acct) => (
                    <label
                      key={acct.id}
                      className="flex cursor-pointer items-center gap-2.5 rounded-md border border-border bg-muted/20 px-3 py-2 hover:bg-muted/40"
                    >
                      <Checkbox
                        checked={scope.cloud_account_ids.includes(acct.id)}
                        onCheckedChange={() => toggleCloudAccount(acct.id)}
                      />
                      <Badge variant="outline" className="uppercase">
                        {providerLabels[acct.provider] ?? acct.provider}
                      </Badge>
                      <span className="text-sm font-medium">{acct.id}</span>
                      <span className="text-xs text-muted-foreground truncate">
                        {acct.account_id || acct.subscription_id || acct.project_id || ''}
                      </span>
                    </label>
                  ))}
                </div>
              )}
            </ScopeSection>

            {/* Identity targets (multi-select from org config) */}
            <ScopeSection
              icon={<KeyRound className="h-4 w-4" />}
              title="Identity Targets"
              count={scope.identity_target_ids.length}
            >
              {loadingOrgScope ? (
                <div className="flex items-center gap-2 text-xs text-muted-foreground">
                  <Loader2 className="h-3.5 w-3.5 animate-spin" /> Loading identity targets…
                </div>
              ) : identityTargets.length === 0 ? (
                <p className="text-xs text-muted-foreground">
                  No identity targets configured. Add them under Config → Identity Targets.
                </p>
              ) : (
                <div className="space-y-1.5">
                  {identityTargets.map((idp) => (
                    <label
                      key={idp.id}
                      className="flex cursor-pointer items-center gap-2.5 rounded-md border border-border bg-muted/20 px-3 py-2 hover:bg-muted/40"
                    >
                      <Checkbox
                        checked={scope.identity_target_ids.includes(idp.id)}
                        onCheckedChange={() => toggleIdentityTarget(idp.id)}
                      />
                      <Badge variant="outline">
                        {identityKindLabels[idp.kind] ?? idp.kind}
                      </Badge>
                      <span className="text-sm font-medium">{idp.display_name || idp.id}</span>
                      <span className="text-xs text-muted-foreground truncate">
                        {idp.domain || idp.tenant_id || ''}
                      </span>
                    </label>
                  ))}
                </div>
              )}
            </ScopeSection>

            {/* Exclusions */}
            <ScopeSection
              icon={<ShieldAlert className="h-4 w-4" />}
              title="Exclusions"
              count={scope.exclusions.length}
            >
              <div className="flex flex-wrap items-end gap-2">
                <div className="flex-1 min-w-[160px] space-y-1">
                  <Label className="text-xs">Pattern</Label>
                  <Input
                    placeholder="production.example.com"
                    value={newExclusion.pattern}
                    onChange={(e) => setNewExclusion({ ...newExclusion, pattern: e.target.value })}
                    onKeyDown={(e) => e.key === 'Enter' && (e.preventDefault(), addExclusion())}
                  />
                </div>
                <div className="flex-1 min-w-[160px] space-y-1">
                  <Label className="text-xs">Reason</Label>
                  <Input
                    placeholder="Why excluded?"
                    value={newExclusion.reason}
                    onChange={(e) => setNewExclusion({ ...newExclusion, reason: e.target.value })}
                    onKeyDown={(e) => e.key === 'Enter' && (e.preventDefault(), addExclusion())}
                  />
                </div>
                <Button type="button" variant="secondary" onClick={addExclusion} disabled={!newExclusion.pattern.trim()}>
                  <Plus className="h-4 w-4" />
                </Button>
              </div>
              {scope.exclusions.length > 0 && (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Pattern</TableHead>
                      <TableHead>Reason</TableHead>
                      <TableHead className="w-[60px]" />
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {scope.exclusions.map((ex, i) => (
                      <TableRow key={i}>
                        <TableCell className="font-mono text-xs">{ex.pattern}</TableCell>
                        <TableCell className="text-muted-foreground text-xs">{ex.reason || '-'}</TableCell>
                        <TableCell>
                          <Button variant="ghost" size="sm" className="text-destructive" onClick={() => removeExclusion(i)}>
                            <Trash2 className="h-4 w-4" />
                          </Button>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </ScopeSection>
          </div>
        </ScrollArea>

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={isSaving}>
            Cancel
          </Button>
          <Button onClick={handleSave} disabled={!name.trim() || isSaving}>
            {isSaving && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
            {isEdit ? 'Save Changes' : 'Create Project'}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

/** A titled scope sub-section with an icon + count chip. */
function ScopeSection({
  icon,
  title,
  count,
  children,
}: {
  icon: React.ReactNode;
  title: string;
  count: number;
  children: React.ReactNode;
}) {
  return (
    <div className="space-y-2.5 rounded-lg border border-border p-3">
      <div className="flex items-center gap-2">
        <span className="text-muted-foreground">{icon}</span>
        <span className="text-sm font-medium">{title}</span>
        <Badge variant="secondary" className="h-5 px-1.5 text-xs">
          {count}
        </Badge>
      </div>
      {children}
    </div>
  );
}
