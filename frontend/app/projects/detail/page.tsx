'use client';

/**
 * Per-project detail (query-param route: /projects/detail?id=<id>).
 *
 * The app is a static export, so this uses ?id= rather than a dynamic
 * [id] segment (which 404s at runtime). Surfaces:
 *   - header (name, description, status, Edit + back link)
 *   - scope summary (networks / domains / repos / cloud / identity / exclusions)
 *   - severity stat tiles (from findings.stats scoped to project_id)
 *   - the project's findings (findings.list { project_id })
 *   - the project's assessments (assessments.list, client-filtered by project_id)
 */

import { Suspense, useMemo, useState } from 'react';
import Link from 'next/link';
import { useRouter, useSearchParams } from 'next/navigation';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { api } from '@/lib/tauri-api';
import type {
  ProjectScope,
  Severity,
  UpdateProjectParams,
} from '@/lib/types';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Card } from '@/components/ui/card';
import { Skeleton } from '@/components/ui/skeleton';
import { ProjectEditorDialog } from '@/components/projects/project-editor-dialog';
import {
  getDisplayTitle,
  statusConfig,
  formatRelativeTime,
  assessmentTimestamp,
} from '@/lib/assessment-display';
import { cn } from '@/lib/utils';
import {
  ArrowLeft,
  Pencil,
  FolderKanban,
  Network,
  Globe,
  FolderGit2,
  Cloud,
  KeyRound,
  ShieldAlert,
  AlertTriangle,
  Radar,
} from 'lucide-react';
import { toast } from 'sonner';

const SEVERITY_TILES: { key: Severity; label: string; color: string }[] = [
  { key: 'critical', label: 'Critical', color: 'text-red-400' },
  { key: 'high', label: 'High', color: 'text-orange-400' },
  { key: 'medium', label: 'Medium', color: 'text-yellow-400' },
  { key: 'low', label: 'Low', color: 'text-blue-400' },
];

const severityBadge: Record<string, string> = {
  critical: 'bg-red-500/15 text-red-400 border-red-500/30',
  high: 'bg-orange-500/15 text-orange-400 border-orange-500/30',
  medium: 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30',
  low: 'bg-blue-500/15 text-blue-400 border-blue-500/30',
  info: 'bg-slate-500/15 text-slate-400 border-slate-500/30',
};

function ProjectDetailContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const queryClient = useQueryClient();
  const projectId = searchParams.get('id') ?? '';

  const [editOpen, setEditOpen] = useState(false);

  const { data: project, isLoading: loadingProject } = useQuery({
    queryKey: ['project', projectId],
    queryFn: () => api.projects.get(projectId),
    enabled: !!projectId,
  });

  const { data: stats } = useQuery({
    queryKey: ['project-stats', projectId],
    queryFn: () => api.findings.stats(undefined, undefined, undefined, undefined, projectId),
    enabled: !!projectId,
  });

  const { data: findingsPage } = useQuery({
    queryKey: ['project-findings', projectId],
    queryFn: () => api.findings.list({ project_id: projectId, limit: 100 }),
    enabled: !!projectId,
  });

  const { data: assessmentsPage } = useQuery({
    queryKey: ['project-assessments', projectId],
    queryFn: () => api.assessments.list({ limit: 200 }),
    enabled: !!projectId,
  });

  const updateMutation = useMutation({
    mutationFn: (data: UpdateProjectParams) => api.projects.update(projectId, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['project', projectId] });
      queryClient.invalidateQueries({ queryKey: ['projects'] });
      toast.success('Project updated');
      setEditOpen(false);
    },
    onError: () => toast.error('Failed to update project'),
  });

  const findings = findingsPage?.data ?? [];
  const projectAssessments = useMemo(
    () => (assessmentsPage?.data ?? []).filter((a) => a.project_id === projectId),
    [assessmentsPage, projectId],
  );

  if (!projectId) {
    return (
      <div className="space-y-4">
        <BackLink router={router} />
        <Card className="glass-card py-12 text-center text-muted-foreground">
          No project specified.
        </Card>
      </div>
    );
  }

  if (loadingProject) {
    return (
      <div className="space-y-6">
        <Skeleton className="h-8 w-64" />
        <div className="grid gap-4 sm:grid-cols-4">
          {[...Array(4)].map((_, i) => (
            <Skeleton key={i} className="h-24 rounded-xl" />
          ))}
        </div>
        <Skeleton className="h-64 rounded-xl" />
      </div>
    );
  }

  if (!project) {
    return (
      <div className="space-y-4">
        <BackLink router={router} />
        <Card className="glass-card py-12 text-center text-muted-foreground">
          Project not found.
        </Card>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <BackLink router={router} />

      {/* Header */}
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="flex items-center gap-2 text-3xl font-bold">
            <FolderKanban className="h-7 w-7 text-primary" />
            {project.name}
            <Badge
              variant={project.status === 'active' ? 'default' : 'secondary'}
              className="capitalize"
            >
              {project.status}
            </Badge>
          </h1>
          {project.description && (
            <p className="mt-1 text-muted-foreground">{project.description}</p>
          )}
        </div>
        <Button variant="outline" onClick={() => setEditOpen(true)}>
          <Pencil className="mr-2 h-4 w-4" />
          Edit
        </Button>
      </div>

      {/* Severity stat tiles */}
      <div className="grid gap-3 sm:grid-cols-4">
        {SEVERITY_TILES.map((tile) => (
          <div key={tile.key} className="glass-card rounded-xl p-4">
            <span className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
              {tile.label}
            </span>
            <div className={cn('mt-1 text-2xl font-bold tabular-nums', tile.color)}>
              {stats?.by_severity?.[tile.key] ?? 0}
            </div>
          </div>
        ))}
      </div>

      {/* Scope summary */}
      <ScopeSummary scope={project.scope} />

      {/* Findings */}
      <section className="space-y-3">
        <div className="flex items-center justify-between">
          <h2 className="flex items-center gap-2 text-lg font-semibold">
            <AlertTriangle className="h-5 w-5 text-muted-foreground" />
            Findings
            <Badge variant="secondary">{stats?.total ?? findings.length}</Badge>
          </h2>
        </div>
        {findings.length === 0 ? (
          <Card className="glass-card py-10 text-center text-sm text-muted-foreground">
            No findings for this project yet.
          </Card>
        ) : (
          <Card className="glass-card divide-y divide-border overflow-hidden">
            {findings.map((f) => (
              <Link
                key={f.id}
                href={`/findings/detail?id=${f.id}`}
                className="flex items-center gap-3 px-4 py-3 transition-colors hover:bg-muted/30"
              >
                <Badge
                  variant="outline"
                  className={cn('shrink-0 capitalize', severityBadge[f.severity] ?? '')}
                >
                  {f.severity}
                </Badge>
                <span className="min-w-0 flex-1 truncate text-sm font-medium">{f.title}</span>
                <span className="hidden shrink-0 truncate text-xs text-muted-foreground sm:block sm:max-w-[200px]">
                  {f.target}
                </span>
              </Link>
            ))}
          </Card>
        )}
      </section>

      {/* Assessments in project */}
      <section className="space-y-3">
        <h2 className="flex items-center gap-2 text-lg font-semibold">
          <Radar className="h-5 w-5 text-muted-foreground" />
          Assessments
          <Badge variant="secondary">{projectAssessments.length}</Badge>
        </h2>
        {projectAssessments.length === 0 ? (
          <Card className="glass-card py-10 text-center text-sm text-muted-foreground">
            No assessments assigned to this project yet.
          </Card>
        ) : (
          <Card className="glass-card divide-y divide-border overflow-hidden">
            {projectAssessments.map((a) => {
              const cfg = statusConfig[a.status] || statusConfig.pending;
              const StatusIcon = cfg.icon;
              return (
                <Link
                  key={a.id}
                  href={`/assessments?id=${a.id}`}
                  className="flex items-center gap-3 px-4 py-3 transition-colors hover:bg-muted/30"
                >
                  <StatusIcon
                    className={cn(
                      'h-4 w-4 shrink-0',
                      cfg.color,
                      a.status === 'running' && 'animate-spin',
                    )}
                  />
                  <span className="min-w-0 flex-1 truncate text-sm font-medium">
                    {getDisplayTitle(a)}
                  </span>
                  <span className={cn('hidden shrink-0 text-xs capitalize sm:block', cfg.color)}>
                    {a.status}
                  </span>
                  <span className="shrink-0 text-xs text-muted-foreground">
                    {formatRelativeTime(assessmentTimestamp(a))}
                  </span>
                </Link>
              );
            })}
          </Card>
        )}
      </section>

      <ProjectEditorDialog
        open={editOpen}
        onOpenChange={setEditOpen}
        project={project}
        onSubmit={(data) => updateMutation.mutate(data)}
        isSaving={updateMutation.isPending}
      />
    </div>
  );
}

/** Compact scope rendering — one card per non-empty dimension. */
function ScopeSummary({ scope }: { scope?: ProjectScope }) {
  const isEmpty =
    !scope ||
    ((scope.networks?.length ?? 0) === 0 &&
      (scope.domains?.length ?? 0) === 0 &&
      (scope.repos?.length ?? 0) === 0 &&
      (scope.cloud_account_ids?.length ?? 0) === 0 &&
      (scope.identity_target_ids?.length ?? 0) === 0 &&
      (scope.exclusions?.length ?? 0) === 0);

  if (isEmpty) {
    return (
      <Card className="glass-card py-8 text-center text-sm text-muted-foreground">
        No scope defined for this project. Click Edit to add networks, domains, repos, or
        cloud / identity references.
      </Card>
    );
  }

  return (
    <div className="grid gap-3 md:grid-cols-2 lg:grid-cols-3">
      {!!scope!.networks?.length && (
        <ScopeCard icon={<Network className="h-4 w-4" />} title="Networks" count={scope!.networks.length}>
          {scope!.networks.map((n, i) => (
            <Chip key={i} mono>{n.cidr}</Chip>
          ))}
        </ScopeCard>
      )}
      {!!scope!.domains?.length && (
        <ScopeCard icon={<Globe className="h-4 w-4" />} title="Domains" count={scope!.domains.length}>
          {scope!.domains.map((d, i) => (
            <Chip key={i} mono>{d.pattern}</Chip>
          ))}
        </ScopeCard>
      )}
      {!!scope!.repos?.length && (
        <ScopeCard icon={<FolderGit2 className="h-4 w-4" />} title="Repositories" count={scope!.repos.length}>
          {scope!.repos.map((r, i) => (
            <Chip key={i} mono>{r}</Chip>
          ))}
        </ScopeCard>
      )}
      {!!scope!.cloud_account_ids?.length && (
        <ScopeCard icon={<Cloud className="h-4 w-4" />} title="Cloud Accounts" count={scope!.cloud_account_ids.length}>
          {scope!.cloud_account_ids.map((id, i) => (
            <Chip key={i}>{id}</Chip>
          ))}
        </ScopeCard>
      )}
      {!!scope!.identity_target_ids?.length && (
        <ScopeCard icon={<KeyRound className="h-4 w-4" />} title="Identity Targets" count={scope!.identity_target_ids.length}>
          {scope!.identity_target_ids.map((id, i) => (
            <Chip key={i}>{id}</Chip>
          ))}
        </ScopeCard>
      )}
      {!!scope!.exclusions?.length && (
        <ScopeCard icon={<ShieldAlert className="h-4 w-4" />} title="Exclusions" count={scope!.exclusions.length}>
          {scope!.exclusions.map((ex, i) => (
            <Chip key={i} mono title={ex.reason}>{ex.pattern}</Chip>
          ))}
        </ScopeCard>
      )}
    </div>
  );
}

function ScopeCard({
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
    <Card className="glass-card p-4">
      <div className="mb-2 flex items-center gap-2">
        <span className="text-muted-foreground">{icon}</span>
        <span className="text-sm font-medium">{title}</span>
        <Badge variant="secondary" className="h-5 px-1.5 text-xs">
          {count}
        </Badge>
      </div>
      <div className="flex flex-wrap gap-1.5">{children}</div>
    </Card>
  );
}

function Chip({
  children,
  mono,
  title,
}: {
  children: React.ReactNode;
  mono?: boolean;
  title?: string;
}) {
  return (
    <span
      title={title}
      className={cn(
        'inline-block max-w-full truncate rounded-md bg-muted/60 px-2 py-0.5 text-xs text-muted-foreground',
        mono && 'font-mono',
      )}
    >
      {children}
    </span>
  );
}

function BackLink({ router }: { router: ReturnType<typeof useRouter> }) {
  return (
    <Button variant="ghost" size="sm" className="-ml-2" onClick={() => router.push('/projects')}>
      <ArrowLeft className="mr-2 h-4 w-4" />
      Back to Projects
    </Button>
  );
}

export default function ProjectDetailPage() {
  return (
    <Suspense
      fallback={
        <div className="space-y-6">
          <Skeleton className="h-8 w-64" />
          <div className="grid gap-3 sm:grid-cols-4">
            {[...Array(4)].map((_, i) => (
              <Skeleton key={i} className="h-24 rounded-xl" />
            ))}
          </div>
          <Skeleton className="h-64 rounded-xl" />
        </div>
      }
    >
      <ProjectDetailContent />
    </Suspense>
  );
}
