'use client';

/**
 * Projects list (WORK section).
 *
 * A project groups scope + findings. This page lists every project as a
 * card (name, description, status, assessment count, scope summary) and
 * launches the create flow via the shared ProjectEditorDialog. Each card
 * deep-links to /projects/detail?id=<id> (query-param route — the app is a
 * static export, so dynamic [id] segments 404 at runtime).
 */

import { useMemo, useState } from 'react';
import { PageHeader } from '@/components/layout/page-header';
import Link from 'next/link';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { api } from '@/lib/tauri-api';
import type { CreateProjectParams, Project, ProjectScope } from '@/lib/types';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { Card } from '@/components/ui/card';
import { Skeleton } from '@/components/ui/skeleton';
import { ProjectEditorDialog } from '@/components/projects/project-editor-dialog';
import {
  FolderKanban,
  Plus,
  Search,
  Radar,
  Target,
  FolderGit2,
  Cloud,
  KeyRound,
} from 'lucide-react';
import { toast } from 'sonner';

/** Compact "3 targets · 1 repo · 2 cloud" summary from a project's scope. */
function scopeSummary(scope?: ProjectScope): { label: string; icon: typeof Target }[] {
  if (!scope) return [];
  const targets = (scope.networks?.length ?? 0) + (scope.domains?.length ?? 0);
  const out: { label: string; icon: typeof Target }[] = [];
  if (targets) out.push({ label: `${targets} target${targets === 1 ? '' : 's'}`, icon: Target });
  if (scope.repos?.length) out.push({ label: `${scope.repos.length} repo${scope.repos.length === 1 ? '' : 's'}`, icon: FolderGit2 });
  if (scope.cloud_account_ids?.length) out.push({ label: `${scope.cloud_account_ids.length} cloud`, icon: Cloud });
  if (scope.identity_target_ids?.length) out.push({ label: `${scope.identity_target_ids.length} identity`, icon: KeyRound });
  return out;
}

export default function ProjectsPage() {
  const queryClient = useQueryClient();
  const [search, setSearch] = useState('');
  const [dialogOpen, setDialogOpen] = useState(false);

  // NOTE: the cloud backend's `?status=active` filter is broken (returns
  // [] even for active rows — see the comment on the assessments page).
  // Pull everything and let the UI decide what to show.
  const { data: projects, isLoading } = useQuery({
    queryKey: ['projects'],
    queryFn: () => api.projects.list(),
  });

  const createMutation = useMutation({
    mutationFn: (data: CreateProjectParams) => api.projects.create(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['projects'] });
      toast.success('Project created');
      setDialogOpen(false);
    },
    onError: () => toast.error('Failed to create project'),
  });

  const filtered = useMemo(() => {
    const list = projects ?? [];
    const q = search.trim().toLowerCase();
    if (!q) return list;
    return list.filter(
      (p) =>
        p.name.toLowerCase().includes(q) ||
        (p.description ?? '').toLowerCase().includes(q),
    );
  }, [projects, search]);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Projects"
        description="Group scope and findings into a single engagement."
        icon={FolderKanban}
        actions={
          <Button onClick={() => setDialogOpen(true)}>
            <Plus className="mr-2 h-4 w-4" />
            New Project
          </Button>
        }
      />

      {/* Search */}
      <div className="relative max-w-md">
        <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
        <Input
          placeholder="Search projects..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="pl-9"
        />
      </div>

      {/* Grid */}
      {isLoading ? (
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {[...Array(6)].map((_, i) => (
            <Skeleton key={i} className="h-40 rounded-xl" />
          ))}
        </div>
      ) : filtered.length === 0 ? (
        <Card className="glass-card flex flex-col items-center justify-center gap-3 py-16 text-center">
          <FolderKanban className="h-10 w-10 text-muted-foreground/50" />
          <div>
            <p className="font-medium">
              {projects?.length ? 'No matching projects' : 'No projects yet'}
            </p>
            <p className="text-sm text-muted-foreground">
              {projects?.length
                ? 'Try a different search.'
                : 'Create your first project to group scope and findings.'}
            </p>
          </div>
          {!projects?.length && (
            <Button onClick={() => setDialogOpen(true)}>
              <Plus className="mr-2 h-4 w-4" />
              New Project
            </Button>
          )}
        </Card>
      ) : (
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {filtered.map((project) => (
            <ProjectCard key={project.id} project={project} />
          ))}
        </div>
      )}

      <ProjectEditorDialog
        open={dialogOpen}
        onOpenChange={setDialogOpen}
        onSubmit={(data) => createMutation.mutate(data)}
        isSaving={createMutation.isPending}
      />
    </div>
  );
}

function ProjectCard({ project }: { project: Project }) {
  const summary = scopeSummary(project.scope);
  return (
    <Link href={`/projects/detail?id=${project.id}`} className="group block">
      <Card className="glass-card h-full overflow-hidden p-4 transition-colors hover:bg-muted/30">
        <div className="flex items-start justify-between gap-2">
          <h3 className="font-semibold leading-tight group-hover:text-primary">
            {project.name}
          </h3>
          <Badge
            variant={project.status === 'active' ? 'default' : 'secondary'}
            className="shrink-0 capitalize"
          >
            {project.status}
          </Badge>
        </div>

        <p className="mt-1.5 line-clamp-2 min-h-[2.5rem] text-sm text-muted-foreground">
          {project.description || 'No description'}
        </p>

        {/* Scope summary chips */}
        {summary.length > 0 && (
          <div className="mt-3 flex flex-wrap gap-1.5">
            {summary.map((chip) => (
              <span
                key={chip.label}
                className="inline-flex items-center gap-1 rounded-full bg-muted/60 px-2 py-0.5 text-[11px] text-muted-foreground"
              >
                <chip.icon className="h-3 w-3" />
                {chip.label}
              </span>
            ))}
          </div>
        )}

        <div className="mt-3 flex items-center gap-1.5 border-t border-border pt-3 text-xs text-muted-foreground">
          <Radar className="h-3.5 w-3.5" />
          {project.assessment_count} assessment{project.assessment_count === 1 ? '' : 's'}
        </div>
      </Card>
    </Link>
  );
}
