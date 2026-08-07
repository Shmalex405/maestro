'use client';

import { useState, useMemo, useEffect, useRef, Suspense } from 'react';
import { useQuery, useMutation, useQueryClient, keepPreviousData } from '@tanstack/react-query';
import { useSearchParams } from 'next/navigation';
import { api } from '@/lib/tauri-api';
import type { Assessment, PaginatedResult, Project } from '@/lib/types';
import { NewAssessmentModal } from '@/components/assessments/new-assessment-modal';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Skeleton } from '@/components/ui/skeleton';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
  DropdownMenuSub,
  DropdownMenuSubTrigger,
  DropdownMenuSubContent,
  DropdownMenuPortal,
} from '@/components/ui/dropdown-menu';
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog';
import {
  Plus,
  Search,
  FolderPlus,
  Folder,
  MoreHorizontal,
  Trash2,
  Edit2,
  MessageSquare,
  PanelLeftClose,
  PanelLeft,
  Radar,
  Loader2,
  CheckCircle2,
  SquarePen,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import {
  statusConfig,
  formatRelativeTime,
  assessmentTimestamp,
  getDisplayTitle,
} from '@/lib/assessment-display';
import { AssessmentTerminalView } from '@/components/terminal/assessment-terminal-view';
import { useLiveAssessmentSessions } from '@/lib/hooks/use-live-assessment-sessions';
import { useLiveAssessmentsStore } from '@/lib/stores/live-assessments-store';
import { useIsReadOnly } from '@/lib/read-only';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';

// ChatGPT-style conversation item
function ConversationItem({
  assessment,
  isActive,
  isLive,
  onClick,
  onDelete,
  onRename,
  onAddToProject,
  projects,
}: {
  assessment: Assessment;
  isActive: boolean;
  /** True when the assessment's tmux session is alive in the container —
   *  reopening reattaches to a running claude. Drives the green-dot indicator. */
  isLive: boolean;
  onClick: () => void;
  onDelete: () => void;
  onRename: () => void;
  onAddToProject: (projectId: string | null) => void;
  projects?: Project[];
}) {
  const status = statusConfig[assessment.status] || statusConfig.pending;
  const StatusIcon = status.icon;
  const displayTitle = getDisplayTitle(assessment);

  return (
    <div
      className={cn(
        'group relative flex items-center gap-2 px-3 py-3 rounded-lg cursor-pointer transition-colors',
        isActive
          ? 'bg-primary/15 ring-1 ring-primary/40 shadow-sm'
          : 'hover:bg-muted/50'
      )}
      onClick={onClick}
    >
      {isActive && (
        <span
          aria-hidden
          className="absolute left-0 top-1/2 -translate-y-1/2 h-6 w-1 rounded-r bg-primary"
        />
      )}
      {/* Actions menu - replacing chat icon */}
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <button
            type="button"
            className="h-5 w-5 flex-shrink-0 flex items-center justify-center text-muted-foreground hover:text-foreground"
            onClick={(e) => e.stopPropagation()}
          >
            <MoreHorizontal className="h-4 w-4" />
          </button>
        </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="w-48">
            <DropdownMenuItem onClick={(e) => { e.stopPropagation(); onRename(); }}>
              <Edit2 className="h-4 w-4 mr-2" />
              Rename
            </DropdownMenuItem>

            {/* Add to project submenu */}
            {projects && projects.length > 0 && (
              <DropdownMenuSub>
                <DropdownMenuSubTrigger onClick={(e) => e.stopPropagation()}>
                  <Folder className="h-4 w-4 mr-2" />
                  {assessment.project_id ? 'Move to project' : 'Add to project'}
                </DropdownMenuSubTrigger>
                <DropdownMenuPortal>
                  <DropdownMenuSubContent>
                    {assessment.project_id && (
                      <>
                        <DropdownMenuItem
                          onClick={(e) => { e.stopPropagation(); onAddToProject(null); }}
                        >
                          <span className="text-muted-foreground">Remove from project</span>
                        </DropdownMenuItem>
                        <DropdownMenuSeparator />
                      </>
                    )}
                    {projects.map((project) => (
                      <DropdownMenuItem
                        key={project.id}
                        onClick={(e) => { e.stopPropagation(); onAddToProject(project.id); }}
                        disabled={assessment.project_id === project.id}
                      >
                        <Folder className="h-4 w-4 mr-2" />
                        {project.name}
                        {assessment.project_id === project.id && (
                          <CheckCircle2 className="h-3 w-3 ml-auto text-primary" />
                        )}
                      </DropdownMenuItem>
                    ))}
                  </DropdownMenuSubContent>
                </DropdownMenuPortal>
              </DropdownMenuSub>
            )}

            <DropdownMenuSeparator />
            <DropdownMenuItem
              className="text-destructive focus:text-destructive"
              onClick={(e) => { e.stopPropagation(); onDelete(); }}
            >
              <Trash2 className="h-4 w-4 mr-2" />
              Delete
            </DropdownMenuItem>
          </DropdownMenuContent>
      </DropdownMenu>

      {/* Content */}
      <div className="flex-1 min-w-0 overflow-hidden">
        <div className="flex items-center gap-1.5 min-w-0">
          {isLive && (
            <span
              className="inline-flex h-2 w-2 rounded-full bg-green-500 animate-pulse shrink-0"
              title="Live session — reopening will reattach"
              aria-label="Live session"
            />
          )}
          <span
            className={cn(
              'text-sm truncate',
              isActive && 'font-medium text-foreground'
            )}
          >
            {displayTitle}
          </span>
        </div>
        <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
          <StatusIcon
            className={cn(
              'h-3 w-3 flex-shrink-0',
              status.color,
              assessment.status === 'running' && 'animate-spin'
            )}
          />
          <span className="truncate">{formatRelativeTime(assessmentTimestamp(assessment))}</span>
        </div>
      </div>
    </div>
  );
}

function AssessmentsPageContent() {
  // Defer rendering until after first client mount.
  // Without this, Next.js static-export pre-renders this component at
  // build time (Suspense resolves with empty searchParams), then client
  // hydration triggers Suspense again because of useQuery / useSearchParams
  // — the static HTML and the hydrated client tree disagree on whether
  // we're showing the suspense fallback or the resolved content. The
  // mounted gate makes the first client render identical to SSR (return
  // null) and only renders real content on subsequent renders.
  const [mounted, setMounted] = useState(false);
  useEffect(() => { setMounted(true); }, []);

  const searchParams = useSearchParams();
  const queryClient = useQueryClient();

  // Get active assessment from URL (for deep link support)
  const urlId = searchParams.get('id') || undefined;

  // Selected assessment. The terminal view requires a non-null id —
  // auto-spawn was removed (Shape A). New assessments are created only
  // via the explicit "New Assessment" modal, which sets this id after
  // the cloud creates the row.
  const [selectedAssessmentId, setSelectedAssessmentId] = useState<string | null>(urlId || null);

  // When the user deletes the assessment they currently have open, we want the
  // view to fall back to the empty "New Assessment" state — NOT auto-resume the
  // next most-recent assessment. The auto-resume effect below fires whenever
  // selection is empty, so this ref suppresses exactly one auto-resume pass
  // after such a delete. Cleared on any explicit select/create.
  const suppressAutoResumeRef = useRef(false);

  // Live tmux session IDs — populates the green dot on assessment list rows.
  // Single docker exec per 10s polled centrally so list scales to N rows for free.
  const { liveIds: liveAssessmentIds } = useLiveAssessmentSessions();

  // Sync URL param to state on mount
  useEffect(() => {
    if (urlId) {
      setSelectedAssessmentId(urlId);
    }
  }, [urlId]);

  // Auto-resume: when the user lands on /assessments without a ?id=
  // and they aren't in a fresh-new-chat flow, select the most recently
  // updated assessment. Without this, every visit auto-spawned a brand
  // new conversation. Runs once per "no ID" land — only fires while
  // selection is empty.
  // Runs after the assessmentsData query loads.
  // (We can't synchronously know if there are assessments on first
  // render, so this is an effect that fires when the list arrives.)

  // Sidebar state
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');

  // Dialog state
  const [showNewProjectDialog, setShowNewProjectDialog] = useState(false);
  const [newProjectName, setNewProjectName] = useState('');
  const [newProjectDescription, setNewProjectDescription] = useState('');
  const [deleteTarget, setDeleteTarget] = useState<{ id: string; name: string; type: 'assessment' | 'project' } | null>(null);
  const [renameTarget, setRenameTarget] = useState<{ id: string; name: string } | null>(null);
  const [newName, setNewName] = useState('');
  const [showAllProjects, setShowAllProjects] = useState(false);
  const [selectedProjectId, setSelectedProjectId] = useState<string | null>(null);
  const [editingProject, setEditingProject] = useState<Project | null>(null);

  // Queries.
  //
  // `placeholderData: keepPreviousData` — without this, if a refetch
  // errors out (transient network blip, JWT mid-refresh, brief 401
  // before retry succeeds) the query data goes to undefined and the
  // list shows "No assessments yet" even though the data exists in
  // the cloud and previous renders had it. Keeping the previous data
  // through refetches makes the list stable: it only flips to empty
  // when the cloud genuinely returns an empty array.
  //
  // `staleTime: 30_000` — the polling interval is still 3s for fresh
  // data on the active page, but tab-focus refetches don't fire if
  // the cached data is younger than 30s. Reduces the "I navigated
  // away and back, list briefly empty" race.
  const { data: assessmentsData, isLoading: loadingAssessments } = useQuery({
    queryKey: ['assessments'],
    queryFn: () => api.assessments.list({ limit: 100 }),
    refetchInterval: 3000,
    staleTime: 30_000,
    placeholderData: keepPreviousData,
    retry: 2, // tolerate two consecutive transient failures before giving up
    retryDelay: (attempt) => Math.min(1000 * 2 ** attempt, 5000),
  });

  // Auto-resume the most recently active assessment when the user lands
  // on /assessments with no ?id= and isn't explicitly starting a new
  // chat. Without this, every page visit ended up spawning a fresh
  // terminal + auto-creating a new "New conversation" row.
  // Fires when the assessments list arrives.
  useEffect(() => {
    if (suppressAutoResumeRef.current) return; // just deleted the open one — stay on empty state
    if (urlId) return; // user has a deep link, leave it alone
    if (selectedAssessmentId) return; // already selected (this run or prior)
    if (loadingAssessments) return; // wait for the list to load

    const list = assessmentsData?.data || [];
    if (list.length === 0) return; // genuine empty state — let the user click New

    // Pick the most recently updated assessment (list is sorted DESC by
    // updated_at by the cloud, but be defensive in case ordering changes).
    const mostRecent = [...list].sort((a, b) => {
      const ta = new Date(assessmentTimestamp(a) || 0).getTime();
      const tb = new Date(assessmentTimestamp(b) || 0).getTime();
      return tb - ta;
    })[0];
    setSelectedAssessmentId(mostRecent.id);
    window.history.replaceState(null, '', `/assessments?id=${mostRecent.id}`);
  }, [urlId, selectedAssessmentId, loadingAssessments, assessmentsData?.data]);

  // NOTE: do NOT pass 'active' here — the cloud backend's status filter
  // is broken (returns [] even though every project row has status="active").
  // Verified 2026-05-18: GET /api/v1/projects returns 5+ projects, GET
  // /api/v1/projects?status=active returns 0. Symptom: user creates a new
  // project, the API call succeeds (POST → 201) but the sidebar stays
  // empty because the list query ran with the broken filter. Tracked in
  // the kali-mcp-pentest-infra repo. Until that's fixed: pull all
  // projects and filter client-side.
  const { data: projects } = useQuery({
    queryKey: ['projects'],
    queryFn: async () => {
      const all = await api.projects.list();
      return all.filter((p) => p.status === 'active' || p.status === null);
    },
  });

  // Mutations
  const deleteAssessmentMutation = useMutation({
    mutationFn: (id: string) => api.assessments.delete(id),
    onSuccess: (_, deletedId) => {
      // Terminate the in-container CLI so it stops burning tokens and the
      // live badge clears instead of lingering as an orphaned session.
      // Fire-and-forget: deletion already succeeded, don't block on it.
      void api.terminal.killAssessmentSessions(deletedId);

      // Drop the card from the live-assessments popup (Zustand store —
      // it only auto-unregisters on status change, never on deletion).
      useLiveAssessmentsStore.getState().unregister(deletedId);

      // Optimistically purge the deleted row from both caches so every
      // view updates this tick rather than waiting on the next poll:
      //  - ['assessments'] feeds the list + the open terminal view AND the
      //    auto-resume effect (which would otherwise re-select the just-
      //    deleted assessment from the stale cache).
      //  - ['live-assessment-sessions'] feeds the sidebar "live" badge.
      queryClient.setQueryData<PaginatedResult<Assessment>>(['assessments'], (prev) =>
        prev
          ? { ...prev, data: prev.data.filter((a) => a.id !== deletedId) }
          : prev,
      );
      queryClient.setQueryData<string[]>(['live-assessment-sessions'], (prev) =>
        prev ? prev.filter((id) => id !== deletedId) : prev,
      );

      // If the deleted assessment was open, clear the view to the empty state.
      // Suppress the auto-resume effect so it doesn't immediately re-open the
      // next most-recent assessment — the user just deleted what they were
      // looking at and expects it gone, not replaced.
      if (selectedAssessmentId === deletedId) {
        suppressAutoResumeRef.current = true;
        setSelectedAssessmentId(null);
        window.history.replaceState(null, '', '/assessments');
      }
      setDeleteTarget(null);

      // Reconcile with the server in the background.
      queryClient.invalidateQueries({ queryKey: ['assessments'] });
      queryClient.invalidateQueries({ queryKey: ['live-assessment-sessions'] });
    },
    onError: (error) => {
      console.error('Failed to delete assessment:', error);
      setDeleteTarget(null);
    },
  });

  const updateAssessmentMutation = useMutation({
    mutationFn: ({ id, name }: { id: string; name: string }) =>
      api.assessments.update(id, { name }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['assessments'] });
      setRenameTarget(null);
      setNewName('');
    },
  });

  const createProjectMutation = useMutation({
    mutationFn: (data: { name: string; description?: string }) => api.projects.create(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['projects'] });
      setShowNewProjectDialog(false);
      setNewProjectName('');
      setNewProjectDescription('');
    },
  });

  const updateProjectMutation = useMutation({
    mutationFn: ({ id, name, description }: { id: string; name: string; description?: string }) =>
      api.projects.update(id, { name, description }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['projects'] });
      setEditingProject(null);
      setNewProjectName('');
      setNewProjectDescription('');
    },
  });

  const deleteProjectMutation = useMutation({
    mutationFn: (id: string) => api.projects.delete(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['projects'] });
      queryClient.invalidateQueries({ queryKey: ['assessments'] });
      if (selectedProjectId === deleteTarget?.id) {
        setSelectedProjectId(null);
      }
      setDeleteTarget(null);
    },
  });

  const assignToProjectMutation = useMutation({
    mutationFn: ({ assessmentId, projectId }: { assessmentId: string; projectId: string | null }) =>
      api.projects.assignAssessment(assessmentId, projectId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['assessments'] });
      queryClient.invalidateQueries({ queryKey: ['projects'] });
    },
  });

  // Filter assessments
  const assessments = assessmentsData?.data || [];

  const filteredAssessments = useMemo(() => {
    let filtered = assessments;

    // Filter by selected project
    if (selectedProjectId) {
      filtered = filtered.filter((a) => a.project_id === selectedProjectId);
    }

    // Filter by search query
    if (searchQuery) {
      const query = searchQuery.toLowerCase();
      filtered = filtered.filter(
        (a) =>
          a.name.toLowerCase().includes(query) ||
          a.targets?.some((t) => t.toLowerCase().includes(query)) ||
          getDisplayTitle(a).toLowerCase().includes(query)
      );
    }

    return filtered;
  }, [assessments, searchQuery, selectedProjectId]);

  // Projects to display (limited or all)
  const displayedProjects = useMemo(() => {
    if (!projects) return [];
    return showAllProjects ? projects : projects.slice(0, 3);
  }, [projects, showAllProjects]);

  // Group by time periods (like ChatGPT)
  const groupedAssessments = useMemo(() => {
    const now = new Date();
    const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
    const yesterday = new Date(today.getTime() - 24 * 60 * 60 * 1000);
    const weekAgo = new Date(today.getTime() - 7 * 24 * 60 * 60 * 1000);
    const monthAgo = new Date(today.getTime() - 30 * 24 * 60 * 60 * 1000);

    const groups: Record<string, Assessment[]> = {
      today: [],
      yesterday: [],
      thisWeek: [],
      thisMonth: [],
      older: [],
    };

    filteredAssessments.forEach((a) => {
      const date = new Date(assessmentTimestamp(a) || Date.now());
      if (date >= today) {
        groups.today.push(a);
      } else if (date >= yesterday) {
        groups.yesterday.push(a);
      } else if (date >= weekAgo) {
        groups.thisWeek.push(a);
      } else if (date >= monthAgo) {
        groups.thisMonth.push(a);
      } else {
        groups.older.push(a);
      }
    });

    return groups;
  }, [filteredAssessments]);

  // Get the selected assessment object
  const selectedAssessment = useMemo(() => {
    if (!selectedAssessmentId) return null;
    return assessments.find(a => a.id === selectedAssessmentId) || null;
  }, [selectedAssessmentId, assessments]);

  const handleSelectAssessment = (id: string) => {
    suppressAutoResumeRef.current = false; // explicit user choice re-enables resume
    setSelectedAssessmentId(id);
    window.history.replaceState(null, '', `/assessments?id=${id}`);
  };

  // New-assessment walkthrough modal — the ONLY path to create a new
  // assessment. The legacy "Skip & start blank" / auto-create path was
  // removed (Shape A). Every assessment shown in the terminal has been
  // explicitly created via this modal.
  const [showNewAssessmentModal, setShowNewAssessmentModal] = useState(false);

  const readOnly = useIsReadOnly();

  const handleNewAssessment = () => {
    if (readOnly) return; // view-only users cannot start assessments
    setShowNewAssessmentModal(true);
  };

  const handleAssessmentCreated = (assessment: Assessment) => {
    suppressAutoResumeRef.current = false; // a freshly created assessment is the new selection
    setSelectedAssessmentId(assessment.id);
    window.history.replaceState(null, '', `/assessments?id=${assessment.id}`);
    // Optimistically insert into the assessments list cache so the
    // immediate post-create render finds the row via selectedAssessment =
    // assessments.find(a => a.id === selectedAssessmentId). Without this,
    // selectedAssessment is null for ~200ms while the invalidate-driven
    // refetch is in flight, AssessmentTerminalView mounts with
    // assessment=null, and terminal-view.tsx's initTerminal closure
    // captures assessment=null — which fails the auto-type gate
    // (`assessment && pty && ...`) so the wizard's pending_prompt is
    // never written into the Claude TUI on the first post-wizard view.
    queryClient.setQueryData<PaginatedResult<Assessment>>(['assessments'], (prev) => {
      const baseData = prev?.data ?? [];
      if (baseData.some((a) => a.id === assessment.id)) return prev;
      return {
        data: [assessment, ...baseData],
        total: (prev?.total ?? baseData.length) + 1,
        page: prev?.page ?? 1,
        limit: prev?.limit ?? 100,
        hasMore: prev?.hasMore ?? false,
      };
    });
    queryClient.invalidateQueries({ queryKey: ['assessments'] });
  };

  const handleRename = () => {
    if (renameTarget && newName.trim()) {
      updateAssessmentMutation.mutate({ id: renameTarget.id, name: newName.trim() });
    }
  };

  const handleCreateProject = () => {
    if (newProjectName.trim()) {
      createProjectMutation.mutate({
        name: newProjectName.trim(),
        description: newProjectDescription.trim() || undefined,
      });
    }
  };

  // Group labels
  const groupLabels: Record<string, string> = {
    today: 'Today',
    yesterday: 'Yesterday',
    thisWeek: 'Previous 7 Days',
    thisMonth: 'Previous 30 Days',
    older: 'Older',
  };

  const groupOrder = ['today', 'yesterday', 'thisWeek', 'thisMonth', 'older'];

  // Hydration gate: render nothing until the client has mounted. This
  // matches what the static-export build emits (the outer Suspense
  // boundary's fallback covers initial paint), so React doesn't see a
  // mismatch between SSR HTML and first-client-render output.
  if (!mounted) return null;

  return (
    <div className="flex h-[calc(100vh-4rem)] -m-6">
      {/* Left Sidebar - ChatGPT Style */}
      <div
        className={cn(
          'flex flex-col border-r bg-sidebar transition-all duration-200 overflow-hidden',
          sidebarCollapsed ? 'w-0' : 'w-80'
        )}
      >
        {/* Header */}
        <div className="p-3 space-y-3">
          <div className="flex items-center gap-2">
            <Button
              onClick={handleNewAssessment}
              disabled={readOnly}
              title={readOnly ? 'Read-only access — you cannot start assessments' : undefined}
              className="flex-1 h-10 bg-primary hover:bg-primary/90"
            >
              <SquarePen className="h-4 w-4 mr-2" />
              New Assessment
            </Button>
            <Button
              variant="ghost"
              size="icon"
              onClick={() => setSidebarCollapsed(true)}
              className="h-10 w-10 flex-shrink-0"
            >
              <PanelLeftClose className="h-5 w-5" />
            </Button>
          </div>

          {/* Search */}
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <Input
              placeholder="Search..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="pl-9 h-10 bg-muted/50 border-0"
            />
          </div>
        </div>

        {/* Projects Section - Always visible like ChatGPT */}
        <div className="px-2 py-2 border-b">
          {/* New Project */}
          <div
            className="group flex items-center gap-3 px-3 py-2.5 rounded-lg cursor-pointer hover:bg-muted/50 transition-colors"
            onClick={() => setShowNewProjectDialog(true)}
          >
            <FolderPlus className="h-4 w-4 text-muted-foreground" />
            <span className="text-sm">New project</span>
          </div>

          {/* Project List */}
          {displayedProjects.map((project) => (
            <div
              key={project.id}
              className={cn(
                'group flex items-center gap-3 px-3 py-2.5 rounded-lg cursor-pointer transition-colors',
                selectedProjectId === project.id
                  ? 'bg-muted/80'
                  : 'hover:bg-muted/50'
              )}
              onClick={() => setSelectedProjectId(
                selectedProjectId === project.id ? null : project.id
              )}
            >
              <Folder className="h-4 w-4 text-muted-foreground" />
              <span className="text-sm flex-1 truncate">{project.name}</span>
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button
                    variant="ghost"
                    size="icon"
                    className="h-6 w-6 opacity-0 group-hover:opacity-100 transition-opacity"
                    onClick={(e) => e.stopPropagation()}
                  >
                    <MoreHorizontal className="h-4 w-4" />
                  </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="end">
                  <DropdownMenuItem onClick={(e) => {
                    e.stopPropagation();
                    setEditingProject(project);
                    setNewProjectName(project.name);
                    setNewProjectDescription(project.description || '');
                  }}>
                    <Edit2 className="h-4 w-4 mr-2" />
                    Rename
                  </DropdownMenuItem>
                  <DropdownMenuSeparator />
                  <DropdownMenuItem
                    className="text-destructive focus:text-destructive"
                    onClick={(e) => {
                      e.stopPropagation();
                      setDeleteTarget({ id: project.id, name: project.name, type: 'project' });
                    }}
                  >
                    <Trash2 className="h-4 w-4 mr-2" />
                    Delete
                  </DropdownMenuItem>
                </DropdownMenuContent>
              </DropdownMenu>
            </div>
          ))}

          {/* See more / See less */}
          {projects && projects.length > 3 && (
            <div
              className="flex items-center gap-3 px-3 py-2.5 rounded-lg cursor-pointer hover:bg-muted/50 transition-colors text-muted-foreground"
              onClick={() => setShowAllProjects(!showAllProjects)}
            >
              <MoreHorizontal className="h-4 w-4" />
              <span className="text-sm">{showAllProjects ? 'See less' : 'See more'}</span>
            </div>
          )}

          {/* Clear filter indicator */}
          {selectedProjectId && projects && (
            <div
              className="flex items-center gap-2 px-3 py-2 mt-1 text-xs text-primary cursor-pointer hover:underline"
              onClick={() => setSelectedProjectId(null)}
            >
              Showing: {projects.find(p => p.id === selectedProjectId)?.name}
              <span className="text-muted-foreground">(click to clear)</span>
            </div>
          )}
        </div>

        {/* Conversation list */}
        <ScrollArea className="flex-1 min-h-0 px-2">
          <div className="space-y-4 pb-4">
            {loadingAssessments ? (
              <div className="space-y-2 px-3">
                {Array.from({ length: 8 }).map((_, i) => (
                  <div key={i} className="space-y-2 py-2">
                    <Skeleton className="h-4 w-full" />
                    <Skeleton className="h-3 w-1/3" />
                  </div>
                ))}
              </div>
            ) : filteredAssessments.length === 0 ? (
              <div className="text-center py-8 text-muted-foreground px-3">
                <MessageSquare className="mx-auto h-8 w-8 mb-2 opacity-50" />
                <p className="text-sm">
                  {searchQuery ? 'No assessments found' : 'No assessments yet'}
                </p>
              </div>
            ) : (
              groupOrder.map((groupKey) => {
                const items = groupedAssessments[groupKey];
                if (!items || items.length === 0) return null;

                return (
                  <div key={groupKey}>
                    <div className="px-3 py-2 text-xs font-medium text-muted-foreground">
                      {groupLabels[groupKey]}
                    </div>
                    <div className="space-y-0.5">
                      {items.map((assessment) => (
                        <ConversationItem
                          key={assessment.id}
                          assessment={assessment}
                          isActive={assessment.id === selectedAssessmentId}
                          isLive={liveAssessmentIds.has(assessment.id)}
                          onClick={() => handleSelectAssessment(assessment.id)}
                          onDelete={() => setDeleteTarget({
                            id: assessment.id,
                            name: getDisplayTitle(assessment),
                            type: 'assessment'
                          })}
                          onRename={() => {
                            setRenameTarget({
                              id: assessment.id,
                              name: assessment.name
                            });
                            setNewName(assessment.name);
                          }}
                          onAddToProject={(projectId) => {
                            assignToProjectMutation.mutate({
                              assessmentId: assessment.id,
                              projectId
                            });
                          }}
                          projects={projects}
                        />
                      ))}
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </ScrollArea>

      </div>

      {/* Collapsed sidebar toggle */}
      {sidebarCollapsed && (
        <div className="flex flex-col items-center py-3 px-2 border-r bg-sidebar">
          <Button
            variant="ghost"
            size="icon"
            onClick={() => setSidebarCollapsed(false)}
            className="h-10 w-10"
          >
            <PanelLeft className="h-5 w-5" />
          </Button>
          <Button
            variant="ghost"
            size="icon"
            onClick={handleNewAssessment}
            disabled={readOnly}
            title={readOnly ? 'Read-only access — you cannot start assessments' : undefined}
            className="h-10 w-10 mt-2"
          >
            <Plus className="h-5 w-5" />
          </Button>
        </div>
      )}

      {/* Main Content - Terminal-First View */}
      <div className="flex-1 flex flex-col min-w-0 h-full">
        {(() => {
          // Three states:
          // 1) Selected assessment → render terminal.
          // 2) Loading assessments list → spinner (avoid flash of empty
          //    state before auto-resume kicks in).
          // 3) Genuinely empty → CTA ("Click New Assessment to start").
          //    Auto-spawn is gone (Shape A) — terminal will only render
          //    against an existing assessment row.
          if (selectedAssessmentId) {
            return (
              <AssessmentTerminalView
                assessmentId={selectedAssessmentId}
                assessment={selectedAssessment}
                onAssessmentCreated={handleAssessmentCreated}
                onAssessmentStatusChanged={() => {
                  queryClient.invalidateQueries({ queryKey: ['assessments'] });
                }}
              />
            );
          }
          if (loadingAssessments) {
            return (
              <div className="flex-1 flex items-center justify-center text-muted-foreground">
                <Loader2 className="h-6 w-6 animate-spin" />
              </div>
            );
          }
          // Truly empty state — no assessments yet, no selection.
          return (
            <div className="flex-1 flex items-center justify-center p-12">
              <div className="text-center max-w-md space-y-4">
                <div className="mx-auto h-16 w-16 rounded-full bg-muted/50 flex items-center justify-center">
                  <MessageSquare className="h-8 w-8 text-muted-foreground" />
                </div>
                <div className="space-y-2">
                  <h2 className="text-xl font-semibold">No assessments yet</h2>
                  <p className="text-sm text-muted-foreground">
                    Start a new conversation with the AI agent to drive a
                    security assessment. Each conversation is automatically
                    saved and resumes where you left off.
                  </p>
                </div>
                <Button onClick={handleNewAssessment} size="lg" disabled={readOnly}>
                  <Plus className="mr-2 h-4 w-4" />
                  Start New Assessment
                </Button>
              </div>
            </div>
          );
        })()}
      </div>

      {/* New Assessment walkthrough — opens when user clicks "New
          Assessment" in the sidebar. Fields: name (required) + project
          (optional, with inline "+ New project…" option). */}
      <NewAssessmentModal
        open={showNewAssessmentModal}
        onOpenChange={setShowNewAssessmentModal}
        onCreated={(assessment) => {
          setShowNewAssessmentModal(false);
          handleAssessmentCreated(assessment);
        }}
        defaultProjectId={selectedProjectId}
      />

      {/* New Project Dialog */}
      <Dialog open={showNewProjectDialog} onOpenChange={setShowNewProjectDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Create Project</DialogTitle>
            <DialogDescription>
              Projects help you organize related assessments together.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-4">
            <div className="space-y-2">
              <Label htmlFor="project-name">Name</Label>
              <Input
                id="project-name"
                placeholder="e.g., Q1 2024 Security Review"
                value={newProjectName}
                onChange={(e) => setNewProjectName(e.target.value)}
                autoFocus
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="project-description">Description (optional)</Label>
              <Textarea
                id="project-description"
                placeholder="Add notes about this project..."
                value={newProjectDescription}
                onChange={(e) => setNewProjectDescription(e.target.value)}
                rows={3}
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowNewProjectDialog(false)}>
              Cancel
            </Button>
            <Button
              onClick={handleCreateProject}
              disabled={!newProjectName.trim() || createProjectMutation.isPending}
            >
              {createProjectMutation.isPending ? 'Creating...' : 'Create Project'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Rename Dialog */}
      <Dialog open={!!renameTarget} onOpenChange={(open) => !open && setRenameTarget(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Rename Assessment</DialogTitle>
          </DialogHeader>
          <div className="py-4">
            <Input
              value={newName}
              onChange={(e) => setNewName(e.target.value)}
              placeholder="Assessment name"
              autoFocus
              onKeyDown={(e) => {
                if (e.key === 'Enter') handleRename();
              }}
            />
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setRenameTarget(null)}>
              Cancel
            </Button>
            <Button
              onClick={handleRename}
              disabled={!newName.trim() || updateAssessmentMutation.isPending}
            >
              {updateAssessmentMutation.isPending ? 'Saving...' : 'Save'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Edit Project Dialog */}
      <Dialog open={!!editingProject} onOpenChange={(open) => !open && setEditingProject(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Edit Project</DialogTitle>
          </DialogHeader>
          <div className="space-y-4 py-4">
            <div className="space-y-2">
              <Label htmlFor="edit-project-name">Name</Label>
              <Input
                id="edit-project-name"
                value={newProjectName}
                onChange={(e) => setNewProjectName(e.target.value)}
                autoFocus
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="edit-project-description">Description (optional)</Label>
              <Textarea
                id="edit-project-description"
                value={newProjectDescription}
                onChange={(e) => setNewProjectDescription(e.target.value)}
                rows={3}
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setEditingProject(null)}>
              Cancel
            </Button>
            <Button
              onClick={() => {
                if (editingProject && newProjectName.trim()) {
                  updateProjectMutation.mutate({
                    id: editingProject.id,
                    name: newProjectName.trim(),
                    description: newProjectDescription.trim() || undefined,
                  });
                }
              }}
              disabled={!newProjectName.trim() || updateProjectMutation.isPending}
            >
              {updateProjectMutation.isPending ? 'Saving...' : 'Save'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Delete Confirmation Dialog */}
      <AlertDialog open={!!deleteTarget} onOpenChange={(open) => !open && setDeleteTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>
              Delete {deleteTarget?.type === 'project' ? 'project' : 'assessment'}?
            </AlertDialogTitle>
            <AlertDialogDescription>
              {deleteTarget?.type === 'project' ? (
                <>This will delete the project &ldquo;{deleteTarget?.name}&rdquo;. Assessments in this project will become unorganized.</>
              ) : (
                <>This will permanently delete &ldquo;{deleteTarget?.name}&rdquo; and all its findings. This action cannot be undone.</>
              )}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => {
                if (deleteTarget?.type === 'project') {
                  deleteProjectMutation.mutate(deleteTarget.id);
                } else if (deleteTarget) {
                  deleteAssessmentMutation.mutate(deleteTarget.id);
                }
              }}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}

export default function AssessmentsPage() {
  return (
    <Suspense fallback={
      <div className="flex h-[calc(100vh-4rem)] -m-6">
        <div className="w-80 border-r bg-sidebar p-3">
          <Skeleton className="h-10 w-full mb-3" />
          <Skeleton className="h-10 w-full mb-4" />
          <div className="space-y-3">
            {Array.from({ length: 8 }).map((_, i) => (
              <div key={i} className="space-y-2">
                <Skeleton className="h-4 w-full" />
                <Skeleton className="h-3 w-1/3" />
              </div>
            ))}
          </div>
        </div>
        <div className="flex-1 flex items-center justify-center">
          <Radar className="h-10 w-10 animate-pulse text-muted-foreground" />
        </div>
      </div>
    }>
      <AssessmentsPageContent />
    </Suspense>
  );
}
