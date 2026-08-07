'use client';

import { useState, useEffect } from 'react';
import { PageHeader } from '@/components/layout/page-header';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { api, isTauri } from '@/lib/tauri-api';
import type { Repository, CodeScanType, Severity } from '@/lib/types';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import { Skeleton } from '@/components/ui/skeleton';
import { Checkbox } from '@/components/ui/checkbox';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
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
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { toast } from 'sonner';
import {
  FolderGit2,
  Plus,
  Play,
  Settings,
  MoreVertical,
  Trash2,
  Eye,
  RefreshCw,
  FolderOpen,
  AlertTriangle,
  CheckCircle2,
  Clock,
  FileCode,
  Github,
  Globe,
  ExternalLink,
  Search,
  Lock,
  Star,
  GitFork,
  Check,
  Loader2,
} from 'lucide-react';
import { ScrollArea } from '@/components/ui/scroll-area';

const SCAN_TYPES: { value: CodeScanType; label: string; description: string }[] = [
  { value: 'sast', label: 'SAST (Semgrep)', description: 'Static application security testing' },
  { value: 'secrets', label: 'Secrets Detection', description: 'Find hardcoded credentials' },
  { value: 'dependencies', label: 'Dependency Audit', description: 'Vulnerable packages' },
  { value: 'iac', label: 'Infrastructure as Code', description: 'Terraform, K8s, Docker' },
  { value: 'python', label: 'Python (Bandit)', description: 'Python-specific scanning' },
  { value: 'javascript', label: 'Node.js (njsscan)', description: 'JavaScript/Node scanning' },
];

const SEVERITY_OPTIONS: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

function getSeverityColor(severity: Severity): string {
  switch (severity) {
    case 'critical':
      return 'bg-red-500';
    case 'high':
      return 'bg-orange-500';
    case 'medium':
      return 'bg-yellow-500';
    case 'low':
      return 'bg-blue-500';
    default:
      return 'bg-gray-500';
  }
}

function formatTimeAgo(dateString: string): string {
  const date = new Date(dateString);
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffMins = Math.floor(diffMs / 60000);
  const diffHours = Math.floor(diffMins / 60);
  const diffDays = Math.floor(diffHours / 24);

  if (diffMins < 60) return `${diffMins} minutes ago`;
  if (diffHours < 24) return `${diffHours} hours ago`;
  return `${diffDays} days ago`;
}

// Repos must be Git-hosted (per the v0.1.57 enterprise direction).
// `local` is kept in the type only for backwards compatibility with
// rows already in the local SQLite from earlier versions — it can no
// longer be created via the UI.
type RepoSourceType = 'local' | 'github';

interface GitHubRepo {
  id: number;
  name: string;
  full_name: string;
  description: string | null;
  private: boolean;
  html_url: string;
  clone_url: string;
  stargazers_count: number;
  forks_count: number;
  language: string | null;
  updated_at: string;
}

export default function RepositoriesPage() {
  const queryClient = useQueryClient();
  const [addDialogOpen, setAddDialogOpen] = useState(false);
  const [settingsDialogOpen, setSettingsDialogOpen] = useState(false);
  const [selectedRepo, setSelectedRepo] = useState<Repository | null>(null);
  const [scanningRepos, setScanningRepos] = useState<Map<string, string>>(new Map());

  // Form state for adding repository
  // GitHub-only since v0.1.57 — no UI surface for local-directory adds.
  // The state hook stays declared so legacy code paths (handleAddRepo,
  // resetForm) keep type-checking, but the value is fixed at 'github'.
  const [repoSourceType, setRepoSourceType] = useState<RepoSourceType>('github');
  const [newRepoPath] = useState('');
  const [newRepoGithubUrl, setNewRepoGithubUrl] = useState('');
  const [newRepoName, setNewRepoName] = useState('');
  const [newRepoScanTypes, setNewRepoScanTypes] = useState<CodeScanType[]>(['sast', 'secrets', 'dependencies']);
  const [newRepoSeverity, setNewRepoSeverity] = useState<Severity>('medium');
  const [newRepoGitHistory, setNewRepoGitHistory] = useState(false);
  const [dialogOpen, setDialogOpen] = useState<(() => Promise<string | null>) | null>(null);

  // GitHub browsing state
  const [githubRepos, setGithubRepos] = useState<GitHubRepo[]>([]);
  const [loadingGithubRepos, setLoadingGithubRepos] = useState(false);
  const [githubSearchQuery, setGithubSearchQuery] = useState('');
  const [selectedGithubRepo, setSelectedGithubRepo] = useState<GitHubRepo | null>(null);

  // Fetch integrations config to check GitHub connection
  const { data: integrations } = useQuery({
    queryKey: ['integrations'],
    queryFn: () => api.config.integrations.get(),
  });

  const isGithubConnected = integrations?.github?.enabled && integrations?.github?.personal_access_token;
  const githubToken = integrations?.github?.personal_access_token;

  // Fetch GitHub repos when tab switches to github and we're connected
  const fetchGithubRepos = async () => {
    if (!githubToken) return;

    setLoadingGithubRepos(true);
    try {
      const response = await fetch('https://api.github.com/user/repos?per_page=100&sort=updated&affiliation=owner,collaborator,organization_member', {
        headers: {
          Authorization: `Bearer ${githubToken}`,
          Accept: 'application/vnd.github.v3+json',
        },
      });

      if (response.ok) {
        const repos = await response.json();
        setGithubRepos(repos);
      }
    } catch (error) {
      console.error('Failed to fetch GitHub repos:', error);
    } finally {
      setLoadingGithubRepos(false);
    }
  };

  // Fetch repos when switching to GitHub tab
  useEffect(() => {
    if (repoSourceType === 'github' && isGithubConnected && githubRepos.length === 0) {
      fetchGithubRepos();
    }
  }, [repoSourceType, isGithubConnected]);

  const filteredGithubRepos = githubRepos.filter(repo =>
    repo.full_name.toLowerCase().includes(githubSearchQuery.toLowerCase()) ||
    (repo.description && repo.description.toLowerCase().includes(githubSearchQuery.toLowerCase()))
  );

  const handleSelectGithubRepo = (repo: GitHubRepo) => {
    setSelectedGithubRepo(repo);
    setNewRepoGithubUrl(repo.clone_url);
    setNewRepoName(repo.name);
  };

  // Dynamically import Tauri dialog plugin
  useEffect(() => {
    if (isTauri()) {
      import('@tauri-apps/plugin-dialog').then((mod) => {
        setDialogOpen(() => async () => {
          const result = await mod.open({
            directory: true,
            multiple: false,
            title: 'Select Repository Directory',
          });
          return result as string | null;
        });
      }).catch(() => {
        // Dialog plugin not available
      });
    }
  }, []);

  // Fetch repositories
  const { data: repositories, isLoading } = useQuery({
    queryKey: ['repositories'],
    queryFn: () => api.repositories.list(),
  });

  // Add repository mutation
  const addRepoMutation = useMutation({
    mutationFn: api.repositories.add,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['repositories'] });
      toast.success('Repository added successfully');
      setAddDialogOpen(false);
      resetForm();
    },
    onError: (error: Error) => {
      toast.error(`Failed to add repository: ${error.message}`);
    },
  });

  // Remove repository mutation
  const removeRepoMutation = useMutation({
    mutationFn: api.repositories.remove,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['repositories'] });
      toast.success('Repository removed');
    },
    onError: (error: Error) => {
      toast.error(`Failed to remove repository: ${error.message}`);
    },
  });

  // Scan a single repository with per-repo tracking and progress toasts
  const startScan = async (repo: Repository) => {
    const scanTypes = repo.default_scan_config?.scan_types ?? ['sast', 'secrets', 'dependencies'];
    const isGitHubRepo = repo.source_type === 'github';

    setScanningRepos((prev) => new Map(prev).set(repo.id, isGitHubRepo ? 'Cloning repository...' : 'Initializing scan...'));

    const toastId = toast.loading(
      `Scanning ${repo.name}...`,
      { description: isGitHubRepo ? 'Cloning repository from GitHub...' : `Running ${scanTypes.join(', ')}`, duration: Infinity },
    );

    // Update status after a delay to show progress stages
    const stageTimers: ReturnType<typeof setTimeout>[] = [];
    if (isGitHubRepo) {
      stageTimers.push(setTimeout(() => {
        setScanningRepos((prev) => new Map(prev).set(repo.id, 'Running security scanners...'));
        toast.loading(`Scanning ${repo.name}...`, { id: toastId, description: `Running ${scanTypes.join(', ')}` });
      }, 8000));
    }
    stageTimers.push(setTimeout(() => {
      setScanningRepos((prev) => new Map(prev).set(repo.id, 'Analyzing results...'));
      toast.loading(`Scanning ${repo.name}...`, { id: toastId, description: 'Analyzing results...' });
    }, isGitHubRepo ? 30000 : 15000));

    try {
      const result = await api.repositories.scan({ id: repo.id, scan_types: scanTypes });
      stageTimers.forEach(clearTimeout);
      setScanningRepos((prev) => { const next = new Map(prev); next.delete(repo.id); return next; });
      queryClient.invalidateQueries({ queryKey: ['repositories'] });

      if (result.findings_count > 0) {
        toast.success(`Scan complete: ${result.findings_count} findings`, {
          id: toastId,
          duration: 8000,
          description: `Completed in ${(result.scan_duration_ms / 1000).toFixed(1)}s`,
          action: { label: 'View Findings', onClick: () => window.location.href = '/findings' },
        });
      } else {
        toast.success('Scan complete: No findings', {
          id: toastId,
          duration: 5000,
          description: `Completed in ${(result.scan_duration_ms / 1000).toFixed(1)}s`,
        });
      }
    } catch (error: unknown) {
      stageTimers.forEach(clearTimeout);
      setScanningRepos((prev) => { const next = new Map(prev); next.delete(repo.id); return next; });
      const message = error instanceof Error ? error.message : typeof error === 'string' ? error : 'Unknown error';
      const isContainerError = message.toLowerCase().includes('container') || message.toLowerCase().includes('mcp') || message.toLowerCase().includes('connection');
      toast.error(`Scan failed`, {
        id: toastId,
        duration: 8000,
        description: isContainerError ? message : `${message}. Check that the Kali container is running.`,
      });
    }
  };

  const resetForm = () => {
    setRepoSourceType('github');
    setNewRepoGithubUrl('');
    setNewRepoName('');
    setNewRepoScanTypes(['sast', 'secrets', 'dependencies']);
    setNewRepoSeverity('medium');
    setNewRepoGitHistory(false);
    setSelectedGithubRepo(null);
    setGithubSearchQuery('');
  };

  // handleBrowse was the directory-picker callback for the local-tab
  // input. Local-directory adds were removed in v0.1.57; the function
  // is gone with them.

  const parseGithubUrl = (url: string): { owner: string; repo: string } | null => {
    // Support formats:
    // https://github.com/owner/repo
    // https://github.com/owner/repo.git
    // git@github.com:owner/repo.git
    // owner/repo
    const httpsMatch = url.match(/github\.com\/([^\/]+)\/([^\/\.]+)/);
    if (httpsMatch) {
      return { owner: httpsMatch[1], repo: httpsMatch[2] };
    }

    const sshMatch = url.match(/git@github\.com:([^\/]+)\/([^\/\.]+)/);
    if (sshMatch) {
      return { owner: sshMatch[1], repo: sshMatch[2] };
    }

    const shortMatch = url.match(/^([^\/]+)\/([^\/]+)$/);
    if (shortMatch) {
      return { owner: shortMatch[1], repo: shortMatch[2] };
    }

    return null;
  };

  const handleGithubUrlChange = (url: string) => {
    setNewRepoGithubUrl(url);
    const parsed = parseGithubUrl(url);
    if (parsed && !newRepoName) {
      setNewRepoName(parsed.repo);
    }
  };

  const handleAddRepo = () => {
    // Local-directory repos were removed in v0.1.57 — Maestro is an
    // enterprise tool, teams attach via Git hosts. The UI no longer
    // exposes a local tab.
    if (!newRepoGithubUrl) {
      toast.error('Please enter a GitHub repository URL');
      return;
    }

    const parsed = parseGithubUrl(newRepoGithubUrl);
    if (!parsed) {
      toast.error('Invalid GitHub URL format');
      return;
    }

    addRepoMutation.mutate({
      name: newRepoName || parsed.repo,
      path: `github:${parsed.owner}/${parsed.repo}`,
      source_type: 'github',
      github_owner: parsed.owner,
      github_repo: parsed.repo,
      default_scan_config: {
        scan_types: newRepoScanTypes,
        severity_threshold: newRepoSeverity,
        include_git_history: newRepoGitHistory,
      },
    });
  };

  const toggleScanType = (scanType: CodeScanType) => {
    setNewRepoScanTypes((prev) =>
      prev.includes(scanType)
        ? prev.filter((t) => t !== scanType)
        : [...prev, scanType]
    );
  };

  return (
    <div className="space-y-6">
      <PageHeader
        title="Code Repositories"
        description="Manage local and GitHub repositories for security scanning"
        actions={
        <Dialog open={addDialogOpen} onOpenChange={setAddDialogOpen}>
          <DialogTrigger asChild>
            <Button>
              <Plus className="h-4 w-4 mr-2" />
              Add Repository
            </Button>
          </DialogTrigger>
          <DialogContent className="max-w-2xl">
            <DialogHeader>
              <DialogTitle>Add Repository</DialogTitle>
              <DialogDescription>
                Add a local or GitHub repository for security scanning
              </DialogDescription>
            </DialogHeader>

            <div className="space-y-4 py-4">
              {/* GitHub-only since v0.1.57 — see
                  memory/feedback_github_only_repos.md for the rationale.
                  Local-directory adds were removed because per-machine
                  paths don't work for an enterprise tool that promises
                  team workflows + cross-machine sync. */}
              <div className="flex items-center gap-2 text-sm font-medium text-muted-foreground">
                <Github className="h-4 w-4" />
                GitHub Repository
              </div>
              <div className="space-y-4 mt-2">
                  {isGithubConnected ? (
                    <>
                      {/* Connected - Show browsable repos */}
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2 text-sm text-green-600">
                          <Check className="h-4 w-4" />
                          <span>Connected as @{integrations?.github?.username}</span>
                        </div>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={fetchGithubRepos}
                          disabled={loadingGithubRepos}
                        >
                          <RefreshCw className={`h-4 w-4 mr-1 ${loadingGithubRepos ? 'animate-spin' : ''}`} />
                          Refresh
                        </Button>
                      </div>

                      {/* Search */}
                      <div className="relative">
                        <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                        <Input
                          placeholder="Search your repositories..."
                          value={githubSearchQuery}
                          onChange={(e) => setGithubSearchQuery(e.target.value)}
                          className="pl-9"
                        />
                      </div>

                      {/* Repos List */}
                      {loadingGithubRepos ? (
                        <div className="flex items-center justify-center py-8">
                          <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
                        </div>
                      ) : (
                        <ScrollArea className="h-[200px] rounded-md border">
                          <div className="p-2 space-y-1">
                            {filteredGithubRepos.length === 0 ? (
                              <p className="text-center py-4 text-muted-foreground text-sm">
                                {githubSearchQuery ? 'No matching repositories' : 'No repositories found'}
                              </p>
                            ) : (
                              filteredGithubRepos.map((repo) => (
                                <div
                                  key={repo.id}
                                  className={`flex items-center justify-between p-2 rounded-md cursor-pointer transition-colors ${
                                    selectedGithubRepo?.id === repo.id
                                      ? 'bg-primary/10 border border-primary'
                                      : 'hover:bg-muted/50'
                                  }`}
                                  onClick={() => handleSelectGithubRepo(repo)}
                                >
                                  <div className="flex-1 min-w-0">
                                    <div className="flex items-center gap-2">
                                      {repo.private ? (
                                        <Lock className="h-3 w-3 text-amber-500 shrink-0" />
                                      ) : (
                                        <Globe className="h-3 w-3 text-green-500 shrink-0" />
                                      )}
                                      <span className="font-medium text-sm truncate">{repo.full_name}</span>
                                    </div>
                                    {repo.description && (
                                      <p className="text-xs text-muted-foreground truncate mt-0.5">
                                        {repo.description}
                                      </p>
                                    )}
                                    <div className="flex items-center gap-2 mt-0.5 text-xs text-muted-foreground">
                                      {repo.language && (
                                        <span>{repo.language}</span>
                                      )}
                                      <span className="flex items-center gap-0.5">
                                        <Star className="h-3 w-3" />
                                        {repo.stargazers_count}
                                      </span>
                                    </div>
                                  </div>
                                  {selectedGithubRepo?.id === repo.id && (
                                    <Check className="h-4 w-4 text-primary shrink-0 ml-2" />
                                  )}
                                </div>
                              ))
                            )}
                          </div>
                        </ScrollArea>
                      )}

                      {/* Selected repo indicator */}
                      {selectedGithubRepo && (
                        <div className="rounded-md bg-primary/5 border border-primary/20 p-3">
                          <div className="flex items-center gap-2">
                            <Github className="h-4 w-4" />
                            <span className="font-medium text-sm">{selectedGithubRepo.full_name}</span>
                            {selectedGithubRepo.private && (
                              <Badge variant="secondary" className="text-xs">
                                <Lock className="h-3 w-3 mr-1" />
                                Private
                              </Badge>
                            )}
                          </div>
                        </div>
                      )}
                    </>
                  ) : (
                    <>
                      {/* Not connected - Show URL input and prompt to connect */}
                      <div className="rounded-md bg-amber-50 dark:bg-amber-950 p-3 text-sm">
                        <div className="flex items-start gap-2">
                          <AlertTriangle className="h-4 w-4 mt-0.5 text-amber-600" />
                          <div>
                            <p className="font-medium text-amber-900 dark:text-amber-100">GitHub Not Connected</p>
                            <p className="text-amber-700 dark:text-amber-300">
                              Connect your GitHub account in{' '}
                              <a href="/config/integrations" className="underline font-medium">
                                Integrations
                              </a>{' '}
                              to browse your repositories directly.
                            </p>
                          </div>
                        </div>
                      </div>

                      <div className="space-y-2">
                        <Label htmlFor="github-url">GitHub Repository URL</Label>
                        <Input
                          id="github-url"
                          placeholder="https://github.com/owner/repo or owner/repo"
                          value={newRepoGithubUrl}
                          onChange={(e) => handleGithubUrlChange(e.target.value)}
                        />
                        <p className="text-xs text-muted-foreground">
                          Supports HTTPS URLs, SSH URLs, or owner/repo format
                        </p>
                      </div>
                    </>
                  )}
              </div>

              {/* Name input */}
              <div className="space-y-2">
                <Label htmlFor="name">Display Name</Label>
                <Input
                  id="name"
                  placeholder="my-app"
                  value={newRepoName}
                  onChange={(e) => setNewRepoName(e.target.value)}
                />
              </div>

              {/* Scan types */}
              <div className="space-y-2">
                <Label>Default Scan Types</Label>
                <div className="grid grid-cols-2 gap-2">
                  {SCAN_TYPES.map((scanType) => (
                    <div
                      key={scanType.value}
                      className="flex items-center space-x-2 p-2 rounded border hover:bg-muted/50 cursor-pointer"
                      onClick={() => toggleScanType(scanType.value)}
                    >
                      <Checkbox
                        checked={newRepoScanTypes.includes(scanType.value)}
                        onCheckedChange={() => toggleScanType(scanType.value)}
                      />
                      <div className="flex-1">
                        <div className="text-sm font-medium">{scanType.label}</div>
                        <div className="text-xs text-muted-foreground">
                          {scanType.description}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Severity threshold */}
              <div className="space-y-2">
                <Label>Severity Threshold</Label>
                <Select
                  value={newRepoSeverity}
                  onValueChange={(v) => setNewRepoSeverity(v as Severity)}
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {SEVERITY_OPTIONS.map((severity) => (
                      <SelectItem key={severity} value={severity}>
                        <span className="capitalize">{severity}</span>
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <p className="text-xs text-muted-foreground">
                  Only report findings at or above this severity level
                </p>
              </div>

              {/* Git history option */}
              <div className="flex items-center space-x-2">
                <Checkbox
                  id="git-history"
                  checked={newRepoGitHistory}
                  onCheckedChange={(checked) => setNewRepoGitHistory(checked === true)}
                />
                <div>
                  <Label htmlFor="git-history" className="cursor-pointer">
                    Include Git History
                  </Label>
                  <p className="text-xs text-muted-foreground">
                    Scan historical commits for secrets (slower)
                  </p>
                </div>
              </div>
            </div>

            <DialogFooter>
              <Button variant="outline" onClick={() => setAddDialogOpen(false)}>
                Cancel
              </Button>
              <Button onClick={handleAddRepo} disabled={addRepoMutation.isPending}>
                {addRepoMutation.isPending ? 'Adding...' : 'Add Repository'}
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
        }
      />

      {/* Repository List */}
      {isLoading ? (
        <div className="space-y-4">
          {[1, 2, 3].map((i) => (
            <Card key={i}>
              <CardContent className="py-6">
                <div className="flex items-center gap-4">
                  <Skeleton className="h-12 w-12 rounded-lg" />
                  <div className="flex-1 space-y-2">
                    <Skeleton className="h-5 w-48" />
                    <Skeleton className="h-4 w-64" />
                  </div>
                  <Skeleton className="h-9 w-24" />
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      ) : repositories && repositories.length > 0 ? (
        <div className="space-y-4">
          {repositories.map((repo) => {
            const isGitHub = repo.source_type === 'github';
            return (
            <Card key={repo.id} className="hover:bg-muted/50 transition-colors">
              <CardContent className="py-6">
                <div className="flex items-center gap-4">
                  {/* Icon */}
                  <div className={`p-3 rounded-lg ${isGitHub ? 'bg-gray-100 dark:bg-gray-800' : 'bg-primary/10'}`}>
                    {isGitHub ? (
                      <Github className="h-6 w-6 text-gray-700 dark:text-gray-300" />
                    ) : (
                      <FolderGit2 className="h-6 w-6 text-primary" />
                    )}
                  </div>

                  {/* Info */}
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <h3 className="font-semibold truncate">{repo.name}</h3>
                      {isGitHub && (
                        <Badge variant="secondary" className="text-xs">
                          <Github className="h-3 w-3 mr-1" />
                          GitHub
                        </Badge>
                      )}
                      {repo.languages.length > 0 && (
                        <div className="flex gap-1">
                          {repo.languages.slice(0, 3).map((lang) => (
                            <Badge key={lang} variant="outline" className="text-xs">
                              {lang}
                            </Badge>
                          ))}
                          {repo.languages.length > 3 && (
                            <Badge variant="outline" className="text-xs">
                              +{repo.languages.length - 3}
                            </Badge>
                          )}
                        </div>
                      )}
                    </div>
                    <div className="flex items-center gap-2">
                      <p className="text-sm text-muted-foreground truncate">
                        {isGitHub && repo.github_owner && repo.github_repo
                          ? `${repo.github_owner}/${repo.github_repo}`
                          : repo.path}
                      </p>
                      {isGitHub && repo.github_owner && repo.github_repo && (
                        <a
                          href={`https://github.com/${repo.github_owner}/${repo.github_repo}`}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-muted-foreground hover:text-foreground"
                          onClick={(e) => e.stopPropagation()}
                        >
                          <ExternalLink className="h-3 w-3" />
                        </a>
                      )}
                    </div>
                    <div className="flex items-center gap-4 mt-2">
                      {repo.last_scan ? (
                        <>
                          <span className="text-xs text-muted-foreground flex items-center gap-1">
                            <Clock className="h-3 w-3" />
                            Last scan: {formatTimeAgo(repo.last_scan)}
                          </span>
                          {repo.last_scan_findings && (
                            <div className="flex items-center gap-2">
                              {repo.last_scan_findings.critical > 0 && (
                                <Badge variant="destructive" className="text-xs">
                                  {repo.last_scan_findings.critical} Critical
                                </Badge>
                              )}
                              {repo.last_scan_findings.high > 0 && (
                                <Badge className="text-xs bg-orange-500">
                                  {repo.last_scan_findings.high} High
                                </Badge>
                              )}
                              {repo.last_scan_findings.medium > 0 && (
                                <Badge className="text-xs bg-yellow-500 text-black">
                                  {repo.last_scan_findings.medium} Medium
                                </Badge>
                              )}
                              {repo.last_scan_findings.critical === 0 &&
                                repo.last_scan_findings.high === 0 &&
                                repo.last_scan_findings.medium === 0 && (
                                  <span className="text-xs text-green-600 flex items-center gap-1">
                                    <CheckCircle2 className="h-3 w-3" />
                                    No significant findings
                                  </span>
                                )}
                            </div>
                          )}
                        </>
                      ) : (
                        <span className="text-xs text-muted-foreground flex items-center gap-1">
                          <AlertTriangle className="h-3 w-3" />
                          Not scanned yet
                        </span>
                      )}
                    </div>
                  </div>

                  {/* Actions */}
                  <div className="flex items-center gap-2">
                    {scanningRepos.has(repo.id) ? (
                      <div className="flex items-center gap-2 text-sm text-muted-foreground">
                        <Loader2 className="h-4 w-4 animate-spin text-primary" />
                        <span className="max-w-[160px] truncate">{scanningRepos.get(repo.id)}</span>
                      </div>
                    ) : (
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => startScan(repo)}
                      >
                        <Play className="h-4 w-4 mr-2" />
                        Scan
                      </Button>
                    )}
                    <DropdownMenu>
                      <DropdownMenuTrigger asChild>
                        <Button variant="ghost" size="icon">
                          <MoreVertical className="h-4 w-4" />
                        </Button>
                      </DropdownMenuTrigger>
                      <DropdownMenuContent align="end">
                        <DropdownMenuItem
                          onClick={() => {
                            setSelectedRepo(repo);
                            setSettingsDialogOpen(true);
                          }}
                        >
                          <Settings className="h-4 w-4 mr-2" />
                          Settings
                        </DropdownMenuItem>
                        <DropdownMenuItem>
                          <Eye className="h-4 w-4 mr-2" />
                          View Findings
                        </DropdownMenuItem>
                        <DropdownMenuItem
                          className="text-red-600"
                          onClick={() => removeRepoMutation.mutate(repo.id)}
                        >
                          <Trash2 className="h-4 w-4 mr-2" />
                          Remove
                        </DropdownMenuItem>
                      </DropdownMenuContent>
                    </DropdownMenu>
                  </div>
                </div>
              </CardContent>
            </Card>
            );
          })}
        </div>
      ) : (
        <Card>
          <CardContent className="py-12">
            <div className="text-center">
              <FileCode className="h-12 w-12 mx-auto text-muted-foreground mb-4" />
              <h3 className="font-semibold text-lg mb-2">No repositories configured</h3>
              <p className="text-muted-foreground mb-4">
                Add a local repository to start scanning for security vulnerabilities
              </p>
              <Button onClick={() => setAddDialogOpen(true)}>
                <Plus className="h-4 w-4 mr-2" />
                Add Repository
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Settings Dialog */}
      <Dialog open={settingsDialogOpen} onOpenChange={setSettingsDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Repository Settings</DialogTitle>
            <DialogDescription>
              Configure scan settings for {selectedRepo?.name}
            </DialogDescription>
          </DialogHeader>
          {selectedRepo && (
            <div className="space-y-4 py-4">
              <div className="space-y-2">
                <Label>Path</Label>
                <p className="text-sm text-muted-foreground">{selectedRepo.path}</p>
              </div>
              <div className="space-y-2">
                <Label>Container Path</Label>
                <p className="text-sm text-muted-foreground">{selectedRepo.container_path}</p>
              </div>
              <div className="space-y-2">
                <Label>Detected Languages</Label>
                <div className="flex flex-wrap gap-1">
                  {selectedRepo.languages.map((lang) => (
                    <Badge key={lang} variant="secondary">
                      {lang}
                    </Badge>
                  ))}
                </div>
              </div>
              <div className="space-y-2">
                <Label>Default Scan Types</Label>
                <div className="flex flex-wrap gap-1">
                  {(selectedRepo.default_scan_config?.scan_types ?? ['sast', 'secrets', 'dependencies']).map((type) => (
                    <Badge key={type} variant="outline">
                      {type}
                    </Badge>
                  ))}
                </div>
              </div>
            </div>
          )}
          <DialogFooter>
            <Button variant="outline" onClick={() => setSettingsDialogOpen(false)}>
              Close
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
