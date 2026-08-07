'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { api } from '@/lib/tauri-api';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Skeleton } from '@/components/ui/skeleton';
import { Switch } from '@/components/ui/switch';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { toast } from 'sonner';
import {
  ArrowLeft,
  Github,
  ExternalLink,
  Check,
  X,
  Eye,
  EyeOff,
  RefreshCw,
  AlertTriangle,
  Key,
  Link as LinkIcon,
  FolderGit2,
  Lock,
  Globe,
  Star,
  GitFork,
  Plus,
  Search,
  Kanban,
} from 'lucide-react';
import { ScrollArea } from '@/components/ui/scroll-area';
import type { JiraProject, JiraBoard } from '@/lib/types';

interface IntegrationsConfig {
  github?: {
    enabled: boolean;
    personal_access_token?: string;
    username?: string;
  };
  jira?: {
    enabled: boolean;
    url?: string;
    email?: string;
    api_token?: string;
    project_key?: string;
  };
}

export default function IntegrationsPage() {
  const router = useRouter();
  const queryClient = useQueryClient();

  // GitHub form state
  const [githubToken, setGithubToken] = useState('');
  const [showGithubToken, setShowGithubToken] = useState(false);
  const [githubEnabled, setGithubEnabled] = useState(false);
  const [testingGithub, setTestingGithub] = useState(false);
  const [githubTestResult, setGithubTestResult] = useState<{ success: boolean; username?: string; error?: string } | null>(null);

  // GitHub repos state
  const [githubRepos, setGithubRepos] = useState<Array<{
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
  }>>([]);
  const [loadingRepos, setLoadingRepos] = useState(false);
  const [repoSearchQuery, setRepoSearchQuery] = useState('');
  const [addingRepo, setAddingRepo] = useState<string | null>(null);

  // Jira form state
  const [jiraEnabled, setJiraEnabled] = useState(false);
  const [jiraUrl, setJiraUrl] = useState('');
  const [jiraEmail, setJiraEmail] = useState('');
  const [jiraToken, setJiraToken] = useState('');
  const [jiraProjectKey, setJiraProjectKey] = useState('');
  const [showJiraToken, setShowJiraToken] = useState(false);
  const [testingJira, setTestingJira] = useState(false);
  const [jiraTestResult, setJiraTestResult] = useState<{ success: boolean; user?: string; error?: string } | null>(null);
  const [jiraProjects, setJiraProjects] = useState<JiraProject[]>([]);
  const [loadingJiraProjects, setLoadingJiraProjects] = useState(false);
  const [jiraBoards, setJiraBoards] = useState<JiraBoard[]>([]);
  const [loadingJiraBoards, setLoadingJiraBoards] = useState(false);

  const { data: integrations, isLoading } = useQuery({
    queryKey: ['integrations'],
    queryFn: async () => {
      try {
        return await api.config.integrations.get();
      } catch {
        // Return default if not found
        return { github: { enabled: false }, jira: { enabled: false } } as IntegrationsConfig;
      }
    },
  });

  // Fetch existing repositories to check which GitHub repos are already added
  const { data: existingRepos } = useQuery({
    queryKey: ['repositories'],
    queryFn: () => api.repositories.list(),
  });

  // Get set of already-added GitHub repo full names for quick lookup
  const addedRepoNames = new Set(
    existingRepos
      ?.filter((r) => r.source_type === 'github' && r.github_owner && r.github_repo)
      .map((r) => `${r.github_owner}/${r.github_repo}`) || []
  );

  // Initialize form state when data loads
  const [initialized, setInitialized] = useState(false);
  useEffect(() => {
    if (integrations && !initialized) {
      if (integrations.github) {
        setGithubEnabled(integrations.github.enabled);
        if (integrations.github.personal_access_token) {
          setGithubToken(integrations.github.personal_access_token);
        }
        // If we have a saved username, show as connected
        if (integrations.github.username) {
          setGithubTestResult({ success: true, username: integrations.github.username });
        }
      }
      if (integrations.jira) {
        setJiraEnabled(integrations.jira.enabled);
        setJiraUrl(integrations.jira.url || '');
        setJiraEmail(integrations.jira.email || '');
        setJiraToken(integrations.jira.api_token || '');
        setJiraProjectKey(integrations.jira.project_key || '');
      }
      setInitialized(true);
    }
  }, [integrations, initialized]);

  // Auto-load GitHub repos when we have a saved token
  useEffect(() => {
    if (initialized && integrations?.github?.enabled && integrations?.github?.personal_access_token && githubRepos.length === 0 && !loadingRepos) {
      fetchGithubRepos(integrations.github.personal_access_token);
    }
  }, [initialized, integrations?.github?.enabled, integrations?.github?.personal_access_token]);

  // Auto-load Jira projects when we have saved credentials
  useEffect(() => {
    if (initialized && jiraEnabled && jiraUrl && jiraEmail && jiraToken && jiraProjects.length === 0 && !loadingJiraProjects) {
      // Mark as connected (we have saved creds) and fetch projects
      setJiraTestResult({ success: true, user: jiraEmail });
      fetchJiraProjects();
    }
  }, [initialized, jiraEnabled, jiraUrl, jiraEmail, jiraToken]);

  const saveMutation = useMutation({
    mutationFn: (config: IntegrationsConfig) => api.config.integrations.update(config),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['integrations'] });
      toast.success('Integrations saved');
    },
    onError: (error: Error) => {
      toast.error(`Failed to save integrations: ${error.message}`);
    },
  });

  const handleSaveGithub = () => {
    const config: IntegrationsConfig = {
      ...integrations,
      github: {
        enabled: githubEnabled,
        personal_access_token: githubToken || undefined,
        username: githubTestResult?.username,
      },
    };
    saveMutation.mutate(config);
  };

  const handleSaveJira = () => {
    const config: IntegrationsConfig = {
      ...integrations,
      jira: {
        enabled: jiraEnabled,
        url: jiraUrl || undefined,
        email: jiraEmail || undefined,
        api_token: jiraToken || undefined,
        project_key: jiraProjectKey || undefined,
      },
    };
    saveMutation.mutate(config);
  };

  const fetchGithubRepos = async (token: string) => {
    setLoadingRepos(true);
    try {
      // Fetch user's repos (includes private repos with repo scope)
      const response = await fetch('https://api.github.com/user/repos?per_page=100&sort=updated&affiliation=owner,collaborator,organization_member', {
        headers: {
          Authorization: `Bearer ${token}`,
          Accept: 'application/vnd.github.v3+json',
        },
      });

      if (response.ok) {
        const repos = await response.json();
        setGithubRepos(repos);
      }
    } catch (error) {
      console.error('Failed to fetch repos:', error);
    } finally {
      setLoadingRepos(false);
    }
  };

  const testGithubConnection = async () => {
    if (!githubToken) {
      toast.error('Please enter a Personal Access Token');
      return;
    }

    setTestingGithub(true);
    setGithubTestResult(null);
    setGithubRepos([]);

    try {
      // Test the token by fetching user info
      const response = await fetch('https://api.github.com/user', {
        headers: {
          Authorization: `Bearer ${githubToken}`,
          Accept: 'application/vnd.github.v3+json',
        },
      });

      if (response.ok) {
        const data = await response.json();
        setGithubTestResult({ success: true, username: data.login });
        toast.success(`Connected as ${data.login}`);
        // Fetch repos after successful connection
        fetchGithubRepos(githubToken);
      } else if (response.status === 401) {
        setGithubTestResult({ success: false, error: 'Invalid token' });
        toast.error('Invalid Personal Access Token');
      } else {
        setGithubTestResult({ success: false, error: `HTTP ${response.status}` });
        toast.error(`GitHub API error: ${response.status}`);
      }
    } catch (error) {
      setGithubTestResult({ success: false, error: 'Connection failed' });
      toast.error('Failed to connect to GitHub');
    } finally {
      setTestingGithub(false);
    }
  };

  const handleAddGithubRepo = async (repo: typeof githubRepos[0]) => {
    setAddingRepo(repo.full_name);
    try {
      await api.repositories.add({
        name: repo.name,
        path: repo.clone_url,
        source_type: 'github',
        github_owner: repo.full_name.split('/')[0],
        github_repo: repo.name,
      });
      toast.success(`Added ${repo.name} to repositories`);
      queryClient.invalidateQueries({ queryKey: ['repositories'] });
    } catch (error) {
      toast.error(`Failed to add repository: ${error}`);
    } finally {
      setAddingRepo(null);
    }
  };

  // Jira connection test
  const testJiraConnection = async () => {
    if (!jiraUrl || !jiraEmail || !jiraToken) {
      toast.error('Please fill in Jira URL, email, and API token');
      return;
    }

    setTestingJira(true);
    setJiraTestResult(null);
    setJiraProjects([]);
    setJiraBoards([]);

    try {
      const result = await api.jira.testConnection({
        url: jiraUrl,
        email: jiraEmail,
        api_token: jiraToken,
      });

      if (result.status === 'ok') {
        setJiraTestResult({ success: true, user: result.user });
        toast.success(`Connected as ${result.user}`);
        // Fetch projects after successful connection
        fetchJiraProjects();
      } else {
        setJiraTestResult({ success: false, error: result.error || 'Connection failed' });
        toast.error(`Jira connection failed: ${result.error}`);
      }
    } catch (error) {
      setJiraTestResult({ success: false, error: 'Connection failed' });
      toast.error('Failed to connect to Jira');
    } finally {
      setTestingJira(false);
    }
  };

  // Fetch Jira projects
  const fetchJiraProjects = async () => {
    setLoadingJiraProjects(true);
    try {
      const result = await api.jira.listProjectsWithCredentials({
        url: jiraUrl,
        email: jiraEmail,
        api_token: jiraToken,
      });

      if (result.status === 'ok' && result.projects) {
        setJiraProjects(result.projects);
        // If we have a saved project key, load its boards
        if (jiraProjectKey) {
          fetchJiraBoards(jiraProjectKey);
        }
      }
    } catch (error) {
      console.error('Failed to fetch Jira projects:', error);
    } finally {
      setLoadingJiraProjects(false);
    }
  };

  // Fetch Jira boards for a project
  const fetchJiraBoards = async (projectKey: string) => {
    if (!projectKey) {
      setJiraBoards([]);
      return;
    }
    setLoadingJiraBoards(true);
    try {
      const result = await api.jira.listBoards(projectKey);
      if (result.status === 'ok' && result.boards) {
        setJiraBoards(result.boards);
      }
    } catch (error) {
      console.error('Failed to fetch Jira boards:', error);
    } finally {
      setLoadingJiraBoards(false);
    }
  };

  // Handle project selection change
  const handleJiraProjectChange = (key: string) => {
    setJiraProjectKey(key);
    setJiraBoards([]);
    if (key) {
      fetchJiraBoards(key);
    }
  };

  const filteredRepos = githubRepos.filter(repo =>
    repo.full_name.toLowerCase().includes(repoSearchQuery.toLowerCase()) ||
    (repo.description && repo.description.toLowerCase().includes(repoSearchQuery.toLowerCase()))
  );

  if (isLoading) {
    return (
      <div className="space-y-6">
        <Skeleton className="h-8 w-48" />
        <Skeleton className="h-64" />
        <Skeleton className="h-64" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <Button
          variant="ghost"
          size="sm"
          onClick={() => router.push('/config')}
          className="mb-2 -ml-2"
        >
          <ArrowLeft className="mr-2 h-4 w-4" />
          Back to Configuration
        </Button>
        <h1 className="text-3xl font-bold">Integrations</h1>
        <p className="text-muted-foreground">
          Connect external services for enhanced functionality
        </p>
      </div>

      {/* GitHub Integration */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-gray-100 dark:bg-gray-800">
                <Github className="h-6 w-6" />
              </div>
              <div>
                <CardTitle>GitHub</CardTitle>
                <CardDescription>Access private repositories for security scanning</CardDescription>
              </div>
            </div>
            <Switch
              checked={githubEnabled}
              onCheckedChange={setGithubEnabled}
            />
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          {githubEnabled && (
            <>
              <div className="rounded-md bg-blue-50 dark:bg-blue-950 p-4">
                <div className="flex gap-3">
                  <AlertTriangle className="h-5 w-5 text-blue-600 shrink-0 mt-0.5" />
                  <div className="text-sm text-blue-800 dark:text-blue-200">
                    <p className="font-medium mb-1">Personal Access Token Required</p>
                    <p className="text-blue-700 dark:text-blue-300">
                      Create a Personal Access Token (Classic) with <code className="bg-blue-100 dark:bg-blue-900 px-1 rounded">repo</code> scope
                      to access private repositories.
                    </p>
                    <a
                      href="https://github.com/settings/tokens/new?scopes=repo&description=Pentest%20Platform"
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-1 mt-2 text-blue-600 dark:text-blue-400 hover:underline"
                    >
                      Create token on GitHub
                      <ExternalLink className="h-3 w-3" />
                    </a>
                  </div>
                </div>
              </div>

              <div className="space-y-2">
                <Label htmlFor="github-token">Personal Access Token</Label>
                <div className="flex gap-2">
                  <div className="relative flex-1">
                    <Input
                      id="github-token"
                      type={showGithubToken ? 'text' : 'password'}
                      placeholder="ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
                      value={githubToken}
                      onChange={(e) => {
                        setGithubToken(e.target.value);
                        setGithubTestResult(null);
                      }}
                    />
                    <Button
                      type="button"
                      variant="ghost"
                      size="icon"
                      className="absolute right-0 top-0 h-full px-3"
                      onClick={() => setShowGithubToken(!showGithubToken)}
                    >
                      {showGithubToken ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                    </Button>
                  </div>
                  <Button
                    variant="outline"
                    onClick={testGithubConnection}
                    disabled={testingGithub || !githubToken}
                  >
                    {testingGithub ? (
                      <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
                    ) : (
                      <LinkIcon className="h-4 w-4 mr-2" />
                    )}
                    Test
                  </Button>
                </div>
              </div>

              {githubTestResult && (
                <div className={`flex items-center gap-2 p-3 rounded-md ${
                  githubTestResult.success
                    ? 'bg-green-50 dark:bg-green-950 text-green-800 dark:text-green-200'
                    : 'bg-red-50 dark:bg-red-950 text-red-800 dark:text-red-200'
                }`}>
                  {githubTestResult.success ? (
                    <>
                      <Check className="h-4 w-4" />
                      <span>Connected as <strong>@{githubTestResult.username}</strong></span>
                    </>
                  ) : (
                    <>
                      <X className="h-4 w-4" />
                      <span>{githubTestResult.error}</span>
                    </>
                  )}
                </div>
              )}

              {/* GitHub Repositories Browser - show if connected or have saved credentials */}
              {(githubTestResult?.success || (integrations?.github?.enabled && integrations?.github?.username) || githubRepos.length > 0) && (
                <div className="space-y-3 pt-4 border-t">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <FolderGit2 className="h-5 w-5 text-muted-foreground" />
                      <h3 className="font-medium">Your Repositories</h3>
                      <Badge variant="secondary">{githubRepos.length}</Badge>
                    </div>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => fetchGithubRepos(githubToken)}
                      disabled={loadingRepos}
                    >
                      <RefreshCw className={`h-4 w-4 mr-1 ${loadingRepos ? 'animate-spin' : ''}`} />
                      Refresh
                    </Button>
                  </div>

                  {/* Search */}
                  <div className="relative">
                    <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                    <Input
                      placeholder="Search repositories..."
                      value={repoSearchQuery}
                      onChange={(e) => setRepoSearchQuery(e.target.value)}
                      className="pl-9"
                    />
                  </div>

                  {/* Repos List */}
                  {loadingRepos ? (
                    <div className="space-y-2">
                      {[1, 2, 3].map((i) => (
                        <Skeleton key={i} className="h-16 w-full" />
                      ))}
                    </div>
                  ) : (
                    <ScrollArea className="h-[300px] rounded-md border">
                      <div className="p-2 space-y-2">
                        {filteredRepos.length === 0 ? (
                          <p className="text-center py-8 text-muted-foreground">
                            {repoSearchQuery ? 'No matching repositories' : 'No repositories found'}
                          </p>
                        ) : (
                          filteredRepos.map((repo) => (
                            <div
                              key={repo.id}
                              className="flex items-center justify-between p-3 rounded-lg border bg-card hover:bg-muted/50 transition-colors"
                            >
                              <div className="flex-1 min-w-0">
                                <div className="flex items-center gap-2">
                                  {repo.private ? (
                                    <Lock className="h-4 w-4 text-amber-500 shrink-0" />
                                  ) : (
                                    <Globe className="h-4 w-4 text-green-500 shrink-0" />
                                  )}
                                  <a
                                    href={repo.html_url}
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    className="font-medium hover:underline truncate"
                                  >
                                    {repo.full_name}
                                  </a>
                                </div>
                                {repo.description && (
                                  <p className="text-sm text-muted-foreground truncate mt-1">
                                    {repo.description}
                                  </p>
                                )}
                                <div className="flex items-center gap-3 mt-1 text-xs text-muted-foreground">
                                  {repo.language && (
                                    <span className="flex items-center gap-1">
                                      <span className="h-2 w-2 rounded-full bg-primary" />
                                      {repo.language}
                                    </span>
                                  )}
                                  <span className="flex items-center gap-1">
                                    <Star className="h-3 w-3" />
                                    {repo.stargazers_count}
                                  </span>
                                  <span className="flex items-center gap-1">
                                    <GitFork className="h-3 w-3" />
                                    {repo.forks_count}
                                  </span>
                                </div>
                              </div>
                              {addedRepoNames.has(repo.full_name) ? (
                                <Badge variant="secondary" className="ml-2 shrink-0">
                                  <Check className="h-3 w-3 mr-1" />
                                  Added
                                </Badge>
                              ) : (
                                <Button
                                  size="sm"
                                  variant="outline"
                                  onClick={() => handleAddGithubRepo(repo)}
                                  disabled={addingRepo === repo.full_name}
                                  className="ml-2 shrink-0"
                                >
                                  {addingRepo === repo.full_name ? (
                                    <RefreshCw className="h-4 w-4 animate-spin" />
                                  ) : (
                                    <>
                                      <Plus className="h-4 w-4 mr-1" />
                                      Add
                                    </>
                                  )}
                                </Button>
                              )}
                            </div>
                          ))
                        )}
                      </div>
                    </ScrollArea>
                  )}
                </div>
              )}

              <div className="flex justify-end pt-2">
                <Button
                  onClick={handleSaveGithub}
                  disabled={saveMutation.isPending}
                >
                  {saveMutation.isPending ? 'Saving...' : 'Save GitHub Settings'}
                </Button>
              </div>
            </>
          )}

          {!githubEnabled && (
            <p className="text-sm text-muted-foreground">
              Enable GitHub integration to scan private repositories and access GitHub-hosted code.
            </p>
          )}
        </CardContent>
      </Card>

      {/* Jira Integration */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-blue-100 dark:bg-blue-900">
                <Key className="h-6 w-6 text-blue-600" />
              </div>
              <div>
                <CardTitle>Jira</CardTitle>
                <CardDescription>Create tickets for security findings</CardDescription>
              </div>
            </div>
            <Switch
              checked={jiraEnabled}
              onCheckedChange={setJiraEnabled}
            />
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          {jiraEnabled && (
            <>
              {/* Credentials Section */}
              <div className="grid gap-4 md:grid-cols-2">
                <div className="space-y-2">
                  <Label htmlFor="jira-url">Jira URL</Label>
                  <Input
                    id="jira-url"
                    placeholder="https://yourcompany.atlassian.net"
                    value={jiraUrl}
                    onChange={(e) => {
                      setJiraUrl(e.target.value);
                      setJiraTestResult(null);
                    }}
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="jira-email">Email</Label>
                  <Input
                    id="jira-email"
                    type="email"
                    placeholder="you@company.com"
                    value={jiraEmail}
                    onChange={(e) => {
                      setJiraEmail(e.target.value);
                      setJiraTestResult(null);
                    }}
                  />
                </div>
              </div>

              <div className="space-y-2">
                <Label htmlFor="jira-token">API Token</Label>
                <div className="flex gap-2">
                  <div className="relative flex-1">
                    <Input
                      id="jira-token"
                      type={showJiraToken ? 'text' : 'password'}
                      placeholder="Your Jira API token"
                      value={jiraToken}
                      onChange={(e) => {
                        setJiraToken(e.target.value);
                        setJiraTestResult(null);
                      }}
                    />
                    <Button
                      type="button"
                      variant="ghost"
                      size="icon"
                      className="absolute right-0 top-0 h-full px-3"
                      onClick={() => setShowJiraToken(!showJiraToken)}
                    >
                      {showJiraToken ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                    </Button>
                  </div>
                  <Button
                    variant="outline"
                    onClick={testJiraConnection}
                    disabled={testingJira || !jiraUrl || !jiraEmail || !jiraToken}
                  >
                    {testingJira ? (
                      <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
                    ) : (
                      <LinkIcon className="h-4 w-4 mr-2" />
                    )}
                    Test
                  </Button>
                </div>
              </div>

              <div className="text-sm text-muted-foreground">
                <a
                  href="https://id.atlassian.com/manage-profile/security/api-tokens"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-1 text-primary hover:underline"
                >
                  Create Jira API token
                  <ExternalLink className="h-3 w-3" />
                </a>
              </div>

              {/* Connection Status */}
              {jiraTestResult && (
                <div className={`flex items-center gap-2 p-3 rounded-md ${
                  jiraTestResult.success
                    ? 'bg-green-50 dark:bg-green-950 text-green-800 dark:text-green-200'
                    : 'bg-red-50 dark:bg-red-950 text-red-800 dark:text-red-200'
                }`}>
                  {jiraTestResult.success ? (
                    <>
                      <Check className="h-4 w-4" />
                      <span>Connected as <strong>{jiraTestResult.user}</strong></span>
                    </>
                  ) : (
                    <>
                      <X className="h-4 w-4" />
                      <span>{jiraTestResult.error}</span>
                    </>
                  )}
                </div>
              )}

              {/* Project & Board Picker - shown after successful connection */}
              {(jiraTestResult?.success || jiraProjects.length > 0) && (
                <div className="space-y-4 pt-4 border-t">
                  <div className="flex items-center gap-2">
                    <Kanban className="h-5 w-5 text-muted-foreground" />
                    <h3 className="font-medium">Project & Board</h3>
                    {loadingJiraProjects && (
                      <RefreshCw className="h-4 w-4 animate-spin text-muted-foreground" />
                    )}
                  </div>

                  <div className="grid gap-4 md:grid-cols-2">
                    {/* Project Picker */}
                    <div className="space-y-2">
                      <Label>Default Project</Label>
                      {jiraProjects.length > 0 ? (
                        <Select value={jiraProjectKey} onValueChange={handleJiraProjectChange}>
                          <SelectTrigger>
                            <SelectValue placeholder="Select a project..." />
                          </SelectTrigger>
                          <SelectContent>
                            {jiraProjects.map((project) => (
                              <SelectItem key={project.key} value={project.key}>
                                <span className="flex items-center gap-2">
                                  <Badge variant="outline" className="font-mono text-xs">
                                    {project.key}
                                  </Badge>
                                  {project.name}
                                </span>
                              </SelectItem>
                            ))}
                          </SelectContent>
                        </Select>
                      ) : loadingJiraProjects ? (
                        <Skeleton className="h-10 w-full" />
                      ) : (
                        <Input
                          placeholder="SEC"
                          value={jiraProjectKey}
                          onChange={(e) => setJiraProjectKey(e.target.value)}
                        />
                      )}
                    </div>

                    {/* Board Display */}
                    <div className="space-y-2">
                      <Label>Boards</Label>
                      {loadingJiraBoards ? (
                        <Skeleton className="h-10 w-full" />
                      ) : jiraBoards.length > 0 ? (
                        <div className="flex flex-wrap gap-2 p-2 rounded-md border bg-muted/30 min-h-[40px] items-center">
                          {jiraBoards.map((board) => (
                            <Badge key={board.id} variant="secondary" className="text-xs">
                              {board.name}
                              <span className="ml-1 text-muted-foreground">
                                ({board.type})
                              </span>
                            </Badge>
                          ))}
                        </div>
                      ) : jiraProjectKey ? (
                        <p className="text-sm text-muted-foreground p-2 border rounded-md bg-muted/30">
                          No boards found for this project
                        </p>
                      ) : (
                        <p className="text-sm text-muted-foreground p-2 border rounded-md bg-muted/30">
                          Select a project to see boards
                        </p>
                      )}
                    </div>
                  </div>

                  {/* Projects List */}
                  {jiraProjects.length > 0 && (
                    <div className="text-xs text-muted-foreground">
                      {jiraProjects.length} project{jiraProjects.length !== 1 ? 's' : ''} available
                    </div>
                  )}
                </div>
              )}

              <div className="flex justify-end gap-2 pt-2">
                <Button
                  onClick={handleSaveJira}
                  disabled={saveMutation.isPending}
                >
                  {saveMutation.isPending ? 'Saving...' : 'Save Jira Settings'}
                </Button>
              </div>
            </>
          )}

          {!jiraEnabled && (
            <p className="text-sm text-muted-foreground">
              Enable Jira integration to automatically create tickets for security findings.
            </p>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
