'use client';

import { useState, useEffect, useMemo, useCallback, useRef, Suspense } from 'react';
import { useSearchParams, useRouter } from 'next/navigation';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { api } from '@/lib/tauri-api';
import { jiraTicketUrl } from '@/lib/jira';
import type { Finding, JiraProject, JiraIssueType, JiraEpic, JiraSearchResult, FindingContentOverride } from '@/lib/types';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Switch } from '@/components/ui/switch';
import { Separator } from '@/components/ui/separator';
import { Skeleton } from '@/components/ui/skeleton';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs';
import { Textarea } from '@/components/ui/textarea';
// Popover removed — using custom dropdown for better z-index control
import {
  ArrowLeft,
  Ticket,
  AlertOctagon,
  AlertTriangle,
  AlertCircle,
  Info,
  Check,
  X,
  RefreshCw,
  ExternalLink,
  Layers,
  Search,
  ChevronsUpDown,
  Eye,
  Pencil,
  RotateCcw,
} from 'lucide-react';
import { toast } from 'sonner';

const severityConfig: Record<string, { icon: typeof AlertOctagon; color: string; textColor: string }> = {
  critical: { icon: AlertOctagon, color: 'bg-red-500', textColor: 'text-red-400' },
  high: { icon: AlertTriangle, color: 'bg-orange-500', textColor: 'text-orange-400' },
  medium: { icon: AlertCircle, color: 'bg-yellow-500', textColor: 'text-yellow-400' },
  low: { icon: Info, color: 'bg-blue-500', textColor: 'text-blue-400' },
  info: { icon: Info, color: 'bg-gray-500', textColor: 'text-slate-400' },
};

// ─── Searchable Epic Combobox ──────────────────────────────────────────────

function EpicCombobox({
  projectKey,
  value,
  onChange,
  epics,
  epicsLoading,
}: {
  projectKey: string;
  value: string;
  onChange: (value: string) => void;
  epics: JiraEpic[];
  epicsLoading: boolean;
}) {
  const [open, setOpen] = useState(false);
  const [search, setSearch] = useState('');
  const [searchResults, setSearchResults] = useState<JiraSearchResult[]>([]);
  const [searching, setSearching] = useState(false);
  const [searchComplete, setSearchComplete] = useState(false);
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const containerRef = useRef<HTMLDivElement | null>(null);
  const inputRef = useRef<HTMLInputElement | null>(null);

  const selectedEpic = useMemo(() => {
    if (!value || value === 'none') return null;
    // Check loaded epics first, then search results
    return epics.find((e) => e.key === value)
      || searchResults.find((r) => r.key === value)
      || null;
  }, [value, epics, searchResults]);

  // Close on outside click
  useEffect(() => {
    if (!open) return;
    const handler = (e: MouseEvent) => {
      if (containerRef.current && !containerRef.current.contains(e.target as Node)) {
        setOpen(false);
      }
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, [open]);

  // Debounced server search
  const doSearch = useCallback(
    async (query: string) => {
      if (!projectKey || !query.trim()) {
        setSearchResults([]);
        setSearching(false);
        setSearchComplete(false);
        return;
      }
      setSearching(true);
      setSearchComplete(false);
      try {
        const result = await api.jira.searchIssues(projectKey, query, {
          issueType: 'Epic',
          maxResults: 30,
        });
        setSearchResults(result.results || []);
      } catch {
        setSearchResults([]);
      } finally {
        setSearching(false);
        setSearchComplete(true);
      }
    },
    [projectKey]
  );

  const handleSearchChange = (val: string) => {
    setSearch(val);
    setSearchComplete(false);
    if (debounceRef.current !== null) clearTimeout(debounceRef.current);
    debounceRef.current = setTimeout(() => doSearch(val), 300);
  };

  // Merge local + server results, deduplicated by key
  const items = useMemo(() => {
    if (!search.trim()) {
      return epics.map((e) => ({ key: e.key, summary: e.summary, status: e.status }));
    }

    const localMatches = epics
      .filter(
        (e) =>
          e.summary.toLowerCase().includes(search.toLowerCase()) ||
          e.key.toLowerCase().includes(search.toLowerCase())
      )
      .map((e) => ({ key: e.key, summary: e.summary, status: e.status }));

    if (!searchComplete) {
      return localMatches;
    }

    // Merge: server results first, then local matches not in server results
    const serverItems = searchResults.map((r) => ({ key: r.key, summary: r.summary, status: r.status }));
    const serverKeys = new Set(serverItems.map((i) => i.key));
    const extraLocal = localMatches.filter((i) => !serverKeys.has(i.key));
    return [...serverItems, ...extraLocal];
  }, [search, searchComplete, searchResults, epics]);

  const selectItem = (key: string) => {
    onChange(key);
    setOpen(false);
    setSearch('');
    setSearchComplete(false);
    setSearchResults([]);
  };

  if (!projectKey) {
    return (
      <p className="text-sm text-muted-foreground p-2 border rounded-md bg-muted/30">
        Select a project first
      </p>
    );
  }

  if (epicsLoading) {
    return <Skeleton className="h-10" />;
  }

  return (
    <div ref={containerRef} className="relative">
      {/* Trigger button */}
      <button
        type="button"
        onClick={() => {
          setOpen(!open);
          // Focus input on next tick
          if (!open) setTimeout(() => inputRef.current?.focus(), 0);
        }}
        className="flex h-10 w-full items-center justify-between rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background hover:bg-accent/50 transition-colors"
      >
        {selectedEpic ? (
          <span className="flex items-center gap-2 truncate">
            <span className="inline-flex items-center rounded border px-1.5 py-0.5 font-mono text-xs text-muted-foreground shrink-0">
              {selectedEpic.key}
            </span>
            <span className="truncate">{selectedEpic.summary}</span>
          </span>
        ) : (
          <span className="text-muted-foreground">No epic (standalone)</span>
        )}
        <ChevronsUpDown className="ml-2 h-4 w-4 shrink-0 opacity-50" />
      </button>

      {/* Dropdown */}
      {open && (
        <div className="absolute left-0 right-0 top-[calc(100%+4px)] z-[100] rounded-md border bg-popover text-popover-foreground shadow-lg animate-in fade-in-0 zoom-in-95 slide-in-from-top-2">
          {/* Search input */}
          <div className="flex items-center gap-2 border-b px-3 py-2.5">
            <Search className="h-4 w-4 text-muted-foreground shrink-0" />
            <input
              ref={inputRef}
              className="flex-1 bg-transparent text-sm outline-none placeholder:text-muted-foreground"
              placeholder="Search epics by name or key..."
              value={search}
              onChange={(e) => handleSearchChange(e.target.value)}
            />
            {searching && <RefreshCw className="h-3.5 w-3.5 animate-spin text-muted-foreground shrink-0" />}
          </div>

          {/* Results list */}
          <div className="max-h-[320px] overflow-y-auto p-1">
            {/* No epic option — always visible */}
            <button
              type="button"
              className={`w-full flex items-center gap-2 rounded-sm px-2 py-2 text-sm cursor-pointer transition-colors ${
                !value || value === 'none'
                  ? 'bg-accent text-accent-foreground'
                  : 'hover:bg-accent/50'
              }`}
              onClick={() => selectItem('none')}
            >
              <Check className={`h-4 w-4 shrink-0 ${!value || value === 'none' ? 'opacity-100' : 'opacity-0'}`} />
              <span className="text-muted-foreground italic">No epic (standalone)</span>
            </button>

            {/* Separator */}
            {(items.length > 0 || searching) && <div className="mx-2 my-1 border-t" />}

            {/* Search status */}
            {search.trim() && searching && items.length === 0 && (
              <div className="flex items-center justify-center gap-2 py-6 text-sm text-muted-foreground">
                <RefreshCw className="h-4 w-4 animate-spin" />
                Searching Jira...
              </div>
            )}

            {search.trim() && searchComplete && items.length === 0 && (
              <div className="py-6 text-center">
                <p className="text-sm text-muted-foreground">No epics found for &ldquo;{search}&rdquo;</p>
                <p className="text-xs text-muted-foreground/60 mt-1">Try a different search term or ticket key</p>
              </div>
            )}

            {/* Epic items */}
            {items.map((item) => (
              <button
                type="button"
                key={item.key}
                className={`w-full flex items-center gap-2 rounded-sm px-2 py-2 text-sm cursor-pointer transition-colors ${
                  value === item.key
                    ? 'bg-accent text-accent-foreground'
                    : 'hover:bg-accent/50'
                }`}
                onClick={() => selectItem(item.key)}
              >
                <Check className={`h-4 w-4 shrink-0 ${value === item.key ? 'opacity-100' : 'opacity-0'}`} />
                <span className="inline-flex items-center rounded border px-1.5 py-0.5 font-mono text-[11px] text-muted-foreground shrink-0">
                  {item.key}
                </span>
                <span className="truncate text-left">{item.summary}</span>
                <span className="ml-auto text-[11px] text-muted-foreground/70 shrink-0 pl-2">
                  {item.status}
                </span>
              </button>
            ))}

            {/* Server search hint when showing local results */}
            {search.trim() && !searchComplete && items.length > 0 && (
              <div className="flex items-center justify-center gap-1.5 py-2 text-[11px] text-muted-foreground/60 border-t mt-1">
                <RefreshCw className="h-3 w-3 animate-spin" />
                Searching Jira for more results...
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Editable Ticket Preview ───────────────────────────────────────────────

function TicketPreview({
  finding,
  override,
  onOverrideChange,
  onReset,
  projectKey,
  issueType,
  epicKey,
}: {
  finding: Finding;
  override: FindingContentOverride;
  onOverrideChange: (field: keyof FindingContentOverride, value: string) => void;
  onReset: () => void;
  projectKey: string;
  issueType: string;
  epicKey: string;
}) {
  const [mode, setMode] = useState<'preview' | 'edit'>('preview');
  const config = severityConfig[finding.severity];

  const effectiveTitle = override.title ?? finding.title;
  const effectiveDescription = override.description ?? finding.description;
  const effectiveEvidence = override.evidence ?? finding.evidence ?? '';
  const effectiveRemediation = override.remediation ?? finding.remediation ?? '';

  const hasOverrides =
    override.title !== undefined ||
    override.description !== undefined ||
    override.evidence !== undefined ||
    override.remediation !== undefined;

  return (
    <div className="rounded-lg border bg-card">
      {/* Ticket header bar */}
      <div className="flex items-center justify-between px-4 py-3 border-b bg-muted/30">
        <div className="flex items-center gap-2 min-w-0">
          <Badge variant="outline" className="font-mono text-xs shrink-0">
            {projectKey || '???'}
          </Badge>
          <Badge variant="secondary" className="text-xs shrink-0">{issueType}</Badge>
          {epicKey && epicKey !== 'none' && (
            <Badge variant="outline" className="text-xs shrink-0">{epicKey}</Badge>
          )}
          <Badge className={`${config?.color || 'bg-gray-500'} text-white text-xs shrink-0`}>
            {finding.severity}
          </Badge>
        </div>
        <div className="flex items-center gap-1 shrink-0">
          {hasOverrides && (
            <Button
              variant="ghost"
              size="sm"
              onClick={onReset}
              className="h-7 px-2 text-xs text-muted-foreground"
            >
              <RotateCcw className="h-3 w-3 mr-1" />
              Reset
            </Button>
          )}
          <Button
            variant="ghost"
            size="sm"
            onClick={() => setMode(mode === 'preview' ? 'edit' : 'preview')}
            className="h-7 px-2 text-xs"
          >
            {mode === 'preview' ? (
              <>
                <Pencil className="h-3 w-3 mr-1" />
                Edit
              </>
            ) : (
              <>
                <Eye className="h-3 w-3 mr-1" />
                Preview
              </>
            )}
          </Button>
        </div>
      </div>

      <div className="p-4 space-y-4">
        {mode === 'edit' ? (
          /* ─── Edit Mode ─── */
          <div className="space-y-4">
            <div className="space-y-1.5">
              <Label className="text-xs text-muted-foreground">Title</Label>
              <Input
                value={effectiveTitle}
                onChange={(e) => onOverrideChange('title', e.target.value)}
                className="font-medium"
              />
            </div>
            <div className="space-y-1.5">
              <Label className="text-xs text-muted-foreground">Description</Label>
              <Textarea
                value={effectiveDescription}
                onChange={(e) => onOverrideChange('description', e.target.value)}
                className="min-h-[100px] text-sm"
              />
            </div>
            <div className="space-y-1.5">
              <Label className="text-xs text-muted-foreground">Evidence</Label>
              <Textarea
                value={effectiveEvidence}
                onChange={(e) => onOverrideChange('evidence', e.target.value)}
                className="min-h-[80px] text-sm font-mono"
                placeholder="No evidence provided"
              />
            </div>
            <div className="space-y-1.5">
              <Label className="text-xs text-muted-foreground">Remediation</Label>
              <Textarea
                value={effectiveRemediation}
                onChange={(e) => onOverrideChange('remediation', e.target.value)}
                className="min-h-[60px] text-sm"
                placeholder="No remediation provided"
              />
            </div>
          </div>
        ) : (
          /* ─── Preview Mode ─── */
          <div className="space-y-4">
            {/* Title */}
            <div>
              <h3 className="font-semibold text-base">
                [Security] {effectiveTitle}
              </h3>
              {finding.target && (
                <p className="text-xs text-muted-foreground mt-0.5">
                  Target: {finding.target}
                </p>
              )}
            </div>

            {/* Description */}
            <div>
              <h4 className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-1">
                Description
              </h4>
              <p className="text-sm whitespace-pre-wrap">{effectiveDescription}</p>
            </div>

            {/* Evidence */}
            {effectiveEvidence && (
              <div>
                <h4 className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-1">
                  Evidence
                </h4>
                <pre className="text-xs bg-muted/50 rounded-md p-3 overflow-x-auto whitespace-pre-wrap border font-mono max-h-[200px] overflow-y-auto">
                  {effectiveEvidence}
                </pre>
              </div>
            )}

            {/* Remediation */}
            {effectiveRemediation && (
              <div>
                <h4 className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-1">
                  Remediation
                </h4>
                <p className="text-sm whitespace-pre-wrap">{effectiveRemediation}</p>
              </div>
            )}

            {/* Metadata footer */}
            <div className="flex flex-wrap gap-2 pt-2 border-t text-xs text-muted-foreground">
              <span>Severity: {finding.severity.toUpperCase()}</span>
              {finding.cve && <span>CVE: {finding.cve}</span>}
              {finding.cwe && <span>CWE: {finding.cwe}</span>}
              {finding.cvss && <span>CVSS: {finding.cvss}</span>}
              {finding.source_tool && <span>Tool: {finding.source_tool}</span>}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

// ─── Main Page ─────────────────────────────────────────────────────────────

function JiraTicketPageContent() {
  const searchParams = useSearchParams();
  const router = useRouter();
  const queryClient = useQueryClient();

  const findingIds = useMemo(() => {
    const ids = searchParams.get('ids');
    return ids ? ids.split(',').filter(Boolean) : [];
  }, [searchParams]);

  // Jira config
  const [projectKey, setProjectKey] = useState('');
  const [issueType, setIssueType] = useState('Bug');
  const [epicKey, setEpicKey] = useState('');
  const [combinedMode, setCombinedMode] = useState(false);
  const [combinedTitle, setCombinedTitle] = useState('');
  const [creating, setCreating] = useState(false);
  const [results, setResults] = useState<Array<{ finding_id: string; status: string; ticket_key?: string; error?: string }> | null>(null);

  // Content overrides for editable preview
  const [contentOverrides, setContentOverrides] = useState<Record<string, FindingContentOverride>>({});

  // Active preview tab (for individual mode with multiple findings)
  const [activePreviewTab, setActivePreviewTab] = useState<string>('');

  // Load integrations config for default project
  const { data: integrations } = useQuery({
    queryKey: ['integrations'],
    queryFn: () => api.config.integrations.get(),
  });

  // Set default project key from saved config
  useEffect(() => {
    if (integrations?.jira?.project_key && !projectKey) {
      setProjectKey(integrations.jira.project_key);
    }
  }, [integrations, projectKey]);

  // Fetch findings
  const { data: findingsData, isLoading: findingsLoading } = useQuery({
    queryKey: ['findings-for-jira', findingIds],
    queryFn: async () => {
      const result = await api.findings.list({ limit: 500 } as Record<string, unknown>);
      return (result?.data || []).filter((f: Finding) => findingIds.includes(f.id));
    },
    enabled: findingIds.length > 0,
  });

  const findings = findingsData || [];

  // Set default active tab when findings load
  useEffect(() => {
    if (findings.length > 0 && !activePreviewTab) {
      const newFindings = findings.filter((f: Finding) => !f.jira_ticket);
      if (newFindings.length > 0) {
        setActivePreviewTab(newFindings[0].id);
      }
    }
  }, [findings, activePreviewTab]);

  // Fetch Jira projects
  const { data: projectsData } = useQuery({
    queryKey: ['jira-projects'],
    queryFn: () => api.jira.listProjects(),
  });
  const projects = projectsData?.projects || [];

  // Fetch issue types when project changes
  const { data: issueTypesData, isLoading: issueTypesLoading } = useQuery({
    queryKey: ['jira-issue-types', projectKey],
    queryFn: () => api.jira.listIssueTypes(projectKey),
    enabled: !!projectKey,
  });
  const issueTypes = issueTypesData?.issueTypes || [];

  // Fetch epics when project changes
  const { data: epicsData, isLoading: epicsLoading } = useQuery({
    queryKey: ['jira-epics', projectKey],
    queryFn: () => api.jira.listEpics(projectKey),
    enabled: !!projectKey,
  });
  const epics = epicsData?.epics || [];

  // Severity breakdown
  const severityCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const f of findings) {
      counts[f.severity] = (counts[f.severity] || 0) + 1;
    }
    return counts;
  }, [findings]);

  // Already-ticketed findings
  const alreadyTicketed = findings.filter((f: Finding) => !!f.jira_ticket);
  const newFindings = findings.filter((f: Finding) => !f.jira_ticket);

  // Override handlers
  const handleOverrideChange = useCallback(
    (findingId: string, field: keyof FindingContentOverride, value: string) => {
      setContentOverrides((prev) => ({
        ...prev,
        [findingId]: { ...prev[findingId], [field]: value },
      }));
    },
    []
  );

  const handleResetOverride = useCallback((findingId: string) => {
    setContentOverrides((prev) => {
      const next = { ...prev };
      delete next[findingId];
      return next;
    });
  }, []);

  const hasAnyOverrides = Object.keys(contentOverrides).length > 0;

  // Create tickets
  const handleCreate = async () => {
    if (!projectKey) {
      toast.error('Please select a project');
      return;
    }

    const idsToCreate = newFindings.map((f: Finding) => f.id);
    if (idsToCreate.length === 0) {
      toast.error('All selected findings already have Jira tickets');
      return;
    }

    setCreating(true);
    setResults(null);

    // Build content_overrides only for findings that have been modified
    const overridesForRequest: Record<string, FindingContentOverride> = {};
    for (const id of idsToCreate) {
      if (contentOverrides[id]) {
        overridesForRequest[id] = contentOverrides[id];
      }
    }

    try {
      const result = await api.jira.createTickets({
        finding_ids: idsToCreate,
        mode: combinedMode ? 'combined' : 'individual',
        options: {
          projectKey,
          issueType,
          epicKey: epicKey && epicKey !== 'none' ? epicKey : undefined,
          ...(Object.keys(overridesForRequest).length > 0 ? { content_overrides: overridesForRequest } : {}),
        },
        title: combinedMode && combinedTitle ? combinedTitle : undefined,
      });

      if (result.status === 'created') {
        if (combinedMode) {
          toast.success(`Combined ticket ${result.ticket_key} created`);
          setResults([{ finding_id: 'combined', status: 'created', ticket_key: result.ticket_key }]);
        } else {
          toast.success(`${result.created} ticket${result.created !== 1 ? 's' : ''} created`);
          setResults(result.results || []);
        }
        queryClient.invalidateQueries({ queryKey: ['findings'] });
        queryClient.invalidateQueries({ queryKey: ['findings-stats'] });
      } else if (result.status === 'partial') {
        toast.warning(`${result.created} created, ${result.failed} failed`);
        setResults(result.results || []);
      } else {
        toast.error(result.error || 'Failed to create tickets');
      }
    } catch (error) {
      toast.error('Failed to create Jira tickets');
    } finally {
      setCreating(false);
    }
  };

  if (findingIds.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-12">
        <p className="text-muted-foreground mb-4">No findings selected</p>
        <Button variant="outline" onClick={() => router.push('/findings')}>
          <ArrowLeft className="mr-2 h-4 w-4" />
          Back to Findings
        </Button>
      </div>
    );
  }

  const jiraBaseUrl = integrations?.jira?.url || '';

  return (
    <div className="space-y-6 max-w-4xl mx-auto">
      {/* Header */}
      <div>
        <Button
          variant="ghost"
          size="sm"
          onClick={() => router.push('/findings')}
          className="mb-2 -ml-2"
        >
          <ArrowLeft className="mr-2 h-4 w-4" />
          Back to Findings
        </Button>
        <div className="flex items-center gap-3">
          <Ticket className="h-6 w-6 text-primary" />
          <div>
            <h1 className="text-2xl font-bold">Create Jira Tickets</h1>
            <p className="text-sm text-muted-foreground">
              {findings.length} finding{findings.length !== 1 ? 's' : ''} selected
            </p>
          </div>
        </div>
      </div>

      {/* Findings Summary */}
      <Card>
        <CardHeader>
          <CardTitle className="text-lg">Selected Findings</CardTitle>
          <CardDescription>
            {newFindings.length} to create
            {alreadyTicketed.length > 0 && ` (${alreadyTicketed.length} already have tickets)`}
          </CardDescription>
        </CardHeader>
        <CardContent>
          {/* Severity breakdown */}
          <div className="flex gap-3 mb-4">
            {Object.entries(severityCounts).map(([severity, count]) => {
              const config = severityConfig[severity];
              return (
                <Badge key={severity} variant="outline" className="gap-1.5">
                  <span className={`h-2 w-2 rounded-full ${config?.color || 'bg-gray-500'}`} />
                  {count} {severity}
                </Badge>
              );
            })}
          </div>

          {/* Findings list */}
          {findingsLoading ? (
            <div className="space-y-2">
              {[1, 2, 3].map((i) => <Skeleton key={i} className="h-12" />)}
            </div>
          ) : (
            <ScrollArea className="max-h-[300px]">
              <div className="space-y-2">
                {findings.map((finding: Finding) => {
                  const config = severityConfig[finding.severity];
                  const hasTicket = !!finding.jira_ticket;
                  const ticketResult = results?.find((r) => r.finding_id === finding.id);

                  return (
                    <div
                      key={finding.id}
                      className={`flex items-center justify-between p-3 rounded-lg border ${
                        hasTicket ? 'opacity-60 bg-muted/30' : 'bg-card'
                      }`}
                    >
                      <div className="flex items-center gap-3 flex-1 min-w-0">
                        <Badge className={`${config?.color || 'bg-gray-500'} text-white text-xs shrink-0`}>
                          {finding.severity}
                        </Badge>
                        <span className="text-sm truncate">{finding.title}</span>
                      </div>
                      <div className="shrink-0 ml-3">
                        {hasTicket ? (
                          jiraTicketUrl(jiraBaseUrl, finding.jira_ticket) ? (
                            <a
                              href={jiraTicketUrl(jiraBaseUrl, finding.jira_ticket)!}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="text-xs text-primary hover:underline flex items-center gap-1"
                            >
                              {finding.jira_ticket}
                              <ExternalLink className="h-3 w-3" />
                            </a>
                          ) : (
                            <span className="text-xs text-primary">{finding.jira_ticket}</span>
                          )
                        ) : ticketResult?.status === 'created' ? (
                          jiraTicketUrl(jiraBaseUrl, ticketResult.ticket_key) ? (
                            <a
                              href={jiraTicketUrl(jiraBaseUrl, ticketResult.ticket_key)!}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="text-xs text-green-500 hover:underline flex items-center gap-1"
                            >
                              <Check className="h-3 w-3" />
                              {ticketResult.ticket_key}
                            </a>
                          ) : (
                            <span className="text-xs text-green-500 flex items-center gap-1">
                              <Check className="h-3 w-3" />
                              {ticketResult.ticket_key}
                            </span>
                          )
                        ) : ticketResult?.status === 'error' ? (
                          <span className="text-xs text-destructive flex items-center gap-1">
                            <X className="h-3 w-3" />
                            Failed
                          </span>
                        ) : (
                          <Badge variant="outline" className="text-xs">Pending</Badge>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            </ScrollArea>
          )}
        </CardContent>
      </Card>

      {/* Ticket Configuration */}
      <Card>
        <CardHeader>
          <CardTitle className="text-lg">Ticket Configuration</CardTitle>
        </CardHeader>
        <CardContent className="space-y-6">
          {/* Project & Issue Type */}
          <div className="grid gap-4 md:grid-cols-2">
            <div className="space-y-2">
              <Label>Project</Label>
              {projects.length > 0 ? (
                <Select value={projectKey} onValueChange={setProjectKey}>
                  <SelectTrigger>
                    <SelectValue placeholder="Select project..." />
                  </SelectTrigger>
                  <SelectContent>
                    {projects.map((p: JiraProject) => (
                      <SelectItem key={p.key} value={p.key}>
                        <span className="flex items-center gap-2">
                          <Badge variant="outline" className="font-mono text-xs">{p.key}</Badge>
                          {p.name}
                        </span>
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              ) : (
                <Skeleton className="h-10" />
              )}
            </div>
            <div className="space-y-2">
              <Label>Issue Type</Label>
              {issueTypesLoading ? (
                <Skeleton className="h-10" />
              ) : issueTypes.length > 0 ? (
                <Select value={issueType} onValueChange={setIssueType}>
                  <SelectTrigger>
                    <SelectValue placeholder="Select type..." />
                  </SelectTrigger>
                  <SelectContent>
                    {issueTypes.map((t: JiraIssueType) => (
                      <SelectItem key={t.id} value={t.name}>
                        {t.name}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              ) : (
                <Select value={issueType} onValueChange={setIssueType}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="Bug">Bug</SelectItem>
                    <SelectItem value="Story">Story</SelectItem>
                    <SelectItem value="Task">Task</SelectItem>
                  </SelectContent>
                </Select>
              )}
            </div>
          </div>

          {/* Epic — searchable combobox */}
          <div className="space-y-2">
            <Label>Attach to Epic (optional)</Label>
            <EpicCombobox
              projectKey={projectKey}
              value={epicKey}
              onChange={setEpicKey}
              epics={epics}
              epicsLoading={epicsLoading}
            />
          </div>

          <Separator />

          {/* Batch mode */}
          {newFindings.length > 1 && (
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <div className="space-y-0.5">
                  <Label className="flex items-center gap-2">
                    <Layers className="h-4 w-4" />
                    Combined Ticket
                  </Label>
                  <p className="text-xs text-muted-foreground">
                    Create one ticket containing all {newFindings.length} findings instead of {newFindings.length} separate tickets
                  </p>
                </div>
                <Switch checked={combinedMode} onCheckedChange={setCombinedMode} />
              </div>

              {combinedMode && (
                <div className="space-y-2">
                  <Label htmlFor="combined-title">Ticket Title</Label>
                  <Input
                    id="combined-title"
                    placeholder={`[Security] ${newFindings.length} vulnerabilities found`}
                    value={combinedTitle}
                    onChange={(e) => setCombinedTitle(e.target.value)}
                  />
                </div>
              )}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Preview — Rich & Editable */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="text-lg">Preview</CardTitle>
              <CardDescription>
                Review and edit ticket content before creating. Changes only affect the Jira ticket, not the original finding.
              </CardDescription>
            </div>
            {hasAnyOverrides && (
              <Button
                variant="outline"
                size="sm"
                onClick={() => setContentOverrides({})}
                className="shrink-0"
              >
                <RotateCcw className="h-3 w-3 mr-1" />
                Reset All
              </Button>
            )}
          </div>
        </CardHeader>
        <CardContent>
          {combinedMode ? (
            /* ─── Combined Mode: Show all findings stacked ─── */
            <div className="space-y-4">
              <div className="rounded-lg border bg-muted/30 p-3">
                <div className="flex items-center gap-2 mb-2">
                  <Badge variant="outline" className="font-mono">{projectKey || '???'}</Badge>
                  <Badge variant="secondary">{issueType}</Badge>
                  {epicKey && epicKey !== 'none' && <Badge variant="outline">{epicKey}</Badge>}
                </div>
                <p className="font-medium">
                  {combinedTitle || `[Security] ${newFindings.length} vulnerabilities found`}
                </p>
                <p className="text-sm text-muted-foreground">
                  1 combined ticket — {newFindings.length} findings listed below
                </p>
              </div>
              {newFindings.map((f: Finding) => (
                <TicketPreview
                  key={f.id}
                  finding={f}
                  override={contentOverrides[f.id] || {}}
                  onOverrideChange={(field, value) => handleOverrideChange(f.id, field, value)}
                  onReset={() => handleResetOverride(f.id)}
                  projectKey={projectKey}
                  issueType={issueType}
                  epicKey={epicKey}
                />
              ))}
            </div>
          ) : newFindings.length === 1 ? (
            /* ─── Single Finding: Show directly ─── */
            <TicketPreview
              finding={newFindings[0]}
              override={contentOverrides[newFindings[0].id] || {}}
              onOverrideChange={(field, value) => handleOverrideChange(newFindings[0].id, field, value)}
              onReset={() => handleResetOverride(newFindings[0].id)}
              projectKey={projectKey}
              issueType={issueType}
              epicKey={epicKey}
            />
          ) : (
            /* ─── Multiple Individual: Tabbed view ─── */
            <Tabs value={activePreviewTab} onValueChange={setActivePreviewTab}>
              <TabsList className="w-full flex-wrap h-auto gap-1 p-1">
                {newFindings.map((f: Finding, i: number) => {
                  const config = severityConfig[f.severity];
                  const hasEdits = !!contentOverrides[f.id];
                  return (
                    <TabsTrigger key={f.id} value={f.id} className="text-xs gap-1.5 relative">
                      <span className={`h-2 w-2 rounded-full ${config?.color || 'bg-gray-500'}`} />
                      <span className="max-w-[120px] truncate">{f.title}</span>
                      {hasEdits && (
                        <span className="absolute -top-0.5 -right-0.5 h-2 w-2 rounded-full bg-primary" />
                      )}
                    </TabsTrigger>
                  );
                })}
              </TabsList>
              {newFindings.map((f: Finding) => (
                <TabsContent key={f.id} value={f.id}>
                  <TicketPreview
                    finding={f}
                    override={contentOverrides[f.id] || {}}
                    onOverrideChange={(field, value) => handleOverrideChange(f.id, field, value)}
                    onReset={() => handleResetOverride(f.id)}
                    projectKey={projectKey}
                    issueType={issueType}
                    epicKey={epicKey}
                  />
                </TabsContent>
              ))}
            </Tabs>
          )}
        </CardContent>
      </Card>

      {/* Actions */}
      <div className="flex items-center justify-between">
        <Button variant="outline" onClick={() => router.push('/findings')}>
          Cancel
        </Button>
        <Button
          onClick={handleCreate}
          disabled={creating || !projectKey || newFindings.length === 0}
          size="lg"
        >
          {creating ? (
            <>
              <RefreshCw className="mr-2 h-4 w-4 animate-spin" />
              Creating...
            </>
          ) : (
            <>
              <Ticket className="mr-2 h-4 w-4" />
              Create {combinedMode ? '1 Combined Ticket' : `${newFindings.length} Ticket${newFindings.length !== 1 ? 's' : ''}`}
            </>
          )}
        </Button>
      </div>

      {/* Results */}
      {results && results.length > 0 && (
        <Card className="border-green-500/50">
          <CardHeader>
            <CardTitle className="text-lg flex items-center gap-2">
              <Check className="h-5 w-5 text-green-500" />
              Tickets Created
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {results.map((r, i) => (
                <div key={i} className="flex items-center justify-between p-2 rounded border">
                  <span className="text-sm">
                    {r.finding_id === 'combined' ? 'Combined ticket' : findings.find((f: Finding) => f.id === r.finding_id)?.title || r.finding_id}
                  </span>
                  {r.ticket_key ? (
                    jiraTicketUrl(jiraBaseUrl, r.ticket_key) ? (
                      <a
                        href={jiraTicketUrl(jiraBaseUrl, r.ticket_key)!}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-primary hover:underline flex items-center gap-1 text-sm"
                      >
                        {r.ticket_key}
                        <ExternalLink className="h-3 w-3" />
                      </a>
                    ) : (
                      <span className="text-primary text-sm">{r.ticket_key}</span>
                    )
                  ) : (
                    <span className="text-xs text-destructive">{r.error || 'Failed'}</span>
                  )}
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

export default function JiraTicketPage() {
  return (
    <Suspense fallback={<div className="flex items-center justify-center p-8 text-muted-foreground">Loading...</div>}>
      <JiraTicketPageContent />
    </Suspense>
  );
}
