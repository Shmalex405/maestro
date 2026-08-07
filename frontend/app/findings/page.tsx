'use client';

import { useState, useMemo, useCallback } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { api } from '@/lib/tauri-api';
import { jiraTicketUrl } from '@/lib/jira';
import type { Finding, FindingCategory, Severity, FindingStatus, Assessment, ScanSnapshot } from '@/lib/types';
import {
  inferCloudFromFinding,
  CATEGORY_LABELS,
  PROVIDER_DISPLAY,
  type CloudCategory,
  type CloudProvider,
} from '@/lib/finding-cloud-inference';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Tabs, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Checkbox } from '@/components/ui/checkbox';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
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
import { Skeleton } from '@/components/ui/skeleton';
import {
  AlertOctagon,
  AlertTriangle,
  AlertCircle,
  Info,
  Search,
  Download,
  RefreshCw,
  ChevronLeft,
  ChevronRight,
  ExternalLink,
  Filter,
  Target,
  FileText,
  List,
  Shield,
  Sparkles,
  Globe,
  Code,
  Server,
  Cloud,
  Fingerprint,
  Crosshair,
  ShieldCheck,
  HelpCircle,
  Trash2,
  CheckSquare,
  X,
  Clock,
  TrendingDown,
  TrendingUp,
  Minus,
  History,
  ArrowUp,
  ArrowDown,
  ArrowUpDown,
  Ticket,
} from 'lucide-react';
import { toast } from 'sonner';
import { cn } from '@/lib/utils';

const severityConfig = {
  critical: { icon: AlertOctagon, color: 'bg-red-500', textColor: 'text-red-400', badge: 'badge-critical', border: 'severity-border-critical', glow: 'glow-critical' },
  high: { icon: AlertTriangle, color: 'bg-orange-500', textColor: 'text-orange-400', badge: 'badge-high', border: 'severity-border-high', glow: 'glow-high' },
  medium: { icon: AlertCircle, color: 'bg-yellow-500', textColor: 'text-yellow-400', badge: 'badge-medium', border: 'severity-border-medium', glow: 'glow-medium' },
  low: { icon: Info, color: 'bg-blue-500', textColor: 'text-blue-400', badge: 'badge-low', border: 'severity-border-low', glow: 'glow-low' },
  info: { icon: Info, color: 'bg-gray-500', textColor: 'text-slate-400', badge: 'badge-info', border: 'severity-border-info', glow: '' },
};

const SEVERITY_RANK: Record<string, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

/**
 * Inline pill rendered next to the primary severity badge when a finding
 * was calibrated. Shows whether the calibrator downgraded (↓) or upgraded
 * (↑) and from what level. Hover text reveals the rule + justification.
 *
 * Surfacing this on the row gives the user a one-glance signal that the
 * severity they see is the calibrated one, not the scanner-raw value —
 * and gives them the *why* without leaving the list.
 */
function CalibrationDeltaBadge({
  original,
  calibrated,
  justification,
  rule,
}: {
  original: Severity;
  calibrated: Severity;
  justification?: string | null;
  rule?: string | null;
}) {
  const origRank = SEVERITY_RANK[original] ?? 0;
  const calRank = SEVERITY_RANK[calibrated] ?? 0;
  const direction = calRank < origRank ? 'down' : calRank > origRank ? 'up' : null;
  if (!direction) return null;
  const tooltipParts: string[] = [`${original.toUpperCase()} → ${calibrated.toUpperCase()}`];
  if (rule) tooltipParts.push(rule);
  if (justification) tooltipParts.push(justification);
  return (
    <span
      className={cn(
        'text-[9px] font-medium uppercase tracking-wide px-1 py-0.5 rounded border',
        direction === 'down'
          ? 'border-green-500/40 bg-green-500/10 text-green-500/90'
          : 'border-red-500/40 bg-red-500/10 text-red-500/90',
      )}
      title={tooltipParts.join(' — ')}
    >
      {direction === 'down' ? '↓' : '↑'} was {original}
    </span>
  );
}

// Each tab's `description` is shown as a tooltip on hover. Canonical
// source-of-truth for these definitions is the doc comment on
// `backend-rs/src/schemas/finding.rs::category_from_source` — keep
// these two in sync when adjusting category routing.
const categoryTabs = [
  {
    value: 'all',
    label: 'All Findings',
    icon: List,
    description: 'Every finding from the assessment, regardless of source.',
  },
  {
    value: 'web_app',
    label: 'Web / API',
    icon: Globe,
    description:
      'HTTP application & API testing: SQLi/XSS/IDOR/SSRF/auth/CORS/headers, GraphQL, file upload, deserialization — plus automated CVE/template scanners (nuclei, nikto). AUTH/AUTHZ/HDR/CORS/INJ/SSRF/CLI/GQL/API/UPLOAD/BIZ/PROTO/DESER agent test IDs.',
  },
  {
    value: 'code_security',
    label: 'Code Security',
    icon: Code,
    description:
      'Static analysis of source and supply chain: SAST (semgrep, bandit, njsscan), secrets (gitleaks, trufflehog), dependency / SCA (grype, trivy, snyk), IaC scanning.',
  },
  {
    value: 'infrastructure',
    label: 'Infrastructure',
    icon: Server,
    description:
      'Network, protocol, and host layer: nmap, sslscan, testssl, DNS / DNSSEC / zone transfer, SSH audit, certificate validation, subdomain enumeration. (Cloud config is now its own Cloud tab.)',
  },
  {
    value: 'identity',
    label: 'Identity / IDP',
    icon: Fingerprint,
    description:
      'Identity-provider red teaming across Active Directory, Entra ID, M365/O365, Okta, Google Workspace, and Ping: directory/user enumeration, lockout-aware spray, OAuth/consent abuse, SAML/federation, token replay, and privilege-escalation paths (identity-recon / identity-exploit agents).',
  },
  // Cloud is now a first-class surface category — backend by_category['cloud']
  // (source-pattern based), split out of Infrastructure.
  {
    value: 'cloud',
    label: 'Cloud',
    icon: Cloud,
    description:
      'Cloud surface (AWS / Azure / GCP / Kubernetes): IAM privesc, storage exposure, serverless, metadata, K8s, secrets, cross-account trust. cloud-recon / cloud-exploit / cloud-analysis agents + ScoutSuite / Prowler / Pacu.',
  },
  {
    value: 'ai',
    label: 'AI / LLM',
    icon: Sparkles,
    description:
      'AI/LLM surface (OWASP LLM Top 10 + MITRE ATLAS): prompt injection, jailbreak, system-prompt extraction, sensitive disclosure, improper output handling, excessive agency, RAG isolation, MCP tool-poisoning. ai-recon / ai-redteam / ai-analysis agents.',
  },
  // Exploited is cross-cutting — filters by `exploitable IN (true,
  // potentially)`. Pulls rows from any category.
  {
    value: 'exploited',
    label: 'Exploited',
    icon: Crosshair,
    description:
      'Cross-cutting overlay. Findings that were actually proven exploitable during the assessment (Fully = true, Partial = potentially). Rows here also appear in their primary category — this tab is a lens, not a partition.',
  },
  // Remediated is cross-cutting — filters by `remediated_at IS NOT NULL`
  // (a finding that WAS exploitable and re-tested as no-longer-reproducing).
  // Rows here also still appear under All — this tab is a lens, not a partition.
  {
    value: 'remediated',
    label: 'Remediated',
    icon: ShieldCheck,
    description:
      'Cross-cutting overlay. Findings that were exploitable in a prior run and, on re-test, no longer reproduce — i.e. the customer patched them. The badge shows what they were before the fix. Clears automatically if the vulnerability regresses (comes back exploitable).',
  },
  // Other catches anything whose `source` doesn't match a routing rule.
  // Visible so the tab counts add up to All Findings total — nothing hides.
  {
    value: 'other',
    label: 'Other',
    icon: HelpCircle,
    description:
      'Safety net. Findings whose source field is NULL or doesn’t match any routing rule. A non-zero count here means a new tool / agent prefix needs a rule added in category_from_source.',
  },
] as const;

// Tool-name patterns that identify cloud-sourced findings. Used to estimate
// the top-level Cloud tab badge count from `globalStats.by_tool` since cloud
// metadata isn't a persisted DB column yet.
const CLOUD_TOOL_PATTERNS: RegExp[] = [
  /cloud-?recon/i,
  /cloud-?exploit/i,
  /prowler|cloudfox|scoutsuite|pmapper|pacu/i,
  /kube-?hunter|kubescape|kube-?bench/i,
  /aws-?cli|^sts$|iam-?enum/i,
  /az-?cli|azure-?cli/i,
  /gcloud|gcp-?audit/i,
];

type ExploitedFilter = 'any' | 'true' | 'potentially';

const statusOptions = ['open', 'in_progress', 'remediated', 'accepted'];

export default function FindingsPage() {
  const queryClient = useQueryClient();
  const router = useRouter();
  const [activeCategory, setActiveCategory] = useState<string>('all');
  const [filters, setFilters] = useState({
    severity: '',
    status: '',
    search: '',
    assessment_id: '',
    target: '',
    page: 1,
    limit: 20,
  });

  // Sort state
  type SortField = 'severity' | 'title' | 'target' | 'source' | 'status' | 'created_at';
  type SortDir = 'asc' | 'desc';
  const [sortField, setSortField] = useState<SortField>('severity');
  const [sortDir, setSortDir] = useState<SortDir>('desc');

  const toggleSort = useCallback((field: SortField) => {
    if (sortField === field) {
      setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'));
    } else {
      setSortField(field);
      setSortDir(field === 'severity' ? 'desc' : 'asc');
    }
    setFilters((f) => ({ ...f, page: 1 }));
  }, [sortField]);

  // Scan history state
  const [selectedSnapshotId, setSelectedSnapshotId] = useState<string | null>(null);

  // Fetch assessments for filter dropdown
  const { data: assessments } = useQuery({
    queryKey: ['assessments'],
    queryFn: () => api.assessments.list(),
  });

  // Application dropdown options come from the Credentials page config
  // (the same source the Credentials page reads from), not from scope.
  // Reason: tonight (2026-05-18) we noticed the dropdown was empty even
  // though two apps were configured under Credentials — scope?.apps was
  // a separate, often-empty source. credentials.applications is the
  // canonical org-shared app catalog.
  const { data: credentials } = useQuery({
    queryKey: ['credentials'],
    queryFn: () => api.config.credentials.get(),
  });

  // Jira base URL for ticket deep-links — from integrations config, never hardcoded
  const { data: integrations } = useQuery({
    queryKey: ['integrations'],
    queryFn: () => api.config.integrations.get(),
  });
  const jiraBaseUrl = integrations?.jira?.url || '';

  // Fetch scan history for the selected target
  const { data: scanHistory } = useQuery({
    queryKey: ['scan-history', filters.target],
    queryFn: () => api.findings.scanHistory(filters.target || undefined),
    enabled: !!filters.target,
  });

  // Auto-select latest snapshot when target changes and snapshots load
  const latestSnapshot = useMemo(() => scanHistory?.[0] ?? null, [scanHistory]);

  // When scan history loads and no snapshot is selected, auto-select latest
  useMemo(() => {
    if (latestSnapshot && !selectedSnapshotId && filters.target) {
      setSelectedSnapshotId(latestSnapshot.id);
    }
  }, [latestSnapshot, filters.target]);

  // Find the selected snapshot and the previous one for delta calculation
  const selectedSnapshot = useMemo(
    () => scanHistory?.find((s: ScanSnapshot) => s.id === selectedSnapshotId) ?? null,
    [scanHistory, selectedSnapshotId]
  );

  const previousSnapshot = useMemo(() => {
    if (!scanHistory || !selectedSnapshotId) return null;
    const idx = scanHistory.findIndex((s: ScanSnapshot) => s.id === selectedSnapshotId);
    return idx >= 0 && idx < scanHistory.length - 1 ? scanHistory[idx + 1] : null;
  }, [scanHistory, selectedSnapshotId]);

  // Build app options from credentials.applications. Each entry becomes:
  //   { id: appName, name: appName, searchPattern: hostFromBaseUrl(base_url) }
  // The dropdown writes searchPattern to filters.search so the existing
  // backend `target ILIKE %search%` filter handles the rest — no backend
  // change needed.
  const appOptions = useMemo(() => {
    const apps = credentials?.applications || {};
    const hostFromBaseUrl = (url: string | undefined): string => {
      if (!url) return '';
      // Strip protocol, then leading wildcard subdomains.
      // "https://*.groovysec.com" → "groovysec.com"
      // "https://api.whiteout.groovysec.com" → "api.whiteout.groovysec.com"
      let host = url.replace(/^https?:\/\//i, '');
      host = host.split('/')[0].split(':')[0];
      host = host.replace(/^\*\./, '');
      return host;
    };
    return Object.entries(apps).map(([name, app]) => ({
      id: name,
      name,
      searchPattern: hostFromBaseUrl((app as { base_url?: string })?.base_url),
    }));
  }, [credentials]);

  // Sub-filter for the Exploited tab. 'any' = true OR potentially.
  const [exploitedFilter, setExploitedFilter] = useState<ExploitedFilter>('any');

  // Sub-filter for the Infrastructure tab — narrows to a cloud category.
  // Reset whenever activeCategory leaves Infrastructure so it doesn't
  // silently apply to other tabs. Inference is client-side (cloud fields
  // aren't persisted DB columns), so this filter applies per-page.
  const [cloudCategoryFilter, setCloudCategoryFilter] = useState<CloudCategory | 'all'>('all');
  const isInfrastructureTab = activeCategory === 'infrastructure';

  // Cloud tab + provider sub-filter (cross-cutting like Exploited).
  const isCloudTab = activeCategory === 'cloud';
  const [cloudProviderFilter, setCloudProviderFilter] = useState<CloudProvider | 'all'>('all');

  // Remediated tab — cross-cutting like Exploited (server filters on
  // `remediated_at IS NOT NULL` via the ?remediated=true param).
  const isRemediatedTab = activeCategory === 'remediated';

  // Category filter for API calls — Exploited, Cloud, and Remediated are
  // cross-cutting (Exploited filters on `exploitable`; Cloud filters
  // client-side on inferred provider; Remediated filters on `remediated_at`).
  // None maps to a backend category column.
  const isExploitedTab = activeCategory === 'exploited';
  const categoryFilter = activeCategory === 'all' || isExploitedTab || isCloudTab || isRemediatedTab
    ? undefined
    : activeCategory as FindingCategory;
  // What we pass to ?exploitable= when on the Exploited tab.
  const exploitableFilter = isExploitedTab ? exploitedFilter : undefined;
  // What we pass to ?remediated= when on the Remediated tab.
  const remediatedFilter = isRemediatedTab ? 'true' : undefined;

  // Global stats (with search but no category filter) — for tab badge counts.
  // activeProjectId was removed in v1.0.0 when the Filters card was retired —
  // the app filter now writes the app's host pattern to filters.search and
  // relies on the backend's `target ILIKE %search%` clause for filtering.
  const { data: globalStats } = useQuery({
    queryKey: ['findings-stats-global', filters.search],
    queryFn: () => api.findings.stats(undefined, undefined, filters.search || undefined, undefined, undefined),
  });

  // Filtered stats (with category + search) — for severity breakdown cards
  const { data: stats, isLoading: statsLoading } = useQuery({
    queryKey: ['findings-stats', activeCategory, exploitedFilter, filters.search],
    queryFn: () => api.findings.stats(
      categoryFilter,
      undefined,
      filters.search || undefined,
      exploitableFilter,
      undefined,
    ),
  });

  // On the Cloud tab the server can't filter by cloud_provider (not a
  // persisted column), so /findings/stats returns all-findings totals on
  // the severity tiles. Fetch all findings once (limit=1000) and derive
  // the cloud-filtered counts client-side. Reused by the provider
  // sub-pills so their counts reflect the global pool rather than the
  // current page.
  const { data: cloudListAll } = useQuery({
    queryKey: ['findings-cloud-all', filters.search],
    queryFn: () =>
      api.findings.list({
        search: filters.search || undefined,
        limit: 1000,
      } as Record<string, unknown>),
    enabled: isCloudTab,
    staleTime: 60_000,
  });

  const allCloudFindings = useMemo<Finding[]>(() => {
    if (!isCloudTab) return [];
    return (cloudListAll?.data ?? []).filter(
      (f) => !!inferCloudFromFinding(f).provider,
    );
  }, [isCloudTab, cloudListAll?.data]);

  // Per-severity counts of all cloud findings (after provider sub-pill).
  // Null when the user isn't on the Cloud tab so the severity cards keep
  // using `stats.by_severity` from the server.
  const cloudSeverityCounts = useMemo<Record<Severity, number> | null>(() => {
    if (!isCloudTab) return null;
    const pool = cloudProviderFilter === 'all'
      ? allCloudFindings
      : allCloudFindings.filter(
          (f) => inferCloudFromFinding(f).provider === cloudProviderFilter,
        );
    const out: Record<Severity, number> = {
      critical: 0, high: 0, medium: 0, low: 0, info: 0,
    };
    for (const f of pool) {
      if (f.severity in out) out[f.severity] += 1;
    }
    return out;
  }, [isCloudTab, allCloudFindings, cloudProviderFilter]);

  const { data: findings, isLoading: findingsLoading, refetch } = useQuery({
    queryKey: ['findings', filters, activeCategory, exploitedFilter, selectedSnapshotId, sortField, sortDir],
    queryFn: () =>
      api.findings.list({
        severity: filters.severity ? [filters.severity as Severity] : undefined,
        status: filters.status ? [filters.status as FindingStatus] : undefined,
        search: filters.search || undefined,
        assessment_id: filters.assessment_id || undefined,
        category: categoryFilter,
        exploitable: exploitableFilter,
        remediated: remediatedFilter,
        page: filters.page,
        limit: filters.limit,
        snapshot_id: selectedSnapshotId || undefined,
        sort_by: sortField,
        sort_dir: sortDir,
      } as Record<string, unknown>),
  });

  // Client-side cloud filter: when the Infrastructure tab is active and a
  // sub-pill is selected, narrow the visible findings to ones whose
  // inferred cloud category matches. Cloud fields aren't persisted DB
  // columns (yet), so filter happens after the server-side page fetch.
  // Tradeoff: pagination counts reflect the unfiltered server result, but
  // since cloud findings cluster by source, per-page filtering is usually
  // a reasonable approximation. Server-side cloud filters are a future
  // backend addition. Declared here (above bulk-selection) so allVisibleIds
  // can derive from the filtered set — "select all" should match what
  // the user actually sees.
  const visibleFindings = useMemo(() => {
    if (isCloudTab) {
      // The paginated /findings response doesn't reliably contain cloud
      // findings on every page (no server-side cloud_provider column to
      // filter on). Source from the cloud-all pool instead so the table
      // matches the severity tile + provider pill counts.
      return cloudProviderFilter === 'all'
        ? allCloudFindings
        : allCloudFindings.filter(
            (f) => inferCloudFromFinding(f).provider === cloudProviderFilter,
          );
    }
    const all: Finding[] = findings?.data ?? [];
    if (isInfrastructureTab && cloudCategoryFilter !== 'all') {
      return all.filter((f) => inferCloudFromFinding(f).category === cloudCategoryFilter);
    }
    return all;
  }, [findings?.data, isInfrastructureTab, cloudCategoryFilter, isCloudTab, cloudProviderFilter, allCloudFindings]);

  // Bulk selection
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());

  const allVisibleIds = useMemo(
    () => visibleFindings.map((f: Finding) => f.id),
    [visibleFindings]
  );

  const allSelected = allVisibleIds.length > 0 && allVisibleIds.every((id: string) => selectedIds.has(id));
  const someSelected = allVisibleIds.some((id: string) => selectedIds.has(id));

  const toggleSelectAll = useCallback(() => {
    if (allSelected) {
      setSelectedIds(new Set());
    } else {
      setSelectedIds(new Set(allVisibleIds));
    }
  }, [allSelected, allVisibleIds]);

  const toggleSelect = useCallback((id: string) => {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }, []);

  const clearSelection = useCallback(() => setSelectedIds(new Set()), []);

  const updateStatusMutation = useMutation({
    mutationFn: ({ id, status }: { id: string; status: 'open' | 'in_progress' | 'remediated' | 'accepted' }) =>
      api.findings.update(id, { status }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['findings'] });
      queryClient.invalidateQueries({ queryKey: ['findings-stats'] });
      queryClient.invalidateQueries({ queryKey: ['findings-stats-global'] });
      toast.success('Status updated');
    },
    onError: () => {
      toast.error('Failed to update status');
    },
  });

  // Bulk status update
  const bulkUpdateStatusMutation = useMutation({
    mutationFn: async ({ ids, status }: { ids: string[]; status: FindingStatus }) => {
      await Promise.all(ids.map((id) => api.findings.update(id, { status })));
    },
    onSuccess: (_, { ids, status }) => {
      queryClient.invalidateQueries({ queryKey: ['findings'] });
      queryClient.invalidateQueries({ queryKey: ['findings-stats'] });
      queryClient.invalidateQueries({ queryKey: ['findings-stats-global'] });
      clearSelection();
      toast.success(`Updated ${ids.length} finding${ids.length > 1 ? 's' : ''} to ${status.replace('_', ' ')}`);
    },
    onError: () => {
      toast.error('Failed to update some findings');
    },
  });

  // Bulk delete
  const bulkDeleteMutation = useMutation({
    mutationFn: async (ids: string[]) => {
      await Promise.all(ids.map((id) => api.findings.delete(id)));
    },
    onSuccess: (_, ids) => {
      queryClient.invalidateQueries({ queryKey: ['findings'] });
      queryClient.invalidateQueries({ queryKey: ['findings-stats'] });
      queryClient.invalidateQueries({ queryKey: ['findings-stats-global'] });
      clearSelection();
      toast.success(`Deleted ${ids.length} finding${ids.length > 1 ? 's' : ''}`);
    },
    onError: () => {
      toast.error('Failed to delete some findings');
    },
  });

  const handleBulkStatusChange = (status: FindingStatus) => {
    const ids = Array.from(selectedIds);
    bulkUpdateStatusMutation.mutate({ ids, status });
  };

  const handleBulkDelete = () => {
    const ids = Array.from(selectedIds);
    if (!confirm(`Delete ${ids.length} finding${ids.length > 1 ? 's' : ''}? This cannot be undone.`)) return;
    bulkDeleteMutation.mutate(ids);
  };

  const handleExport = async (format: 'json' | 'csv' | 'markdown') => {
    try {
      const data = await api.findings.export(format, {
        severity: filters.severity ? [filters.severity as Severity] : undefined,
        status: filters.status ? [filters.status as FindingStatus] : undefined,
        assessment_id: filters.assessment_id || undefined,
        target: filters.target || undefined,
        category: categoryFilter,
      });

      const blob = new Blob([data], {
        type:
          format === 'json'
            ? 'application/json'
            : format === 'csv'
            ? 'text/csv'
            : 'text/markdown',
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `findings.${format === 'markdown' ? 'md' : format}`;
      a.click();
      URL.revokeObjectURL(url);
      toast.success(`Exported as ${format.toUpperCase()}`);
    } catch (error) {
      toast.error('Failed to export findings');
    }
  };

  const handlePdfExport = async () => {
    try {
      toast.loading('Generating PDF report...', { id: 'pdf-export' });
      // Export as markdown first, then use MCP to generate PDF
      const md = await api.findings.export('markdown', {
        severity: filters.severity ? [filters.severity as Severity] : undefined,
        status: filters.status ? [filters.status as FindingStatus] : undefined,
        assessment_id: filters.assessment_id || undefined,
        target: filters.target || undefined,
        category: categoryFilter,
      });
      // Call the MCP PDF generation tool via the reports API
      const result = await api.reports.generatePdf({
        markdown_content: md,
        title: 'Security Findings Report',
        output_filename: 'findings-report.pdf',
      });
      toast.success('PDF report generated', { id: 'pdf-export', duration: 3000 });
      // If we get a path back, offer download
      if (result?.path) {
        toast.info(`Report saved to: ${result.path}`);
      }
    } catch (error) {
      toast.error('Failed to generate PDF report', { id: 'pdf-export', duration: 3000 });
    }
  };

  const handleCategoryChange = (value: string) => {
    setActiveCategory(value);
    setFilters((f) => ({ ...f, page: 1 }));
    // Reset sub-filters when leaving their parent tab so they don't silently
    // apply when the user returns to a different tab.
    if (value !== 'infrastructure') {
      setCloudCategoryFilter('all');
    }
    if (value !== 'cloud') {
      setCloudProviderFilter('all');
    }
  };

  // Approximate top-level Cloud tab count from globalStats.by_tool — cloud
  // metadata isn't a persisted column yet, so the server can't aggregate it.
  // Pattern-matches the tool name against known cloud scanners.
  const cloudTabCount = useMemo(() => {
    const byTool = globalStats?.by_tool;
    if (!byTool) return 0;
    return Object.entries(byTool).reduce((acc, [tool, n]) => {
      return acc + (CLOUD_TOOL_PATTERNS.some((re) => re.test(tool)) ? (n as number) : 0);
    }, 0);
  }, [globalStats?.by_tool]);

  // When the user picks an Application, write the app's host pattern
  // to filters.search — the backend's existing `target ILIKE %search%`
  // filter does the rest, so no /findings schema change is needed.
  // Selecting "All Applications" clears the search. Same field is used
  // because layering app + free-text search needs a backend `app_host`
  // column that doesn't exist yet; can be added later if users ask.
  const selectedAppId = useMemo(() => {
    const cur = filters.search.trim();
    if (!cur) return 'all';
    const match = appOptions.find((a) => a.searchPattern === cur);
    return match ? match.id : 'all';
  }, [filters.search, appOptions]);

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Findings</h1>
          <p className="text-sm text-muted-foreground mt-0.5">
            Discovered vulnerabilities from security assessments
          </p>
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          {/* Application filter — top-level because it's the only filter
              dimension users want persistent across navigation. Assessments
              are ephemeral and not a useful long-term filter; the old
              Filters card with Search + Status + Assessment + Application
              was retired in v1.0.0. */}
          <Select
            value={selectedAppId}
            onValueChange={(value) => {
              if (value === 'all') {
                setFilters((f) => ({ ...f, search: '', page: 1 }));
              } else {
                const app = appOptions.find((a) => a.id === value);
                setFilters((f) => ({
                  ...f,
                  search: app?.searchPattern ?? '',
                  page: 1,
                }));
              }
            }}
          >
            <SelectTrigger className="w-[220px]">
              <Target className="mr-2 h-4 w-4 text-muted-foreground" />
              <SelectValue placeholder="Application" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Applications</SelectItem>
              {appOptions.map((app) => (
                <SelectItem key={app.id} value={app.id}>
                  <span className="truncate max-w-[180px]">{app.name}</span>
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Button
            variant="outline"
            onClick={() => {
              // Invalidate every query this page reads so Refresh actually
              // refreshes the tab counts and severity cards too — not just
              // the findings list. Without this, the button looked like a
              // no-op when the stats queries had cached data.
              queryClient.invalidateQueries({ queryKey: ['findings'] });
              queryClient.invalidateQueries({ queryKey: ['findings-stats'] });
              queryClient.invalidateQueries({ queryKey: ['findings-stats-global'] });
              queryClient.invalidateQueries({ queryKey: ['scan-history'] });
              refetch();
            }}
          >
            <RefreshCw className="mr-2 h-4 w-4" />
            Refresh
          </Button>
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="outline">
                <Download className="mr-2 h-4 w-4" />
                Export
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              <DropdownMenuItem onClick={() => handleExport('json')}>
                <FileText className="mr-2 h-4 w-4" />
                JSON
              </DropdownMenuItem>
              <DropdownMenuItem onClick={() => handleExport('csv')}>
                <FileText className="mr-2 h-4 w-4" />
                CSV
              </DropdownMenuItem>
              <DropdownMenuItem onClick={() => handleExport('markdown')}>
                <FileText className="mr-2 h-4 w-4" />
                Markdown
              </DropdownMenuItem>
              <DropdownMenuItem onClick={handlePdfExport}>
                <FileText className="mr-2 h-4 w-4" />
                PDF Report
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </div>

      {/* Category Tabs — wrap to multiple rows so all categories stay visible
          instead of clipping off the right edge on narrower windows. */}
      <Tabs value={activeCategory} onValueChange={handleCategoryChange}>
        <TabsList className="w-full justify-start flex-wrap h-auto gap-1">
          {categoryTabs.map((tab) => {
            const Icon = tab.icon;
            const count = tab.value === 'all'
              ? (globalStats?.total ?? 0)
              : tab.value === 'exploited'
              ? (globalStats?.exploitable_count ?? 0)
              : tab.value === 'remediated'
              ? (globalStats?.remediated_count ?? 0)
              : tab.value === 'cloud'
              ? cloudTabCount
              : (globalStats?.by_category?.[tab.value as FindingCategory] ?? 0);

            return (
              <TabsTrigger
                key={tab.value}
                value={tab.value}
                className="flex items-center gap-2 flex-none"
                title={tab.description}
                aria-label={`${tab.label}: ${tab.description}`}
              >
                <Icon className="h-4 w-4" />
                <span>{tab.label}</span>
                {count > 0 && (
                  <Badge variant="secondary" className="ml-1 h-5 min-w-[20px] px-1.5 text-xs">
                    {count}
                  </Badge>
                )}
              </TabsTrigger>
            );
          })}
        </TabsList>
      </Tabs>

      {/* Infrastructure sub-filter — narrows by inferred cloud category.
          Counts reflect the current page only because cloud fields aren't
          persisted DB columns yet — server can't pre-aggregate. Acceptable
          tradeoff for v1; backend cloud filters are a future extension. */}
      {isInfrastructureTab && (
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-xs text-muted-foreground mr-1">Cloud category:</span>
          {(['all', 'iam', 'storage', 'compute', 'k8s', 'networking', 'logging'] as const).map((cat) => {
            const active = cloudCategoryFilter === cat;
            const label = cat === 'all' ? 'All' : CATEGORY_LABELS[cat];
            // Per-page count for the current category. Recomputed on
            // every render — fine since findings.data is small (<=20 rows).
            const count = cat === 'all'
              ? (findings?.data?.length ?? 0)
              : (findings?.data ?? []).filter(
                  (f: Finding) => inferCloudFromFinding(f).category === cat,
                ).length;
            return (
              <Button
                key={cat}
                size="sm"
                variant={active ? 'default' : 'outline'}
                onClick={() => setCloudCategoryFilter(cat)}
              >
                {label}
                <Badge
                  variant={active ? 'secondary' : 'outline'}
                  className="ml-1.5 h-5 min-w-[20px] px-1.5 text-xs"
                >
                  {count}
                </Badge>
              </Button>
            );
          })}
        </div>
      )}

      {/* Cloud provider sub-filter — only visible when the Cloud tab is active.
          Counts are per-page (current findings only) because cloud provider
          isn't a persisted DB column — same limitation as the Infrastructure
          cloud-category sub-pills. */}
      {isCloudTab && (
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-xs text-muted-foreground mr-1">Provider:</span>
          {(['all', 'aws', 'azure', 'gcp', 'k8s'] as const).map((prov) => {
            const active = cloudProviderFilter === prov;
            const label = prov === 'all' ? 'All' : PROVIDER_DISPLAY[prov].label;
            // Counts derived from the cloud-all pool (limit=1000) so they
            // reflect every cloud finding in the org, not just the page.
            const count = prov === 'all'
              ? allCloudFindings.length
              : allCloudFindings.filter(
                  (f) => inferCloudFromFinding(f).provider === prov,
                ).length;
            return (
              <Button
                key={prov}
                size="sm"
                variant={active ? 'default' : 'outline'}
                onClick={() => setCloudProviderFilter(prov)}
              >
                {prov !== 'all' && (
                  <span className={cn('h-2 w-2 rounded-sm mr-1.5', PROVIDER_DISPLAY[prov].color)} />
                )}
                {label}
                <Badge
                  variant={active ? 'secondary' : 'outline'}
                  className="ml-1.5 h-5 min-w-[20px] px-1.5 text-xs"
                >
                  {count}
                </Badge>
              </Button>
            );
          })}
        </div>
      )}

      {/* Exploited sub-filter — only visible when the Exploited tab is active.
          Three pills mirror the backend stats split: All (any) / Fully (true)
          / Partial (potentially). Counts come from the global stats so they
          stay accurate regardless of project/search narrowing. */}
      {isExploitedTab && (
        <div className="flex items-center gap-2">
          <span className="text-xs text-muted-foreground mr-1">Filter:</span>
          {([
            { value: 'any',          label: 'All exploited', count: globalStats?.exploitable_count       ?? 0 },
            { value: 'true',         label: 'Fully',         count: globalStats?.fully_exploited_count   ?? 0 },
            { value: 'potentially',  label: 'Partial',       count: globalStats?.partial_exploited_count ?? 0 },
          ] as const).map((p) => {
            const active = exploitedFilter === p.value;
            return (
              <Button
                key={p.value}
                size="sm"
                variant={active ? 'default' : 'outline'}
                onClick={() => setExploitedFilter(p.value)}
              >
                {p.label}
                <Badge
                  variant={active ? 'secondary' : 'outline'}
                  className="ml-1.5 h-5 min-w-[20px] px-1.5 text-xs"
                >
                  {p.count}
                </Badge>
              </Button>
            );
          })}
        </div>
      )}

      {/* Stats Cards */}
      <div className="grid gap-3 md:grid-cols-5">
        {statsLoading
          ? Array.from({ length: 5 }).map((_, i) => (
              <div key={i} className="glass-card rounded-xl p-4">
                <Skeleton className="h-4 w-16 mb-3" />
                <Skeleton className="h-8 w-12" />
              </div>
            ))
          : (['critical', 'high', 'medium', 'low', 'info'] as const).map((severity) => {
              const config = severityConfig[severity];
              // On the Cloud tab, override the server-side stats with the
              // client-derived cloud counts (cloud_provider isn't a DB
              // column the backend can aggregate on).
              const count = cloudSeverityCounts
                ? cloudSeverityCounts[severity]
                : (stats?.by_severity[severity] || 0);
              const Icon = config.icon;
              const isActive = filters.severity === severity;

              return (
                <div
                  key={severity}
                  className={`glass-card rounded-xl p-4 cursor-pointer hover-lift transition-all ${
                    isActive ? 'ring-1 ring-primary/50 ' + config.glow : ''
                  } ${count > 0 ? config.glow : ''}`}
                  onClick={() =>
                    setFilters((f) => ({
                      ...f,
                      severity: isActive ? '' : severity,
                      page: 1,
                    }))
                  }
                >
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
                      {severity}
                    </span>
                    <Icon className={`h-4 w-4 ${config.textColor}`} />
                  </div>
                  <div className="flex items-baseline gap-1.5">
                    <span className={`text-2xl font-bold tabular-nums ${count > 0 ? config.textColor : 'text-muted-foreground/50'}`}>
                      {count}
                    </span>
                  </div>
                </div>
              );
            })}
      </div>

      {/* Scan History */}
      {filters.target ? (
        scanHistory && scanHistory.length > 0 ? (
          <Card>
            <CardHeader className="pb-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <History className="h-5 w-5 text-muted-foreground" />
                  <CardTitle className="text-lg">Scan History</CardTitle>
                </div>
                <Select
                  value={selectedSnapshotId || ''}
                  onValueChange={(value) => {
                    setSelectedSnapshotId(value || null);
                    setFilters((f) => ({ ...f, page: 1 }));
                  }}
                >
                  <SelectTrigger className="w-[320px]">
                    <Clock className="mr-2 h-4 w-4 text-muted-foreground" />
                    <SelectValue placeholder="Select a scan..." />
                  </SelectTrigger>
                  <SelectContent>
                    {scanHistory.map((snap: ScanSnapshot, idx: number) => {
                      const date = new Date(snap.scanned_at);
                      const assessment = assessments?.data?.find((a: Assessment) => a.id === snap.assessment_id);
                      return (
                        <SelectItem key={snap.id} value={snap.id}>
                          <div className="flex items-center gap-2">
                            <span className="font-medium">
                              {date.toLocaleDateString()} {date.toLocaleTimeString()}
                            </span>
                            {idx === 0 && (
                              <Badge variant="secondary" className="text-[10px] h-4 px-1">Latest</Badge>
                            )}
                            <span className="text-xs text-muted-foreground truncate max-w-[120px]">
                              {assessment?.name || ''}
                            </span>
                          </div>
                        </SelectItem>
                      );
                    })}
                  </SelectContent>
                </Select>
              </div>
            </CardHeader>
            {selectedSnapshot && (
              <CardContent className="pt-0">
                <div className="flex items-center gap-3 flex-wrap">
                  {(['critical', 'high', 'medium', 'low', 'info'] as const).map((sev) => {
                    const countKey = `${sev}_count` as keyof ScanSnapshot;
                    const current = (selectedSnapshot[countKey] as number) || 0;
                    const prev = previousSnapshot ? ((previousSnapshot[countKey] as number) || 0) : null;
                    const delta = prev !== null ? current - prev : null;

                    return (
                      <div key={sev} className="flex items-center gap-1.5">
                        <Badge
                          className={`${severityConfig[sev].color} text-white text-xs`}
                        >
                          {sev}
                        </Badge>
                        <span className="font-semibold text-sm">{current}</span>
                        {delta !== null && delta !== 0 && (
                          <span
                            className={`flex items-center text-xs font-medium ${
                              delta > 0 ? 'text-red-500' : 'text-green-500'
                            }`}
                          >
                            {delta > 0 ? (
                              <TrendingUp className="h-3 w-3 mr-0.5" />
                            ) : (
                              <TrendingDown className="h-3 w-3 mr-0.5" />
                            )}
                            {delta > 0 ? '+' : ''}{delta}
                          </span>
                        )}
                        {delta === 0 && prev !== null && (
                          <span className="flex items-center text-xs text-muted-foreground">
                            <Minus className="h-3 w-3" />
                          </span>
                        )}
                      </div>
                    );
                  })}
                  <div className="ml-auto text-xs text-muted-foreground">
                    {selectedSnapshot.total_count} total findings
                    {previousSnapshot && (
                      <span>
                        {' '}| vs previous: {previousSnapshot.total_count}
                      </span>
                    )}
                  </div>
                </div>
              </CardContent>
            )}
          </Card>
        ) : (
          <Card>
            <CardContent className="py-4">
              <div className="flex items-center gap-2 text-muted-foreground text-sm">
                <History className="h-4 w-4" />
                No scan history for this target yet. Complete an assessment to create a snapshot.
              </div>
            </CardContent>
          </Card>
        )
      ) : (
        <Card>
          <CardContent className="py-4">
            <div className="flex items-center gap-2 text-muted-foreground text-sm">
              <History className="h-4 w-4" />
              Select a target to view scan history and delta badges.
            </div>
          </CardContent>
        </Card>
      )}

      {/* Filters card retired in v1.0.0 — the Application dropdown lives
          in the top bar above. Free-text search, Status filter, and
          Assessment filter were removed: assessments are ephemeral and
          not a useful long-term filter dimension. If a future user asks
          for them back, prefer adding them as inline header controls,
          not re-introducing a heavy Filters card. */}

      {/* Bulk Action Bar */}
      {selectedIds.size > 0 && (
        <Card className="border-primary/50 bg-primary/5">
          <CardContent className="py-3 px-4 flex items-center gap-4">
            <div className="flex items-center gap-2">
              <CheckSquare className="h-4 w-4 text-primary" />
              <span className="text-sm font-medium">
                {selectedIds.size} selected
              </span>
            </div>
            <div className="flex items-center gap-2">
              <Select onValueChange={(v) => handleBulkStatusChange(v as FindingStatus)}>
                <SelectTrigger className="h-8 w-[160px]">
                  <SelectValue placeholder="Change status..." />
                </SelectTrigger>
                <SelectContent>
                  {statusOptions.map((status) => (
                    <SelectItem key={status} value={status}>
                      {status.replace('_', ' ')}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <Button
                variant="outline"
                size="sm"
                className="h-8"
                onClick={() => {
                  const ids = Array.from(selectedIds);
                  router.push(`/findings/jira?ids=${ids.join(',')}`);
                }}
              >
                <Ticket className="mr-1.5 h-3.5 w-3.5" />
                Create Jira Tickets
              </Button>
              <Button
                variant="destructive"
                size="sm"
                className="h-8"
                onClick={handleBulkDelete}
                disabled={bulkDeleteMutation.isPending}
              >
                <Trash2 className="mr-1.5 h-3.5 w-3.5" />
                Delete
              </Button>
            </div>
            <div className="flex-1" />
            <Button variant="ghost" size="sm" className="h-8" onClick={clearSelection}>
              <X className="mr-1.5 h-3.5 w-3.5" />
              Clear
            </Button>
          </CardContent>
        </Card>
      )}

      {/* Findings Table */}
      <Card className="glass-card overflow-hidden">
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-[40px]">
                  <Checkbox
                    checked={allSelected}
                    onCheckedChange={toggleSelectAll}
                    aria-label="Select all"
                    className={someSelected && !allSelected ? 'data-[state=unchecked]:bg-primary/20' : ''}
                  />
                </TableHead>
                {([
                  { field: 'severity' as SortField, label: 'Severity', width: 'w-[100px]' },
                  { field: 'title' as SortField, label: 'Title', width: '' },
                  { field: 'target' as SortField, label: 'Target', width: '' },
                  { field: 'source' as SortField, label: 'Source', width: 'w-[100px]' },
                ] as const).map(({ field, label, width }) => (
                  <TableHead
                    key={field}
                    className={`${width} cursor-pointer select-none hover:text-foreground transition-colors`}
                    onClick={() => toggleSort(field)}
                  >
                    <div className="flex items-center gap-1">
                      {label}
                      {sortField === field ? (
                        sortDir === 'asc' ? <ArrowUp className="h-3.5 w-3.5" /> : <ArrowDown className="h-3.5 w-3.5" />
                      ) : (
                        <ArrowUpDown className="h-3.5 w-3.5 opacity-30" />
                      )}
                    </div>
                  </TableHead>
                ))}
                <TableHead className="w-[160px]">Location</TableHead>
                <TableHead className="w-[150px]">Assessment</TableHead>
                <TableHead
                  className="w-[140px] cursor-pointer select-none hover:text-foreground transition-colors"
                  onClick={() => toggleSort('status')}
                >
                  <div className="flex items-center gap-1">
                    Status
                    {sortField === 'status' ? (
                      sortDir === 'asc' ? <ArrowUp className="h-3.5 w-3.5" /> : <ArrowDown className="h-3.5 w-3.5" />
                    ) : (
                      <ArrowUpDown className="h-3.5 w-3.5 opacity-30" />
                    )}
                  </div>
                </TableHead>
                <TableHead className="w-[100px]">Jira</TableHead>
                <TableHead
                  className="w-[100px] cursor-pointer select-none hover:text-foreground transition-colors"
                  onClick={() => toggleSort('created_at')}
                >
                  <div className="flex items-center gap-1">
                    Date
                    {sortField === 'created_at' ? (
                      sortDir === 'asc' ? <ArrowUp className="h-3.5 w-3.5" /> : <ArrowDown className="h-3.5 w-3.5" />
                    ) : (
                      <ArrowUpDown className="h-3.5 w-3.5 opacity-30" />
                    )}
                  </div>
                </TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {findingsLoading ? (
                Array.from({ length: 5 }).map((_, i) => (
                  <TableRow key={i}>
                    <TableCell><Skeleton className="h-4 w-4" /></TableCell>
                    <TableCell><Skeleton className="h-6 w-16" /></TableCell>
                    <TableCell><Skeleton className="h-4 w-48" /></TableCell>
                    <TableCell><Skeleton className="h-4 w-32" /></TableCell>
                    <TableCell><Skeleton className="h-4 w-16" /></TableCell>
                    <TableCell><Skeleton className="h-4 w-24" /></TableCell>
                    <TableCell><Skeleton className="h-4 w-24" /></TableCell>
                    <TableCell><Skeleton className="h-8 w-28" /></TableCell>
                    <TableCell><Skeleton className="h-4 w-16" /></TableCell>
                    <TableCell><Skeleton className="h-4 w-20" /></TableCell>
                  </TableRow>
                ))
              ) : visibleFindings.length ? (
                visibleFindings.map((finding: Finding) => {
                  const config = severityConfig[finding.severity];
                  const assessment = assessments?.data?.find((a: Assessment) => a.id === finding.assessment_id);
                  const cloud = inferCloudFromFinding(finding);
                  const provider = cloud.provider ? PROVIDER_DISPLAY[cloud.provider] : null;

                  return (
                    <TableRow key={finding.id} className={`${config.border} ${selectedIds.has(finding.id) ? 'bg-primary/5' : 'hover:bg-white/[0.02]'} transition-colors`}>
                      <TableCell>
                        <Checkbox
                          checked={selectedIds.has(finding.id)}
                          onCheckedChange={() => toggleSelect(finding.id)}
                          aria-label={`Select ${finding.title}`}
                        />
                      </TableCell>
                      <TableCell>
                        <div className="flex items-center gap-1.5">
                          <span className={`text-[10px] font-semibold uppercase px-2 py-1 rounded-md ${config.badge}`}>
                            {finding.severity}
                          </span>
                          {finding.original_severity &&
                            finding.calibrated_severity &&
                            finding.original_severity !== finding.calibrated_severity && (
                              <CalibrationDeltaBadge
                                original={finding.original_severity}
                                calibrated={finding.calibrated_severity}
                                justification={finding.calibration_justification}
                                rule={finding.calibration_rule}
                              />
                            )}
                        </div>
                      </TableCell>
                      <TableCell>
                        {provider && (
                          <Badge
                            className={`${provider.color} text-white text-[10px] px-1.5 py-0 mr-2`}
                            title={cloud.arn || `${provider.label} finding`}
                          >
                            {provider.label}
                          </Badge>
                        )}
                        <Link
                          href={`/findings/detail?id=${finding.id}`}
                          className="font-medium hover:underline"
                        >
                          {finding.title}
                        </Link>
                        {(finding.occurrence_count ?? 1) > 1 && (
                          <Badge
                            variant="outline"
                            className="ml-2 text-xs font-mono"
                            title={(() => {
                              // Build a tooltip showing the full trend
                              // window: when this vuln was first seen +
                              // when the last assessment confirmed it.
                              // If last_seen_at stops advancing, that's
                              // the signal the customer remediated it.
                              const parts: string[] = [];
                              if (finding.first_seen_at) {
                                parts.push(
                                  `First seen ${new Date(finding.first_seen_at).toLocaleDateString()}`,
                                );
                              }
                              if (finding.last_seen_at) {
                                parts.push(
                                  `last seen ${new Date(finding.last_seen_at).toLocaleDateString()}`,
                                );
                              }
                              parts.push(`across ${finding.occurrence_count} assessments`);
                              return parts.join(' · ');
                            })()}
                          >
                            ×{finding.occurrence_count}
                          </Badge>
                        )}
                        {finding.remediated_at && (
                          <Badge
                            variant="outline"
                            className="ml-2 text-xs border-green-500/40 bg-green-500/10 text-green-500/90"
                            title={(() => {
                              // This vuln was exploitable in a prior run and
                              // re-tested as no-longer-reproducing — i.e. the
                              // customer patched it. Show what it was before
                              // the fix + when/which run proved it.
                              const parts: string[] = ['No longer exploitable on re-test'];
                              if (finding.prior_exploitable) {
                                parts.push(
                                  `was ${finding.prior_exploitable === 'true' ? 'fully exploited' : 'partially exploited'}`,
                                );
                              }
                              parts.push(
                                `fixed as of ${new Date(finding.remediated_at!).toLocaleDateString()}`,
                              );
                              if (finding.remediated_in_assessment_id) {
                                parts.push(`proven in assessment ${finding.remediated_in_assessment_id}`);
                              }
                              return parts.join(' · ');
                            })()}
                          >
                            ✓ Fixed
                          </Badge>
                        )}
                      </TableCell>
                      <TableCell className="max-w-[200px] truncate text-muted-foreground">
                        {finding.target}
                      </TableCell>
                      <TableCell>
                        {(finding.source || finding.source_tool) ? (
                          <Badge variant="outline" className="text-xs font-mono">
                            {finding.source || finding.source_tool}
                          </Badge>
                        ) : (
                          <span className="text-muted-foreground text-sm">-</span>
                        )}
                      </TableCell>
                      <TableCell>
                        {finding.file_path ? (
                          <span
                            className="font-mono text-xs text-muted-foreground truncate block max-w-[150px]"
                            title={finding.file_path}
                          >
                            {finding.file_path.split('/').pop()}
                            {finding.line_start != null && `:${finding.line_start}`}
                          </span>
                        ) : (
                          <span className="text-muted-foreground text-sm">-</span>
                        )}
                      </TableCell>
                      <TableCell>
                        {assessment ? (
                          <Link
                            href={`/assessments/detail?id=${assessment.id}`}
                            className="text-sm text-muted-foreground hover:text-primary hover:underline truncate block max-w-[140px]"
                            title={assessment.name}
                          >
                            {assessment.name}
                          </Link>
                        ) : (
                          <span className="text-muted-foreground text-sm">-</span>
                        )}
                      </TableCell>
                      <TableCell>
                        <Select
                          value={finding.status}
                          onValueChange={(value) =>
                            updateStatusMutation.mutate({
                              id: finding.id,
                              status: value as 'open' | 'in_progress' | 'remediated' | 'accepted',
                            })
                          }
                        >
                          <SelectTrigger className="h-8 w-[120px]">
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            {statusOptions.map((status) => (
                              <SelectItem key={status} value={status}>
                                {status.replace('_', ' ')}
                              </SelectItem>
                            ))}
                          </SelectContent>
                        </Select>
                      </TableCell>
                      <TableCell>
                        {finding.jira_ticket ? (
                          jiraTicketUrl(jiraBaseUrl, finding.jira_ticket) ? (
                            <a
                              href={jiraTicketUrl(jiraBaseUrl, finding.jira_ticket)!}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="text-primary hover:underline flex items-center gap-1"
                            >
                              {finding.jira_ticket}
                              <ExternalLink className="h-3 w-3" />
                            </a>
                          ) : (
                            <span className="text-primary">{finding.jira_ticket}</span>
                          )
                        ) : (
                          <Button
                            variant="ghost"
                            size="sm"
                            className="h-7 px-2 text-xs text-muted-foreground hover:text-primary"
                            onClick={(e) => {
                              e.stopPropagation();
                              router.push(`/findings/jira?ids=${finding.id}`);
                            }}
                          >
                            <Ticket className="mr-1 h-3 w-3" />
                            Create
                          </Button>
                        )}
                      </TableCell>
                      <TableCell className="text-muted-foreground text-sm">
                        {new Date(finding.created_at).toLocaleDateString()}
                      </TableCell>
                    </TableRow>
                  );
                })
              ) : (
                <TableRow>
                  <TableCell colSpan={10} className="text-center py-8 text-muted-foreground">
                    No findings found
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      {/* Pagination */}
      {findings && findings.total > filters.limit && (
        <div className="flex items-center justify-between">
          <p className="text-sm text-muted-foreground">
            Showing {(filters.page - 1) * filters.limit + 1} to{' '}
            {Math.min(filters.page * filters.limit, findings.total)} of {findings.total}{' '}
            findings
          </p>
          <div className="flex gap-2">
            <Button
              variant="outline"
              size="sm"
              disabled={filters.page === 1}
              onClick={() => setFilters((f) => ({ ...f, page: f.page - 1 }))}
            >
              <ChevronLeft className="h-4 w-4" />
              Previous
            </Button>
            <Button
              variant="outline"
              size="sm"
              disabled={!findings.hasMore}
              onClick={() => setFilters((f) => ({ ...f, page: f.page + 1 }))}
            >
              Next
              <ChevronRight className="h-4 w-4" />
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}
