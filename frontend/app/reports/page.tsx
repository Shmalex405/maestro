'use client';

import { useState, useMemo, useEffect } from 'react';
import { useQuery } from '@tanstack/react-query';
import Link from 'next/link';
import { api } from '@/lib/tauri-api';
import type { Report, ReportFile, Assessment } from '@/lib/types';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Card, CardContent } from '@/components/ui/card';
import { Skeleton } from '@/components/ui/skeleton';
import { ReportViewer } from '@/components/reports/report-viewer';
import {
  getDisplayTitle,
  formatRelativeTime,
  assessmentTimestamp,
  statusConfig,
} from '@/lib/assessment-display';
import { cn } from '@/lib/utils';
import {
  FileText,
  Download,
  ChevronDown,
  ChevronUp,
  ChevronRight,
  Search,
  Calendar,
  HardDrive,
  FileType,
  Plus,
  File,
  Cloud,
  Activity,
  Clock,
} from 'lucide-react';

// Lightweight title-based detection of cloud reports. Avoids an extra
// query+join with assessments — most cloud-assessment reports already
// say "cloud", "AWS", "Azure", "GCP", "K8s", "IAM", or "CIS" in their
// title or filename. False negatives are acceptable: missing chip ≠ wrong
// data, just a missed visual cue.
const CLOUD_TITLE_PATTERN = /\b(cloud|aws|azure|gcp|kubernetes|k8s|iam|cis\s+benchmark|arn:|ec2|s3\b|eks|gke|aks)\b/i;
function isLikelyCloudReport(title: string): boolean {
  return CLOUD_TITLE_PATTERN.test(title);
}

// Unified report item combining DB reports and filesystem reports
interface ReportItem {
  id: string;
  title: string;
  // Optional because cloud `reports.created_at` is nullable in the
  // backend schema (Option<DateTime<Utc>>); missing values render as
  // "—" and sort to the bottom of the list rather than producing
  // "Jan 1, 1970" via new Date(null).
  date?: string;
  format: 'markdown' | 'pdf';
  source: 'database' | 'filesystem';
  // For DB reports
  dbReport?: Report;
  // For filesystem reports
  fileReport?: ReportFile;
  // Severity stats (from DB reports or parsed from markdown)
  criticalCount?: number;
  highCount?: number;
  mediumCount?: number;
  lowCount?: number;
  findingsCount?: number;
}

function formatFileSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

/** Format an ISO timestamp safely. Returns "—" for null / undefined /
 *  empty / non-parseable inputs instead of falling through to
 *  `new Date(null)` → the Unix epoch (Jan 1, 1970), which is what the
 *  raw `new Date(...).toLocaleDateString(...)` path would do. */
function formatDate(dateStr: string | null | undefined): string {
  if (!dateStr) return '—';
  const d = new Date(dateStr);
  const ms = d.getTime();
  if (!Number.isFinite(ms) || ms <= 0) return '—';
  return d.toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

/** Parseable millis-since-epoch for sorting; returns -Infinity for
 *  missing/invalid so reports without a date sink to the bottom under a
 *  descending sort. */
function dateForSort(dateStr: string | null | undefined): number {
  if (!dateStr) return -Infinity;
  const ms = new Date(dateStr).getTime();
  if (!Number.isFinite(ms) || ms <= 0) return -Infinity;
  return ms;
}

// Completion time-frame filter — shared by the Reports and Completed Assessments
// columns so you can narrow either to a recent window.
type TimeFrame = 'all' | '24h' | '7d' | '30d' | '90d';

const TIME_FRAME_OPTIONS: { value: TimeFrame; label: string }[] = [
  { value: 'all', label: 'All time' },
  { value: '24h', label: 'Last 24 hours' },
  { value: '7d', label: 'Last 7 days' },
  { value: '30d', label: 'Last 30 days' },
  { value: '90d', label: 'Last 90 days' },
];

const TIME_FRAME_MS: Record<Exclude<TimeFrame, 'all'>, number> = {
  '24h': 24 * 60 * 60 * 1000,
  '7d': 7 * 24 * 60 * 60 * 1000,
  '30d': 30 * 24 * 60 * 60 * 1000,
  '90d': 90 * 24 * 60 * 60 * 1000,
};

/** True when `dateStr` falls within `frame` of `now`. 'all' always passes;
 *  undated / unparseable rows drop out once a specific frame is chosen. */
function withinTimeFrame(
  dateStr: string | null | undefined,
  frame: TimeFrame,
  now: number,
): boolean {
  if (frame === 'all') return true;
  const ms = dateForSort(dateStr);
  if (ms === -Infinity) return false;
  return ms >= now - TIME_FRAME_MS[frame];
}

/** Compact time-frame dropdown reused by both columns. */
function TimeFrameFilter({
  value,
  onChange,
}: {
  value: TimeFrame;
  onChange: (v: TimeFrame) => void;
}) {
  return (
    <Select value={value} onValueChange={(v) => onChange(v as TimeFrame)}>
      <SelectTrigger className="h-9 w-[148px] shrink-0 gap-1.5 text-xs">
        <Clock className="h-3.5 w-3.5 text-muted-foreground" />
        <SelectValue />
      </SelectTrigger>
      <SelectContent>
        {TIME_FRAME_OPTIONS.map((o) => (
          <SelectItem key={o.value} value={o.value} className="text-xs">
            {o.label}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  );
}

function parseTitleFromFilename(name: string): string {
  // Remove extension
  const base = name.replace(/\.(md|pdf)$/, '');
  // Replace hyphens and underscores with spaces, capitalize words
  return base
    .replace(/[-_]/g, ' ')
    .replace(/\b\w/g, (c) => c.toUpperCase());
}

/** Inline PDF previewer — cloud-only.
 *
 *  Reports are stored in the per-customer S3 bucket; the desktop
 *  fetches a 15-min presigned URL from the backend and points an
 *  iframe at it. There is intentionally no local-file fallback:
 *  PDFs live in cloud storage exclusively, accessed via the
 *  application. If a row exists without bytes (legacy reports
 *  generated before cloud-only persistence shipped), the user
 *  re-generates the assessment to get a fresh cloud-backed PDF —
 *  scavenging from local disk is not part of the supported flow. */
function PdfPreview({ report }: { report: ReportItem }) {
  const [previewUrl, setPreviewUrl] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const hasArtifact = !!report.dbReport?.has_artifact;
  const title = report.title;
  const dbId = report.dbReport?.id;

  // Fetch the presigned URL once when the panel expands. 15-min TTL
  // is comfortably longer than a typical viewing session; re-expand
  // gets a fresh URL.
  useEffect(() => {
    if (!hasArtifact || !dbId) return;
    let cancelled = false;
    setLoading(true);
    setError(null);
    setPreviewUrl(null);
    api.reports
      .artifactUrl(dbId, 'inline')
      .then((url) => {
        if (!cancelled) setPreviewUrl(url);
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          const msg = err instanceof Error ? err.message : String(err);
          setError(msg);
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [dbId, hasArtifact]);

  const handleDownload = async () => {
    if (!dbId) return;
    const { toast } = await import('sonner');
    try {
      const filename = `${title.replace(/[/\\]/g, '_')}.pdf`;
      const savedPath = await api.reports.downloadToDisk(dbId, 'pdf', filename, true);
      toast.success(`Saved to ${savedPath}`);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      toast.error(`Failed to download PDF: ${msg}`);
    }
  };

  if (hasArtifact) {
    return (
      <div className="flex flex-col">
        <div className="flex items-center justify-end gap-2 px-4 py-2 border-b border-border">
          <Button variant="outline" size="sm" onClick={handleDownload}>
            <Download className="h-4 w-4 mr-2" />
            Download PDF
          </Button>
        </div>
        {loading && (
          <div className="flex items-center justify-center py-12 text-muted-foreground">
            <p className="text-sm">Loading preview…</p>
          </div>
        )}
        {error && (
          <div className="flex flex-col items-center justify-center py-12 text-red-500">
            <p className="text-sm mb-2">Failed to load preview</p>
            <p className="text-xs">{error}</p>
          </div>
        )}
        {previewUrl && (
          <iframe
            src={previewUrl}
            title={title}
            className="w-full h-[70vh] border-0 bg-muted"
          />
        )}
      </div>
    );
  }

  // Legacy row — exists in the cloud DB but no bytes in S3 (predates
  // cloud-only persistence). Re-generating the assessment is the
  // recovery path.
  return (
    <div className="flex flex-col items-center justify-center py-12 px-6 text-muted-foreground">
      <File className="h-12 w-12 mb-4 opacity-50" />
      <p className="text-sm mb-2">Report unavailable</p>
      <p className="text-xs text-muted-foreground/70 max-w-md text-center">
        This report row pre-dates cloud artifact storage, so the PDF bytes were never uploaded.
        Re-run the assessment to generate a fresh, cloud-backed copy.
      </p>
    </div>
  );
}

export default function ReportsPage() {
  const [searchQuery, setSearchQuery] = useState('');
  const [assessmentQuery, setAssessmentQuery] = useState('');
  const [formatFilter, setFormatFilter] = useState<'all' | 'markdown' | 'pdf'>('all');
  const [assessmentTimeFrame, setAssessmentTimeFrame] = useState<TimeFrame>('all');
  const [reportTimeFrame, setReportTimeFrame] = useState<TimeFrame>('all');
  // Captured once at mount so relative time-frame filtering doesn't call
  // Date.now() in render (which the lint purity rule flags).
  const [now] = useState(() => Date.now());
  const [expandedReport, setExpandedReport] = useState<string | null>(null);
  const [reportContent, setReportContent] = useState<Record<string, string>>({});
  const [loadingContent, setLoadingContent] = useState<Record<string, boolean>>({});

  // Fetch DB reports
  const { data: dbReports, isLoading: dbLoading } = useQuery({
    queryKey: ['reports'],
    queryFn: () => api.reports.list(),
  });

  // Fetch filesystem reports
  const { data: fileReports, isLoading: fileLoading } = useQuery({
    queryKey: ['report-files'],
    queryFn: () => api.reports.listFiles(),
  });

  // Fetch assessments that have run — drives the "Ran Assessments" execution
  // overview section. Include archived rows so closed-out runs stay visible
  // (they get an "Archived" badge).
  const { data: assessmentsData } = useQuery({
    queryKey: ['assessments', { include_archived: true, limit: 200 }],
    queryFn: () => api.assessments.list({ include_archived: true, limit: 200 }),
    // Runs complete (auto or manual) outside this page — poll + refetch on
    // focus so a freshly-completed run shows up without a hard refresh.
    refetchInterval: 30_000,
    refetchOnWindowFocus: true,
  });

  // Only assessments that actually started and aren't still pending. Covers
  // completed / failed / cancelled / running, plus archived rows.
  const ranAssessments = useMemo(() => {
    const list = assessmentsData?.data || [];
    return list
      .filter((a) => a.started_at && a.status !== 'pending')
      .sort(
        (a, b) =>
          new Date(assessmentTimestamp(b) || 0).getTime() -
          new Date(assessmentTimestamp(a) || 0).getTime(),
      );
  }, [assessmentsData]);

  // Search the assessments column by display title, mirroring the reports search.
  const filteredAssessments = useMemo(() => {
    const q = assessmentQuery.trim().toLowerCase();
    return ranAssessments.filter((a) => {
      if (!withinTimeFrame(assessmentTimestamp(a), assessmentTimeFrame, now)) return false;
      if (q && !getDisplayTitle(a).toLowerCase().includes(q)) return false;
      return true;
    });
  }, [ranAssessments, assessmentQuery, assessmentTimeFrame, now]);

  const isLoading = dbLoading || fileLoading;

  // Merge DB and filesystem reports into unified list
  const allReports: ReportItem[] = useMemo(() => {
    const items: ReportItem[] = [];

    // Add DB reports
    const dbList = dbReports?.data || [];
    for (const r of dbList) {
      items.push({
        id: `db-${r.id}`,
        title: r.title || 'Untitled Report',
        date: r.created_at,
        format: r.format === 'pdf' ? 'pdf' : 'markdown',
        source: 'database',
        dbReport: r,
        criticalCount: r.critical_count,
        highCount: r.high_count,
        mediumCount: r.medium_count,
        lowCount: r.low_count,
        findingsCount: r.findings_count,
      });
    }

    // Add filesystem reports (avoiding duplicates by filename)
    const fileList = fileReports || [];
    for (const f of fileList) {
      items.push({
        id: `file-${f.path}`,
        title: f.title || parseTitleFromFilename(f.name),
        date: f.modified_at,
        format: f.format,
        source: 'filesystem',
        fileReport: f,
      });
    }

    // Sort by date descending — undated reports sink to the bottom.
    items.sort((a, b) => dateForSort(b.date) - dateForSort(a.date));

    return items;
  }, [dbReports, fileReports]);

  // Apply filters
  const filteredReports = useMemo(() => {
    return allReports.filter((r) => {
      // Format filter
      if (formatFilter !== 'all' && r.format !== formatFilter) return false;
      // Time-frame filter (by report date)
      if (!withinTimeFrame(r.date, reportTimeFrame, now)) return false;
      // Search filter
      if (searchQuery) {
        const q = searchQuery.toLowerCase();
        return r.title.toLowerCase().includes(q);
      }
      return true;
    });
  }, [allReports, searchQuery, formatFilter, reportTimeFrame, now]);

  // Stats
  const totalReports = allReports.length;
  const mdCount = allReports.filter((r) => r.format === 'markdown').length;
  const pdfCount = allReports.filter((r) => r.format === 'pdf').length;

  // Load report content on expand
  const handleToggleExpand = async (report: ReportItem) => {
    const key = report.id;

    if (expandedReport === key) {
      setExpandedReport(null);
      return;
    }

    setExpandedReport(key);

    // Only load if we don't have it cached and it's a markdown file
    if (!reportContent[key] && report.format === 'markdown') {
      setLoadingContent((prev) => ({ ...prev, [key]: true }));
      try {
        let content = '';
        if (report.source === 'filesystem' && report.fileReport) {
          content = await api.reports.readFile(report.fileReport.path);
        } else if (report.source === 'database' && report.dbReport) {
          content = report.dbReport.content || '';
        }
        setReportContent((prev) => ({ ...prev, [key]: content }));
      } catch (err) {
        console.error('Failed to load report content:', err);
        setReportContent((prev) => ({
          ...prev,
          [key]: `_Error loading report content: ${err}_`,
        }));
      } finally {
        setLoadingContent((prev) => ({ ...prev, [key]: false }));
      }
    }
  };

  // Loading state
  if (isLoading) {
    return (
      <div className="space-y-6">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Reports &amp; Completed Assessments</h1>
          <p className="text-sm text-muted-foreground mt-0.5">
            Completed-assessment execution overviews and the reports they generated
          </p>
        </div>
        <div className="grid gap-3 md:grid-cols-3">
          {[1, 2, 3].map((i) => (
            <div key={i} className="glass-card rounded-xl p-4">
              <Skeleton className="h-4 w-20 mb-3" />
              <Skeleton className="h-8 w-12" />
            </div>
          ))}
        </div>
        <div className="space-y-4">
          {[1, 2, 3].map((i) => (
            <Skeleton key={i} className="h-32 w-full" />
          ))}
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Reports &amp; Completed Assessments</h1>
          <p className="text-sm text-muted-foreground mt-0.5">
            Completed-assessment execution overviews and the reports they generated
          </p>
        </div>
        <Button asChild>
          <Link href="/assessments">
            <Plus className="h-4 w-4 mr-2" />
            Generate Report
          </Link>
        </Button>
      </div>

      {/* Stats Cards — Total Reports | Completed Assessments | File Reports.
          (Critical/High aggregates removed — they duplicated the per-row
          severity chips shown on each assessment/report below.) */}
      <div className="grid gap-3 md:grid-cols-3">
        <div className="glass-card rounded-xl p-4">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-medium uppercase tracking-wider text-muted-foreground">Total Reports</span>
            <FileText className="h-4 w-4 text-muted-foreground" />
          </div>
          <div className="text-2xl font-bold tabular-nums">{totalReports}</div>
          <p className="text-[11px] text-muted-foreground mt-1">
            {mdCount} Markdown, {pdfCount} PDF
          </p>
        </div>
        <div className="glass-card rounded-xl p-4">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-medium uppercase tracking-wider text-muted-foreground">Completed Assessments</span>
            <Activity className="h-4 w-4 text-muted-foreground" />
          </div>
          <div className="text-2xl font-bold tabular-nums">{ranAssessments.length}</div>
          <p className="text-[11px] text-muted-foreground mt-1">With execution overviews</p>
        </div>
        <div className="glass-card rounded-xl p-4">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-medium uppercase tracking-wider text-muted-foreground">File Reports</span>
            <HardDrive className="h-4 w-4 text-muted-foreground" />
          </div>
          <div className="text-2xl font-bold tabular-nums">{(fileReports || []).length}</div>
          <p className="text-[11px] text-muted-foreground mt-1">From reports/ directory</p>
        </div>
      </div>

      {/* Side-by-side parallel views: Completed Assessments | Reports */}
      <div className="grid gap-6 lg:grid-cols-2 items-start">
        {/* LEFT — Completed Assessments (execution overviews) */}
        <section className="space-y-3">
          <div>
            <h2 className="text-lg font-semibold tracking-tight flex items-center gap-2">
              <Activity className="h-4 w-4 text-muted-foreground" />
              Completed Assessments
            </h2>
            <p className="text-sm text-muted-foreground mt-0.5">
              Execution overview — what ran, coverage, cost.
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <div className="relative flex-1 min-w-[160px]">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search assessments..."
                value={assessmentQuery}
                onChange={(e) => setAssessmentQuery(e.target.value)}
                className="pl-9"
              />
            </div>
            <TimeFrameFilter value={assessmentTimeFrame} onChange={setAssessmentTimeFrame} />
          </div>
          {filteredAssessments.length === 0 ? (
            <Card>
              <CardContent className="flex items-center justify-center py-8 text-sm text-muted-foreground">
                {assessmentQuery ? 'No matching assessments.' : 'No assessments have run yet.'}
              </CardContent>
            </Card>
          ) : (
            <div className="space-y-2 stagger-children">
              {filteredAssessments.map((a) => (
                <RanAssessmentRow key={a.id} assessment={a} />
              ))}
            </div>
          )}
        </section>

        {/* RIGHT — Reports */}
        <section className="space-y-3">
          <div>
            <h2 className="text-lg font-semibold tracking-tight flex items-center gap-2">
              <FileText className="h-4 w-4 text-muted-foreground" />
              Reports
            </h2>
            <p className="text-sm text-muted-foreground mt-0.5">
              Generated markdown &amp; PDF assessment reports.
            </p>
          </div>

          {/* Search + time frame + format filter */}
          <div className="flex flex-wrap items-center gap-2">
            <div className="relative flex-1 min-w-[160px]">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search reports..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-9"
              />
            </div>
            <TimeFrameFilter value={reportTimeFrame} onChange={setReportTimeFrame} />
            <div className="flex items-center gap-1">
              <Button
                variant={formatFilter === 'all' ? 'secondary' : 'ghost'}
                size="sm"
                onClick={() => setFormatFilter('all')}
              >
                All
              </Button>
              <Button
                variant={formatFilter === 'markdown' ? 'secondary' : 'ghost'}
                size="sm"
                onClick={() => setFormatFilter('markdown')}
              >
                <FileText className="h-3.5 w-3.5 mr-1.5" />
                MD
              </Button>
              <Button
                variant={formatFilter === 'pdf' ? 'secondary' : 'ghost'}
                size="sm"
                onClick={() => setFormatFilter('pdf')}
              >
                <File className="h-3.5 w-3.5 mr-1.5" />
                PDF
              </Button>
            </div>
          </div>

          {/* Report Cards */}
      {filteredReports.length > 0 ? (
        <div className="space-y-3 stagger-children">
          {filteredReports.map((report) => {
            const isExpanded = expandedReport === report.id;
            const isContentLoading = loadingContent[report.id];
            const content = reportContent[report.id];

            return (
              <Card key={report.id} className="glass-card overflow-hidden">
                {/* Card Header / Summary */}
                <div
                  className="flex items-center gap-4 p-4 cursor-pointer hover:bg-muted/30 transition-colors"
                  onClick={() => handleToggleExpand(report)}
                >
                  {/* Icon */}
                  <div className="flex-shrink-0">
                    {report.format === 'pdf' ? (
                      <div className="h-10 w-10 rounded-lg bg-red-500/10 flex items-center justify-center">
                        <File className="h-5 w-5 text-red-400" />
                      </div>
                    ) : (
                      <div className="h-10 w-10 rounded-lg bg-primary/10 flex items-center justify-center">
                        <FileText className="h-5 w-5 text-primary" />
                      </div>
                    )}
                  </div>

                  {/* Title & Meta */}
                  <div className="flex-1 min-w-0">
                    <h3 className="font-semibold text-foreground truncate">
                      {report.title}
                    </h3>
                    <div className="flex items-center gap-3 mt-1 text-xs text-muted-foreground">
                      <span className="flex items-center gap-1">
                        <Calendar className="h-3 w-3" />
                        {formatDate(report.date)}
                      </span>
                      {report.fileReport && (
                        <span className="flex items-center gap-1">
                          <HardDrive className="h-3 w-3" />
                          {formatFileSize(report.fileReport.size)}
                        </span>
                      )}
                      <span className="flex items-center gap-1">
                        <FileType className="h-3 w-3" />
                        {report.source === 'database' ? 'Database' : 'File'}
                      </span>
                    </div>
                  </div>

                  {/* Cloud chip — surfaces cloud-assessment reports at a
                      glance. Title-based detection sidesteps the extra
                      assessment join the audit flagged as future work. */}
                  {isLikelyCloudReport(report.title) && (
                    <Badge className="bg-primary/10 text-primary border-primary/30 gap-1" variant="outline">
                      <Cloud className="h-3 w-3" />
                      Cloud
                    </Badge>
                  )}

                  {/* Format Badge */}
                  <Badge
                    variant="outline"
                    className={
                      report.format === 'pdf'
                        ? 'border-red-500/30 text-red-400'
                        : 'border-primary/30 text-primary'
                    }
                  >
                    {report.format === 'pdf' ? 'PDF' : 'MD'}
                  </Badge>

                  {/* Severity Badges (if available) */}
                  {report.findingsCount != null && report.findingsCount > 0 && (
                    <div className="hidden md:flex items-center gap-1.5">
                      {(report.criticalCount || 0) > 0 && (
                        <span className="badge-critical text-[10px] font-semibold px-1.5 py-0.5 rounded-md">
                          {report.criticalCount} C
                        </span>
                      )}
                      {(report.highCount || 0) > 0 && (
                        <span className="badge-high text-[10px] font-semibold px-1.5 py-0.5 rounded-md">
                          {report.highCount} H
                        </span>
                      )}
                      {(report.mediumCount || 0) > 0 && (
                        <span className="badge-medium text-[10px] font-semibold px-1.5 py-0.5 rounded-md">
                          {report.mediumCount} M
                        </span>
                      )}
                      {(report.lowCount || 0) > 0 && (
                        <span className="badge-low text-[10px] font-semibold px-1.5 py-0.5 rounded-md">
                          {report.lowCount} L
                        </span>
                      )}
                    </div>
                  )}

                  {/* Actions */}
                  <div className="flex items-center gap-1">
                    {/* Filesystem-source row buttons (markdown download +
                        open-in-system-viewer) intentionally removed —
                        reports live in cloud storage; `report.fileReport`
                        never populates in cloud mode. Cloud-backed
                        markdown rows download via the expanded panel's
                        own controls (handled by ReportViewer). */}
                    {isExpanded ? (
                      <ChevronUp className="h-4 w-4 text-muted-foreground" />
                    ) : (
                      <ChevronDown className="h-4 w-4 text-muted-foreground" />
                    )}
                  </div>
                </div>

                {/* Expanded Content */}
                {isExpanded && (
                  <div className="border-t border-border">
                    {report.format === 'pdf' ? (
                      <PdfPreview report={report} />
                    ) : isContentLoading ? (
                      <div className="p-6 space-y-3">
                        <Skeleton className="h-4 w-3/4" />
                        <Skeleton className="h-4 w-1/2" />
                        <Skeleton className="h-4 w-5/6" />
                        <Skeleton className="h-4 w-2/3" />
                        <Skeleton className="h-32 w-full" />
                      </div>
                    ) : content ? (
                      <ReportViewer content={content} maxHeight="60vh" />
                    ) : (
                      <div className="flex items-center justify-center py-12 text-muted-foreground">
                        <p className="text-sm">No content available</p>
                      </div>
                    )}
                  </div>
                )}
              </Card>
            );
          })}
        </div>
      ) : (
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-12">
            <FileText className="h-12 w-12 text-muted-foreground mb-4" />
            <h3 className="text-lg font-medium mb-2">
              {searchQuery || formatFilter !== 'all'
                ? 'No Matching Reports'
                : 'No Reports Yet'}
            </h3>
            <p className="text-muted-foreground text-center mb-4">
              {searchQuery || formatFilter !== 'all' ? (
                <>
                  Try adjusting your search or filter criteria.
                </>
              ) : (
                <>
                  Reports are generated after assessments complete.
                  <br />
                  Run an assessment to generate your first report.
                </>
              )}
            </p>
            {!searchQuery && formatFilter === 'all' && (
              <Button asChild>
                <Link href="/assessments">
                  Start Assessment
                </Link>
              </Button>
            )}
          </CardContent>
        </Card>
      )}
        </section>
      </div>
    </div>
  );
}

function RanAssessmentRow({ assessment }: { assessment: Assessment }) {
  const status = statusConfig[assessment.status] || statusConfig.pending;
  const StatusIcon = status.icon;
  const findingsTotal = assessment.findings_count ?? 0;
  const critical = assessment.critical_count ?? 0;
  const high = assessment.high_count ?? 0;

  return (
    <Link href={`/reports/assessment?id=${assessment.id}`} className="block">
      <Card className="glass-card overflow-hidden transition-colors hover:bg-muted/30">
        <div className="flex items-center gap-4 p-4">
          {/* Status icon */}
          <div className="flex-shrink-0">
            <div className="h-10 w-10 rounded-lg bg-primary/10 flex items-center justify-center">
              <StatusIcon
                className={cn(
                  'h-5 w-5',
                  status.color,
                  assessment.status === 'running' && 'animate-spin',
                )}
              />
            </div>
          </div>

          {/* Title + meta */}
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 min-w-0">
              <h3 className="font-semibold text-foreground truncate">
                {getDisplayTitle(assessment)}
              </h3>
              {assessment.archived_at && (
                <Badge variant="outline" className="text-[10px] text-muted-foreground shrink-0">
                  Archived
                </Badge>
              )}
            </div>
            <div className="flex items-center gap-3 mt-1 text-xs text-muted-foreground">
              <span className="flex items-center gap-1">
                <Calendar className="h-3 w-3" />
                {formatRelativeTime(assessmentTimestamp(assessment))}
              </span>
              <span className={cn('flex items-center gap-1 capitalize', status.color)}>
                {assessment.status}
              </span>
            </div>
          </div>

          {/* Severity chips */}
          {findingsTotal > 0 && (
            <div className="hidden md:flex items-center gap-1.5">
              {critical > 0 && (
                <span className="badge-critical text-[10px] font-semibold px-1.5 py-0.5 rounded-md">
                  {critical} C
                </span>
              )}
              {high > 0 && (
                <span className="badge-high text-[10px] font-semibold px-1.5 py-0.5 rounded-md">
                  {high} H
                </span>
              )}
            </div>
          )}

          {/* Findings total */}
          <div className="text-right shrink-0">
            <div className="text-sm font-semibold tabular-nums">{findingsTotal}</div>
            <div className="text-[10px] uppercase tracking-wide text-muted-foreground">
              finding{findingsTotal === 1 ? '' : 's'}
            </div>
          </div>

          <ChevronRight className="h-4 w-4 text-muted-foreground shrink-0" />
        </div>
      </Card>
    </Link>
  );
}
