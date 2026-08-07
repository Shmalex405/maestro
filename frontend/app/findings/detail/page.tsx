'use client';

import { useState, useMemo, Suspense } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useSearchParams, useRouter } from 'next/navigation';
import { api } from '@/lib/tauri-api';
import { jiraTicketUrl } from '@/lib/jira';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Skeleton } from '@/components/ui/skeleton';
import { Separator } from '@/components/ui/separator';
import { AlertOctagon, AlertTriangle, AlertCircle, Info, ArrowLeft, ExternalLink, Ticket, Trash2, Cloud, Container, MapPin, Box, Copy, Check } from 'lucide-react';
import { toast } from 'sonner';
import { ReportViewer } from '@/components/reports/report-viewer';
import { inferCloudFromFinding, PROVIDER_DISPLAY } from '@/lib/finding-cloud-inference';

const severityConfig = { critical: { icon: AlertOctagon, color: 'bg-red-500' }, high: { icon: AlertTriangle, color: 'bg-orange-500' }, medium: { icon: AlertCircle, color: 'bg-yellow-500' }, low: { icon: Info, color: 'bg-blue-500' }, info: { icon: Info, color: 'bg-gray-500' } };
const statusOptions = ['open', 'in_progress', 'remediated', 'accepted'];

/* eslint-disable @typescript-eslint/no-explicit-any */
function buildFindingMarkdown(finding: any): string {
  // If description already contains markdown sections (## headers, tables, code blocks),
  // it's a full report-format finding — render it directly
  const desc = finding.description || '';
  const isFullMarkdown = desc.includes('##') || desc.includes('| ') || desc.includes('```');

  if (isFullMarkdown) {
    return desc;
  }

  // Otherwise, build markdown from individual fields (fallback for simple findings)
  const lines: string[] = [];

  lines.push('| Attribute | Value |');
  lines.push('|-----------|-------|');
  lines.push(`| **Severity** | **${(finding.severity || '').toUpperCase()}** |`);
  lines.push(`| **Exploitable** | ${(finding.exploitable || 'potentially').toUpperCase()} |`);
  if (finding.cwe) lines.push(`| **CWE** | ${finding.cwe} |`);
  if (finding.cve) lines.push(`| **CVE** | ${finding.cve} |`);
  lines.push(`| **Target** | \`${finding.target}\` |`);
  if (finding.file_path) lines.push(`| **File** | \`${finding.file_path}\` |`);
  if (finding.line_start) {
    const lineRange = finding.line_end ? `${finding.line_start}–${finding.line_end}` : `${finding.line_start}`;
    lines.push(`| **Lines** | ${lineRange} |`);
  }
  if (finding.source) lines.push(`| **Source** | ${finding.source} |`);
  if (finding.cycode_ref) lines.push(`| **Cycode Refs** | ${finding.cycode_ref} |`);
  lines.push('');

  lines.push('## Description');
  lines.push('');
  lines.push(desc || 'No description available.');
  lines.push('');

  if (finding.code_snippet) {
    lines.push('## Vulnerable Code');
    lines.push('');
    if (finding.file_path) {
      lines.push(`**File:** \`${finding.file_path}\`${finding.line_start ? ` (line ${finding.line_start})` : ''}`);
      lines.push('');
    }
    lines.push('```');
    lines.push(finding.code_snippet);
    lines.push('```');
    lines.push('');
  }

  if (finding.file_locations) {
    try {
      const locations = typeof finding.file_locations === 'string'
        ? JSON.parse(finding.file_locations)
        : finding.file_locations;
      if (Array.isArray(locations) && locations.length > 0) {
        lines.push('## Affected File Locations');
        lines.push('');
        lines.push('| # | File | Line | Context |');
        lines.push('|---|------|------|---------|');
        locations.forEach((loc: any, i: number) => {
          lines.push(`| ${i + 1} | \`${loc.file}\` | ${loc.line || '—'} | ${loc.context || '—'} |`);
        });
        lines.push('');
      }
    } catch {
      // skip
    }
  }

  if (finding.evidence) {
    lines.push('## Exploitation Evidence');
    lines.push('');
    lines.push('```');
    lines.push(finding.evidence);
    lines.push('```');
    lines.push('');
  }

  if (finding.remediation || finding.remediation_code) {
    lines.push('## Remediation');
    lines.push('');
    if (finding.remediation) {
      lines.push(finding.remediation);
      lines.push('');
    }
    if (finding.remediation_code) {
      lines.push('**Fixed Code:**');
      lines.push('');
      lines.push('```');
      lines.push(finding.remediation_code);
      lines.push('```');
      lines.push('');
    }
    if (finding.remediation_explanation) {
      lines.push(`**Why this works:** ${finding.remediation_explanation}`);
      lines.push('');
    }
  }

  return lines.join('\n');
}

// Small clipboard-copy button for ARN values. ARNs are long and reviewers
// frequently paste them into the cloud console — give them a one-click copy.
function ArnCopyButton({ value }: { value: string }) {
  const [copied, setCopied] = useState(false);
  const onCopy = async () => {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch (err) {
      console.warn('[finding-detail] copy ARN failed', err);
    }
  };
  return (
    <Button variant="ghost" size="icon" className="h-6 w-6 shrink-0" onClick={onCopy} title="Copy">
      {copied ? <Check className="h-3 w-3 text-green-500" /> : <Copy className="h-3 w-3" />}
    </Button>
  );
}

function FindingDetailContent() {
  const searchParams = useSearchParams();
  const router = useRouter();
  const queryClient = useQueryClient();
  const [jiraProjectKey, setJiraProjectKey] = useState('');
  const [jiraDialogOpen, setJiraDialogOpen] = useState(false);
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);

  const id = searchParams.get('id');

  const { data: finding, isLoading, error } = useQuery({ queryKey: ['finding', id], queryFn: () => api.findings.get(id as string), enabled: !!id });

  // Jira base URL for the ticket deep-link — sourced from integrations config, never hardcoded
  const { data: integrations } = useQuery({ queryKey: ['integrations'], queryFn: () => api.config.integrations.get() });
  const jiraBaseUrl = integrations?.jira?.url || '';

  const updateMutation = useMutation({
    mutationFn: (data: { status?: 'open' | 'in_progress' | 'remediated' | 'accepted' }) => api.findings.update(id as string, data),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ['finding', id] }); queryClient.invalidateQueries({ queryKey: ['findings'] }); toast.success('Finding updated'); },
    onError: () => toast.error('Failed to update finding'),
  });

  const createJiraMutation = useMutation({
    mutationFn: () => api.findings.createJiraTicket(id as string, { project_key: jiraProjectKey }),
    onSuccess: (data) => { queryClient.invalidateQueries({ queryKey: ['finding', id] }); setJiraDialogOpen(false); toast.success(`Jira ticket ${data.ticket_key} created`); },
    onError: () => toast.error('Failed to create Jira ticket'),
  });

  const deleteMutation = useMutation({
    mutationFn: () => api.findings.delete(id as string),
    onSuccess: () => { toast.success('Finding deleted'); router.push('/findings'); },
    onError: () => toast.error('Failed to delete finding'),
  });

  const markdown = useMemo(() => finding ? buildFindingMarkdown(finding) : '', [finding]);

  if (!id) return (<div className="flex flex-col items-center justify-center py-12"><p className="text-muted-foreground mb-4">No finding ID provided</p><Button variant="outline" onClick={() => router.push('/findings')}><ArrowLeft className="mr-2 h-4 w-4" />Back to Findings</Button></div>);

  if (isLoading) return (<div className="space-y-6"><Skeleton className="h-8 w-48" /><div className="grid gap-6 lg:grid-cols-3"><div className="lg:col-span-2 space-y-6"><Skeleton className="h-64" /><Skeleton className="h-96" /></div><Skeleton className="h-64" /></div></div>);

  if (error || !finding) return (<div className="flex flex-col items-center justify-center py-12"><p className="text-muted-foreground mb-4">Finding not found</p><Button variant="outline" onClick={() => router.push('/findings')}><ArrowLeft className="mr-2 h-4 w-4" />Back to Findings</Button></div>);

  const config = severityConfig[finding.severity as keyof typeof severityConfig];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div className="space-y-1">
          <Button variant="ghost" size="sm" onClick={() => router.push('/findings')} className="mb-2 -ml-2"><ArrowLeft className="mr-2 h-4 w-4" />Back to Findings</Button>
          <div className="flex items-center gap-3">
            <Badge className={`${config?.color || 'bg-gray-500'} text-white`}>{finding.severity}</Badge>
            {finding.original_severity &&
              finding.calibrated_severity &&
              finding.original_severity !== finding.calibrated_severity && (
                <Badge
                  variant="outline"
                  className="text-xs font-medium border-dashed"
                  title={
                    [
                      `${finding.original_severity.toUpperCase()} → ${finding.calibrated_severity.toUpperCase()}`,
                      finding.calibration_rule,
                      finding.calibration_justification,
                    ]
                      .filter(Boolean)
                      .join(' — ')
                  }
                >
                  was {finding.original_severity}
                </Badge>
              )}
            <h1 className="text-2xl font-bold">{finding.title}</h1>
          </div>
          <p className="text-muted-foreground">{finding.target}</p>
        </div>
        <div className="flex gap-2">
          <Dialog open={jiraDialogOpen} onOpenChange={setJiraDialogOpen}><DialogTrigger asChild><Button variant="outline" disabled={!!finding.jira_ticket}><Ticket className="mr-2 h-4 w-4" />{finding.jira_ticket ? 'Ticket Created' : 'Create Jira Ticket'}</Button></DialogTrigger><DialogContent><DialogHeader><DialogTitle>Create Jira Ticket</DialogTitle><DialogDescription>Create a Jira ticket for this finding.</DialogDescription></DialogHeader><div className="space-y-4 py-4"><div className="space-y-2"><Label htmlFor="project">Project Key</Label><Input id="project" placeholder="SEC" value={jiraProjectKey} onChange={(e) => setJiraProjectKey(e.target.value.toUpperCase())} /></div></div><DialogFooter><Button variant="outline" onClick={() => setJiraDialogOpen(false)}>Cancel</Button><Button onClick={() => createJiraMutation.mutate()} disabled={!jiraProjectKey || createJiraMutation.isPending}>{createJiraMutation.isPending ? 'Creating...' : 'Create'}</Button></DialogFooter></DialogContent></Dialog>
          <Dialog open={deleteDialogOpen} onOpenChange={setDeleteDialogOpen}><DialogTrigger asChild><Button variant="outline" className="text-destructive"><Trash2 className="mr-2 h-4 w-4" />Delete</Button></DialogTrigger><DialogContent><DialogHeader><DialogTitle>Delete Finding</DialogTitle><DialogDescription>This cannot be undone.</DialogDescription></DialogHeader><DialogFooter><Button variant="outline" onClick={() => setDeleteDialogOpen(false)}>Cancel</Button><Button variant="destructive" onClick={() => deleteMutation.mutate()} disabled={deleteMutation.isPending}>{deleteMutation.isPending ? 'Deleting...' : 'Delete'}</Button></DialogFooter></DialogContent></Dialog>
        </div>
      </div>

      {/* Two-column layout: Full finding document + sidebar details */}
      <div className="grid gap-6 lg:grid-cols-3">
        {/* Main content — rendered as markdown matching report format */}
        <div className="lg:col-span-2">
          <Card className="overflow-hidden">
            <ReportViewer content={markdown} maxHeight="calc(100vh - 200px)" />
          </Card>
        </div>

        {/* Sidebar — metadata & actions */}
        <div className="space-y-6">
          {(() => {
            // Sniff cloud shape from finding fields. When non-empty, render
            // a dedicated Cloud Resource card so reviewers get provider /
            // ARN / account / region in one place instead of having to
            // parse the target string by eye.
            const cloud = inferCloudFromFinding(finding);
            if (!cloud.provider) return null;
            const provider = PROVIDER_DISPLAY[cloud.provider];
            return (
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Badge className={`${provider.color} text-white text-xs gap-1`}>
                      {cloud.provider === 'k8s' ? (
                        <Container className="h-3 w-3" />
                      ) : (
                        <Cloud className="h-3 w-3" />
                      )}
                      {provider.label}
                    </Badge>
                    Cloud Resource
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-3">
                  {cloud.arn && (
                    <div>
                      <Label className="text-xs text-muted-foreground">ARN</Label>
                      <div className="mt-1 flex items-center gap-1">
                        <code className="font-mono text-xs break-all flex-1 px-2 py-1 rounded bg-muted">
                          {cloud.arn}
                        </code>
                        <ArnCopyButton value={cloud.arn} />
                      </div>
                    </div>
                  )}
                  {cloud.account_id && (
                    <div>
                      <Label className="text-xs text-muted-foreground">
                        {cloud.provider === 'aws'
                          ? 'AWS Account'
                          : cloud.provider === 'azure'
                            ? 'Subscription'
                            : cloud.provider === 'gcp'
                              ? 'Project'
                              : 'Account'}
                      </Label>
                      <p className="mt-1 font-mono text-sm break-all">{cloud.account_id}</p>
                    </div>
                  )}
                  {cloud.region && (
                    <div>
                      <Label className="text-xs text-muted-foreground">Region</Label>
                      <div className="mt-1 flex items-center gap-1">
                        <MapPin className="h-3 w-3 text-muted-foreground" />
                        <span className="font-mono text-sm">{cloud.region}</span>
                      </div>
                    </div>
                  )}
                  {cloud.resource_type && (
                    <div>
                      <Label className="text-xs text-muted-foreground">Resource Type</Label>
                      <div className="mt-1 flex items-center gap-1">
                        <Box className="h-3 w-3 text-muted-foreground" />
                        <span className="font-mono text-sm">{cloud.resource_type}</span>
                      </div>
                    </div>
                  )}
                  {cloud.k8s_cluster && (
                    <div>
                      <Label className="text-xs text-muted-foreground">Kubernetes</Label>
                      <p className="mt-1 font-mono text-sm break-all">
                        {cloud.k8s_cluster}
                        {cloud.k8s_namespace && (
                          <span className="text-muted-foreground"> / {cloud.k8s_namespace}</span>
                        )}
                      </p>
                    </div>
                  )}
                </CardContent>
              </Card>
            );
          })()}

          {/* Severity calibration card — only renders when the calibrator
              produced a delta. Shows the original severity, the rule
              that fired, and the prose justification so reviewers can
              audit why the dashboard severity differs from the scanner-
              raw severity for this row. */}
          {finding.calibrated_severity &&
            finding.original_severity &&
            finding.original_severity !== finding.calibrated_severity && (
              <Card>
                <CardHeader>
                  <CardTitle>Severity calibration</CardTitle>
                </CardHeader>
                <CardContent className="space-y-3">
                  <div className="flex items-center gap-2">
                    <Badge
                      className={`${severityConfig[finding.original_severity as keyof typeof severityConfig]?.color || 'bg-gray-500'} text-white`}
                    >
                      {finding.original_severity}
                    </Badge>
                    <span className="text-muted-foreground text-sm">→</span>
                    <Badge
                      className={`${severityConfig[finding.calibrated_severity as keyof typeof severityConfig]?.color || 'bg-gray-500'} text-white`}
                    >
                      {finding.calibrated_severity}
                    </Badge>
                    <span className="text-xs text-muted-foreground">
                      (scanner → calibrated)
                    </span>
                  </div>
                  {finding.calibration_rule && (
                    <div>
                      <Label className="text-xs text-muted-foreground">Rule</Label>
                      <p className="mt-1 text-sm">{finding.calibration_rule}</p>
                    </div>
                  )}
                  {finding.calibration_justification && (
                    <div>
                      <Label className="text-xs text-muted-foreground">Why</Label>
                      <p className="mt-1 text-sm leading-relaxed">
                        {finding.calibration_justification}
                      </p>
                    </div>
                  )}
                </CardContent>
              </Card>
            )}

          <Card><CardHeader><CardTitle>Details</CardTitle></CardHeader><CardContent className="space-y-4">
            <div><Label className="text-xs text-muted-foreground">Status</Label><Select value={finding.status} onValueChange={(v) => updateMutation.mutate({ status: v as 'open' | 'in_progress' | 'remediated' | 'accepted' })}><SelectTrigger className="mt-1"><SelectValue /></SelectTrigger><SelectContent>{statusOptions.map((s) => (<SelectItem key={s} value={s}>{s.replace('_', ' ')}</SelectItem>))}</SelectContent></Select></div>
            <Separator />
            {finding.exploitable && (<div><Label className="text-xs text-muted-foreground">Exploitable</Label><div className="mt-1"><Badge variant={finding.exploitable === 'true' ? 'destructive' : 'outline'} className="font-mono text-xs">{finding.exploitable.toUpperCase()}</Badge></div></div>)}
            <div><Label className="text-xs text-muted-foreground">Target</Label><p className="mt-1 font-mono text-sm break-all">{finding.target}</p></div>
            {finding.source && (<div><Label className="text-xs text-muted-foreground">Source</Label><div className="mt-1"><Badge variant="outline" className="font-mono text-xs">{finding.source}</Badge></div></div>)}
            {finding.cve && (<div><Label className="text-xs text-muted-foreground">CVE</Label><a href={`https://nvd.nist.gov/vuln/detail/${finding.cve}`} target="_blank" rel="noopener noreferrer" className="mt-1 text-primary hover:underline flex items-center gap-1">{finding.cve}<ExternalLink className="h-3 w-3" /></a></div>)}
            {finding.cwe && (<div><Label className="text-xs text-muted-foreground">CWE</Label><a href={`https://cwe.mitre.org/data/definitions/${finding.cwe.replace('CWE-', '')}.html`} target="_blank" rel="noopener noreferrer" className="mt-1 text-primary hover:underline flex items-center gap-1">{finding.cwe}<ExternalLink className="h-3 w-3" /></a></div>)}
            {finding.file_path && (<><Separator /><div><Label className="text-xs text-muted-foreground">File</Label><p className="mt-1 font-mono text-sm break-all">{finding.file_path}</p></div></>)}
            {finding.line_start && (<div><Label className="text-xs text-muted-foreground">Lines</Label><p className="mt-1 font-mono text-sm">{finding.line_start}{finding.line_end ? `–${finding.line_end}` : ''}</p></div>)}
            {finding.cycode_ref && (<div><Label className="text-xs text-muted-foreground">Cycode Refs</Label><p className="mt-1 font-mono text-xs break-all">{finding.cycode_ref}</p></div>)}
            {finding.jira_ticket && (<div><Label className="text-xs text-muted-foreground">Jira</Label>{jiraTicketUrl(jiraBaseUrl, finding.jira_ticket) ? (<a href={jiraTicketUrl(jiraBaseUrl, finding.jira_ticket)!} target="_blank" rel="noopener noreferrer" className="mt-1 text-primary hover:underline flex items-center gap-1">{finding.jira_ticket}<ExternalLink className="h-3 w-3" /></a>) : (<span className="mt-1 text-primary flex items-center gap-1">{finding.jira_ticket}</span>)}</div>)}
            <Separator />
            <div><Label className="text-xs text-muted-foreground">Assessment</Label><p className="mt-1 text-sm">{finding.assessment_id || '—'}</p></div>
            <div><Label className="text-xs text-muted-foreground">Created</Label><p className="mt-1 text-sm">{new Date(finding.created_at).toLocaleString()}</p></div>
            <div><Label className="text-xs text-muted-foreground">ID</Label><p className="mt-1 font-mono text-xs text-muted-foreground break-all">{finding.id}</p></div>
          </CardContent></Card>
        </div>
      </div>
    </div>
  );
}

export default function FindingDetailPage() {
  return (
    <Suspense fallback={<div className="space-y-6"><Skeleton className="h-8 w-48" /><div className="grid gap-6 lg:grid-cols-3"><div className="lg:col-span-2 space-y-6"><Skeleton className="h-64" /><Skeleton className="h-96" /></div><Skeleton className="h-64" /></div></div>}>
      <FindingDetailContent />
    </Suspense>
  );
}
