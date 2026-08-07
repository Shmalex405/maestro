'use client';

import { useState, useCallback } from 'react';
import { PageHeader } from '@/components/layout/page-header';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { api } from '@/lib/tauri-api';
import type { ParsedFinding, ImportedFinding, Import, Severity, Repository } from '@/lib/types';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Checkbox } from '@/components/ui/checkbox';
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
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { ScrollArea } from '@/components/ui/scroll-area';
import { toast } from 'sonner';
import {
  Upload,
  FileSpreadsheet,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Play,
  FileCode,
  ExternalLink,
  Clock,
  Trash2,
  FolderOpen,
  RefreshCw,
} from 'lucide-react';

function getSeverityBadge(severity: Severity | string) {
  const severityLower = severity.toLowerCase() as Severity;
  const colors: Record<Severity, string> = {
    critical: 'bg-red-500 text-white',
    high: 'bg-orange-500 text-white',
    medium: 'bg-yellow-500 text-black',
    low: 'bg-blue-500 text-white',
    info: 'bg-gray-500 text-white',
  };

  return (
    <Badge className={colors[severityLower] || 'bg-gray-500 text-white'}>
      {severity.toUpperCase()}
    </Badge>
  );
}

function formatDate(dateString: string): string {
  try {
    return new Date(dateString).toLocaleString();
  } catch {
    return dateString;
  }
}

export default function ImportPage() {
  const queryClient = useQueryClient();
  const [csvContent, setCsvContent] = useState('');
  const [importName, setImportName] = useState('');
  const [previewFindings, setPreviewFindings] = useState<ParsedFinding[]>([]);
  const [selectedIndices, setSelectedIndices] = useState<Set<number>>(new Set());
  const [selectedRepo, setSelectedRepo] = useState<string>('');
  const [activeTab, setActiveTab] = useState('upload');
  const [uploadedFilename, setUploadedFilename] = useState<string | null>(null);

  // Fetch repositories for linking
  const { data: repositories } = useQuery({
    queryKey: ['repositories'],
    queryFn: () => api.repositories.list(),
  });

  // Fetch import history
  const { data: imports, isLoading: importsLoading } = useQuery({
    queryKey: ['imports'],
    queryFn: () => api.imports.list(),
  });

  // Fetch pending validation findings
  const { data: pendingFindings, isLoading: pendingLoading } = useQuery({
    queryKey: ['imported-findings-pending'],
    queryFn: () => api.importedFindings.getPending(),
  });

  // Fetch import statistics
  const { data: importStats } = useQuery({
    queryKey: ['import-stats'],
    queryFn: () => api.imports.getStats(),
  });

  // Preview CSV mutation
  const previewMutation = useMutation({
    mutationFn: (content: string) => api.imports.previewCsv(content),
    onSuccess: (result) => {
      setPreviewFindings(result.findings);
      setSelectedIndices(new Set(result.findings.map((_, i) => i)));
      setActiveTab('preview');
      if (result.errors.length > 0) {
        toast.warning(`Parsed ${result.findings.length} findings with ${result.errors.length} warnings`);
      } else {
        toast.success(`Parsed ${result.total_count} findings`);
      }
    },
    onError: (error: Error) => {
      toast.error(`Failed to parse CSV: ${error.message}`);
    },
  });

  // Import CSV mutation
  const importMutation = useMutation({
    mutationFn: () =>
      api.imports.importCsv(csvContent, {
        name: importName || undefined,
        filename: uploadedFilename || undefined,
        selected_indices: Array.from(selectedIndices),
      }),
    onSuccess: (result) => {
      queryClient.invalidateQueries({ queryKey: ['imports'] });
      queryClient.invalidateQueries({ queryKey: ['imported-findings-pending'] });
      queryClient.invalidateQueries({ queryKey: ['import-stats'] });
      toast.success(`Imported ${result.imported_count} findings`);
      setCsvContent('');
      setImportName('');
      setPreviewFindings([]);
      setUploadedFilename(null);
      setActiveTab('pending');
    },
    onError: (error: Error) => {
      toast.error(`Failed to import: ${error.message}`);
    },
  });

  // Delete import mutation
  const deleteImportMutation = useMutation({
    mutationFn: (id: string) => api.imports.delete(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['imports'] });
      queryClient.invalidateQueries({ queryKey: ['imported-findings-pending'] });
      queryClient.invalidateQueries({ queryKey: ['import-stats'] });
      toast.success('Import deleted');
    },
    onError: (error: Error) => {
      toast.error(`Failed to delete import: ${error.message}`);
    },
  });

  // Create validation assessment mutation
  const validateMutation = useMutation({
    mutationFn: (findingIds: string[]) =>
      api.importedFindings.createValidationAssessment({
        finding_ids: findingIds,
        repository_id: selectedRepo || undefined,
        // Generic name — imports accept any CSV source, not just Cycode.
        name: 'Imported findings validation',
      }),
    onSuccess: (assessment) => {
      queryClient.invalidateQueries({ queryKey: ['imported-findings-pending'] });
      toast.success('Validation assessment started');
      window.location.href = `/assessments/detail?id=${assessment.id}`;
    },
    onError: (error: Error) => {
      toast.error(`Failed to start validation: ${error.message}`);
    },
  });

  const handleFileUpload = useCallback(
    (event: React.ChangeEvent<HTMLInputElement>) => {
      const file = event.target.files?.[0];
      if (!file) return;

      setUploadedFilename(file.name);
      const reader = new FileReader();
      reader.onload = (e) => {
        const content = e.target?.result as string;
        setCsvContent(content);
        previewMutation.mutate(content);
      };
      reader.readAsText(file);
    },
    [previewMutation]
  );

  const handleDrop = useCallback(
    (event: React.DragEvent<HTMLDivElement>) => {
      event.preventDefault();
      const file = event.dataTransfer.files?.[0];
      if (!file) return;

      setUploadedFilename(file.name);
      const reader = new FileReader();
      reader.onload = (e) => {
        const content = e.target?.result as string;
        setCsvContent(content);
        previewMutation.mutate(content);
      };
      reader.readAsText(file);
    },
    [previewMutation]
  );

  const handleDragOver = useCallback((event: React.DragEvent<HTMLDivElement>) => {
    event.preventDefault();
  }, []);

  const toggleFinding = (index: number) => {
    setSelectedIndices((prev) => {
      const next = new Set(prev);
      if (next.has(index)) {
        next.delete(index);
      } else {
        next.add(index);
      }
      return next;
    });
  };

  const toggleAll = () => {
    if (selectedIndices.size === previewFindings.length) {
      setSelectedIndices(new Set());
    } else {
      setSelectedIndices(new Set(previewFindings.map((_, i) => i)));
    }
  };

  return (
    <div className="space-y-6">
      <PageHeader
        title="Import Vulnerabilities"
        description="Import findings from SAST scans, CSV exports, or other sources for validation"
        actions={importStats && (
          <div className="flex gap-4 text-sm">
            <div className="text-center">
              <div className="text-2xl font-bold">{importStats.total_imports ?? 0}</div>
              <div className="text-muted-foreground">Imports</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold">{importStats.total_findings ?? 0}</div>
              <div className="text-muted-foreground">Findings</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-amber-500">
                {importStats.by_status?.pending_validation ?? 0}
              </div>
              <div className="text-muted-foreground">Pending</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-green-500">
                {importStats.by_status?.confirmed ?? 0}
              </div>
              <div className="text-muted-foreground">Confirmed</div>
            </div>
          </div>
        )}
      />

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList>
          <TabsTrigger value="upload">Upload</TabsTrigger>
          <TabsTrigger value="preview" disabled={previewFindings.length === 0}>
            Preview ({previewFindings.length})
          </TabsTrigger>
          <TabsTrigger value="pending">
            Pending Validation ({pendingFindings?.length || 0})
          </TabsTrigger>
          <TabsTrigger value="history">Import History ({imports?.length || 0})</TabsTrigger>
        </TabsList>

        {/* Upload Tab */}
        <TabsContent value="upload" className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>Upload CSV</CardTitle>
              <CardDescription>
                Drop a CSV export file or click to choose one. Supports Semgrep and
                generic CSV formats.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              {/* Drop zone */}
              <div
                onDrop={handleDrop}
                onDragOver={handleDragOver}
                className="border-2 border-dashed rounded-lg p-12 text-center hover:border-primary transition-colors cursor-pointer"
                onClick={() => document.getElementById('csv-upload')?.click()}
              >
                <input
                  id="csv-upload"
                  type="file"
                  accept=".csv"
                  className="hidden"
                  onChange={handleFileUpload}
                />
                <FileSpreadsheet className="h-12 w-12 mx-auto text-muted-foreground mb-4" />
                <p className="font-medium">Drop CSV file here or click to upload</p>
                <p className="text-sm text-muted-foreground mt-1">
                  Supports Semgrep results and custom CSV formats
                </p>
                {uploadedFilename && (
                  <Badge variant="secondary" className="mt-2">
                    {uploadedFilename}
                  </Badge>
                )}
              </div>

              {/* Import name */}
              <div className="space-y-2">
                <Label htmlFor="import-name">Import Name (optional)</Label>
                <Input
                  id="import-name"
                  placeholder="e.g., SAST Scan - Jan 2026"
                  value={importName}
                  onChange={(e) => setImportName(e.target.value)}
                />
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Preview Tab */}
        <TabsContent value="preview" className="space-y-6">
          <Card>
            <CardHeader>
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle>Preview Findings</CardTitle>
                  <CardDescription>
                    Review and select findings to import ({selectedIndices.size} of{' '}
                    {previewFindings.length} selected)
                  </CardDescription>
                </div>
                <div className="flex gap-2">
                  <Button variant="outline" onClick={() => setActiveTab('upload')}>
                    Back
                  </Button>
                  <Button
                    onClick={() => importMutation.mutate()}
                    disabled={selectedIndices.size === 0 || importMutation.isPending}
                  >
                    {importMutation.isPending ? 'Importing...' : 'Import Selected'}
                    <Upload className="h-4 w-4 ml-2" />
                  </Button>
                </div>
              </div>
            </CardHeader>
            <CardContent>
              <div className="border rounded-lg">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead className="w-12">
                        <Checkbox
                          checked={selectedIndices.size === previewFindings.length}
                          onCheckedChange={toggleAll}
                        />
                      </TableHead>
                      <TableHead className="w-24">Severity</TableHead>
                      <TableHead>Type</TableHead>
                      <TableHead>File</TableHead>
                      <TableHead className="w-20">Line</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {previewFindings.map((finding, index) => (
                      <TableRow key={index}>
                        <TableCell>
                          <Checkbox
                            checked={selectedIndices.has(index)}
                            onCheckedChange={() => toggleFinding(index)}
                          />
                        </TableCell>
                        <TableCell>{getSeverityBadge(finding.severity)}</TableCell>
                        <TableCell className="font-medium">{finding.vulnerability_type}</TableCell>
                        <TableCell className="font-mono text-sm truncate max-w-xs">
                          {finding.file_path || '-'}
                        </TableCell>
                        <TableCell className="font-mono text-sm">
                          {finding.line_number || '-'}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Pending Validation Tab */}
        <TabsContent value="pending" className="space-y-6">
          <Card>
            <CardHeader>
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle>Pending Validation</CardTitle>
                  <CardDescription>
                    Imported findings awaiting security validation
                  </CardDescription>
                </div>
                {pendingFindings && pendingFindings.length > 0 && (
                  <div className="flex items-center gap-4">
                    <Select
                      value={selectedRepo || 'none'}
                      onValueChange={(v) => setSelectedRepo(v === 'none' ? '' : v)}
                    >
                      <SelectTrigger className="w-64">
                        <SelectValue placeholder="Link to repository (optional)" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="none">No repository</SelectItem>
                        {repositories?.map((repo) => (
                          <SelectItem key={repo.id} value={repo.id}>
                            {repo.name}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                    <Button
                      onClick={() =>
                        validateMutation.mutate(pendingFindings.map((f) => f.id))
                      }
                      disabled={validateMutation.isPending}
                    >
                      {validateMutation.isPending ? 'Starting...' : 'Validate All'}
                      <Play className="h-4 w-4 ml-2" />
                    </Button>
                  </div>
                )}
              </div>
            </CardHeader>
            <CardContent>
              {pendingLoading ? (
                <div className="text-center py-12">
                  <RefreshCw className="h-8 w-8 mx-auto text-muted-foreground animate-spin mb-4" />
                  <p className="text-muted-foreground">Loading...</p>
                </div>
              ) : pendingFindings && pendingFindings.length > 0 ? (
                <div className="border rounded-lg">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead className="w-24">Severity</TableHead>
                        <TableHead>Type</TableHead>
                        <TableHead>File</TableHead>
                        <TableHead className="w-20">Line</TableHead>
                        <TableHead className="w-32">Status</TableHead>
                        <TableHead className="w-20"></TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {pendingFindings.map((finding) => (
                        <TableRow key={finding.id}>
                          <TableCell>{getSeverityBadge(finding.severity)}</TableCell>
                          <TableCell className="font-medium">
                            {finding.vulnerability_type}
                          </TableCell>
                          <TableCell className="font-mono text-sm truncate max-w-xs">
                            {finding.file_path || '-'}
                          </TableCell>
                          <TableCell className="font-mono text-sm">
                            {finding.line_number || '-'}
                          </TableCell>
                          <TableCell>
                            {finding.status === 'imported' && (
                              <Badge variant="secondary">
                                <AlertTriangle className="h-3 w-3 mr-1" />
                                Pending
                              </Badge>
                            )}
                            {finding.status === 'validating' && (
                              <Badge className="bg-blue-500">
                                <Play className="h-3 w-3 mr-1" />
                                Validating
                              </Badge>
                            )}
                            {finding.status === 'confirmed' && (
                              <Badge className="bg-red-500">
                                <CheckCircle2 className="h-3 w-3 mr-1" />
                                Confirmed
                              </Badge>
                            )}
                            {finding.status === 'false_positive' && (
                              <Badge variant="outline">
                                <XCircle className="h-3 w-3 mr-1" />
                                False Positive
                              </Badge>
                            )}
                          </TableCell>
                          <TableCell>
                            <Button
                              variant="ghost"
                              size="icon"
                              aria-label={`View finding ${finding.id}`}
                              onClick={() => {
                                window.location.href = `/findings/detail?id=${finding.id}`;
                              }}
                            >
                              <ExternalLink className="h-4 w-4" />
                            </Button>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
              ) : (
                <div className="text-center py-12">
                  <FileCode className="h-12 w-12 mx-auto text-muted-foreground mb-4" />
                  <h3 className="font-semibold text-lg mb-2">No pending findings</h3>
                  <p className="text-muted-foreground mb-4">
                    Import a CSV to add findings for validation
                  </p>
                  <Button variant="outline" onClick={() => setActiveTab('upload')}>
                    <Upload className="h-4 w-4 mr-2" />
                    Import CSV
                  </Button>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* Import History Tab */}
        <TabsContent value="history" className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>Import History</CardTitle>
              <CardDescription>View and manage all previous imports</CardDescription>
            </CardHeader>
            <CardContent>
              {importsLoading ? (
                <div className="text-center py-12">
                  <RefreshCw className="h-8 w-8 mx-auto text-muted-foreground animate-spin mb-4" />
                  <p className="text-muted-foreground">Loading...</p>
                </div>
              ) : imports && imports.length > 0 ? (
                <ScrollArea className="h-[500px]">
                  <div className="space-y-3">
                    {imports.map((imp) => (
                      <div
                        key={imp.id}
                        className="flex items-center justify-between p-4 border rounded-lg hover:bg-muted/50 transition-colors"
                      >
                        <div className="flex items-center gap-4">
                          <div className="p-2 rounded-lg bg-muted">
                            <FolderOpen className="h-5 w-5 text-muted-foreground" />
                          </div>
                          <div>
                            <div className="font-medium">{imp.name}</div>
                            <div className="text-sm text-muted-foreground flex items-center gap-2">
                              <Badge variant="outline">{imp.source}</Badge>
                              <span>{imp.findings_count} findings</span>
                              <span className="flex items-center gap-1">
                                <Clock className="h-3 w-3" />
                                {formatDate(imp.created_at)}
                              </span>
                            </div>
                            {imp.filename && (
                              <div className="text-xs text-muted-foreground mt-1">
                                {imp.filename}
                              </div>
                            )}
                          </div>
                        </div>
                        <div className="flex items-center gap-2">
                          <Badge
                            className={
                              imp.status === 'completed'
                                ? 'bg-green-500'
                                : imp.status === 'failed'
                                ? 'bg-red-500'
                                : 'bg-yellow-500'
                            }
                          >
                            {imp.status}
                          </Badge>
                          <Button
                            variant="ghost"
                            size="icon"
                            onClick={() => deleteImportMutation.mutate(imp.id)}
                            disabled={deleteImportMutation.isPending}
                          >
                            <Trash2 className="h-4 w-4 text-destructive" />
                          </Button>
                        </div>
                      </div>
                    ))}
                  </div>
                </ScrollArea>
              ) : (
                <div className="text-center py-12">
                  <FolderOpen className="h-12 w-12 mx-auto text-muted-foreground mb-4" />
                  <h3 className="font-semibold text-lg mb-2">No imports yet</h3>
                  <p className="text-muted-foreground mb-4">
                    Import your first CSV to get started
                  </p>
                  <Button variant="outline" onClick={() => setActiveTab('upload')}>
                    <Upload className="h-4 w-4 mr-2" />
                    Import CSV
                  </Button>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
