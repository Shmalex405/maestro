'use client';

// =============================================================================
// Code Security surface (/surfaces/code) — the SAST / source-code drill-down.
//
// Static analysis findings (Semgrep, Bandit, njsscan, secret scanning, SCA /
// dependency CVEs, IaC) land in the `code_security` category. Before this
// surface they had no lens — only the global /findings list — so the 17+ SAST
// findings an assessment produces were invisible to the per-surface graphs.
//
// Aggregation view — same shared FilterBar + SurfaceAnalytics + DashboardFindingsTable
// the other surfaces use, pinned to the `code` surface. No new data path.
// =============================================================================

import { Suspense, useEffect } from 'react';
import { useQuery } from '@tanstack/react-query';
import Link from 'next/link';
import { FileCode2, ArrowRight, ShieldCheck, KeyRound, Boxes, ServerCog } from 'lucide-react';
import { Skeleton } from '@/components/ui/skeleton';
import { Button } from '@/components/ui/button';
import { FilterBar } from '@/components/dashboard/filter-bar';
import { DashboardFindingsTable } from '@/components/dashboard/dashboard-findings-table';
import { SurfaceAnalytics } from '@/components/dashboard/surface-analytics';
import { FindingsOverTime } from '@/components/dashboard/findings-over-time';
import { api } from '@/lib/tauri-api';
import { useDashboardFilterStore } from '@/lib/stores/dashboard-filter-store';

// What the code-security surface aggregates — the SAST tool families.
const COVERAGE = [
  {
    icon: FileCode2,
    title: 'Static analysis (SAST)',
    detail:
      'Semgrep, Bandit, njsscan and friends — injection sinks, unsafe deserialization, weak crypto, path traversal, and other source-level vulnerabilities, with file + line + data-flow context.',
  },
  {
    icon: KeyRound,
    title: 'Secrets',
    detail:
      'Hardcoded credentials, API keys, and private keys found in source and git history (gitleaks / secret scanning) — each as a standalone finding with the real value and commit reference.',
  },
  {
    icon: Boxes,
    title: 'Dependencies (SCA)',
    detail:
      'Vulnerable third-party packages and their advisory CVEs, with the parent chain and a codebase-specific exploitation scenario.',
  },
  {
    icon: ServerCog,
    title: 'Infrastructure as Code',
    detail:
      'Misconfigurations in Terraform / CloudFormation / Kubernetes manifests and CI/CD workflow files.',
  },
];

function CodeSurface() {
  const setSurface = useDashboardFilterStore((s) => s.setSurface);

  // Pin the FilterBar to the code surface on mount.
  useEffect(() => {
    setSurface('code');
  }, [setSurface]);

  // Count for the header chip — same backend filter the table uses.
  const { data: findings } = useQuery({
    queryKey: ['code-finding-count'],
    queryFn: () => api.findings.list({ category: 'code_security' }),
  });
  const codeCount = Array.isArray(findings) ? findings.length : 0;

  return (
    <div className="space-y-5 max-w-[1400px] mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <div className="flex items-center gap-3">
          <div className="rounded-lg bg-primary/10 p-2">
            <FileCode2 className="h-5 w-5 text-primary" />
          </div>
          <div>
            <h1 className="text-2xl font-bold tracking-tight">Code Security</h1>
            <p className="text-sm text-muted-foreground mt-0.5">
              Static analysis, secrets, dependencies, and IaC — the source-code attack surface.
            </p>
          </div>
        </div>
        <Link href="/findings?surface=code">
          <Button variant="outline" size="sm" className="gap-1.5">
            All code findings <ArrowRight className="h-3.5 w-3.5" />
          </Button>
        </Link>
      </div>

      {/* Shared FilterBar — surface pinned to code */}
      <div className="glass-card rounded-xl p-3">
        <FilterBar showSurface={false} />
      </div>

      {/* Analytics strip — severity tiles (clickable filters) + donut + breakdown */}
      <SurfaceAnalytics />

      {/* Findings over time (trend) — locked to the code surface */}
      <FindingsOverTime initialDays={30} category="code_security" />

      {/* Code findings (surface lens) */}
      <div className="glass-card rounded-xl overflow-hidden">
        <div className="flex items-center gap-2 border-b border-border/50 px-4 py-3">
          <FileCode2 className="h-4 w-4 text-muted-foreground" />
          <span className="text-sm font-medium">Code Security findings</span>
          {codeCount > 0 && (
            <span className="ml-auto text-xs font-semibold text-primary">{codeCount}</span>
          )}
        </div>
        <DashboardFindingsTable />
      </div>

      {/* Coverage card — what the code surface aggregates. */}
      <div className="glass-card rounded-xl overflow-hidden">
        <div className="flex items-center gap-2 border-b border-border/50 px-4 py-3">
          <ShieldCheck className="h-4 w-4 text-muted-foreground" />
          <span className="text-sm font-medium">What code-security covers</span>
          <span className="text-[10px] text-muted-foreground">
            populated when a repo is in scope for the assessment
          </span>
        </div>
        <div className="divide-y divide-border/40">
          {COVERAGE.map((item) => {
            const Icon = item.icon;
            return (
              <div key={item.title} className="flex items-start gap-3 p-4">
                <div className="rounded-lg bg-muted/50 p-2">
                  <Icon className="h-4 w-4 text-muted-foreground" />
                </div>
                <div className="flex-1">
                  <span className="text-sm font-medium">{item.title}</span>
                  <p className="mt-0.5 text-xs text-muted-foreground">{item.detail}</p>
                </div>
              </div>
            );
          })}
        </div>
        <div className="border-t border-border/40 px-4 py-3 text-xs text-muted-foreground">
          Add a repository under <span className="font-mono">Code Repos</span> or include a repo path
          in an assessment — the SAST agents (scan + analysis) populate this surface and the SAST
          Companion Report.
        </div>
      </div>
    </div>
  );
}

export default function CodeSurfacePage() {
  return (
    <Suspense fallback={<div className="p-6"><Skeleton className="h-40 w-full" /></div>}>
      <CodeSurface />
    </Suspense>
  );
}
