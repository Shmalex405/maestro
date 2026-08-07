'use client';

// =============================================================================
// AI / LLM surface (/surfaces/ai) — the AI-plane drill-down.
//
// Standalone AI/LLM security assessment (see docs/ai-surface-plan.md): prompt
// injection, jailbreak, system-prompt leakage, sensitive disclosure, improper
// output handling, excessive agency, and unbounded consumption against a
// customer-owned, in-scope AI system (chatbot / agent / RAG app / MCP server /
// raw model API). An AI assessment runs only when `ai_targets` is defined in
// config/scope.yml; its findings land in the `ai` category (backend-rs
// category_from_source) and surface here via the shared lens
// (lib/surface.ts → ai: ['ai']).
//
// Aggregation view — same shared FilterBar + DashboardFindingsTable the cloud,
// web, and identity surfaces use, pinned to the AI surface. No parallel data
// path. Behind NEXT_PUBLIC_AI_ENABLED (default on); when no AI target has been
// scanned the shared table renders its own empty state and the coverage card
// below explains what scoping an ai_target unlocks.
// =============================================================================

import { Suspense, useEffect } from 'react';
import { useQuery } from '@tanstack/react-query';
import Link from 'next/link';
import { Bot, ArrowRight, MessageSquare, Wrench, BookOpenText, FileWarning, KeySquare, Gauge, ShieldCheck } from 'lucide-react';
import { Skeleton } from '@/components/ui/skeleton';
import { Button } from '@/components/ui/button';
import { FilterBar } from '@/components/dashboard/filter-bar';
import { DashboardFindingsTable } from '@/components/dashboard/dashboard-findings-table';
import { SurfaceAnalytics } from '@/components/dashboard/surface-analytics';
import { FindingsOverTime } from '@/components/dashboard/findings-over-time';
import { api } from '@/lib/tauri-api';
import { useDashboardFilterStore } from '@/lib/stores/dashboard-filter-store';

// The AI plane is structured around the OWASP Top 10 for LLM Applications (2025)
// plus agentic/MCP-specific risks. Each row is a capability family the AI agents
// (ai-recon → ai-redteam → ai-analysis) exercise; the report maps every finding
// to OWASP LLM + MITRE ATLAS.
const COVERAGE = [
  {
    icon: MessageSquare,
    title: 'Prompt injection & jailbreak (LLM01)',
    detail:
      'Direct and indirect prompt injection (via retrieved docs, tool outputs, fetched content), jailbreak batteries, and guardrail bypass — scored over N trials as a success-rate.',
  },
  {
    icon: KeySquare,
    title: 'System-prompt & sensitive disclosure (LLM07 / LLM02)',
    detail:
      'System-prompt / instruction / tool-schema extraction, plus cross-tenant, training-data, and backend-secret disclosure probes.',
  },
  {
    icon: FileWarning,
    title: 'Improper output handling (LLM05)',
    detail:
      'Model output driven into a downstream sink (HTML render → XSS, SQL concat, shell) — ai-redteam proves the sink itself end-to-end, no hand-off.',
  },
  {
    icon: Wrench,
    title: 'Excessive agency (LLM06)',
    detail:
      'Coerce a tool-using agent into firing a dangerous tool. Capability-not-execution: the captured tool call + arguments is the proof — real side effects pause for confirmation.',
  },
  {
    icon: BookOpenText,
    title: 'RAG isolation & misinformation (LLM08 / LLM09)',
    detail:
      'Retrieval / embedding tenant-isolation checks for RAG apps and confidently-wrong output probes in security-relevant contexts.',
  },
  {
    icon: Gauge,
    title: 'Unbounded consumption (LLM10)',
    detail:
      'A short, hard-capped proof that a rate / token / cost limit is absent — probe-only, never a sustained flood (the AI Safety Mandate).',
  },
];

function AiSurface() {
  const setSurface = useDashboardFilterStore((s) => s.setSurface);

  // Pin the FilterBar to the AI surface on mount.
  useEffect(() => {
    setSurface('ai');
  }, [setSurface]);

  // Count AI findings for the header chip — same backend filter the shared table
  // uses (category=ai), so the chip and the grid stay in lockstep.
  const { data: findings } = useQuery({
    queryKey: ['ai-finding-count'],
    queryFn: () => api.findings.list({ category: 'ai' }),
  });
  const aiCount = Array.isArray(findings) ? findings.length : 0;

  return (
    <div className="space-y-5 max-w-[1400px] mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <div className="flex items-center gap-3">
          <div className="rounded-lg bg-primary/10 p-2">
            <Bot className="h-5 w-5 text-primary" />
          </div>
          <div>
            <h1 className="text-2xl font-bold tracking-tight">AI / LLM</h1>
            <p className="text-sm text-muted-foreground mt-0.5">
              Prompt injection, excessive agency, and output-handling red teaming — the AI plane.
            </p>
          </div>
        </div>
        <Link href="/findings?surface=ai">
          <Button variant="outline" size="sm" className="gap-1.5">
            All AI findings <ArrowRight className="h-3.5 w-3.5" />
          </Button>
        </Link>
      </div>

      {/* Shared FilterBar — surface pinned to ai */}
      <div className="glass-card rounded-xl p-3">
        <FilterBar showSurface={false} />
      </div>

      {/* Analytics strip — severity tiles (clickable filters) + donut + breakdown */}
      <SurfaceAnalytics />

      {/* Findings over time (trend) — locked to the AI surface */}
      <FindingsOverTime initialDays={30} category="ai" />

      {/* AI findings (surface lens) */}
      <div className="glass-card rounded-xl overflow-hidden">
        <div className="flex items-center gap-2 border-b border-border/50 px-4 py-3">
          <Bot className="h-4 w-4 text-muted-foreground" />
          <span className="text-sm font-medium">AI / LLM findings</span>
          {aiCount > 0 && (
            <span className="ml-auto text-xs font-semibold text-primary">{aiCount}</span>
          )}
        </div>
        <DashboardFindingsTable />
      </div>

      {/* Coverage card — what scoping an ai_target unlocks. */}
      <div className="glass-card rounded-xl overflow-hidden">
        <div className="flex items-center gap-2 border-b border-border/50 px-4 py-3">
          <ShieldCheck className="h-4 w-4 text-muted-foreground" />
          <span className="text-sm font-medium">What AI / LLM testing covers</span>
          <span className="text-[10px] text-muted-foreground">
            runs only when <span className="font-mono">ai_targets</span> is in scope
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
          Scope a target under <span className="font-mono">Config → AI Targets</span> (writes
          <span className="font-mono"> ai_targets</span> in scope.yml) — its endpoint must also be in
          an in-scope <span className="font-mono">domains</span>/<span className="font-mono">networks</span> entry.
          Run it with <span className="font-mono">/assess-ai</span>. Consumption is probe-only and
          excessive-agency is capability-not-execution; state-changing steps pause for confirmation.
        </div>
      </div>
    </div>
  );
}

export default function AiSurfacePage() {
  return (
    <Suspense fallback={<div className="p-6"><Skeleton className="h-40 w-full" /></div>}>
      <AiSurface />
    </Suspense>
  );
}
