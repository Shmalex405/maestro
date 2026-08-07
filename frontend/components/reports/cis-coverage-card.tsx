'use client';

/**
 * CIS Benchmark Coverage card + markdown parser.
 *
 * Phase 1 added CIS Benchmark mappings to the compliance agent — every cloud
 * finding now gets cis_aws / cis_azure / cis_gcp / cis_k8s annotations and
 * the agent emits a coverage matrix to the report. This component closes
 * the loop by surfacing that coverage as a structured card at the top of
 * the report viewer instead of leaving it buried in a markdown table the
 * reader has to find.
 *
 * Why parse the markdown body instead of fetching compliance-results.json
 * directly: in cloud-routed mode (production), reports are stored in the
 * cloud backend with markdown-only payloads — the sibling JSON checkpoint
 * file is a local-only artifact the report-writer agent uses during
 * generation. By the time the desktop renders a report, only the markdown
 * is available. So we parse what's there.
 *
 * Parser strategy: scan for headings matching /CIS.*Coverage/i and the
 * adjacent table, then extract per-provider rows. Returns null when no CIS
 * section is found — caller treats null as "this report doesn't have CIS
 * data, render normally."
 */

import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Cloud, Container, CheckCircle2, XCircle, MinusCircle } from 'lucide-react';
import { cn } from '@/lib/utils';

export type CisProvider = 'cis_aws' | 'cis_azure' | 'cis_gcp' | 'cis_k8s';

export interface CisProviderCoverage {
  status: 'tested' | 'not_tested';
  controls_evaluated?: number;
  controls_passed?: number;
  controls_failed?: number;
  reason?: string;
}

export type CisCoverage = Record<CisProvider, CisProviderCoverage>;

const PROVIDER_DISPLAY: Record<
  CisProvider,
  { label: string; benchmark: string; color: string; icon: typeof Cloud }
> = {
  cis_aws: { label: 'AWS', benchmark: 'CIS AWS Foundations v3.0', color: 'bg-orange-500', icon: Cloud },
  cis_azure: { label: 'Azure', benchmark: 'CIS Azure Foundations v2.1', color: 'bg-blue-500', icon: Cloud },
  cis_gcp: { label: 'GCP', benchmark: 'CIS GCP Foundations v3.0', color: 'bg-red-500', icon: Cloud },
  cis_k8s: { label: 'Kubernetes', benchmark: 'CIS Kubernetes v1.9', color: 'bg-cyan-600', icon: Container },
};

const ALL_PROVIDERS: CisProvider[] = ['cis_aws', 'cis_azure', 'cis_gcp', 'cis_k8s'];

/**
 * Parse CIS coverage from report markdown. Looks for either:
 * 1. A heading matching `## CIS ... Coverage` followed by a table whose
 *    rows reference AWS / Azure / GCP / Kubernetes. Extracts numeric
 *    pass/fail counts from the table cells.
 * 2. Inline labeled values like "CIS AWS: 12 passed, 4 failed".
 *
 * Returns null when the markdown has no CIS coverage section — caller
 * should render the markdown without the card.
 */
export function parseCisCoverageFromMarkdown(content: string): CisCoverage | null {
  if (!content || !/cis/i.test(content)) return null;

  const result: Partial<CisCoverage> = {};

  // Strategy 1: find a CIS coverage heading and the adjacent table.
  // Headings: "## CIS Benchmark Coverage", "### CIS Coverage", "## Coverage"
  // followed by a table. Markdown tables look like:
  //   | Provider | Status | Passed | Failed |
  //   |----------|--------|--------|--------|
  //   | CIS AWS  | TESTED | 12     | 4      |
  const headingMatch = content.match(
    /(?:^|\n)#{1,4}\s+(?:cis\b[^\n]*coverage|coverage[^\n]*cis\b)[^\n]*\n([\s\S]+?)(?=\n#{1,4}\s|\n*$)/i,
  );
  const tableSection = headingMatch?.[1] ?? content; // fallback: scan whole doc

  // Find table rows mentioning each provider
  for (const provider of ALL_PROVIDERS) {
    const display = PROVIDER_DISPLAY[provider];
    // Match a row like "| CIS AWS | TESTED | 12 | 4 |" — case-insensitive
    // for the label, lenient on column count.
    const rowPattern = new RegExp(
      `\\|\\s*(?:cis[\\s-]+)?${display.label}\\b[^|]*\\|([^\\n]+)`,
      'i',
    );
    const rowMatch = tableSection.match(rowPattern);
    if (rowMatch) {
      const cells = rowMatch[1].split('|').map((c) => c.trim());
      // Heuristic: cells often go [Status, Evaluated, Passed, Failed] or
      // [Status, Passed, Failed]. Look for status keyword + numbers.
      const statusCell = cells[0]?.toLowerCase() ?? '';
      const isTested = /tested|pass|present|covered/.test(statusCell)
        && !/not\s*tested|n\/?a|skip/.test(statusCell);
      // Pull all numbers from the cells; map by position when we have them.
      const numbers = cells
        .map((c) => {
          const m = c.match(/(\d+)/);
          return m ? parseInt(m[1], 10) : null;
        })
        .filter((n): n is number => n !== null);
      if (isTested) {
        result[provider] = {
          status: 'tested',
          controls_evaluated: numbers[0],
          controls_passed: numbers[1],
          controls_failed: numbers[2],
        };
      } else {
        result[provider] = {
          status: 'not_tested',
          reason: cells.slice(1).join(' ').trim() || 'Not in scope',
        };
      }
      continue;
    }

    // Strategy 2 fallback: inline mention like "CIS AWS: 12 passed, 4 failed"
    const inlinePattern = new RegExp(
      `cis[\\s-]+${display.label}[\\s:]+([^\\n]+)`,
      'i',
    );
    const inlineMatch = content.match(inlinePattern);
    if (inlineMatch) {
      const tail = inlineMatch[1];
      const passedMatch = tail.match(/(\d+)\s*passed/i);
      const failedMatch = tail.match(/(\d+)\s*failed/i);
      const evaluatedMatch = tail.match(/(\d+)\s*(?:evaluated|controls|total)/i);
      if (passedMatch || failedMatch) {
        result[provider] = {
          status: 'tested',
          controls_evaluated:
            evaluatedMatch ? parseInt(evaluatedMatch[1], 10)
            : (passedMatch && failedMatch
              ? parseInt(passedMatch[1], 10) + parseInt(failedMatch[1], 10)
              : undefined),
          controls_passed: passedMatch ? parseInt(passedMatch[1], 10) : undefined,
          controls_failed: failedMatch ? parseInt(failedMatch[1], 10) : undefined,
        };
      }
    }
  }

  // Default un-mentioned providers to not_tested with reason "no findings"
  // so the card always shows all four — the absence is itself information.
  for (const provider of ALL_PROVIDERS) {
    if (!result[provider]) {
      result[provider] = { status: 'not_tested', reason: 'Not in scope' };
    }
  }

  // Only return a card if at least ONE provider was tested. Otherwise the
  // card would just say "everything not tested" — noise without value.
  const anyTested = ALL_PROVIDERS.some((p) => result[p]?.status === 'tested');
  if (!anyTested) return null;

  return result as CisCoverage;
}

interface CisCoverageCardProps {
  coverage: CisCoverage;
  className?: string;
}

export function CisCoverageCard({ coverage, className }: CisCoverageCardProps) {
  return (
    <Card className={cn('mb-4', className)}>
      <CardHeader className="pb-3">
        <CardTitle className="text-sm font-semibold flex items-center gap-2">
          <Cloud className="h-4 w-4 text-primary" />
          CIS Benchmark Coverage
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {ALL_PROVIDERS.map((provider) => {
            const display = PROVIDER_DISPLAY[provider];
            const data = coverage[provider];
            const Icon = display.icon;
            const tested = data.status === 'tested';
            const passed = data.controls_passed ?? 0;
            const failed = data.controls_failed ?? 0;
            const evaluated = data.controls_evaluated ?? passed + failed;
            // Pass rate guides the border color — green if everything passed,
            // amber if anything failed, neutral if not tested.
            const accent = !tested
              ? 'border-border'
              : failed === 0
                ? 'border-green-500/40'
                : 'border-amber-500/40';

            return (
              <div
                key={provider}
                className={cn(
                  'rounded-lg border p-3 bg-card flex flex-col gap-2',
                  accent,
                )}
              >
                <div className="flex items-center gap-2">
                  <Badge className={cn(display.color, 'text-white text-[10px] px-1.5 py-0 gap-1')}>
                    <Icon className="h-2.5 w-2.5" />
                    {display.label}
                  </Badge>
                </div>
                <div className="text-[10px] text-muted-foreground">
                  {display.benchmark}
                </div>
                {tested ? (
                  <div className="flex items-center gap-3 text-xs">
                    <span className="flex items-center gap-1 text-green-500" title="Controls passed">
                      <CheckCircle2 className="h-3.5 w-3.5" />
                      <span className="font-semibold tabular-nums">{passed}</span>
                    </span>
                    <span className="flex items-center gap-1 text-red-500" title="Controls failed">
                      <XCircle className="h-3.5 w-3.5" />
                      <span className="font-semibold tabular-nums">{failed}</span>
                    </span>
                    {evaluated > 0 && (
                      <span className="text-muted-foreground ml-auto tabular-nums">
                        {evaluated} total
                      </span>
                    )}
                  </div>
                ) : (
                  <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
                    <MinusCircle className="h-3.5 w-3.5" />
                    <span className="truncate" title={data.reason}>
                      {data.reason || 'Not tested'}
                    </span>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </CardContent>
    </Card>
  );
}
