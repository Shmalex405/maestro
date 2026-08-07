'use client';

// Scheduled DAST → Vulnerabilities. The dedicated DAST-only findings view
// (scan_id IS NOT NULL, migration 0035) — separate from LLM-assessment findings.

import { Card, CardContent } from '@/components/ui/card';
import { VulnerabilitiesView } from '@/components/scheduled/dast-shared';

export default function ScheduledVulnerabilitiesPage() {
  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-xl font-bold tracking-tight">Vulnerabilities</h1>
        <p className="mt-0.5 text-sm text-muted-foreground">
          Findings from your scheduled / on-demand DAST scans only — the normal exploitation and
          validation findings live under the main Findings view.
        </p>
      </div>
      <Card className="glass-card overflow-hidden">
        <CardContent className="p-0">
          <VulnerabilitiesView />
        </CardContent>
      </Card>
    </div>
  );
}
