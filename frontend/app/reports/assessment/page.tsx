'use client';

import { Suspense } from 'react';
import { useSearchParams } from 'next/navigation';
import Link from 'next/link';
import { ChevronLeft } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Skeleton } from '@/components/ui/skeleton';
import { ExecutionOverviewPanel } from '@/components/assessments/execution-overview-panel';

/**
 * Per-assessment execution overview route — the drill-in target from the
 * Reports page's "Ran Assessments" section. Renders an ExecutionOverview for
 * one assessment.
 *
 * URL shape: /reports/assessment?id=<assessmentId>
 *
 * Why a query param rather than a `/reports/assessment/[id]` path segment:
 * tauri.conf.json's frontendDist uses Next's static export (`output: export`),
 * which can only emit pages for build-time-known params. Assessment IDs are
 * runtime values, and the packaged desktop serves files straight from `../out`
 * with no SPA fallback — so an arbitrary `[id]` path segment 404s in the
 * shipped app. The query-param form is the same pattern the existing
 * `/assessments/detail` and `/findings/detail` routes use, and is guaranteed
 * to resolve. See the report notes for this deviation from the requested
 * `[id]` shape.
 */
function ReportAssessmentContent() {
  const searchParams = useSearchParams();
  const assessmentId = searchParams.get('id');

  return (
    <div className="space-y-6">
      <div>
        <Button asChild variant="ghost" size="sm" className="-ml-2 mb-2 text-muted-foreground">
          <Link href="/reports">
            <ChevronLeft className="h-4 w-4 mr-1" />
            Back to Reports
          </Link>
        </Button>
        <h1 className="text-2xl font-bold tracking-tight">Assessment Execution Overview</h1>
        <p className="text-sm text-muted-foreground mt-0.5">
          What ran, coverage, scope decisions, and cost for this assessment.
        </p>
      </div>

      {assessmentId ? (
        <ExecutionOverviewPanel assessmentId={assessmentId} />
      ) : (
        <div className="text-sm text-muted-foreground">
          No assessment selected.{' '}
          <Link href="/reports" className="text-primary hover:underline">
            Return to Reports
          </Link>
          .
        </div>
      )}
    </div>
  );
}

export default function ReportAssessmentPage() {
  return (
    <Suspense
      fallback={
        <div className="space-y-6">
          <Skeleton className="h-7 w-72" />
          <Skeleton className="h-40 w-full" />
        </div>
      }
    >
      <ReportAssessmentContent />
    </Suspense>
  );
}
