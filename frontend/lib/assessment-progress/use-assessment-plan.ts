// Fetch the scope-filtered assessment skeleton from the MCP server.
// GET /api/assessment-plan → AssessmentPlan (phases → agents → test ids).

import { useQuery } from '@tanstack/react-query';
import type { AssessmentPlan, ScopeDimension } from './types';

const MCP_BASE =
  process.env.NEXT_PUBLIC_DEPLOY_MODE === 'web'
    ? ''
    : process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3001';

export async function fetchAssessmentPlan(opts?: {
  dims?: ScopeDimension[];
  inScopeOnly?: boolean;
}): Promise<AssessmentPlan> {
  const params = new URLSearchParams();
  if (opts?.dims?.length) params.set('dims', opts.dims.join(','));
  if (opts?.inScopeOnly) params.set('inScopeOnly', '1');
  const qs = params.toString();
  const res = await fetch(
    `${MCP_BASE}/api/assessment-plan${qs ? `?${qs}` : ''}`
  );
  if (!res.ok) throw new Error(`assessment-plan ${res.status}`);
  return (await res.json()) as AssessmentPlan;
}

export function useAssessmentPlan(opts?: {
  dims?: ScopeDimension[];
  inScopeOnly?: boolean;
  enabled?: boolean;
}) {
  return useQuery({
    queryKey: ['assessment-plan', opts?.dims ?? [], opts?.inScopeOnly ?? false],
    queryFn: () => fetchAssessmentPlan(opts),
    enabled: opts?.enabled ?? true,
    staleTime: 60_000,
  });
}
