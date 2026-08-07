// Shared "Prove this finding" launcher — the two-engine differentiator.
//
// Escalates a single cheap-scan / correlation finding to an on-demand LLM
// exploit: creates (but does not start) a scoped assessment seeded with a
// single-finding-exploit prompt that the assessment terminal auto-types on first
// spawn. Used by the Scheduled DAST drill-in and the Coverage Dashboard W4
// correlation cards so the prompt/shape stays in one place.

import { api } from '@/lib/tauri-api';
import type { AssessmentType } from '@/lib/types';

export interface ProveRunInput {
  /** The finding whose exploitable status the run should update. */
  findingId: string;
  title: string;
  severity?: string;
  cve?: string | null;
  description?: string;
  /** In-scope value to exploit against — a URL / host / reachable endpoint. */
  targetValue: string;
  /** Extra prompt context lines (e.g. the cloud workload + image for a W4 hit). */
  context?: string[];
  type?: AssessmentType;
  capabilities?: string[];
}

/** Create a scoped single-finding exploit run; returns the new assessment id. */
export async function createProveRun(input: ProveRunInput): Promise<string> {
  const prompt = [
    '/assess',
    '',
    'Prove (or disprove) exactly ONE finding via on-demand exploitation. Do NOT run a full assessment.',
    '',
    `Target (in-scope): ${input.targetValue}`,
    '',
    'Finding to validate:',
    `- Title: ${input.title}`,
    input.severity ? `- Severity: ${input.severity}` : '',
    input.cve ? `- CVE: ${input.cve}` : '',
    `- Finding ID: ${input.findingId}`,
    ...(input.context ?? []),
    '',
    input.description ? `Description: ${input.description}` : '',
    '',
    'Attempt full non-destructive exploitation against the live target. Send real',
    'payloads, capture the real HTTP request + response as evidence, and conclude',
    'with one of: EXPLOITED / PARTIAL / NOT EXPLOITABLE. Then update finding',
    `${input.findingId}'s exploitable status and evidence with the result. Validate scope first.`,
  ]
    .filter((l) => l !== '')
    .join('\n');

  // Typed loose (matches the assessment-create call elsewhere): these keys
  // (brain/capabilities/pending_prompt/prove_finding_id) aren't on the strict
  // AssessmentOptions shape, and an inline literal would trip excess-property
  // checks — the intermediate variable avoids that.
  const options: Record<string, unknown> = {
    brain: 'claude',
    capabilities: input.capabilities ?? ['web_app'],
    pending_prompt: prompt,
    prove_finding_id: input.findingId,
  };
  const assessment = await api.assessments.create({
    name: `Prove: ${input.title.slice(0, 60)}`,
    type: (input.type ?? 'web_app') as AssessmentType,
    targets: [input.targetValue],
    start: false,
    options,
  });
  return assessment.id;
}
