// Seed prompt for a single-finding "Prove it" exploit run.
//
// Mirrors `frontend/lib/prove-finding.ts` (createProveRun) so the headless
// auto-escalation path (orchestrator → promoteDeterministicFindings) seeds the
// exact same prompt the desktop "Prove it" button does. Keep the two in sync.

export interface ProvePromptInput {
  findingId: string;
  title: string;
  severity?: string;
  cve?: string | null;
  description?: string;
  /** In-scope value to exploit against. */
  targetValue: string;
  /** Extra context lines. */
  context?: string[];
}

export function buildProvePrompt(input: ProvePromptInput): string {
  return [
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
}
