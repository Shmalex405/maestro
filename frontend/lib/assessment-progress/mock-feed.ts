// Scripted ProgressFeed for UI development. Walks the real plan phase-by-phase,
// emitting believable tool events (started → ok, the occasional error) with the
// SAME ProgressEvent shape the live SSE feed produces — so the Assessment View
// components are validated against this and then light up live unchanged.

import type { ProgressFeed } from './feed';
import type { AssessmentPlan, ProgressEvent, ProgressStatus } from './types';

const DEMO_TARGET = 'https://app.acme-demo.test';

// A couple of representative tool calls per agent so narration reads real.
const AGENT_TOOLS: Record<string, Array<{ tool: string; target?: string }>> = {
  'recon-infra': [
    { tool: 'scan_ports', target: DEMO_TARGET },
    { tool: 'enumerate_subdomains', target: DEMO_TARGET },
    { tool: 'scan_ssl_tls', target: DEMO_TARGET },
  ],
  'sast-scan': [
    { tool: 'scan_repository' },
    { tool: 'scan_semgrep' },
    { tool: 'scan_secrets' },
    { tool: 'scan_dependencies' },
  ],
  'sast-analysis': [{ tool: 'analyze_code_context' }, { tool: 'analyze_code_context' }],
  'web-security': [
    { tool: 'run_sqlmap', target: `${DEMO_TARGET}/login` },
    { tool: 'test_xss', target: `${DEMO_TARGET}/search` },
    { tool: 'test_cors', target: DEMO_TARGET },
    { tool: 'test_ssrf', target: `${DEMO_TARGET}/fetch` },
  ],
  'api-graphql': [
    { tool: 'test_graphql_security', target: `${DEMO_TARGET}/graphql` },
    { tool: 'test_idor', target: `${DEMO_TARGET}/api/orders` },
    { tool: 'run_nuclei', target: DEMO_TARGET },
  ],
  'cloud-recon': [{ tool: 'check_s3_bucket' }, { tool: 'test_cloud_metadata' }],
  'cloud-exploit': [{ tool: 'test_cloud_metadata' }, { tool: 'check_s3_bucket' }],
  'identity-recon': [{ tool: 'enumerate_subdomains', target: 'login.acme-demo.test' }],
  'identity-exploit': [{ tool: 'analyze_jwt' }],
  'ai-recon': [{ tool: 'ai_fingerprint_target' }],
  'ai-redteam': [{ tool: 'ai_probe_injection' }, { tool: 'ai_extract_system_prompt' }],
  'chain-analysis': [{ tool: 'correlate_dast_findings' }],
  'crossval-qa': [{ tool: 'test_xss', target: `${DEMO_TARGET}/search` }],
  'severity-calibrator': [{ tool: 'analyze_code_context' }],
  compliance: [{ tool: 'generate_report' }],
  'report-writer': [{ tool: 'generate_report' }],
  'report-enrichment': [{ tool: 'generate_report' }],
  'pdf-renderer': [{ tool: 'generate_report' }],
};

function prettyTarget(target?: string): string {
  if (!target) return 'the target';
  return target.replace(/^[a-z]+:\/\//i, '').replace(/\/+$/, '');
}

// Compact local narration (the live feed gets its narration from the server).
function mockNarrate(tool: string, target: string | undefined, status: ProgressStatus): string {
  const t = prettyTarget(target);
  const map: Record<string, string> = {
    scan_ports: `Scanning ports on ${t}`,
    enumerate_subdomains: `Enumerating subdomains of ${t}`,
    scan_ssl_tls: `Analyzing the SSL/TLS configuration on ${t}`,
    scan_repository: 'Scanning the repository',
    scan_semgrep: 'Running Semgrep over the codebase',
    scan_secrets: 'Scanning the codebase for secrets',
    scan_dependencies: 'Scanning dependencies for known CVEs',
    analyze_code_context: 'Analyzing code context around a finding',
    run_sqlmap: `Probing ${t} for SQL injection with sqlmap`,
    test_xss: `Testing ${t} for cross-site scripting`,
    test_cors: `Testing the CORS policy on ${t}`,
    test_ssrf: `Testing ${t} for server-side request forgery`,
    test_graphql_security: `Testing GraphQL security on ${t}`,
    test_idor: `Testing ${t} for IDOR / broken object-level auth`,
    run_nuclei: `Running Nuclei CVE templates against ${t}`,
    check_s3_bucket: 'Checking S3 bucket permissions',
    test_cloud_metadata: 'Probing the cloud metadata endpoint',
    analyze_jwt: 'Analyzing JWT structure and signing',
    ai_fingerprint_target: 'Fingerprinting the AI target',
    ai_probe_injection: 'Probing the AI surface for prompt injection',
    ai_extract_system_prompt: 'Attempting system-prompt extraction',
    correlate_dast_findings: 'Correlating reachable + vulnerable findings',
    generate_report: 'Generating the report',
  };
  const base = map[tool] ?? `Running ${tool.replace(/_/g, ' ')}`;
  if (status === 'ok') return `${base.replace(/^(\w+ing)/, (m) => m)} — done`;
  if (status === 'error') return `${base} — failed`;
  return base;
}

export function createMockFeed(
  plan: AssessmentPlan,
  opts?: { stepMs?: number; nowIso?: () => string }
): ProgressFeed {
  const stepMs = opts?.stepMs ?? 550;
  const nowIso = opts?.nowIso ?? (() => new Date().toISOString());

  // Flatten the plan into an ordered emission schedule (phase order; parallel
  // phases interleave their agents one tool at a time).
  const schedule: Array<Omit<ProgressEvent, 'narration'>> = [];
  for (const phase of plan.phases) {
    const agents = phase.agents.filter((a) => a.inScope);
    if (agents.length === 0) continue;
    const perAgent = agents.map((a) => ({
      agent: a.name,
      tools: AGENT_TOOLS[a.name] ?? [{ tool: 'analyze_code_context' }],
      testIds: a.tests,
    }));
    const maxLen = Math.max(...perAgent.map((p) => p.tools.length));
    for (let i = 0; i < maxLen; i++) {
      for (const pa of perAgent) {
        const call = pa.tools[i];
        if (!call) continue;
        // ~1 in 9 tool calls errors, for realism.
        const errored = (i + pa.agent.length) % 9 === 0 && call.tool.startsWith('test_');
        const base = {
          assessmentId: 'mock',
          tool: call.tool,
          target: call.target,
          testId: pa.testIds[i],
          agent: pa.agent,
          phase: phase.phase,
        };
        schedule.push({ ...base, status: 'started', ts: '' });
        schedule.push({
          ...base,
          status: errored ? 'error' : 'ok',
          durationMs: 800 + ((i * 137 + pa.agent.length * 53) % 5000),
          ts: '',
        });
      }
    }
  }

  return {
    subscribe(cb) {
      const timers: ReturnType<typeof setTimeout>[] = [];
      schedule.forEach((evt, idx) => {
        const t = setTimeout(() => {
          cb({
            ...evt,
            ts: nowIso(),
            narration: mockNarrate(evt.tool, evt.target, evt.status),
          } as ProgressEvent);
        }, idx * stepMs);
        timers.push(t);
      });
      return () => timers.forEach(clearTimeout);
    },
  };
}
