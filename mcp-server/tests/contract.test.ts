/**
 * MCP tool contract test.
 *
 * For every tool in `allTools`, build a minimal valid input from
 * `inputSchema.required`, invoke its handler, and assert:
 *   - the handler is callable (not throwing on plumbing)
 *   - the handler returns either a string or a serializable object
 *
 * `executeInKali`, child_process and fs operations are mocked so the test
 * runs without Docker / Kali / a real filesystem. This catches the class
 * of bug where a handler has shifted its return shape, a required-arg
 * destructure throws, or a recent refactor broke its plumbing — without
 * needing the full security toolchain.
 *
 * Tools that hit external network or require real binaries beyond
 * executeInKali are listed in `SKIP_TOOLS` below with a reason.
 */

jest.mock('@modelcontextprotocol/sdk/server/index.js', () => ({ Server: class {} }), { virtual: true });
jest.mock('@modelcontextprotocol/sdk/types.js', () => ({
  CallToolRequestSchema: {},
  ListToolsRequestSchema: {},
}), { virtual: true });

jest.mock('../src/utils/docker-exec', () => ({
  executeInKali: jest.fn().mockResolvedValue(''),
  isKaliRunning: jest.fn().mockResolvedValue(true),
  executeInKaliWithTimeout: jest.fn().mockResolvedValue(''),
  executeInKaliDetailed: jest.fn().mockResolvedValue({ stdout: '', stderr: '', exitCode: 0 }),
}));

// findings-db opens a SQLite handle on module load. Stub the public API
// surface so handlers that persist findings don't hit a real database.
jest.mock('../src/integrations/findings-db', () => ({
  upsertFinding: jest.fn().mockResolvedValue({
    finding: { id: 'test-id', occurrence_count: 1 },
    isNew: true,
    wasUpdated: false,
    evidenceAdded: false,
  }),
  addEvidence: jest.fn().mockResolvedValue(undefined),
  linkFindingToAssessment: jest.fn().mockResolvedValue(undefined),
  getFindingWithEvidence: jest.fn().mockResolvedValue(null),
  getFindingsForAssessment: jest.fn().mockResolvedValue([]),
  createFinding: jest.fn().mockResolvedValue(undefined),
  getFindings: jest.fn().mockResolvedValue([]),
  generateReportContent: jest.fn().mockResolvedValue({ markdown: '', findingsCount: 0 }),
  saveReportRecord: jest.fn().mockResolvedValue(undefined),
  compareAssessments: jest.fn().mockResolvedValue({ diff: [] }),
  // Oracle verdict layer — synchronous, SQLite-backed.
  getFindingById: jest.fn().mockReturnValue({
    id: 'test-id',
    title: 'test',
    target: 'example.com',
    verdict: 'candidate',
  }),
  applyVerdict: jest.fn().mockReturnValue({
    finding_id: 'test-id',
    verdict: 'candidate',
    oracle_kind: 'idempotent_replay',
    downgraded: false,
  }),
}));

// cloud-session lookup — handlers branch on `hasCloudSession()`. Force the
// local path so the test exercises the in-process code rather than HTTP.
jest.mock('../src/integrations/cloud-session', () => ({
  hasCloudSession: jest.fn().mockReturnValue(false),
  cloudRequest: jest.fn().mockResolvedValue({}),
  CloudSessionError: class CloudSessionError extends Error {},
}));

jest.mock('child_process', () => ({
  exec: jest.fn((_cmd: string, cb: Function) => cb(null, '', '')),
  execSync: jest.fn().mockReturnValue(Buffer.from('')),
  spawn: jest.fn(() => ({
    stdout: { on: jest.fn() },
    stderr: { on: jest.fn() },
    on: jest.fn(),
    kill: jest.fn(),
  })),
}));

jest.mock('fs', () => {
  const actual = jest.requireActual('fs') as typeof import('fs');
  return {
    ...actual,
    existsSync: jest.fn().mockReturnValue(true),
    readFileSync: jest.fn().mockReturnValue(''),
    writeFileSync: jest.fn(),
    readdirSync: jest.fn().mockReturnValue([]),
    statSync: jest.fn().mockReturnValue({ isDirectory: () => false, size: 0, mtime: new Date() }),
    mkdirSync: jest.fn(),
    promises: {
      ...actual.promises,
      readFile: jest.fn().mockResolvedValue(''),
      writeFile: jest.fn().mockResolvedValue(undefined),
      readdir: jest.fn().mockResolvedValue([]),
      stat: jest.fn().mockResolvedValue({ isDirectory: () => false, size: 0 }),
      mkdir: jest.fn().mockResolvedValue(undefined),
      access: jest.fn().mockResolvedValue(undefined),
    },
  };
});

import { allTools, allHandlers } from '../src/server';

type ToolDef = {
  name: string;
  description: string;
  inputSchema: {
    type: string;
    properties?: Record<string, { type?: string; enum?: unknown[]; default?: unknown }>;
    required?: string[];
  };
};

/**
 * Tools we skip in the contract test, with rationale. These either need
 * real network/state, drive multi-step agent workflows, or have side
 * effects (writes to local DB / spawns processes) that can't be cleanly
 * mocked without rewriting them.
 */
const SKIP_TOOLS: Record<string, string> = {
  // Agent runners spawn long-running orchestration loops with LLM calls;
  // hitting them in a unit test would require mocking the entire LLM
  // factory + every downstream tool. Covered by the e2e golden-path test.
  run_orchestrator: 'agent runner — covered by e2e',
  run_recon_agent: 'agent runner',
  run_vuln_scan_agent: 'agent runner',
  run_web_app_agent: 'agent runner',
  run_exploit_agent: 'agent runner',
  run_security_scan_agent: 'agent runner',
  run_code_intel_agent: 'agent runner',
  run_qa_agent: 'agent runner',
  run_report_agent: 'agent runner',
  run_auth_agent: 'agent runner',
  run_api_security_agent: 'agent runner',
  run_infra_security_agent: 'agent runner',
  run_compliance_agent: 'agent runner',
  run_chain_analysis_agent: 'agent runner',
  run_cloud_recon_agent: 'agent runner',
  run_cloud_exploit_agent: 'agent runner',
  // Interactive prompt — blocks waiting for user input by design.
  request_user_guidance: 'interactive — blocks on user input',
  prompt_for_otp: 'interactive — blocks on user input',
  prompt_for_input: 'interactive — blocks on user input',
  // Spawns an Orchestrator that opens its own SQLite handle on construction.
  resume_assessment: 'spawns orchestrator with SQLite — covered by e2e',
  pause_assessment: 'spawns orchestrator with SQLite — covered by e2e',
};

function minimalArgsFor(schema: ToolDef['inputSchema']): Record<string, unknown> {
  const args: Record<string, unknown> = {};
  const required = schema.required ?? [];
  const properties = schema.properties ?? {};
  for (const field of required) {
    const def = properties[field];
    if (!def) {
      args[field] = 'x';
      continue;
    }
    if (def.default !== undefined) {
      args[field] = def.default;
      continue;
    }
    if (def.enum && def.enum.length > 0) {
      args[field] = def.enum[0];
      continue;
    }
    switch (def.type) {
      case 'string': args[field] = 'example.com'; break;
      case 'number':
      case 'integer': args[field] = 1; break;
      case 'boolean': args[field] = false; break;
      case 'array': args[field] = []; break;
      case 'object': args[field] = {}; break;
      default: args[field] = 'x';
    }
  }
  return args;
}

/** Each handler must finish within this many ms or it counts as a hang. */
const PER_TOOL_TIMEOUT_MS = 2000;

function withTimeout<T>(p: Promise<T>, ms: number, label: string): Promise<T> {
  return Promise.race([
    p,
    new Promise<T>((_, reject) =>
      setTimeout(() => reject(new Error(`timeout after ${ms}ms (${label})`)), ms)
    ),
  ]);
}

describe('MCP tool contract', () => {
  jest.setTimeout(60_000);

  it('every handler is callable with minimal valid input and returns a serializable result', async () => {
    const failures: string[] = [];
    const hangs: string[] = [];
    let invoked = 0;

    for (const tool of allTools as ToolDef[]) {
      if (SKIP_TOOLS[tool.name]) continue;
      const handler = allHandlers[tool.name];
      if (typeof handler !== 'function') continue;
      const args = minimalArgsFor(tool.inputSchema);
      try {
        const result = await withTimeout(
          Promise.resolve().then(() => handler(args)),
          PER_TOOL_TIMEOUT_MS,
          tool.name
        );
        invoked++;
        try {
          JSON.stringify(result);
        } catch (e) {
          failures.push(`${tool.name}: result not JSON-serializable — ${(e as Error).message}`);
        }
      } catch (e) {
        const msg = (e as Error).message;
        if (msg.startsWith('timeout after')) {
          hangs.push(`${tool.name}: ${msg}`);
        } else {
          failures.push(`${tool.name}: handler threw — ${msg}`);
        }
      }
    }

    // Hangs and throws are listed separately so it's obvious whether the
    // failure mode is "broken plumbing" (throw) or "unmocked external call"
    // (hang). Both fail the test.
    if (failures.length || hangs.length) {
      const lines = [
        `Hangs (${hangs.length}): probable unmocked external call`,
        ...hangs.map(h => '  - ' + h),
        '',
        `Failures (${failures.length}): handler threw or returned bad shape`,
        ...failures.map(f => '  - ' + f),
      ];
      throw new Error('\n' + lines.join('\n'));
    }
    expect(invoked).toBeGreaterThan(50);
  });
});
