// maestro-assess-recon — Workflow chunk A of the Maestro security assessment.
// ============================================================================
// This is the first of three Workflow chunks that replace the Team-system
// orchestration (TeamCreate + Agent) the team lead used to drive by hand.
//
// Chunk A covers the recon/SAST-scan phases:
//   - Phase 2a (parallel): recon-infra ‖ sast-scan ‖ cloud-recon (cloud only)
//   - Phase 2b (sequential): sast-analysis  (reads sast-scan's checkpoint)
//
// WHY A SEPARATE CHUNK (not one monolithic workflow): workflows run in the
// background and cannot drive interactive OTP, and Maestro re-auths between
// phases (15-min JWT TTL). So the interactive `/assess` lead handles Phase 1
// auth, invokes this chunk, then re-auths before invoking chunk B. Chunk
// boundaries sit exactly on the existing token-refresh points.
//
// DESIGN INVARIANTS (see .claude/plans + CLAUDE.md):
//   1. Agents are reused via `agentType` — their .claude/agents/*.md system
//      prompts (test lists, evidence rules, checkpoint format) are unchanged.
//   2. Checkpoint files (reports/{agent}-results.json) remain the inter-agent
//      data bus. The `schema` return here is consumed by THIS script for
//      control-flow only (completeness gate, AUTH_EXPIRED signalling, summary).
//   3. config/team-assessment.yml stays authoritative. The `/assess` skill
//      reads it and passes the data in via `args` (scripts have no fs access).
//   4. The dispatch prompt keeps the cache-optimized layout from
//      skills/team-assessment/SKILL.md: STABLE → CHECKPOINTS → TASK.
//
// args (built by .claude/commands/assess.md before invoking):
//   {
//     target:        "https://app.example.com",
//     scopeSummary:  "1-3 line brief from config/scope.yml",
//     repoPath:      "/mnt/host-home/.../repo"  | null,
//     cloudInScope:  true | false,
//     cloudAccounts: "acct-1 (aws), acct-2 (gcp)" | "n/a",
//     authToken:     "eyJhbG..."  (the REAL current-chunk bearer; goes in TASK,
//                     never the STABLE prefix, so re-auth doesn't bust cache),
//     assessmentId:  "uuid",
//     reportVersion: 1,
//     reportPrefix:  "acme",
//     expectedCounts:{ "recon-infra":10, "sast-scan":14, "sast-analysis":10,
//                      "cloud-recon":15 }   (from team-assessment.yml; fallback below)
//   }
// ============================================================================

export const meta = {
  name: 'maestro-assess-recon',
  description: 'Maestro assessment chunk A — recon-infra ‖ sast-scan ‖ cloud-recon, then sast-analysis',
  phases: [
    { title: 'Recon + SAST Scan', detail: 'recon-infra ‖ sast-scan ‖ cloud-recon (cloud scope only)' },
    { title: 'SAST Analysis', detail: 'sast-analysis reads the sast-scan checkpoint' },
  ],
}

// --- Structured return contract every worker must satisfy --------------------
// Mirrors the reports/{agent}-results.json checkpoint shape from
// .claude/agents/_preamble.md, plus a top-level `status` the script reads to
// detect mid-phase token expiry (AUTH_EXPIRED) and short returns.
const AGENT_RESULT_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['agent', 'status', 'test_results', 'finding_ids', 'summary', 'results_file'],
  properties: {
    agent: { type: 'string' },
    status: { type: 'string', enum: ['COMPLETE', 'AUTH_EXPIRED', 'BLOCKED'] },
    test_results: {
      type: 'array',
      items: {
        type: 'object',
        additionalProperties: false,
        required: ['test_id', 'status', 'finding_count', 'notes'],
        properties: {
          test_id: { type: 'string' },
          status: { type: 'string', enum: ['PASS', 'FAIL', 'N_A', 'BLOCKED'] },
          finding_count: { type: 'integer' },
          notes: { type: 'string' },
        },
      },
    },
    finding_ids: { type: 'array', items: { type: 'string' } },
    summary: {
      type: 'object',
      additionalProperties: false,
      required: ['total', 'pass', 'fail', 'n_a', 'blocked'],
      properties: {
        total: { type: 'integer' }, pass: { type: 'integer' }, fail: { type: 'integer' },
        n_a: { type: 'integer' }, blocked: { type: 'integer' },
      },
    },
    results_file: { type: 'string' },
  },
}

// Fallback expected test counts (authoritative source is team-assessment.yml,
// passed via args.expectedCounts — this only covers a missing/partial args).
const DEFAULT_COUNTS = { 'recon-infra': 10, 'sast-scan': 14, 'sast-analysis': 10, 'cloud-recon': 15 }

// --- Cache-optimized dispatch builder ---------------------------------------
// Reproduces the SKILL.md "Dispatch Payload Protocol": a byte-stable STABLE
// block, an append-only CHECKPOINTS block, and the DYNAMIC task (incl. the
// fresh token) at the very end so the cache boundary stays put across agents.
function stableContext(a) {
  return [
    '=== STABLE ASSESSMENT CONTEXT ===',
    `Target: ${a.target}`,
    `Scope summary: ${a.scopeSummary || 'see config/scope.yml'}`,
    `Repo path: ${a.repoPath || 'n/a'}`,
    `Cloud accounts in scope: ${a.cloudInScope ? (a.cloudAccounts || 'see scope.yml') : 'n/a'}`,
    'Auth: real bearer token provided in YOUR TASK below (use the literal value, never a placeholder)',
    `Assessment ID: ${a.assessmentId || 'n/a'}`,
    `Report version: ${a.reportVersion || 1}`,
  ].join('\n')
}

function dispatch(a, priorCheckpoints, task) {
  const checkpoints = priorCheckpoints && priorCheckpoints.length
    ? priorCheckpoints.map((c) => `- ${c}`).join('\n')
    : '(none — this is the first chunk)'
  return [
    stableContext(a),
    '',
    '=== PRIOR PHASE CHECKPOINTS ===',
    checkpoints,
    '',
    '=== YOUR TASK ===',
    task,
    '',
    `Current bearer token (use this literal value in every authenticated request): ${a.authToken || 'NONE — run unauthenticated tests only'}`,
    '',
    'Follow your agent instructions exactly: execute every assigned test, call',
    'create_finding for each vulnerability with the exploitable field set, and',
    'write your byte-stable checkpoint to reports/<agent>-results.json BEFORE',
    'returning. Then return the structured result object (the harness will',
    'require it). If you get HTTP 401 mid-phase, call the authenticate MCP tool',
    '(app_name from the credential-app context) for a fresh bearer, update your',
    'Authorization header, and retry — do NOT mark tests BLOCKED for a 401',
    'without re-authenticating first.',
    '',
    'NON-INTERACTIVE EXECUTION: you run inside a background Workflow chunk with NO',
    'user to answer prompts. NEVER call request_user_guidance, prompt_for_otp,',
    'prompt_for_input, or any tool that waits for user input, and never block',
    'waiting for a response — it hangs the whole chunk. If something needs a human',
    'decision, document it, mark the test PARTIAL/BLOCKED with the reason, and',
    'continue to your next test.',
  ].join('\n')
}

// ----------------------------------------------------------------------------
// Defensive: a Workflow caller may pass `args` as a JSON STRING rather than an
// object (the /assess lead has done exactly this). When it does, every
// `args.field` below reads `undefined` — workers then run UNAUTHENTICATED and
// repo-less (the auth-churn + empty-SAST bug, ~$50/run of wasted re-dispatch).
// Normalize to an object first; use `A` for all field reads below.
const A = (typeof args === 'string') ? JSON.parse(args) : (args || {})
const counts = { ...DEFAULT_COUNTS, ...(A?.expectedCounts || {}) }

// === Phase 2a: parallel recon + SAST scan (+ cloud recon when in scope) ======
phase('Recon + SAST Scan')

const phase2aTasks = [
  () => agent(
    dispatch(A, [], 'Run RECON-01..06 + TLS-01..04 and the full endpoint-discovery sweep (crawl depth 3, swagger/JS parsing, big-wordlist + API + extension fuzzing). Compile the deduplicated endpoint map — it is the attack surface every downstream agent tests against.'),
    { agentType: 'recon-infra', schema: AGENT_RESULT_SCHEMA, phase: 'Recon + SAST Scan', label: 'recon-infra' },
  ),
  () => agent(
    dispatch(A, [], `Run SAST-01..10 + SAST-SC-01..04 against the repo at ${A.repoPath || '(no repo — mark all SAST tests N_A with reason "no repo_path in scope")'}. Detect languages, run every scanner (semgrep owasp + security-audit + dangerous-functions, secrets incl. git history, dependencies, IaC, bandit/njsscan), and save raw scanner outputs into your checkpoint for sast-analysis to read.`),
    { agentType: 'sast-scan', schema: AGENT_RESULT_SCHEMA, phase: 'Recon + SAST Scan', label: 'sast-scan' },
  ),
]

if (A.cloudInScope) {
  phase2aTasks.push(() => agent(
    dispatch(A, [], 'Run the cloud reconnaissance tests (CLOUD recon set) against the in-scope cloud accounts: enumerate assets, IAM, storage, and cloud network surface read-only. Save the cloud-recon checkpoint for cloud-exploit and cloud-analysis.'),
    { agentType: 'cloud-recon', schema: AGENT_RESULT_SCHEMA, phase: 'Recon + SAST Scan', label: 'cloud-recon' },
  ))
}

const phase2a = (await parallel(phase2aTasks)).filter(Boolean)

// === Phase 2b: sast-analysis (sequential — needs the sast-scan checkpoint) ====
// sast-analysis reads reports/sast-scan-results.json off disk (the data bus),
// so we do NOT inline the 43–80K of raw scanner output into its prompt.
phase('SAST Analysis')

let sastAnalysis = null
if (A.repoPath) {
  sastAnalysis = await agent(
    dispatch(
      args,
      ['Phase 2a: reports/sast-scan-results.json (raw scanner outputs)', 'Phase 2a: reports/recon-infra-results.json (endpoint map)'],
      'Run SAST-DF-01..05 + SAST-DEF-01..05. Read reports/sast-scan-results.json for the raw scanner output, run analyze_code_context on every finding, trace data flows (taint), verify defenses, and write the SAST companion report. Do NOT re-run scanners.',
    ),
    { agentType: 'sast-analysis', schema: AGENT_RESULT_SCHEMA, phase: 'SAST Analysis', label: 'sast-analysis' },
  )
} else {
  log('No repo_path in scope — skipping sast-analysis (SAST-DF/SAST-DEF marked N_A by the coverage gate).')
}

// === Assemble the chunk return + light completeness check ====================
const results = [...phase2a, sastAnalysis].filter(Boolean)

const shortReturns = []
for (const r of results) {
  const expected = counts[r.agent]
  if (expected != null && r.summary && r.summary.total < expected) {
    shortReturns.push(`${r.agent}: returned ${r.summary.total}/${expected} tests`)
  }
}

const authExpired = results.filter((r) => r.status === 'AUTH_EXPIRED').map((r) => r.agent)

if (shortReturns.length) log(`⚠ short returns (lead should re-dispatch): ${shortReturns.join('; ')}`)
if (authExpired.length) log(`⚠ AUTH_EXPIRED reported by: ${authExpired.join(', ')} — lead must re-auth before chunk B`)
log(`chunk A complete — ${results.length} agents, ${results.reduce((n, r) => n + (r.summary?.total || 0), 0)} tests, output tokens so far: ${Math.round(budget.spent() / 1000)}k`)

return {
  chunk: 'recon',
  agents: results.map((r) => ({
    agent: r.agent,
    status: r.status,
    total: r.summary?.total ?? 0,
    pass: r.summary?.pass ?? 0,
    fail: r.summary?.fail ?? 0,
    n_a: r.summary?.n_a ?? 0,
    blocked: r.summary?.blocked ?? 0,
    finding_count: r.finding_ids?.length ?? 0,
    results_file: r.results_file,
  })),
  checkpoints: results.map((r) => r.results_file).filter(Boolean),
  short_returns: shortReturns,
  auth_expired: authExpired,
  needs_redispatch: shortReturns.length > 0 || authExpired.length > 0,
}
