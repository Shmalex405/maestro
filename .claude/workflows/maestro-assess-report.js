// maestro-assess-report — Workflow chunk C of the Maestro security assessment.
// ============================================================================
// Chunk C is the sequential tail: cross-validation, second chain touch,
// severity calibration, cloud analysis, compliance, and the report pipeline.
//   - 4    crossval-qa        (exploit-validate + cross-validate + SAST enrich)
//   - 4.5  chain-analysis     (Touch 2 — validate hypotheses vs exploit results)
//   - 4.75 severity-calibrator(re-rate by exploitation outcome)
//   - 4.8  cloud-analysis     (Cloud Companion Report; cloud scope only)
//   - 5a   compliance         (OWASP/NIST/PCI/CVSS mapping)
//   - 5b   report-writer      (full markdown report; writes in its own 6 chunks)
//   - 5b.5 report-enrichment  (validate quality, fill gaps, re-fetch evidence)
//   - 5c   pdf-renderer        (markdown → PDF, bind to assessment row)
//
// Invoked by the interactive `/assess` lead after it re-authenticates (the
// post-3.5 refresh). Every agent reads chunk A+B checkpoints off disk. The
// report agents do NOT write reports/{agent}-results.json (checkpoint_file is
// null in team-assessment.yml); they emit markdown/PDF, captured via REPORT_SCHEMA.
//
// args: chunk A/B shape PLUS:
//   reports: { main: "reports/acme-assessment-2026-06-03.md",
//              sast: "reports/acme-sast-2026-06-03.md",
//              cloud:"reports/acme-cloud-2026-06-03.md" | null }
//   expectedCounts: { "crossval-qa":13, "chain-analysis":4 }  // chain Touch 2
// ============================================================================

export const meta = {
  name: 'maestro-assess-report',
  description: 'Maestro assessment chunk C — crossval, chain-validate, severity calibration, cloud analysis, compliance, report, PDF',
  phases: [
    { title: 'Cross-Validation' }, { title: 'Chain Validate' }, { title: 'Severity Calibration' },
    { title: 'Cloud Analysis' }, { title: 'Compliance' }, { title: 'Report' },
    { title: 'Report Enrichment' }, { title: 'PDF' },
  ],
}

// Worker agents that report tests + write a checkpoint JSON.
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
        type: 'object', additionalProperties: false,
        required: ['test_id', 'status', 'finding_count', 'notes'],
        properties: {
          test_id: { type: 'string' },
          status: { type: 'string', enum: ['PASS', 'FAIL', 'N_A', 'BLOCKED'] },
          finding_count: { type: 'integer' }, notes: { type: 'string' },
        },
      },
    },
    finding_ids: { type: 'array', items: { type: 'string' } },
    summary: {
      type: 'object', additionalProperties: false,
      required: ['total', 'pass', 'fail', 'n_a', 'blocked'],
      properties: {
        total: { type: 'integer' }, pass: { type: 'integer' }, fail: { type: 'integer' },
        n_a: { type: 'integer' }, blocked: { type: 'integer' },
      },
    },
    results_file: { type: 'string' },
  },
}

// Reporting agents that emit markdown/PDF artifacts instead of a test checkpoint.
const REPORT_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['agent', 'status', 'outputs', 'notes'],
  properties: {
    agent: { type: 'string' },
    status: { type: 'string', enum: ['COMPLETE', 'BLOCKED'] },
    outputs: {
      type: 'array',
      items: {
        type: 'object', additionalProperties: false,
        required: ['kind', 'path'],
        properties: {
          kind: {
            type: 'string',
            enum: ['main_markdown', 'sast_markdown', 'cloud_markdown', 'main_pdf', 'sast_pdf', 'cloud_pdf'],
          },
          path: { type: 'string' },
        },
      },
    },
    notes: { type: 'string' },
  },
}

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
    : '(none)'
  return [
    stableContext(a), '',
    '=== PRIOR PHASE CHECKPOINTS ===', checkpoints, '',
    '=== YOUR TASK ===', task, '',
    `Current bearer token (use this literal value in every authenticated request): ${a.authToken || 'NONE — run unauthenticated tests only'}`,
    '',
    'Follow your agent instructions exactly. Analysis/report agents must NOT',
    're-scan or re-exploit — read the prior checkpoints off disk. Write your',
    'output (checkpoint JSON or markdown/PDF) BEFORE returning, then return the',
    'structured result object.',
    '',
    'NON-INTERACTIVE EXECUTION: you run inside a background Workflow chunk with NO',
    'user to answer prompts. NEVER call request_user_guidance, prompt_for_otp,',
    'prompt_for_input, or any tool that waits for user input, and never block',
    'waiting for a response — it hangs the whole chunk. If something needs a human',
    'decision, document it, note the reason, and continue.',
  ].join('\n')
}

// All upstream checkpoints chunk C agents may read.
function allCheckpoints(a) {
  const cp = [
    'reports/recon-infra-results.json', 'reports/sast-scan-results.json',
    'reports/sast-analysis-results.json', 'reports/web-security-results.json',
    'reports/api-graphql-results.json', 'reports/chain-analysis-results.json',
  ]
  if (a.cloudInScope) {
    cp.push('reports/cloud-recon-results.json', 'reports/cloud-exploit-results.json')
  }
  return cp
}

// Defensive: a Workflow caller may pass `args` as a JSON STRING rather than an
// object (the /assess lead has done this). When it does, every `args.field`
// reads undefined. Normalize first; use `A` for all field reads below.
const A = (typeof args === 'string') ? JSON.parse(args) : (args || {})
const counts = { 'crossval-qa': 13, 'chain-analysis': 4, ...(A?.expectedCounts || {}) }
const reports = A.reports || {}
const cp = allCheckpoints(A)
const workerResults = []
const reportOutputs = []

// === Phase 4: cross-validation + QA + SAST enrichment =======================
phase('Cross-Validation')
const crossval = await agent(
  dispatch(A, cp, 'Run crossval-qa (XVAL-01..15). Validate SAST findings against live endpoints, re-test every critical/high finding end-to-end, assign a 1–10 confidence score per finding, flag false positives, check coverage gaps against the test matrix, and enrich the SAST companion with DAST evidence. XVAL-12 (cloud) / XVAL-13 (cloud+repo) are N_A when cloud is out of scope; XVAL-14 (identity) / XVAL-15 (identity+repo) are N_A when identity is out of scope — reconcile XVAL-14/15 against identity-exploit evidence, never re-spray (Lockout Mandate). Write reports/crossval-qa-results.json.'),
  { agentType: 'crossval-qa', schema: AGENT_RESULT_SCHEMA, phase: 'Cross-Validation', label: 'crossval-qa' },
)
workerResults.push(crossval)

// === Phase 4.5: chain-analysis Touch 2 (validate) ===========================
phase('Chain Validate')
const chainValidate = await agent(
  dispatch(A, [...cp, 'reports/crossval-qa-results.json'], 'Run chain-analysis Touch 2 (CHAIN-05..08 — validate). Confirm or refute each hypothesized chain against the actual exploit + cross-validation results, compute combined severity, and do the defense-in-depth analysis. Update reports/chain-analysis-results.json with validated chains.'),
  { agentType: 'chain-analysis', schema: AGENT_RESULT_SCHEMA, phase: 'Chain Validate', label: 'chain-analysis:validate' },
)
workerResults.push(chainValidate)

// === Phase 4.75: severity-calibrator ========================================
phase('Severity Calibration')
const calibrate = await agent(
  dispatch(A, [...cp, 'reports/crossval-qa-results.json'], 'Run severity-calibrator (0 tests — calibration only). Re-rate every finding by actual exploitation outcome (EXPLOITED/PARTIAL/NOT EXPLOITABLE), reachability, and chain context using the 6 calibration rules. Keep parser-internal library CVEs at full severity. Produce per-finding calibrated_severity + justification + delta. Write reports/severity-calibrator-results.json. Never re-scan or re-test.'),
  { agentType: 'severity-calibrator', schema: AGENT_RESULT_SCHEMA, phase: 'Severity Calibration', label: 'severity-calibrator' },
)
workerResults.push(calibrate)

// === Phase 4.8: cloud-analysis (cloud scope only) ===========================
if (A.cloudInScope) {
  phase('Cloud Analysis')
  const cloudAnalysis = await agent(
    dispatch(A, [...cp, 'reports/crossval-qa-results.json', 'reports/severity-calibrator-results.json'],
      `Run cloud-analysis (0 tests — synthesis only). Build the Cloud Companion Report at ${reports.cloud || 'reports/<prefix>-cloud-<date>.md'}: the Identity & Escalation Graph (every privesc path tagged EXPLOITED / DETECTED-ONLY / GATED), validated cloud chains (CHAIN-31..40), and detected-but-not-executed findings. Read cloud-recon/cloud-exploit checkpoints + the findings DB only — never re-scan or touch the cloud.`),
    { agentType: 'cloud-analysis', schema: REPORT_SCHEMA, phase: 'Cloud Analysis', label: 'cloud-analysis' },
  )
  reportOutputs.push(cloudAnalysis)
} else {
  log('No cloud_accounts in scope — skipping cloud-analysis (Cloud Companion Report).')
}

// === Phase 5a: compliance ===================================================
phase('Compliance')
const compliance = await agent(
  dispatch(A, [...cp, 'reports/crossval-qa-results.json', 'reports/severity-calibrator-results.json'], 'Run compliance (mapping only). Map every finding to OWASP Top 10 2021, OWASP API Top 10, CWE, NIST 800-53, PCI-DSS, and compute CVSS v3.1 vectors. Produce the compliance coverage matrix. Write reports/compliance-results.json.'),
  { agentType: 'compliance', schema: AGENT_RESULT_SCHEMA, phase: 'Compliance', label: 'compliance' },
)
workerResults.push(compliance)

// === Phase 5b: report-writer ================================================
phase('Report')
const reportWriter = await agent(
  dispatch(A, [...cp, 'reports/crossval-qa-results.json', 'reports/severity-calibrator-results.json', 'reports/compliance-results.json'],
    `Run report-writer. Write the full markdown report to ${reports.main || 'reports/<prefix>-assessment-<date>.md'} and the SAST companion to ${reports.sast || 'reports/<prefix>-sast-<date>.md'}${A.cloudInScope ? ` (cross-reference the Cloud Companion at ${reports.cloud})` : ''}. Render BOTH original and calibrated severity. Write in 6 sequential chunks using the <!-- REPORT_CONTINUE --> sentinel to stay under the 32K output-token limit (Write chunk 1, Edit/append chunks 2–6). Include the full coverage checklist, exploitation summary matrix, and per-phase walkthrough.`),
  { agentType: 'report-writer', schema: REPORT_SCHEMA, phase: 'Report', label: 'report-writer' },
)
reportOutputs.push(reportWriter)

// === Phase 5b.5: report-enrichment ==========================================
phase('Report Enrichment')
const enrichment = await agent(
  dispatch(A, cp, `Run report-enrichment. Validate ${reports.main || 'the main report'} (and the SAST/cloud companions) against the 12 quality checks (banned vague words, placeholder tokens, missing evidence, incomplete tables, count mismatches). Re-execute MCP tools to fill any gap you find. Enforce ALL-means-ALL. Return the validated markdown paths.`),
  { agentType: 'report-enrichment', schema: REPORT_SCHEMA, phase: 'Report Enrichment', label: 'report-enrichment' },
)
reportOutputs.push(enrichment)

// === Phase 5c: pdf-renderer =================================================
phase('PDF')
const pdf = await agent(
  dispatch(A, [], `Run pdf-renderer. Convert the validated markdown reports (${reports.main}${reports.sast ? `, ${reports.sast}` : ''}${A.cloudInScope && reports.cloud ? `, ${reports.cloud}` : ''}) to PDF by calling the **generate_pdf_report** MCP tool for EACH report, passing **markdown_path** (the absolute path to the on-disk .md file) and the assessment_id (the 'Assessment ID' from your STABLE context). CRITICAL: pass markdown_path, NOT markdown_content — the tool reads the file from disk and renders it FAITHFULLY; passing the file's content inline lets a long report get silently condensed (this is how a 67-page report once shipped as 7 pages). The tool renders AND uploads to the cloud Reports dashboard in ONE step. Do NOT shell out to md-to-pdf.js directly: that skips the cloud upload and the report never appears in the app. After each call you MUST do BOTH checks before reporting that PDF as produced: (1) upload_status === 'ok', AND (2) independently confirm the PDF exists and is non-zero on disk — run \`ls -la <output.pdf>\` and confirm it is present and a plausible size for the source markdown (a multi-hundred-KB report must NOT render to a few KB; if it does, the render is truncated — re-render via markdown_path and re-check). If ANY render produced no file, a 0-byte/tiny file, or upload_status !== 'ok', do NOT report success for it — escalate with the assessment_id, the path, the on-disk size, and the status. Only return PDF paths you have verified exist non-empty on disk. As part of your end-of-run promotion (alongside complete_assessment and promote_tool_provenance), ALSO call **promote_execution_meta** with the same assessment_id — it imports the reports/*-results.json checkpoints into the execution-overview store and pushes the per-test results + scope decisions to the cloud so the Assessment Execution Overview is populated.`),
  { agentType: 'pdf-renderer', schema: REPORT_SCHEMA, phase: 'PDF', label: 'pdf-renderer' },
)
reportOutputs.push(pdf)

// === Assemble return ========================================================
const cleanWorkers = workerResults.filter(Boolean)
const shortReturns = []
for (const r of cleanWorkers) {
  const expected = counts[r.agent]
  if (expected != null && r.summary && r.summary.total < expected) {
    shortReturns.push(`${r.agent}: returned ${r.summary.total}/${expected} tests`)
  }
}
const pdfPaths = reportOutputs.filter(Boolean).flatMap((r) => (r.outputs || []).filter((o) => o.kind.endsWith('_pdf')).map((o) => o.path))

// PDF completeness gate. The pdf-renderer must produce one PDF per written
// report (main + SAST companion + Cloud companion when in scope). A renderer
// that fails silently — e.g. returns pdf_paths:[] when md-to-pdf chokes — used
// to slip through because the only redispatch signal was per-test short
// returns. Fold a PDF shortfall into the redispatch signal so the lead
// re-dispatches instead of shipping a run with missing/zero PDFs.
const expectedPdfCount = 1 + (reports.sast ? 1 : 0) + (A.cloudInScope && reports.cloud ? 1 : 0)
if (pdfPaths.length < expectedPdfCount) {
  shortReturns.push(`pdf-renderer: produced ${pdfPaths.length}/${expectedPdfCount} PDFs (missing/failed render — re-dispatch with markdown_path + on-disk stat check)`)
}

if (shortReturns.length) log(`⚠ short returns (lead should re-dispatch): ${shortReturns.join('; ')}`)
log(`chunk C complete — reports: ${pdfPaths.length} PDFs, output tokens this run: ${Math.round(budget.spent() / 1000)}k`)

return {
  chunk: 'report',
  workers: cleanWorkers.map((r) => ({
    agent: r.agent, status: r.status, total: r.summary?.total ?? 0,
    finding_count: r.finding_ids?.length ?? 0, results_file: r.results_file,
  })),
  report_outputs: reportOutputs.filter(Boolean).flatMap((r) => (r.outputs || []).map((o) => ({ agent: r.agent, ...o }))),
  pdf_paths: pdfPaths,
  short_returns: shortReturns,
  needs_redispatch: shortReturns.length > 0,
}
