Run a full team-based security assessment. The user specifies a target profile name via $ARGUMENTS — the name of any profile defined in `config/assessments.local.yml` or `config/assessments.yml`. The test set is the **scope-derived in-scope subset** of the `config/test-matrix.yml` superset — computed at runtime from each test's `applies_when` gate vs the active scope, never a fixed number.

## Setup

1. Find the profile matching `$ARGUMENTS`. Check `config/assessments.local.yml` first (gitignored personal overrides), then fall back to `config/assessments.yml` (committed template). The `.local` file takes precedence per profile id.
2. If no profile matches `$ARGUMENTS`:
   a. **If the invoking message already supplies inline scope** — a "Targets (in-scope):" list, and optionally an "Authenticate using credential app: …" line, "Repositories to scan" paths, a "Cloud account:" block, an "Identity targets (in-scope):" block, or an "AI targets (in-scope):" block — then **use that inline scope directly**: treat those targets as in-scope, the named credential app as the auth profile, the listed repos as `repo_paths`, the cloud block as `cloud_accounts`, the identity-targets block as the in-scope `identity_targets` ids (the identity surface — see below), the AI-targets block as the in-scope `ai_targets` ids (the AI surface — see below), and proceed to Phase 1. Do NOT list profiles or halt waiting for one. (This is the path the **New Assessment** wizard uses — it prepends `/assess` and supplies inline scope instead of a profile name.)
   b. Otherwise (no profile arg AND no inline scope), list available profiles from BOTH files (deduped) and ask the user to pick one.
3. Read the profile's config to get: target URL, auth details, repo path, previous reports, and report prefix
4. **Resolve the repo path** the SAST agents will scan, in this STRICT priority — and **verify it exists in the container before using it** (`ls` the resolved path; if it's missing/empty, do NOT silently fall through to a different path):
   a. If the profile has a `repo_name`, **this WINS over any `repo_path`**. Read `/mnt/host-home/.kali-mcp-pentest/repo-registry.json`, find the entry whose `name` matches, and use its `container_path` — works for local-directory repos (e.g. `/mnt/host-home/Desktop/foo`) AND GitHub-attached repos (clones under `/mnt/host-home/.kali-mcp-pentest/repo-cache/<owner>_<repo>/`). **If that path doesn't exist yet** (GitHub repo not cloned), tell the user to click "Scan" on the Code Repositories page to clone/refresh it, then retry — do **NOT** fall back to a stale snapshot or a local path.
   b. Else if the profile has `container_repo_path`, use that (after the existence check).
   c. Else fall back to `repo_path` translated to the container path (`~/foo` → `/mnt/host-home/foo`) — **but only if it exists**. If `repo_path` is set but does NOT exist in the container and no `repo_name` was given, treat SAST as out-of-scope (genuinely no repo): set `args.repoPath = null` and tell the user the configured path is missing — do NOT pass a dead path that makes the SAST workers silently mark every test N_A.

   Set `args.repoPath` to the VERIFIED path (or `null` if there is genuinely no repo). Never thread an unverified or non-existent path through to the SAST workers — the groovysec run did exactly that (a dead `~/Desktop/...` path shadowed the GitHub-attached clone) and SAST ran empty.
5. Verify the target is in scope. Same priority: `config/scope.local.yml` first, then `config/scope.yml`. (For desktop users, scope is also stored in the cloud backend and read by the MCP server at runtime — the YAML is the offline fallback.)
6. Read `skills/team-assessment/SKILL.md` for the team orchestration protocol
7. Read `config/test-matrix.yml` and compute the scope-derived **in-scope checklist** for this run (every test whose `applies_when` is satisfied by the active scope — cloud tests only with `cloud_accounts`, identity tests only with an identity provider target, etc.). This set + its count is `{IN_SCOPE_TEST_IDS}` / `{IN_SCOPE_TEST_COUNT}`, which the lead verifies against and passes to the report agents.
8. Read `config/team-assessment.yml` for agent-to-test mapping

## Determine Report Filenames

Use today's date (YYYY-MM-DD) and the profile's `report_prefix`:
- Main: `reports/{report_prefix}-assessment-{date}.md`
- SAST: `reports/{report_prefix}-sast-{date}.md`

If files with those names already exist, warn the user and ask to proceed (will overwrite) or rename.

## Authentication (Phase 1)

Authenticate using the profile's `auth` config:
- If `method: POST` — call the login endpoint, extract the token, and store the REAL token value
- If `method: OTP` — initiate OTP flow and prompt the user for the code
- If `method: TOTP` — reference credentials.yml for auto-TOTP generation

**CRITICAL:** Store the actual Bearer token string. Every agent and every finding's evidence MUST use this real token — never `$TOKEN`, `<TOKEN>`, `<PASSWORD>`, or any placeholder. Each run must use its OWN fresh token from the current authentication — never copy tokens from previous reports.

## Previous Report Reference

If the profile has `previous_reports`, read them and pass key findings to agents as context. This lets agents:
- Confirm whether previously-found vulnerabilities still exist
- Use prior evidence as a starting point (but must gather FRESH evidence with current session's token)
- Identify any new findings not in the previous report

**Important:** Previous reports are for CONTEXT ONLY. All evidence (tokens, response bodies, headers) must come from the current session's live testing. Never copy-paste evidence from previous reports.

## Execute Assessment

The assessment runs as **three Workflow chunks** in `.claude/workflows/`, with
you (the lead) handling interactive auth between them. This is the default. The
hand-driven Team protocol (`skills/team-assessment/SKILL.md`) remains available
as a fallback when the profile sets `orchestrator: team` (or for environments
whose `claude` predates the Workflow tool — needs claude-code ≥ 2.1.152).

**Why chunks, not one run:** Workflows run in the background and cannot drive
interactive OTP, and Maestro re-auths every ~15 min (JWT TTL). So the lead does
the auth, the Workflow does the fan-out, the lead re-auths between chunks. The
chunk boundaries sit exactly on the existing token-refresh points (post-2b,
post-3.5). All agents are reused by `agentType`, so behaviour and the
`reports/{agent}-results.json` checkpoint files are identical to the Team path —
only the conductor changed.

> **The workflow scripts are immutable — never Read, Edit, or Write
> `.claude/workflows/maestro-assess-*.js`.** Your only interaction with them is
> `Workflow { name, args }`. They already encode the agent dispatch, the
> auth/401 self-refresh tail, and the checkpoint writes — there is nothing to
> add or fix inside them. Wherever this flow says "update `args.authToken`", that
> means reassign that field on the in-memory `args` object you built in Phase 1
> *before the next `Workflow{...}` call* — it NEVER means editing a script file.
> (A `Write`/`Edit` against `.claude/**` is also denied by project settings.)
>
> **CRITICAL — pass `args` as an actual JSON object, NOT a JSON string.** Call
> `Workflow { name: "maestro-assess-recon", args: { target, authToken, repoPath, … } }`
> with `args` as a real object. If you stringify it (`args: "{\"target\":…}"`),
> every `args.field` reads `undefined` inside the script — workers then run
> **unauthenticated and repo-less** (the auth-churn + empty-SAST failure). The
> scripts now defensively `JSON.parse` a stringified `args`, but pass an object
> so it's right at the source.

### Flow

1. **Phase 1 — you (lead), interactive:** authenticate, test AUTH-01..08, and
   capture the REAL bearer token. Build the shared `args` object from the
   profile + `config/scope.yml` + `config/team-assessment.yml`:
   ```
   args = {
     target, scopeSummary, repoPath, cloudInScope, cloudAccounts,
     authToken,            // REAL current bearer — lands in each chunk's dynamic task slot
     assessmentId, reportVersion, reportPrefix,
     reports: { main: "reports/{prefix}-assessment-{date}.md",
                sast: "reports/{prefix}-sast-{date}.md",
                cloud: cloudInScope ? "reports/{prefix}-cloud-{date}.md" : null },
     expectedCounts: {           // from config/team-assessment.yml (authoritative)
       "recon-infra":10,"sast-scan":14,"sast-analysis":10,"cloud-recon":15,
       "web-security":28,"api-graphql":27,"cloud-exploit":14,
       "chain-analysis":4,"crossval-qa":13 }
   }
   ```

2. **Chunk A — `Workflow { name: "maestro-assess-recon", args }`:** phases 2a
   (recon-infra ‖ sast-scan ‖ cloud-recon) + 2b (sast-analysis). Read its return.
   → **Re-authenticate** (token refresh); reassign `args.authToken` on your in-memory args object (do NOT edit the script).

3. **Chunk B — `Workflow { name: "maestro-assess-exploit", args }`:** phases 3
   (web-security ‖ api-graphql ‖ cloud-exploit) + 3.5 (chain-analysis hypothesize).
   → **Re-authenticate** (token refresh); reassign `args.authToken` on your in-memory args object (do NOT edit the script).

4. **Chunk C — `Workflow { name: "maestro-assess-report", args }`:** phases 4 →
   4.5 → 4.75 → 4.8 (cloud only) → 5a → 5b → 5b.5 → 5c. Returns the PDF paths.

### Reading each chunk's return

Each chunk returns a structured object. After every chunk:
- If `needs_redispatch` is true, re-dispatch **only** the named short-returning
  agent (use the same Workflow with a one-agent `args`, or spawn that single
  `agentType` directly) — do not re-run the whole chunk.
- If `auth_expired` is non-empty, re-authenticate before the next chunk (its
  agents hit a 401 mid-phase).
- Accumulate each chunk's `agents[]`/`workers[]` summaries — you need them for
  the in-scope completeness verification (every `{IN_SCOPE_TEST_ID}` accounted for)
  before the report is final.

The Workflow journal makes each chunk independently resumable: if a chunk dies,
re-invoke it with `resumeFromRunId` and only the failed agent onward re-runs.

### Fallback: Team orchestration (`orchestrator: team`)

Drive the assessment by hand per `skills/team-assessment/SKILL.md` (TeamCreate +
Agent per phase). Pass to every agent: the real Bearer token (actual value), the
target URL, the repo path (container path) if available, and any previous-report
findings relevant to their test scope.

### Identity surface (conditional — when `identity_targets` is in scope)

Identity / IDP is a conditional surface. **What counts as "identity in scope" depends
on how the run was launched** — the inline kickoff scope is authoritative when present:

- **Launched with inline scope (the New Assessment wizard path):** the identity surface
  is driven **only** by the "Identity targets (in-scope):" block in the kickoff — i.e.
  the IDPs the operator *ticked* in the wizard. **No block → identity is not in scope
  for this run → do NOT run any identity agent, even if `config/scope.yml` has
  `identity_targets`.** The wizard's selection is the deliberate per-run choice; honor
  it. Gracefully skip the entire identity surface (no identity-recon/identity-exploit/
  identity-analysis; the `IDENTITY-*` tests are out of scope, in the N_A appendix) —
  the run proceeds exactly as a non-identity assessment.
- **Bare manual `/assess` with NO inline scope (a profile, or scope.yml directly):**
  fall back to `config/scope.yml` — `identity_targets` present there means in scope,
  the same way `cloud_accounts`/`ai_targets` auto-apply.

When identity *is* in scope (by either rule above), `config/team-assessment.yml` adds
**identity-recon** (Phase 2a), **identity-exploit** (Phase 3), and **identity-analysis**
(Phase 4.85). On the **Team path** this is automatic — the agents carry
`applies_when: identity_targets`, so they fire only in identity scope and otherwise
N_A their tests.

**The three immutable Workflow chunks predate the identity surface and do NOT dispatch
the identity agents.** So on the default Workflow-chunk path, after Chunk C, **dispatch
the identity triad yourself via the `Agent` tool** (identity-recon → identity-exploit →
identity-analysis), passing the in-scope `identity_targets` ids + the brokered per-target
auth. The identity tests are the scope-derived `IDENTITY-*` subset of
`config/test-matrix.yml`; include them in `{IN_SCOPE_TEST_IDS}`. Follow the **Lockout
Mandate**: lockout-aware spray, fail-closed, never touch break-glass / excluded principals.

### AI surface (conditional — when `ai_targets` is in scope)

AI/LLM is a conditional surface. **What counts as "AI in scope" depends on how the
run was launched** — the inline kickoff scope is authoritative when present:

- **Launched with inline scope (the New Assessment wizard path):** the AI surface is
  driven **only** by the "AI targets (in-scope):" block in the kickoff — i.e. the
  targets the operator *ticked* in the wizard. **No block → AI is not in scope for
  this run → do NOT run any AI agent, even if `config/scope.yml` has `ai_targets`.**
  The wizard's selection is the deliberate per-run choice; honor it. Gracefully skip
  the entire AI surface (no ai-recon/ai-redteam/ai-analysis; the `AI-*` tests are
  out of scope, in the N_A appendix) — the run proceeds exactly as a non-AI assessment.
- **Bare manual `/assess` with NO inline scope (a profile, or scope.yml directly):**
  fall back to `config/scope.yml` — `ai_targets` present there means in scope, the
  same way `cloud_accounts`/`identity_targets` auto-apply.

When AI *is* in scope (by either rule above), `config/team-assessment.yml` adds
**ai-recon** (Phase 2a), **ai-redteam** (Phase 3), and **ai-analysis** (Phase 4.9).
On the **Team path** this is automatic — the agents carry `applies_when: ai_targets`,
so they fire only in AI scope and otherwise N_A their tests.

**The three immutable Workflow chunks predate the AI surface and do NOT dispatch
the AI agents.** So on the default Workflow-chunk path, after Chunk C, **dispatch
the AI triad yourself via the `Agent` tool** (ai-recon → ai-redteam → ai-analysis),
passing the in-scope `ai_targets` ids + the brokered per-target auth. The AI tests
are the scope-derived `AI-*` subset of `config/test-matrix.yml`; include them in
`{IN_SCOPE_TEST_IDS}`. For an AI-only or AI-focused engagement, prefer the
dedicated **`/assess-ai`** entry point (`skills/ai-assessment/SKILL.md`). Follow the
**AI Safety Mandate** (`docs/ai-surface-plan.md` §10): consumption probe-only,
excessive agency capability-not-execution, never the upstream model provider.

## Agent Evidence Rules (pass to every agent)

Every agent MUST follow these evidence rules in their findings:
- Use the REAL Bearer token in all curl commands (the actual `eyJhbG...` string)
- Use the REAL password in all login commands (the actual password, not `<PASSWORD>`)
- Paste ACTUAL HTTP response bodies — never write comments like `# Returns HTTP 200 with user data`
- Every finding needs numbered reproduction steps with real requests AND real responses
- Every finding needs an exploitation scenario

## SAST Reconciliation (MANDATORY — Phase 4.5)

**This step runs AFTER the SAST agent completes but BEFORE generating the final report. It exists because the SAST agent produces detailed findings that the main report's coverage checklist often contradicts by marking tests as PASS when the SAST companion correctly marks them as FAIL or N_A.**

After the SAST agent returns its results:

1. Read the SAST companion report's test coverage checklist (the table with SAST-01 through SAST-SC-04)
2. For EVERY SAST test (all 24 tests), compare the SAST companion's status against what will go in the main report
3. **The SAST companion's status ALWAYS wins** — it ran the actual scanners and has the ground truth
4. Apply these specific rules:
   - If the SAST companion says a scanner couldn't detect package managers → mark as **N_A** (not PASS)
   - If the SAST companion found child_process/eval/exec instances → mark dangerous function check as **FAIL** (not PASS)
   - If the SAST companion found XSS data flows (template var-in-href) → mark XSS data flow as **FAIL** (not PASS)
   - If the SAST companion found RCE data flows (child_process in extensions) → mark RCE data flow as **FAIL** (not PASS)
   - If the SAST companion found SSRF data flows (dynamic urllib) → mark SSRF data flow as **FAIL** (not PASS)
   - Dependency-related tests (SAST-03, SAST-SC-01, SAST-SC-02) must match companion exactly
5. Build the reconciled SAST status list and pass it to the report agent

**Known recurring mismatches to watch for** (these have occurred in every assessment so far):
| Test | Common Error | Correct Resolution |
|------|-------------|-------------------|
| SAST-03 | Marked PASS ("no vulns") | Should be N_A if scanner couldn't detect package manager |
| SAST-09 | Marked PASS ("no dangerous functions") | Should be FAIL if child_process instances found |
| SAST-DF-02 | Marked PASS ("no XSS flows in backend") | Should be FAIL if template var-in-href XSS found |
| SAST-DF-03 | Marked PASS ("no command injection flows") | Should be FAIL if child_process RCE found |
| SAST-DF-04 | Marked PASS ("no SSRF flows") | Should be FAIL if dynamic urllib found |
| SAST-SC-01/02 | Marked PASS ("no CVEs") | Should be N_A if scanner couldn't detect packages |

## Report Generation

After all agents complete:

1. Verify every in-scope test is accounted for — `{IN_SCOPE_TEST_COUNT}` tests, all PASS, FAIL, BLOCKED, or N_A (never SKIPPED). Pass `{IN_SCOPE_TEST_IDS}` + `{IN_SCOPE_TEST_COUNT}` to report-writer and report-enrichment.
2. Apply the SAST reconciliation from the step above
3. Generate both markdown reports
4. **Run the Math Verification Gate** (see below) before rendering PDFs
5. Render both as PDFs using the md-to-pdf.js script in the Kali container:
   ```
   cp <md-file> /tmp/report.md
   cd /opt/pentest/scripts && node md-to-pdf.js /tmp/report.md /tmp/report.pdf
   ```
   Then `docker cp kali-pentest:/tmp/report.pdf reports/` to copy back
6. Final verification: grep for any remaining placeholders (`<PASSWORD>`, `<TOKEN>`, `$TOKEN`) — must be zero

## Math Verification Gate (MANDATORY — runs before PDF generation)

**Every number in the report must be internally consistent. This gate catches arithmetic errors before they reach the PDF.**

### Check 1: Coverage Table Row Sums
For every row in the Coverage Summary table, verify:
`PASS + FAIL + BLOCKED + N_A = Total (category count)`

If any row's status columns don't sum to the Total column, fix it. Common error: a test is counted in the Total but missing from the PASS/FAIL/BLOCKED/N_A breakdown.

### Check 2: Coverage Table Column Sums
Sum each column across all category rows and verify:
- Sum of all Total = `{IN_SCOPE_TEST_COUNT}` (the scope-derived in-scope count — NOT a fixed number)
- Sum of all PASS = exec summary PASS
- Sum of all FAIL = exec summary FAIL
- Sum of all BLOCKED = exec summary BLOCKED
- Sum of all N_A = exec summary N_A

### Check 3: Executive Summary Consistency
The exec summary's PASS/FAIL/BLOCKED/N_A counts must:
- Sum to exactly `{IN_SCOPE_TEST_COUNT}` (the active in-scope total; out-of-scope dimensions live in the N_A appendix, not this sum)
- Match the Coverage Summary table's Total row exactly

### Check 4: Finding Count Consistency
The exec summary's finding count table (CRITICAL + HIGH + MEDIUM + LOW + INFORMATIONAL) must match the actual number of `### FINDING N:` headings in the report.

### Check 5: SAST Companion Internal Consistency
In the SAST companion report:
- If a section header says "N instances" → the table/list below must contain exactly N items
- The exec summary finding counts must match the number of findings in each section

**If any check fails, fix the discrepancy before generating PDFs. Do not proceed with known inconsistencies.**

## SAST Cross-References in Main Report

When the main report mentions a SAST-sourced finding (secrets, code vulnerabilities, CI/CD issues, etc.), it MUST NOT duplicate the full SAST detail. Instead:

- Reference the SAST companion by finding number: *"See SAST Companion Report, Finding SAST-02 for the complete 240-secret breakdown by file and type."*
- Include only a summary table (top 3-5 items) in the main report, then reference the companion for the full list
- For code-level findings, the main report states the vulnerability and impact; the SAST companion provides the code, file paths, and fix

This keeps the main report focused on exploitability while the SAST companion serves as the authoritative code-level reference.

## SAST Companion Report — Code-First Evidence Standard

The SAST companion is a **code security audit**. Every finding MUST show the actual vulnerable code from the repository and a concrete fix — not hypothetical patterns or generic advice.

### Required for Every SAST Finding:

1. **Exact location**: File path + line number(s) (e.g., `backend/app/auth/jwt_handler.py:42-58`)
2. **Vulnerable code** — paste the ACTUAL code from the repo using `analyze_code_context` or `Read` tool:
   ```python
   # VULNERABLE (backend/app/auth/jwt_handler.py:45)
   token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
   # No 'aud' claim in payload, verify_aud=False in decode
   ```
3. **Why it's vulnerable** — 1-2 sentences explaining the specific risk in context
4. **Fixed code** — show the ACTUAL fix as it would appear in the codebase, not a generic example:
   ```python
   # FIXED (backend/app/auth/jwt_handler.py:45)
   payload["aud"] = settings.JWT_AUDIENCE  # the target's actual audience claim
   payload["jti"] = str(uuid.uuid4())
   token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
   ```
5. **Fix explanation** — 1 sentence on why the fix works

### Anti-patterns — NEVER do these in the SAST companion:
- "Consider adding input validation" → Show the exact Pydantic model or validation code to add, in the exact file
- "Use parameterized queries" → Show the actual SQLAlchemy ORM line that's already safe (or the raw SQL that isn't)
- "Rotate this secret" → Show which file, which line, the actual secret type, and the rotation command
- "Add a USER directive to Dockerfile" → Show the exact `RUN adduser` + `USER` lines and where in the Dockerfile they go
- Showing generic OWASP examples instead of code from the actual repository

### Reading Source Code During SAST

The SAST agent MUST use `analyze_code_context` or `scan_semgrep` with the repo path to read actual source code. For every finding:
1. Identify the vulnerable file and line range from scanner output
2. Read the actual code at that location
3. Understand the surrounding context (what framework, what patterns are used)
4. Write the fix using the same framework/patterns the codebase already uses

If the repo uses FastAPI + Pydantic, fixes should use FastAPI + Pydantic patterns.
If the repo uses SQLAlchemy ORM, fixes should use SQLAlchemy ORM patterns.
Never suggest a fix using a framework or library the codebase doesn't already use.

## SAST Companion Section Count Rule

When the SAST companion report has section headers with counts (e.g., "XSS via Template Variables (N instances)"), the count N must exactly match the number of items listed in the section below it. Cross-check every section header count against the actual table rows.

## Docker Troubleshooting

If MCP tools fail with Docker errors:
- Check `docker ps` to verify the kali-pentest container is running
- If container is stopped, run `docker start kali-pentest`
- If tools timeout, retry once — ALB connection filtering can cause transient failures for SSL/TLS tools
- Mark tests as BLOCKED (not PASS) when tools genuinely cannot execute due to infrastructure issues
- Never mark a test as PASS just because the tool didn't return an error — PASS means the security control was positively verified

## If $ARGUMENTS is empty

List available profiles from `config/assessments.yml` and ask:
- Which profile to assess
- Whether to run a full team assessment (scope-derived in-scope set) or a quick scan
