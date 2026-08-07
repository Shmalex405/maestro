# Team-Based Assessment Skill

> **Orchestration status (rollout):** This Team protocol is now the **fallback**.
> The default `/assess` path drives the same up-to-22 agents through three **Workflow**
> chunks (`.claude/workflows/maestro-assess-{recon,exploit,report}.js`) —
> deterministic JS control flow with the agents reused verbatim via `agentType`.
> The Workflow path needs claude-code ≥ 2.1.162 (the container pin). This Team
> protocol still runs when a profile sets `orchestrator: team` or the CLI is
> older. Everything below — phases, agents, checkpoints, evidence rules — is
> shared by both paths and remains authoritative for agent behaviour.

## Purpose

Drive a full team-based security assessment using Claude Code's **Team system** (`TeamCreate` + `Agent` tool). Each assessment phase runs in its own agent with its own context window, preventing context exhaustion that causes late-phase tests to be silently skipped. The test set is the **scope-derived subset** of the `config/test-matrix.yml` superset (see "Test count convention").

**Use this skill for full multi-phase assessments.** For quick scans (<30 tests) or single-phase testing, use `skills/assessment/SKILL.md` instead.

### Test count convention — the denominator is SCOPE-DERIVED, never hardcoded

`config/test-matrix.yml` is a **superset of 209 tests** (73 DAST + 24 SAST + 15 XVAL + 8 CHAIN + 29 CLOUD + 60 IDENTITY). The number that runs on a given assessment — and the denominator the lead verifies against and passes to the report — is the **in-scope subset**, computed at runtime from each test's `applies_when` gate vs the active scope. **Do not hardcode a per-run total anywhere** (no "147", no "116", no "209"); the matrix grows and scope varies, and a frozen number silently drops whole test families (the exact bug where a 116-test checklist dropped every CLOUD and IDENTITY test).

**The in-scope rule** — a test is in scope when:
1. it has **no `applies_when`** (always-on base — DAST recon/TLS/auth, SAST, XVAL, CHAIN core); OR
2. its `applies_when` names a **configured scope dimension** — `cloud_accounts`, a specific identity provider target (`active_directory` / `entra_id` / `m365` / `okta` / `google_workspace` / `ping`), `kubernetes` clusters, or `repo_paths`; OR
3. its `applies_when` is a **surface-discovery condition** ("GraphQL endpoint discovered", "File upload functionality discovered", etc.) — always in scope, status **N_A** when recon did not find the surface.

Tests gated on a scope dimension that is **NOT** configured are **out of scope** — record them once in an "Out of Scope (N_A)" appendix and exclude them from the active denominator:

| Scope condition | Out-of-scope tests (N_A appendix; agents not spawned) |
|---|---|
| `cloud_accounts` empty | all 29 CLOUD-* + XVAL-12/13 → cloud-recon/cloud-exploit/cloud-analysis not spawned |
| `cloud_accounts` set, `kubernetes` empty | the K8s-gated CLOUD tests → N_A; other cloud tests run |
| `identity_targets` empty (or a provider has no target) | that provider's IDENTITY-* → identity-recon/exploit/analysis not spawned for it |
| `repo_paths` empty | all SAST-* → N_A; XVAL-13 → N_A |

The lead computes the in-scope set, verifies every in-scope test is accounted for (PASS / FAIL / N_A / BLOCKED — never SKIPPED, never silently omitted), and passes it to the report agents as `{IN_SCOPE_TEST_IDS}` + `{IN_SCOPE_TEST_COUNT}`.

## Why Teams Instead of Single-Conversation

A single Claude Code conversation running the full in-scope test set accumulates recon output, scan results, browser sessions, SAST output, and report generation in one context window. This causes:
- Context exhaustion before completing Phases 8-10 (Exploit Validation, QA, Compliance)
- Silent skipping of late-phase tests
- Vague "tool issue" reasons for SKIPPED tests

The team architecture gives each phase its own agent with a fresh context window. The team lead orchestrates, handles interactive auth, and passes context between agents via `SendMessage`.

## Architecture: Up to 19 Agents (1 Lead + 18 Workers)

Nine workers are **scope-conditional**: the three cloud workers (`cloud-recon`, `cloud-exploit`, `cloud-analysis`) spawn only when `cloud_accounts` is defined in `config/scope.yml`, the three identity workers (`identity-recon`, `identity-exploit`, `identity-analysis`) spawn only when `identity_targets` is defined, and the three AI workers (`ai-recon`, `ai-redteam`, `ai-analysis`) spawn only when `ai_targets` is defined. So the agent count scales with scope: **web/API/SAST-only = 13 agents** (1 lead + 12 always-on workers), **+ cloud = 16**, **+ identity = 16**, **+ AI = 16**, **+ all three = 22**. (Authoritative agent/phase/test mapping: `config/team-assessment.yml`.) The AI workers carry the same `applies_when: ai_targets` gate; on the immutable Workflow-chunk path (which predates AI) the lead dispatches the AI triad via the `Agent` tool — see `.claude/commands/assess.md` → "AI surface (conditional)". For an AI-focused engagement use the dedicated `/assess-ai` (`skills/ai-assessment/SKILL.md`).

| Agent | Name | Role | Tests | ~Tool Calls |
|-------|------|------|-------|-------------|
| **Team Lead** | (you) | Auth, coordination, dispatch | AUTH-01 to AUTH-08 (8 tests) | ~20 |
| **Worker 1** | `recon-infra` | Reconnaissance + SSL/TLS/DNS | RECON-01–06, TLS-01–04 (10 tests) | ~15 |
| **Worker 2** | `sast-scan` | Scanner execution only | SAST-01–10, SAST-SC-01–04 (14 tests) | ~15 |
| **Worker 3** | `sast-analysis` | Code analysis + SAST report | SAST-DF-01–05, SAST-DEF-01–05 (10 tests) | ~30 |
| **Worker 4** | `web-security` | Web app testing | AUTHZ(4), HDR(4), CORS(3), INJ(8), SSRF(3), CLI(6) = 28 tests | ~35 |
| **Worker 5** | `api-graphql` | API + vuln scanning | GQL(8), API(6), VSCAN(3), UPLOAD(3), BIZ(3), PROTO(3), DESER(1) = 27 tests | ~35 |
| **Worker 6** | `cloud-recon` *(cloud only)* | Cloud asset enum + IAM/storage/compute/K8s recon | CLOUD-01–05, CLOUD-10–12, CLOUD-16, CLOUD-20–21, CLOUD-25–28 (15 tests) | ~25 |
| **Worker 7** | `cloud-exploit` *(cloud only)* | IAM privesc, storage abuse, K8s attacks, log tamper | CLOUD-06–09, CLOUD-13–15, CLOUD-17–19, CLOUD-22–24, CLOUD-29 (14 tests) | ~30 |
| **Worker 8** | `cloud-analysis` *(cloud only)* | Cloud Companion Report — escalation graph, cloud chains (analysis only, no re-scan) | 0 tests (report synthesis only) | ~5 |
| **Worker 9** | `identity-recon` *(identity only)* | AD / Entra / M365 / Okta / Google Workspace / Ping enumeration (provider-gated) | IDENTITY recon set (23 tests) | ~25 |
| **Worker 10** | `identity-exploit` *(identity only)* | AD / Entra / M365 / Okta / GWS / Ping exploitation — Kerberoast/DCSync/ADCS, spray (lockout-gated), consent, exfil (provider-gated) | IDENTITY exploit set (37 tests) | ~35 |
| **Worker 11** | `identity-analysis` *(identity only)* | Identity Companion Report — escalation graph, identity chains (analysis only, never re-scans/re-sprays) | 0 tests (report synthesis only) | ~5 |
| **Worker 12** | `chain-analysis` | Attack chain analysis (Touch 1 hypothesize + Touch 2 validate) | CHAIN-01–08 (8 tests) | ~15 |
| **Worker 13** | `crossval-qa` | Cross-validation + QA + SAST enrichment | XVAL-01–15 (15 tests; XVAL-12/13 N_A when cloud out of scope, XVAL-14/15 N_A when identity out of scope) | ~25 |
| **Worker 14** | `severity-calibrator` | Re-rate severity by exploitation outcome | 0 tests (calibration only) | ~5 |
| **Worker 15** | `compliance` | Compliance framework mapping (incl. CIS) | 0 tests (mapping only) | ~10 |
| **Worker 16** | `report-writer` | Full markdown report (chunked) | 0 tests (report only) | ~12 |
| **Worker 17** | `report-enrichment` | Report QA + gap filling | 0 tests (validation only) | ~20-60 |
| **Worker 18** | `pdf-renderer` | PDF generation | 0 tests (PDF only) | ~3 |

**Total runs per assessment = the scope-derived in-scope count** (see "Test count convention" above) — not a fixed number. The table's per-agent test ranges are the full matrix; on any given run, out-of-scope dimensions (cloud, identity, SAST) drop to the N_A appendix and their agents are not spawned.

## Before Starting

1. Read `config/scope.yml` to verify targets are in scope
2. Read `config/test-matrix.yml` and compute the **in-scope checklist** for this run (apply the in-scope rule in "Test count convention" — every test whose `applies_when` is satisfied by the active scope). This set + its count is what you verify against and pass to the report agents as `{IN_SCOPE_TEST_IDS}` / `{IN_SCOPE_TEST_COUNT}`.
3. Read `config/team-assessment.yml` for the agent-to-test mapping
4. Read `config/credentials.yml` for auth configuration
5. **Do NOT read any previous assessment reports** — not for context, not for formatting, not for comparison. See "No Previous Report Contamination" in the preamble. If old reports exist in `reports/`, ignore them completely.
6. Tell the user the plan and ask them to watch for OTP prompts

## Execution Flow

```
Phase 1:   Team Lead handles auth (interactive OTP with user)
           |-- Creates team + tasks
           |-- Runs AUTH-01 through AUTH-08, extracts Bearer token
           |-- Saves browser state, captures GraphQL endpoint

Phase 2a:  PARALLEL -- Recon+Infra || SAST Scanning
           |-- recon-infra agent: RECON-01-06 + TLS-01-04
           |-- sast-scan agent: SAST-01-10 + SAST-SC-01-04
           [Team lead re-authenticates after Phase 2a]

Phase 2b:  SEQUENTIAL -- SAST Analysis (needs scan results)
           |-- sast-analysis agent: SAST-DF-01-05 + SAST-DEF-01-05
           |-- Writes SAST companion report

Phase 3:   PARALLEL -- Web Security || API+GraphQL
           |-- web-security agent: AUTHZ, HDR, CORS, INJ, SSRF, CLI tests
           |-- api-graphql agent: GQL, API, VSCAN, UPLOAD, BIZ, PROTO, DESER tests

Phase 3.5: SEQUENTIAL -- Chain Analysis (hypothesize)
           |-- chain-analysis agent: CHAIN-01-04 (first pass)
           [Team lead re-authenticates after Phase 3.5]

Phase 4:   SEQUENTIAL -- Cross-Validation + QA + SAST Enrichment
           |-- crossval-qa agent: XVAL-01-15 (12/13 cloud, 14/15 identity), validate findings, enrich SAST companion

Phase 4.5: SEQUENTIAL -- Chain Analysis Touch 2
           |-- chain-analysis agent: CHAIN-05-08 (validate against exploit results)

Phase 4.75: SEQUENTIAL -- Severity Calibration
           |-- severity-calibrator agent: re-rate every finding by actual exploitation outcome + reachability

Phase 4.8: SEQUENTIAL -- Cloud Analysis (cloud scope only)
           |-- cloud-analysis agent: synthesize Cloud Companion Report (escalation graph, cloud chains)
           |-- analysis only — reads cloud-recon/exploit checkpoints, never re-scans

Phase 4.85: SEQUENTIAL -- Identity Analysis (identity scope only)
           |-- identity-analysis agent: synthesize Identity Companion Report (escalation graph, identity chains)
           |-- analysis only — reads identity-recon/exploit checkpoints, never re-scans or re-sprays

Phase 5a:  SEQUENTIAL -- Compliance Mapping
           |-- compliance agent: OWASP/NIST/PCI/CVSS mapping

Phase 5b:  SEQUENTIAL -- Report Writing
           |-- report-writer agent: full markdown report

Phase 5b.5: SEQUENTIAL -- Report Enrichment
           |-- report-enrichment agent: validate report, fix gaps, re-fetch missing evidence

Phase 5c:  SEQUENTIAL -- PDF Rendering + Finalize
           |-- pdf-renderer agent: main + SAST companion + Cloud companion + Identity companion PDFs
           |-- complete_assessment: promote curated findings to cloud backend
           |-- correlate_cloud_findings (cloud scope only): join promoted
           |   inventory x findings(CVE) x reachability — MUST be after finalize
```

> **Cloud reachability-correlation ordering (cloud scope only).** Three calls
> must fire in this exact order across the end of the run:
> 1. `promote_cloud_inventory` — cloud-exploit Phase 6 (Phase 3): pushes the
>    typed asset+reachability inventory while creds are live.
> 2. `complete_assessment` — pdf-renderer Step 3 (Phase 5c): promotes curated
>    findings (incl. container/CVE findings written locally during the run).
> 3. `correlate_cloud_findings` — pdf-renderer Step 3.5 (Phase 5c): joins the
>    now-promoted assets against the now-promoted findings. Running it before
>    step 2 finds zero findings and correlates nothing.

## Token Refresh Protocol

JWT tokens typically have a 15-minute TTL. Long phases can cause token expiry mid-run.

Before dispatching each phase:
1. Check token age — if >10 minutes since last auth, re-authenticate
2. Pass fresh token to every agent in that phase
3. Between Phase 2a and Phase 2b: ALWAYS re-authenticate (Phase 2a takes 10-15 min)
4. Between Phase 3.5 and Phase 4: ALWAYS re-authenticate (Phase 3 takes 15-20 min)

Agent instruction (included in common preamble):
> If you receive HTTP 401 on any request, report it in your completion message as AUTH_EXPIRED. Do NOT attempt to re-authenticate yourself.

## Dispatch Payload Protocol (Caching-Optimized)

**Why this protocol exists**: Anthropic prompt caching only hits when the prefix of the request is byte-identical to a prior request. Without a stable dispatch shape, each new worker spawn pushes the cacheable boundary later in the payload, and cache hits shrink as the assessment progresses.

By structuring every dispatch as `[STABLE] → [APPENDED CHECKPOINTS] → [DYNAMIC TASK]`, the cacheable prefix grows **monotonically** across phases. Phase 4's dispatch reuses all of Phase 3's prior-checkpoint content; Phase 5b reuses Phases 1-5a; and so on.

**Estimated impact**: 10–20% reduction in within-run LLM cost vs. ad-hoc dispatch structure. See `docs/caching-plan-2026-05-22.md` Phase 1.5 for the full analysis.

### Required dispatch structure

Every `Agent` tool call the team lead makes MUST follow this layout, in this order:

```
=== STABLE ASSESSMENT CONTEXT ===
Target: {target}
Scope summary: {scope brief — 1-3 lines from config/scope.yml}
Repo path: {path or "n/a"}
Cloud accounts in scope: {list or "n/a"}
Auth: {reference to token slot, NOT the token value}
Assessment ID: {uuid}
Report version: {N}

=== PRIOR PHASE CHECKPOINTS ===
{For every completed phase whose output is relevant to this agent, list:}
- {phase_name}: reports/{agent}-results.json [content_hash:{first 12 chars of sha256}]
{The list grows append-only as phases complete — never reorder, never remove.}

=== YOUR TASK ===
{The dynamic part — what this specific agent should do this phase}
{Anything new: tokens, fresh findings since the last checkpoint, etc.}
```

### Rules

1. **Stable section is byte-identical across all phases of one assessment.** Never reorder. Never insert dynamic data here.
2. **Checkpoints are append-only.** When Phase 3 dispatches, the checkpoint list ends at Phase 2b. When Phase 4 dispatches, the same Phase 2b lines appear unchanged, with Phase 3 appended after them.
3. **Reference checkpoints by file path + content hash, NOT inline content.** The worker reads via tool call (also cached) when it needs detail.
4. **Dynamic section is at the END.** Anything that varies between dispatches lives here. The cache boundary sits between section 2 and section 3.
5. **No exceptions for re-spawn.** If a worker fails and is re-dispatched, use the same dispatch payload structure with one extra line in the dynamic section: `RE_DISPATCH (attempt {N}): {brief reason}`. Don't restructure the payload — that destroys cache hits.

### Cache-friendly tool calls

When a worker needs to inspect prior findings, prefer:
- `get_findings_by_ids(["finding-id-1", "finding-id-2"])` — tool result is cacheable
- `read_file(reports/{phase}-results.json)` — also cached

Avoid: inlining finding details into dispatch messages, since that forces a cache miss every time the finding set changes.

### Verification

After every dispatch, the lead's telemetry should show `cache_read_input_tokens > 0` on the second-and-later workers of an assessment. If cache reads are 0 across the board, the harness isn't passing through the cache-control beta header — open an issue, don't try to work around it.

## Step-by-Step Orchestration Protocol

### Step 0: Clear Previous Findings + Determine Report Version (MANDATORY)

Before starting any new assessment:

**0a. Clear the findings database:**
```
MCP tool: clear_findings
Arguments: { "confirm": true }
```

This deletes ALL findings, evidence, and assessment links from the SQLite DB. Without this step, `generate_report` will return findings from ALL previous assessments mixed with the current one.

**0b. Determine report version:**
Check if reports already exist for today's date (use `ls reports/{target-slug}*{date}*`). If they do:
- Use the next version number: if `v1` exists, use `v2`. If `v2` exists, use `v3`. Etc.
- Apply to BOTH main report and SAST companion: `{target-slug}-assessment-{date}-v3.md`, `{target-slug}-sast-{date}-v3.md`
- Pass the versioned filenames to report-writer and pdf-renderer agents
- **Do NOT read, open, or reference the existing reports** — only check if the filenames exist to determine the version number

If no reports exist for today, use the base name without a version suffix.

### Step 1: Create Team

```
TeamCreate:
  team_name: "assessment-<target-slug>"
  description: "Security assessment of <target>"
```

### Step 2: Create Tasks (YAML-Driven)

**Do NOT use a hardcoded task list.** The team lead reads the `phases:` array from `config/team-assessment.yml` and creates **one TaskCreate per phase entry, in YAML order**. This guarantees that any new phase added to the YAML — including new agents added later — is automatically scheduled by every future assessment.

Algorithm:

1. Read `config/team-assessment.yml`. Walk the `phases:` array top-to-bottom.
2. For each phase, evaluate `applies_when` (if present) against the current scope. Phases whose condition evaluates false are **still scheduled as TaskCreate** but the lead notes "N_A — <condition not satisfied>" in the description, so the coverage checklist still accounts for their tests. (Example: with no `cloud_accounts` in scope.yml, the cloud phases run as N_A bookkeeping — no agent is spawned, but the task exists.)
3. For each phase, create:
   ```
   TaskCreate:
     subject: "Phase {phase}: {name}"
     description: "Agents: {agents joined}. Tests: {sum of agent.count}. {description}"
   ```
4. Wire dependencies from the YAML's `blocked_by` field:
   ```
   TaskUpdate(taskId=<phase>, addBlockedBy=[<every task created for a blocked_by phase>])
   ```

**Verification before moving on:** count the TaskCreate calls you made. It MUST equal the number of phases in the YAML (currently 12 phases — 1, 2a, 2b, 3, 3.5, 4, 4.5, 4.75, 5a, 5b, 5b.5, 5c). If the count is short, you skipped a phase — re-read the YAML and add the missing tasks.

If the YAML is malformed or missing entirely, halt the assessment and tell the user. Do not fall back to a hardcoded list — that defeats the entire point of this protocol.

### Step 2.5: Pre-Dispatch Validation Gate (applies to every phase)

**Before dispatching any phase, the team lead MUST verify that every `blocked_by` agent has produced its `checkpoint_file`.** This is what prevents the "I forgot to schedule Phase 4.75, then dispatched Phase 5 anyway" failure mode.

Algorithm (run before every `Agent` tool call that dispatches a worker):

1. Look up the phase in `config/team-assessment.yml` `phases:` array.
2. For each agent listed in that phase's `blocked_by`:
   - Look up `agents.<name>.checkpoint_file` in the YAML.
   - If the agent has `applies_when` and the condition is false, treat its checkpoint as satisfied (the phase ran as N_A bookkeeping).
   - If `checkpoint_file` is `null` (e.g., report-writer writes markdown, pdf-renderer writes PDFs), validate against the agent's primary output instead (`report_markdown_path` or `report_pdf_path`).
   - Otherwise, verify the file exists on disk via `Bash: test -f <path>` (substitute `{TARGET_SLUG}` if the path contains it).
3. If **any** required checkpoint is missing, **do not dispatch the next phase**. Instead:
   - Dispatch the missing agent first, wait for completion, re-check.
   - If the missing agent has already been "dispatched" per the task list but produced no checkpoint, treat it as failed — respawn with the leaner-prompt protocol from the Error Recovery section.
4. Only when every `blocked_by` checkpoint exists do you proceed to dispatch the current phase.

**Why this is a hard gate, not a soft warning:** the report-writer renders calibrated severity from `reports/severity-calibration-results.json`. If that file is missing because Phase 4.75 was skipped, the report silently loses a column. The fix is to refuse to advance until the file exists — never to "continue without it."

### Step 3: Run Auth (Team Lead — Interactive)

The team lead handles auth directly because OTP requires user interaction:

1. `browser_navigate` to login page
2. `browser_fill` + `browser_click` to submit email
3. `prompt_for_otp` to get code from user
4. Complete login flow
5. `browser_save_state` to persist session in container
6. `browser_navigate` to a data page
7. `browser_network_log` to discover API endpoints and capture Bearer token
8. `browser_evaluate` to extract tokens from localStorage/cookies
9. `analyze_jwt` on extracted token
10. Run AUTH-04 through AUTH-08

Record results for AUTH-01 through AUTH-08. Extract:
- Bearer token string
- GraphQL endpoint URL (if discovered)
- Cookie names and flags
- API base URL
- **Authenticated role** for `{AUTH_ROLE}`: call `get_auth_role` (pass `app_name` if more than one app is configured) — it returns `{app, role}` for any auth type without logging in. Use the returned `role` (`admin`/`privileged`/`standard`/`readonly`) as `{AUTH_ROLE}`; if it returns `unknown`, pass `unknown — no role declared`. This drives the expected-for-role finding calibration (severity-calibrator Rule 8) — record it once here and substitute it into every worker's preamble.

### Step 3.5: Fetch Baseline (Phase 1.5 of Caching Plan)

Before dispatching any worker, fetch the prior-assessment baseline for each target. This lets crossval-qa skip re-validating findings that haven't drifted since last time, while preserving the safety guarantees (full revalidation every Nth run, critical/high always re-tested, code-change invalidation).

**Skip this step when**:
- This is the first-ever assessment of the target (no prior findings exist)
- `caching_enabled = false` for the org (the baseline endpoint will return `force_full_revalidation: true` anyway, but you can skip the fetch)
- The user passed `--no-cache` (force-rescan flag)

**For each target_id in this assessment**:

1. **Resolve target_id** — for each raw target in scope.yml, call the targets canonicalization (Rust util in backend-rs, or the parity TS helper). Look up the target_id by canonical fingerprint. If no row exists yet, the target is being assessed for the first time — there's no baseline to fetch.

2. **Call the baseline endpoint**:
   ```
   GET /findings/baseline?target_id=<uuid>
   Authorization: Bearer <session JWT>
   ```
   The response includes:
   - `baseline`: prior findings with last_seen_at, calibrated_severity, file_path, evidence excerpts
   - `force_full_revalidation`: true when cadence demands a fresh pass this run
   - `assessments_since_last_full_revalidation`: counter for UX display
   - `baseline_max_age_days`: per-org config, controls staleness cutoff
   - `caching_enabled`: master kill switch

3. **For repo targets, compute code diff** since the prior assessment's commit:
   ```
   git diff --name-only <prior_commit_sha> HEAD
   ```
   The list of changed files becomes the `code_diff` input to crossval-qa. Findings whose `file_path` is in this list MUST be re-validated regardless of age.

4. **Save baseline snapshot** to `reports/baseline-snapshot.json`. Follow the byte-stability rules from `_preamble.md`:
   - Sort keys alphabetically
   - Move timestamps to `_metadata` block
   - Compute `_content_hash` over the data portion
   - Sort all finding ID arrays

   The file structure:
   ```json
   {
     "baseline_findings": [...],       // from GET /findings/baseline
     "code_diff": {                    // optional, per repo target
       "target_id": "tgt-...",
       "prior_commit_sha": "abc123",
       "current_commit_sha": "def456",
       "changed_files": ["src/auth/login.py", "..."]
     },
     "force_full_revalidation": false,
     "cadence": {
       "assessments_since_last_full_revalidation": 2,
       "full_revalidation_interval": 4,
       "next_full_revalidation_due_after": 2
     },
     "_metadata": {
       "fetched_at": "2026-05-22T15:00:00Z",
       "_content_hash": "sha256:..."
     }
   }
   ```

5. **Reference the snapshot in every subsequent dispatch** via the dispatch payload protocol (`[STABLE] → [APPENDED CHECKPOINTS] → [DYNAMIC TASK]`). crossval-qa specifically receives:
   ```
   Baseline checkpoint: reports/baseline-snapshot.json [content_hash:abc...]
   ```
   And the cache prefix hits across phases.

**If the baseline endpoint returns `force_full_revalidation: true`**: surface this to the user before continuing. E.g.:
> "Cadence: 4 assessments since last forced revalidation. This run will fully re-validate all baseline findings (cache reuse disabled this run)."

This is expected behavior, not an error. The Nth-run safety pass is the cost of the cache being trustworthy long-term.

### Step 4: Dispatch Phase 2a Agents (Parallel)

Spawn the Phase 2a agents in parallel using a single message with multiple `Agent` tool calls. Always dispatch `recon-infra` and `sast-scan`. **Also dispatch `cloud-recon` when `cloud_accounts` is defined in `config/scope.yml`** — skip it on web/API-only runs (the lead will inject N_A entries for CLOUD-01–05, CLOUD-10–12, CLOUD-16, CLOUD-20–21, CLOUD-25–28 in the final verification step).

#### recon-infra Agent

```
Agent tool:
  subagent_type: "general-purpose"
  team_name: "assessment-<target-slug>"
  name: "recon-infra"
  run_in_background: true
  prompt: <see Agent Prompt Templates below>
```

#### sast-scan Agent

**IMPORTANT:** You MUST include `repo_paths` in the sast-scan prompt. Without it, all 14 SAST tests will be marked N_A. Translate the user's local path to the container mount path (e.g., `~/Desktop/my-app` → `/mnt/host-home/Desktop/my-app`).

```
Agent tool:
  subagent_type: "general-purpose"
  team_name: "assessment-<target-slug>"
  name: "sast-scan"
  run_in_background: true
  prompt: <see Agent Prompt Templates below — substitute {REPO_PATH}>
```

#### cloud-recon Agent *(spawn only when `cloud_accounts` is defined)*

The full mapping of CLOUD-* tests to this agent lives in `config/team-assessment.yml` under `cloud-recon.tests`. Pass the `cloud_accounts` and `kubernetes` blocks from scope as inputs.

```
Agent tool:
  subagent_type: "general-purpose"
  team_name: "assessment-<target-slug>"
  name: "cloud-recon"
  run_in_background: true
  prompt: <use the cloud-recon agent file at .claude/agents/cloud-recon.md>
```

If `cloud_accounts` is empty, do not spawn this agent — the lead will inject 15 N_A entries for cloud-recon's tests during Step 11.

Wait for all dispatched agents to complete (idle notifications arrive automatically).

### Step 5: Collect Phase 2a Results

Read completion messages from each agent dispatched in Step 4. Verify:
- recon-infra reported exactly 10 test results
- sast-scan reported exactly 14 test results
- cloud-recon reported exactly 15 test results *(only if spawned)*

If any tests are missing, message the responsible agent to account for them.

#### Scope Expansion Check
After recon-infra completes, review its `discovered_out_of_scope` list:
1. Present out-of-scope discoveries to the user
2. Ask: "The following targets were discovered but are outside the current scope. Would you like to add any of them?"
3. If the user approves, update `config/scope.yml` to include the new targets
4. Notify downstream agents of any scope additions

Extract from recon-infra:
- Open ports, subdomains, web technologies
- SSL/TLS findings
- DNS records
- **Full endpoint map** (from crawl + API spec + fuzz — see recon-infra agent's Endpoint Discovery output)
- Endpoint discovery summary (total unique endpoints, sources breakdown, unauthenticated endpoints, admin endpoints)

Extract from sast-scan:
- Entry points discovered
- SAST finding IDs
- Pre-digested finding summaries (for sast-analysis)

### Step 5.5: Dispatch Phase 2b Agent (Sequential)

**Re-authenticate before this step** (token refresh protocol).

#### sast-analysis Agent

Pre-digest sast-scan findings into a compact summary (~2K tokens) before passing to sast-analysis. Format:
```yaml
findings:
- id: "finding-uuid-1"
  title: "GitHub Actions Shell Injection"
  severity: HIGH
  file: ".github/workflows/deploy.yml"
  line: 45
  scanner: semgrep
  rule_id: javascript.github-actions.security.audit.shell-injection
- id: "finding-uuid-2"
  ...
```

Pass this summary (NOT raw scanner output) plus entry points to the sast-analysis agent.

Wait for completion. Verify sast-analysis reported exactly 10 test results and produced the SAST companion report path.

**Running test count checkpoint** *(illustrative — the real denominator is the scope-derived `{IN_SCOPE_TEST_COUNT}`, not a fixed total)*: 8 (auth) + 10 (recon) + 14 (sast-scan) + 10 (sast-analysis) + 15 (cloud-recon, when in scope) so far. Identity adds IDENTITY-01..60 (provider-gated) when `identity_targets` is in scope.

### Step 5.7: Merge Endpoint Map (MANDATORY)

Before dispatching Phase 3, the team lead MUST merge the recon-discovered endpoints with SAST-discovered entry points into a single unified attack surface map:

1. Take the full endpoint map from recon-infra (`discovered_data.endpoints`)
2. Take the entry points from sast-scan (`entry_points`)
3. Merge by path — deduplicate, keeping the richer metadata
4. Flag any SAST entry points NOT found by recon (these may be hidden/undocumented routes — high-priority test targets)
5. Flag any recon endpoints NOT in SAST (may be third-party, CDN, or infrastructure endpoints)
6. Store the merged map in the checkpoint file under `merged_endpoints` and update `endpoint_discovery_summary`

**Update checkpoint immediately after merging.** Write the merged endpoint map and summary to `reports/{TARGET_SLUG}-checkpoint.yml` so it survives context compaction. This is critical — if the lead loses context mid-assessment, the checkpoint must have the full endpoint map for downstream agents.

The merged endpoint map is passed to ALL downstream agents: web-security, api-graphql, crossval-qa, and chain-analysis.

### Step 6: Dispatch Phase 3 Agents (Parallel)

Spawn the Phase 3 agents in parallel, passing context from Phase 2. Always dispatch `web-security` and `api-graphql`. **Also dispatch `cloud-exploit` when `cloud_accounts` is defined in `config/scope.yml`** and `cloud-recon` produced an inventory in Phase 2a.

#### web-security Agent

Include in prompt:
- Auth token from Step 3 (re-authenticate if >10 min old)
- **Merged endpoint map** (from Step 5.7 — recon + SAST combined)
- Entry points from sast-scan (for targeted testing)

#### api-graphql Agent

Include in prompt:
- Auth token from Step 3 (re-authenticate if >10 min old)
- GraphQL endpoint from Step 3
- **Merged endpoint map** (from Step 5.7 — recon + SAST combined)
- API entry points from sast-scan

#### cloud-exploit Agent *(spawn only when `cloud_accounts` is defined)*

Include in prompt:
- Auth token from Step 3 (re-authenticate if >10 min old)
- `cloud_inventory`, `iam_findings`, `network_map`, `k8s_inventory` from cloud-recon (Phase 2a)
- The in-scope `cloud_accounts` entries from `config/scope.yml` — each entry's `provider` + `account_id` (+ region). cloud-exploit needs these to run `promote_cloud_inventory` (Phase 6) and they flow through to the end-of-run `correlate_cloud_findings` call.
- `{ASSESSMENT_ID}` from `$MAESTRO_ASSESSMENT_ID` — so the promoted inventory attaches to this run.
- Reference the cloud-exploit agent file at `.claude/agents/cloud-exploit.md`

cloud-exploit's final step (Phase 6) calls `promote_cloud_inventory` for each in-scope cloud account, persisting the typed asset+reachability inventory to the cloud backend. This is the keystone for the end-of-run `correlate_cloud_findings` step (Step 10d.5b) — without the promoted inventory there is nothing to join against.

If `cloud_accounts` is empty, do not spawn — the lead will inject 14 N_A entries for cloud-exploit's tests during Step 11.

### Step 7: Collect Phase 3 Results

Verify:
- web-security reported exactly 28 test results
- api-graphql reported exactly 27 test results
- cloud-exploit reported exactly 14 test results *(only if spawned)*

**Running test count checkpoint** *(illustrative — denominator is the scope-derived `{IN_SCOPE_TEST_COUNT}`)*: + 28 (web) + 27 (api) + 14 (cloud-exploit, when in scope) this phase. Identity adds the identity-exploit tests when `identity_targets` is in scope.

If either agent reported fewer tests than expected, message the agent to account for the missing ones before proceeding.

### Step 7.5: Dispatch Chain Analysis (Phase 3.5)

Dispatch chain-analysis agent for first pass (CHAIN-01 through CHAIN-04: hypothesize).

Include in prompt:
- All finding IDs from all previous agents (recon, sast, web, api)
- **Merged endpoint map** (from Step 5.7)
- Entry points from sast-scan
- Note: "This is Touch 1 — run CHAIN-01 through CHAIN-04 only (hypothesize). Touch 2 runs after crossval-qa."

### Step 8: Dispatch Phase 4 Agent (Sequential)

**Re-authenticate before this step** (token refresh protocol).

#### crossval-qa Agent

Include in prompt:
- All finding IDs from all previous agents
- SAST findings that need live endpoint validation
- All test results collected so far (should be 89 at this point)
- Targets and auth token
- **Merged endpoint map** (from Step 5.7)
- SAST companion report path (for enrichment)

The crossval-qa agent:
1. Runs XVAL-01 through XVAL-15. XVAL-12/13 are N_A when `cloud_accounts` is not in scope (XVAL-13 also N_A when no `repo_paths`); XVAL-14/15 are N_A when `identity_targets` is not in scope (XVAL-15 also N_A when no `repo_paths`)
2. Validates all HIGH/CRITICAL findings by re-testing
3. Assigns confidence scores
4. Identifies false positives
5. Reports coverage gaps
6. **Enriches the SAST companion report** with cross-validation results (updates exploitability status, adds DAST evidence)

### Step 9: Collect Phase 4 Results

Verify crossval-qa reported all 15 XVAL test results (XVAL-01 through XVAL-15; XVAL-12/13 N_A when cloud out of scope, XVAL-14/15 N_A when identity out of scope).

**Running test count checkpoint** *(illustrative — denominator is the scope-derived `{IN_SCOPE_TEST_COUNT}`)*: + 4 (chain Touch 1) + 15 (crossval-qa; XVAL-12/13 N_A when cloud out of scope) this phase. Remaining: 4 chain Touch 2 tests.

### Step 9.5: Dispatch Chain Analysis Touch 2

After crossval-qa completes successfully, dispatch chain-analysis for its second touch (CHAIN-05 through CHAIN-08).

**If crossval-qa only partially completed** (fewer than 13 test results), still dispatch Touch 2 but note which XVAL tests are missing — chain validation may be incomplete for those attack paths.

Include in prompt:
- All finding IDs (all agents)
- All exploit results from crossval-qa
- Cross-validation findings (XVAL results)
- QA validation results (confidence scores, false positives)
- Chain hypotheses from Touch 1 (CHAIN-01 through CHAIN-04 results)
- **Merged endpoint map** (from Step 5.7)
- Note: "This is Touch 2 — run CHAIN-05 through CHAIN-08 only (validate). Use exploit results to confirm/refute hypotheses from Touch 1."

**Task**: Validate chain hypotheses from Phase 3.5 against actual exploit outcomes. Confirm which chains were proven, refute those that failed, and discover any emergent chains from cross-validation.

**Output**: Validated chain analysis with confirmed/refuted/emergent chains

### Step 9.75: Dispatch Severity Calibration (Phase 4.75)

After chain-analysis Touch 2 completes, dispatch the severity-calibrator agent. This agent re-rates every finding based on what was *actually proven* during the assessment (EXPLOITED/PARTIAL/NOT EXPLOITABLE outcomes from crossval-qa, reachability from sast-analysis, chain context from chain-analysis), not on the intrinsic CVE/CWE severity.

Include in prompt:
- All finding IDs collected so far
- Path to `reports/crossval-qa-results.json`
- Path to `reports/chain-analysis-results.json`
- Path to `reports/sast-analysis-results.json`
- Path to `reports/compliance-results.json` (if it already exists — otherwise compliance runs after and reads the calibration output)

The severity-calibrator agent:
1. Loads all evidence artifacts
2. Walks 6 calibration rules per finding (see `.claude/agents/severity-calibrator.md`)
3. Produces a per-finding `calibrated_severity` + `justification` + `delta` + `rule_applied`
4. Saves to `reports/severity-calibration-results.json` for downstream agents

**Why this runs before compliance:** compliance maps findings to CVSS/OWASP frameworks, which represent intrinsic severity. Calibration produces team-facing severity that reflects actual exploitation in this codebase. Both are kept in the final report — they are not competing values, they are complementary lenses.

**Sanity check before dispatching:** the team lead should expect the calibrated severity totals to broadly track the EXPLOITED count. If the assessment found 2 EXPLOITED findings but somehow comes back with 10 calibrated-Criticals, that's a calibrator bug — re-spawn with the explicit reminder to apply Rule 2 (library-level exception) sparingly.

### Step 9.8: Dispatch Cloud Analysis (Phase 4.8) — cloud scope only

**Only when `cloud_accounts` is defined in `config/scope.yml`** (i.e., cloud-recon and cloud-exploit were spawned). If cloud is out of scope, skip this step entirely — there is no Cloud Companion Report and `{CLOUD_REPORT_PATH}` stays empty downstream.

After severity calibration completes, dispatch the cloud-analysis agent to synthesize the Cloud Companion Report. This agent is **analysis-only** — it reads checkpoints and the findings DB and never re-scans, re-exploits, or touches the cloud.

Include in prompt:
- The cloud finding IDs (from cloud-recon + cloud-exploit completion messages — CLOUD-01..29)
- Path to `reports/cloud-recon-results.json`
- Path to `reports/cloud-exploit-results.json`
- Path to `reports/chain-analysis-results.json` (for validated cloud chains CHAIN-31..40)
- Path to `reports/severity-calibration-results.json` (for dual severity, if present)
- Reference the cloud-analysis agent file at `.claude/agents/cloud-analysis.md`

The cloud-analysis agent:
1. Reads the cloud checkpoints + pulls cloud findings via `generate_report` (with finding_ids)
2. Builds the Identity & Escalation Graph (EXPLOITED / DETECTED-ONLY / GATED per path)
3. Writes the Cloud Companion Report to `reports/{target-slug}-cloud-{date}.md`
4. Saves `reports/cloud-analysis-results.json` with `cloud_report_path`

**Output**: `cloud_report_path` — passed to report-writer (cross-reference) and pdf-renderer (3rd PDF).

### Step 9.85: Dispatch Identity Analysis (Phase 4.85) — identity scope only

**Only when `identity_targets` is defined in `config/scope.yml`** (i.e., identity-recon and identity-exploit were spawned). If identity is out of scope, skip this step entirely — there is no Identity Companion Report and `{IDENTITY_REPORT_PATH}` stays empty downstream.

After severity calibration completes, dispatch the identity-analysis agent to synthesize the Identity Companion Report. This agent is **analysis-only** — it reads checkpoints and the findings DB and **never re-scans, re-sprays, re-cracks, or makes any authentication attempt** against the directory/tenant (the Lockout Mandate).

Include in prompt:
- The identity finding IDs (from identity-recon + identity-exploit completion messages — IDENTITY-01..60, per-provider gated: AD/Entra/M365/hybrid 01–40, Okta 41–50, Google Workspace 51–56, Ping 57–60)
- Path to `reports/identity-recon-results.json`
- Path to `reports/identity-exploit-results.json`
- Path to `reports/chain-analysis-results.json` (for validated identity chains CHAIN-41..50)
- Path to `reports/severity-calibration-results.json` (for dual severity, if present)
- Reference the identity-analysis agent file at `.claude/agents/identity-analysis.md`

The identity-analysis agent:
1. Reads the identity checkpoints + pulls identity findings via `generate_report` (with finding_ids)
2. Builds the Privilege-Escalation Graph (EXPLOITED / DETECTED-ONLY / GATED per path)
3. Writes the Identity Companion Report to `reports/{target-slug}-identity-{date}.md`
4. Saves `reports/identity-analysis-results.json` with `identity_report_path`

**Output**: `identity_report_path` — passed to report-writer (cross-reference) and pdf-renderer (additional PDF).

### Step 10: Dispatch Phase 5 Agents (Sequential Pipeline)

#### Step 10a: compliance Agent

Include in prompt:
- **All finding IDs as a list** (collected from all agent completion messages — NOT "from MCP DB")
- All in-scope test results (the scope-derived set; surface-absent tests are N_A, out-of-scope dimensions in the appendix)

**CRITICAL:** Pass the actual finding ID list (e.g., `["uuid-1", "uuid-2", ...]`) collected from every agent's `finding_ids` output. The compliance agent must pass these to `generate_report` with the `finding_ids` parameter. Without this, `generate_report` returns ALL findings from ALL previous assessments.

The compliance agent:
1. Maps each finding to OWASP Top 10, CWE, NIST 800-53, PCI-DSS
2. Calculates CVSS v3.1 vectors
3. Returns structured compliance mapping table

#### Step 10a.5: Pre-Report Manifest Check (MANDATORY)

Before dispatching report-writer, the team lead runs a final manifest check against `config/team-assessment.yml`. This is the last line of defense — if Step 2.5's blocked_by gate ever fails to catch a skipped phase, this catches it before the report goes out.

Algorithm:

1. Read `config/team-assessment.yml` `agents:` map.
2. For each agent:
   - If `applies_when` is present and the condition is false (e.g., `cloud_accounts` not in scope for cloud-recon/cloud-exploit), skip the agent — its tests will be N_A in the coverage checklist.
   - If `checkpoint_file` is `null`, skip the agent (report-writer and pdf-renderer haven't run yet — they come after this check).
   - Otherwise, substitute `{TARGET_SLUG}` and verify the file exists on disk via `Bash: test -f <path>`.
3. Build a manifest report:
   ```
   Manifest check (example: web/API-only run = 13 agents; cloud + identity out of scope → N_A):
     team-lead:           reports/<slug>-checkpoint.yml         ✓
     recon-infra:         reports/recon-infra-results.json      ✓
     sast-scan:           reports/sast-scan-results.json        ✓
     sast-analysis:       reports/sast-analysis-results.json    ✓
     web-security:        reports/web-security-results.json     ✓
     api-graphql:         reports/api-graphql-results.json      ✓
     chain-analysis:      reports/chain-analysis-results.json   ✓
     crossval-qa:         reports/crossval-qa-results.json      ✓
     severity-calibrator: reports/severity-calibration-results.json ✓
     compliance:          reports/compliance-results.json       ✓
     cloud-recon:         (N_A — no cloud_accounts in scope)
     cloud-exploit:       (N_A — no cloud_accounts in scope)
     cloud-analysis:      (N_A — no cloud_accounts in scope)
     identity-recon:      (N_A — no identity_targets in scope)
     identity-exploit:    (N_A — no identity_targets in scope)
     identity-analysis:   (N_A — no identity_targets in scope)
   ```
4. If **any** non-N_A checkpoint is missing, halt before report-writer and dispatch the missing agent. Do NOT proceed with a missing checkpoint — the report will be silently incomplete (missing calibrated severity column, missing compliance mapping, missing chain validation, etc.).
5. Show the manifest report to the user before dispatching report-writer so they see the full set of agent outputs at a glance.

**This is the single check that guarantees newly-added agents actually ran.** When you add a new agent to `config/team-assessment.yml` and give it a `checkpoint_file`, this loop will fail-loud if a future team lead forgets to dispatch it — no silent skip is possible.

#### Step 10b: report-writer Agent

Include in prompt:
- **All finding IDs as a list** (same list passed to compliance — report-writer uses this for `generate_report` filtering)
- Complete results for every in-scope test, plus `{IN_SCOPE_TEST_IDS}` and `{IN_SCOPE_TEST_COUNT}` (the scope-derived checklist denominator). Surface-absent tests carry N_A; out-of-scope dimensions go in the appendix.
- Compliance mapping table (from compliance agent)
- **Severity calibration results** (from severity-calibrator — path to `reports/severity-calibration-results.json` plus the inline summary). Report-writer renders BOTH original and calibrated severity columns.
- Finding summaries with evidence
- QA validation results (including secrets validation summary from XVAL-11)
- SAST companion report path
- **Cloud companion report path** (`{CLOUD_REPORT_PATH}` from cloud-analysis — only when cloud is in scope; report-writer cross-references it and adds the cloud cross-reference table)
- **Identity companion report path** (`{IDENTITY_REPORT_PATH}` from identity-analysis — only when identity is in scope; report-writer cross-references it and adds the identity cross-reference table)
- Agent attribution map
- Assessment metadata (date, targets, etc.)
- **Recon context** (open ports, subdomains, web technologies, DNS records)
- **Merged endpoint map** with discovery summary (total endpoints, sources, unauthenticated, admin)
- Chain analysis results (confirmed/refuted chains)

The report-writer agent:
1. Reads `skills/report/SKILL.md` for formatting rules
2. Writes the full markdown report
3. Does NOT generate PDFs
4. Does NOT do compliance mapping (already done)

#### Step 10c: report-enrichment Agent

Include in prompt:
- Main report markdown path (from report-writer)
- SAST companion markdown path
- Cloud companion markdown path (`{CLOUD_REPORT_PATH}` — only when cloud is in scope)
- Identity companion markdown path (`{IDENTITY_REPORT_PATH}` — only when identity is in scope)
- All finding IDs (same list as report-writer)
- Repo paths (for re-running SAST tools if needed)
- Targets and auth token (for re-running DAST tools if needed)

The report-enrichment agent:
1. Reads the report and all agent checkpoint files
2. Runs 12 validation checks against CLAUDE.md quality standards
3. Fixes gaps by editing the report (banned words, missing tables, placeholder tokens)
4. Re-executes MCP tools if evidence is missing (dependencies, secrets, CORS, etc.)
5. Validates the SAST companion report for completeness
6. Saves enrichment results to `reports/report-enrichment-results.json`

This is the final quality gate — nothing goes to PDF until every standard is met.

#### Step 10d: pdf-renderer Agent

Include in prompt:
- Main report markdown path (enriched)
- SAST companion markdown path (enriched)
- Cloud companion markdown path (`{CLOUD_REPORT_PATH}` — only when cloud is in scope; pdf-renderer renders a 3rd PDF with the same assessment_id, and skips it cleanly when absent)
- Identity companion markdown path (`{IDENTITY_REPORT_PATH}` — only when identity is in scope; pdf-renderer renders an additional PDF with the same assessment_id, and skips it cleanly when absent)
- **{ASSESSMENT_ID}** — read from `$MAESTRO_ASSESSMENT_ID` env var (set by the desktop terminal spawn for every assessment session). The pdf-renderer agent will refuse to run without this — see `.claude/agents/pdf-renderer.md`.

The pdf-renderer agent:
1. Reads each markdown file
2. Calls `generate_pdf_report` for each, **passing `assessment_id`** so the MCP tool POSTs a row to the cloud `/reports` endpoint after rendering
3. Returns both PDF paths AND the cloud `upload_status` for each (`"ok"`, `"skipped_no_assessment_id"`, or `"failed"`)

The team lead can also do this step directly if preferred (it's mechanical) — but make sure you pass `assessment_id` to `generate_pdf_report` in both calls.

#### Step 10d.5: Post-PDF Cloud Upload Verification (MANDATORY)

After pdf-renderer completes, the team lead verifies that BOTH PDFs were registered in the cloud Reports page — not just that they exist on disk. The agent's completion message must include `upload_status` for each render:

- `"ok"` — PDF rendered AND cloud `/reports` POST succeeded. Pass.
- `"skipped_no_assessment_id"` — agent didn't have `assessment_id`. The Reports page will not show this PDF. FAIL — re-dispatch with `{ASSESSMENT_ID}` populated from `$MAESTRO_ASSESSMENT_ID`.
- `"failed"` — cloud POST errored (network blip, auth expired, etc.). The team lead retries the upload directly: call `generate_pdf_report` with `markdown_content` of the existing report, the same `output_filename`, AND `assessment_id`. Do NOT regenerate the PDF from scratch — the existing one is fine, we just need the cloud POST to land.

This check pairs with Step 10a.5's manifest verification: the manifest check enforces "the file exists on disk"; this check enforces "the file is discoverable in the desktop Reports page." v0.1.103 shipped a bug where pdf-renderer didn't pass `assessment_id` — PDFs rendered cleanly, Reports page showed 0. v0.1.104 fixes both the agent prompt and the env-var fallback in `generate_pdf_report`. This verification step is the human-readable confirmation that the fix is still working.

If either upload failed and cannot be retried successfully, escalate to the user before declaring the assessment complete. Do NOT silently mark complete with a missing Reports row.

#### Step 10d.5b: Correlate Cloud Findings (cloud scope only — AFTER finalize)

**Only when `cloud_accounts` is defined in `config/scope.yml`.** Skip entirely on web/API-only runs.

The pdf-renderer agent runs this as its Step 3.5, immediately after `complete_assessment` (its Step 3). The ordering is load-bearing:

1. `promote_cloud_inventory` — pushed the asset inventory (cloud-exploit, Phase 6)
2. `complete_assessment` — promoted curated findings to the cloud backend (pdf-renderer Step 3 / Step 10d)
3. `correlate_cloud_findings` — joins the now-promoted assets × findings(CVE) × reachability and upserts "deployed + reachable + vulnerable" correlation findings (pdf-renderer Step 3.5)

Because container/CVE findings are written LOCALLY during the run (Shape A) and only land in the cloud Postgres backend at `complete_assessment`, `correlate_cloud_findings` MUST run after it — otherwise the join finds zero findings and silently correlates nothing. For each in-scope cloud account it is called with `provider` + `cloud_account_id` (from scope) and `assessment_id` (`$MAESTRO_ASSESSMENT_ID`).

Verify the agent's completion message reports the correlation outcome (`correlated` count + `finding_ids`). `correlated: 0` is valid (no internet-facing workload runs a CVE-bearing image). If it returned `ok:false` (no cloud session) or errored, the team lead can re-run `correlate_cloud_findings` directly with the same args.

**DAST correlation (always — pdf-renderer Step 3.6).** The network/web analog runs on every assessment, not just cloud ones. After `complete_assessment`, pdf-renderer calls `correlate_dast_findings` (`target` = the primary URL/host, `assessment_id`). It backfills structured port/service keys onto the promoted findings, then joins them against the recon `ports` snapshot to upsert "reachable + vulnerable" correlation findings + a computed `reachability` attack-path graph. Same load-bearing ordering as the cloud join: it MUST run after `complete_assessment` (and after a port scan promoted the recon snapshot), or it correlates 0. Verify the agent reports `correlated` + `keys_backfilled`; `correlated: 0` is valid.

### Step 11: Final Verification

Before declaring the assessment complete:

1. Collect all test results from all agents
2. Build the coverage map: every **in-scope** test ID → status (the in-scope set you computed in "Before Starting" Step 2)
3. **Verify every in-scope test ID is accounted for** — count them and confirm the total equals `{IN_SCOPE_TEST_COUNT}`. If any are missing, identify them by cross-checking against `{IN_SCOPE_TEST_IDS}`. Tests gated on an unconfigured scope dimension (no `cloud_accounts`, no target for an identity provider, no `repo_paths`) go in the "Out of Scope (N_A)" appendix — the lead writes these directly when the corresponding agents were not spawned. Surface-discovery-gated tests that found no surface are N_A and still in the active set.
4. If any in-scope test is unaccounted for, run it directly or document as BLOCKED with root cause
5. **BLOCKED triage** — review every BLOCKED test:
   - Was the root cause a token expiry? → Re-authenticate and re-run the test
   - Was it a tool error (scanner crash, timeout)? → Retry once with the same parameters
   - Was it a 404/endpoint not found? → Check if the endpoint exists via the merged endpoint map. If it doesn't exist, change to N_A with justification
   - Only leave as BLOCKED if the test genuinely could not run after retry
6. **Pass the in-scope set + count to report-writer and report-enrichment** — provide `{IN_SCOPE_TEST_IDS}` (the scope-derived list) and `{IN_SCOPE_TEST_COUNT}`, and state the tally: "`{IN_SCOPE_TEST_COUNT}` in-scope tests: X PASS, Y FAIL, Z N_A, W BLOCKED". Never assert a hardcoded total — the count is whatever the scope produced.
7. Confirm the report was generated successfully

## Agent Prompt Files

Agent prompts are stored as individual skill files in `.claude/agents/`. Each file has YAML frontmatter and the agent's complete instructions.

### File Layout

```
.claude/agents/
├── _preamble.md        # Common rules included in every agent prompt
├── recon-infra.md      # 10 tests: RECON-01–06, TLS-01–04
├── sast-scan.md        # 14 tests: SAST-01–10, SAST-SC-01–04
├── sast-analysis.md    # 10 tests: SAST-DF-01–05, SAST-DEF-01–05
├── web-security.md     # 28 tests: AUTHZ, HDR, CORS, INJ, SSRF, CLI
├── api-graphql.md      # 27 tests: GQL, API, VSCAN, UPLOAD, BIZ, PROTO, DESER
├── chain-analysis.md   #  8 tests: CHAIN-01–08
├── cloud-recon.md      # 15 tests: CLOUD-01–05, 10–12, 16, 20–21, 25–28 (cloud-only)
├── cloud-exploit.md    # 14 tests: CLOUD-06–09, 13–15, 17–19, 22–24, 29 (cloud-only)
├── cloud-analysis.md   #  0 tests: Cloud Companion Report synthesis (cloud-only)
├── identity-recon.md   # 23 tests: IDENTITY recon set, per-provider gated (identity-only)
├── identity-exploit.md # 37 tests: IDENTITY exploit set, per-provider gated (identity-only)
├── identity-analysis.md #  0 tests: Identity Companion Report synthesis (identity-only)
├── crossval-qa.md      # 15 tests: XVAL-01–15 (XVAL-12/13 N_A no cloud; XVAL-14/15 N_A no identity)
├── severity-calibrator.md #  0 tests: per-finding severity calibration from exploitation outcomes
├── compliance.md       #  0 tests: mapping only (incl. CIS Benchmarks)
├── report-writer.md    #  0 tests: report only
├── report-enrichment.md #  0 tests: validation + gap fixing
└── pdf-renderer.md     #  0 tests: PDF only
```

### How to Use Agent Prompts

When dispatching an agent, build the prompt by:
1. Read `.claude/agents/_preamble.md` — substitute `{AGENT_NAME}`, `{N}`, `{TARGET_SLUG}`, `{TARGETS_JSON}`, `{AUTH_TOKEN}`, `{AUTH_ROLE}`
2. Read `.claude/agents/<agent-name>.md` — substitute any `{PLACEHOLDER}` values with real data
3. Concatenate preamble + agent prompt as the `prompt` parameter to the `Agent` tool

This keeps prompts maintainable (edit one file per agent) and context-efficient (only the relevant prompt is loaded).

### Placeholder Substitution Guide (Per Agent)

Every `{PLACEHOLDER}` in agent prompt files must be replaced with real data at dispatch time. Here is the complete list:

**Preamble (all agents):**
| Placeholder | Source | Example |
|-------------|--------|---------|
| `{AGENT_NAME}` | Agent name | `recon-infra` |
| `{N}` | Test count for this agent | `10` |
| `{TARGET_SLUG}` | Slugified target name | `groovysec` |
| `{TARGETS_JSON}` | JSON array of targets | `["https://app.example.com"]` |
| `{AUTH_TOKEN}` | Bearer token from auth phase | `Bearer eyJhbG...` (or "No auth token") |
| `{AUTH_ROLE}` | `role` from `get_auth_role` (called in the auth phase). Pass the bare value; if it returns `unknown`, pass `unknown — no role declared` | `admin` (or `unknown — no role declared`) |

**recon-infra:** No additional placeholders (uses preamble only)

**sast-scan:**
| `{REPO_PATH}` | Local repo path in container | `/mnt/host-home/Desktop/my-app` |

**sast-analysis:**
| `{SAST_FINDINGS_SUMMARY}` | Pre-digested YAML list from sast-scan (see format below) | YAML string |
| `{ENTRY_POINTS}` | Entry points from sast-scan `map_entry_points` output | YAML string |
| `{REPO_PATH}` | Same repo path as sast-scan | `/mnt/host-home/Desktop/my-app` |

**web-security:**
| `{MERGED_ENDPOINTS}` | Merged endpoint map from Step 5.7 (YAML array) | See format below |

**api-graphql:**
| `{MERGED_ENDPOINTS}` | Same merged endpoint map | See format below |
| `{GRAPHQL_ENDPOINT}` | GraphQL URL discovered in auth phase | `https://api.example.com/graphql` |
| `{API_BASE_URL}` | Base API URL | `https://api.example.com` |

**chain-analysis:**
| `{ALL_FINDINGS}` | All finding IDs from all previous agents | YAML list of UUIDs |
| `{EXPLOIT_RESULTS}` | (Touch 2 only) Results from crossval-qa | YAML string |
| `{MERGED_ENDPOINTS}` | Same merged endpoint map | See format below |
| `{ENTRY_POINTS}` | Entry points from sast-scan | YAML string |
| `{TOUCH1_CHAIN_HYPOTHESES}` | (Touch 2 only) Results from Touch 1 | YAML string |

**crossval-qa:**
| `{SAST_FINDING_SUMMARY}` | SAST finding IDs + titles | YAML list |
| `{DAST_FINDING_SUMMARY}` | Web + API finding IDs + titles | YAML list |
| `{TEST_RESULTS_SO_FAR}` | All test results from phases 1-3.5 | YAML list |
| `{ENTRY_POINTS}` | Entry points from sast-scan | YAML string |
| `{MERGED_ENDPOINTS}` | Same merged endpoint map | See format below |
| `{SAST_REPORT_PATH}` | Path to SAST companion report | `reports/target-sast-2026-03-10.md` |

**severity-calibrator:**
| `{ALL_FINDING_IDS}` | All finding IDs from MCP DB | YAML list of UUIDs |
| `{CROSSVAL_QA_PATH}` | Path to crossval-qa results JSON | `reports/crossval-qa-results.json` |
| `{CHAIN_ANALYSIS_PATH}` | Path to chain-analysis results JSON | `reports/chain-analysis-results.json` |
| `{SAST_ANALYSIS_PATH}` | Path to sast-analysis results JSON | `reports/sast-analysis-results.json` |
| `{COMPLIANCE_PATH}` | Path to compliance results JSON (may not yet exist) | `reports/compliance-results.json` |

**compliance:**
| `{ALL_FINDING_IDS}` | All finding IDs from MCP DB | YAML list of UUIDs |
| `{ALL_TEST_RESULTS}` | In-scope test results (N_A for surface-absent, out-of-scope in appendix) | YAML list |
| `{SEVERITY_CALIBRATION_PATH}` | Path to severity-calibrator output | `reports/severity-calibration-results.json` |

**report-writer:**
| `{ALL_TEST_RESULTS}` | In-scope test results (N_A for surface-absent, out-of-scope in appendix) | YAML list |
| `{IN_SCOPE_TEST_IDS}` | Scope-derived in-scope test ID set (the checklist denominator) | YAML list |
| `{IN_SCOPE_TEST_COUNT}` | Count of in-scope tests for this run | integer |
| `{ALL_FINDING_IDS}` | All finding IDs | YAML list |
| `{COMPLIANCE_MAPPING}` | Structured mapping from compliance agent | YAML |
| `{QA_RESULTS}` | QA validation from crossval-qa | YAML |
| `{SECRETS_VALIDATION_SUMMARY}` | XVAL-11 results from crossval-qa | YAML |
| `{SAST_REPORT_PATH}` | SAST companion report path | file path string |
| `{CLOUD_REPORT_PATH}` | Cloud companion report path (empty when cloud out of scope) | file path string |
| `{IDENTITY_REPORT_PATH}` | Identity companion report path (empty when identity out of scope) | file path string |
| `{TARGETS}` | Target URLs | JSON array |
| `{REPO_PATHS}` | Repo paths | JSON array |
| `{DATE}` | Assessment date | `2026-03-10` |
| `{AGENT_ATTRIBUTION_MAP}` | Which agent ran which tests | YAML map |
| `{RECON_CONTEXT}` | Recon data (ports, subdomains, DNS, tech) | YAML |
| `{MERGED_ENDPOINTS}` | Same merged endpoint map | See format below |
| `{ENDPOINT_DISCOVERY_SUMMARY}` | Summary stats from recon-infra | YAML |
| `{CHAIN_RESULTS}` | Chain analysis results (confirmed/refuted) | YAML |
| `{SEVERITY_CALIBRATION}` | Per-finding original vs calibrated severity + justifications | YAML (from severity-calibration-results.json) |

**report-enrichment:**
| `{REPORT_MARKDOWN_PATH}` | Main report .md path | `reports/target-assessment-2026-03-10.md` |
| `{SAST_MARKDOWN_PATH}` | SAST companion .md path | `reports/target-sast-2026-03-10.md` |
| `{CLOUD_MARKDOWN_PATH}` | Cloud companion .md path (empty when cloud out of scope) | `reports/target-cloud-2026-03-10.md` |
| `{IDENTITY_MARKDOWN_PATH}` | Identity companion .md path (empty when identity out of scope) | `reports/target-identity-2026-03-10.md` |
| `{ALL_FINDING_IDS}` | All finding IDs from MCP DB | YAML list of UUIDs |
| `{IN_SCOPE_TEST_IDS}` | Scope-derived in-scope test ID set (for ENRICH-07) | YAML list |
| `{IN_SCOPE_TEST_COUNT}` | Count of in-scope tests for this run | integer |
| `{REPO_PATHS}` | Repo paths (for re-running SAST tools) | JSON array |
| `{TARGETS_JSON}` | Target URLs | JSON array |
| `{AUTH_TOKEN}` | Bearer token (for re-running DAST tools) | `Bearer eyJhbG...` |

**pdf-renderer:**
| `{REPORT_MARKDOWN_PATH}` | Main report .md path | `reports/target-assessment-2026-03-10.md` |
| `{SAST_MARKDOWN_PATH}` | SAST companion .md path | `reports/target-sast-2026-03-10.md` |
| `{CLOUD_MARKDOWN_PATH}` | Cloud companion .md path (empty when cloud out of scope — pdf-renderer skips it cleanly) | `reports/target-cloud-2026-03-10.md` |
| `{IDENTITY_MARKDOWN_PATH}` | Identity companion .md path (empty when identity out of scope — pdf-renderer skips it cleanly) | `reports/target-identity-2026-03-10.md` |
| `{ASSESSMENT_ID}` | UUID of the cloud `assessments` row this run belongs to. Read from `$MAESTRO_ASSESSMENT_ID` env var (set by the desktop terminal spawn). REQUIRED — pdf-renderer aborts without it because the PDFs would land on disk without being registered in the cloud Reports page. | `c0ffee01-…` |

### Standard Data Formats

**Merged Endpoint Map** (`{MERGED_ENDPOINTS}`):
```yaml
- path: "/auth/login"
  methods: ["POST"]
  auth_required: false
  source: "crawl"
- path: "/admin/users"
  methods: ["GET", "POST", "DELETE"]
  auth_required: true
  source: "swagger"
  notes: "Admin-only endpoint"
- path: "/logs"
  methods: ["GET"]
  auth_required: true
  source: "fuzz"
  response_size: "large"
  notes: "Bulk data — potential exposure"
```

**SAST Findings Summary** (`{SAST_FINDINGS_SUMMARY}`):
```yaml
findings:
- id: "finding-uuid-1"
  title: "GitHub Actions Shell Injection"
  severity: HIGH
  file: ".github/workflows/deploy.yml"
  line: 45
  scanner: semgrep
  rule_id: javascript.github-actions.security.audit.shell-injection
- id: "finding-uuid-2"
  title: "Hardcoded API Key"
  severity: HIGH
  file: "backend/.env"
  line: 1
  scanner: gitleaks
```

**Endpoint Discovery Summary** (`{ENDPOINT_DISCOVERY_SUMMARY}`):
```yaml
total_unique_endpoints: 50
sources:
  crawl: 12
  swagger: 15
  fuzz: 17
  probe: 3
  sast: 33
unauthenticated_endpoints: 14
admin_endpoints: ["/admin/users", "/admin/settings"]
bulk_data_endpoints: ["/logs", "/export"]
```

### Foreground vs Background Agents

**Use `run_in_background: true` ONLY for parallel phases** where two agents run simultaneously:
- Phase 2a: recon-infra + sast-scan (parallel — both background)
- Phase 3: web-security + api-graphql (parallel — both background)

**All sequential agents run in foreground** (no `run_in_background`):
- Phase 2b: sast-analysis (foreground)
- Phase 3.5: chain-analysis (foreground)
- Phase 4: crossval-qa (foreground)
- Phase 4.75: severity-calibrator (foreground)
- Phase 5a/5b/5b.5/5c: compliance, report-writer, report-enrichment, pdf-renderer (foreground)

Foreground agents stream their progress directly in the user's session, so the user can see tool calls executing in real-time without needing to check manually.

### Progress Monitoring

Agents send progress updates after each test (see preamble rule 8).

**For background agents** (Phase 2a, Phase 3), the team lead monitors and relays progress:

1. While waiting for background agents, periodically check for progress messages
2. Display combined progress to the user:

```
Phase 2a Progress:
  recon-infra:  ████████░░ 8/10  (80%) — Completed RECON-05 (PASS)
  sast-scan:    ██████░░░░ 9/14  (64%) — Completed SAST-07 (FAIL)
```

3. Progress bar: 10 characters wide — █ for completed portions, ░ for remaining
4. Update the user each time new progress messages arrive
5. When an agent reaches 100%, show its final summary immediately

**For foreground agents**, progress streams naturally via visible tool calls. Show a one-line summary on completion:
```
sast-analysis: ██████████ 10/10 (100%) — Complete (3 findings)
```

### User Status Updates

The team lead MUST keep the user informed. After dispatching background agents:
1. Tell the user which agents were launched and what they're doing
2. When a background agent completes, summarize its results to the user immediately
3. Between phases, tell the user what's next and re-authenticate if needed
4. If an agent is taking longer than expected, proactively tell the user (don't wait to be asked)

Example status updates:
- "Phase 2a launched: recon-infra and sast-scan running in parallel. I'll summarize results when they finish."
- "recon-infra completed: 10/10 tests done, 2 findings. Still waiting on sast-scan..."
- "sast-scan completed: 14/14 tests, 9 findings. Re-authenticating before Phase 2b..."
- "Starting sast-analysis in foreground — you'll see the code analysis calls streaming."

## No-Skip Enforcement

### Banned Status: SKIPPED

`SKIPPED` is **not a valid status** in team-based assessments. Every test MUST have one of:

| Status | Meaning | Requirements |
|--------|---------|-------------|
| **PASS** | Test ran, result obtained (finding or no finding) | None |
| **FAIL** | Test ran, vulnerability confirmed | Finding created via `create_finding` |
| **N_A** | Test does not apply to this target | Justification required (e.g., "No file upload functionality exists") |
| **BLOCKED** | Test could not execute | Root cause, what was tried, and recommended follow-up required |

### Lead-Level Verification

Before spawning the compliance agent, the team lead:
1. Collects all `test_results` from all agents
2. Counts total results — must equal `{IN_SCOPE_TEST_COUNT}` (the scope-derived in-scope set). Surface-discovery tests with no surface are N_A and still in the active set; out-of-scope dimensions (no cloud_accounts / no identity target / no repo_paths) are recorded in the "Out of Scope (N_A)" appendix
3. If any in-scope test is missing, messages the responsible agent
4. If an agent is unresponsive, the lead runs the missing tests directly
5. Only after every in-scope test is accounted for does the report phase begin

## Data Flow

### Findings: MCP Database (Primary)

Every agent calls `create_finding` via MCP for each vulnerability. Findings accumulate in the shared SQLite DB. The report agent reads all findings from the DB via `generate_report`.

### Context: SendMessage (Coordination)

The team lead passes context to agents via structured messages.

**Lead -> Worker (dispatch)**:
```json
{
  "targets": ["https://app.example.com"],
  "repo_paths": ["/mnt/host-home/projects/app"],
  "auth_token": "Bearer eyJhbG...",
  "graphql_endpoint": "https://api.example.com/graphql",
  "recon_context": { "open_ports": {}, "subdomains": [], "web_tech": {}, "endpoints": [] },
  "merged_endpoints": [],
  "assigned_tests": ["RECON-01", "RECON-02"]
}
```

**Worker -> Lead (completion)**:
```json
{
  "test_results": [
    {"test_id": "RECON-01", "status": "PASS", "finding_count": 0, "notes": "Ports 80,443 open"},
    {"test_id": "TLS-01", "status": "BLOCKED", "finding_count": 0, "notes": "testssl.sh timed out after 120s, retried with nmap ssl-enum, still failed — DNS resolver issue in container"}
  ],
  "finding_ids": ["uuid-1", "uuid-2"],
  "discovered_data": { "endpoints": [], "subdomains": [] }
}
```

### sast-scan -> sast-analysis Data Format

The team lead pre-digests sast-scan output into a compact summary for sast-analysis:
```yaml
findings:
- id: "finding-uuid-1"
  title: "GitHub Actions Shell Injection"
  severity: HIGH
  file: ".github/workflows/deploy.yml"
  line: 45
  scanner: semgrep
  rule_id: javascript.github-actions.security.audit.shell-injection
```
This keeps sast-analysis input small (~2K tokens for 15 findings) vs raw scanner output (43-80K tokens).

## Auth Handling

Auth stays with the team lead because OTP requires direct user interaction:

1. Lead runs AUTH-01-08 using MCP browser tools (`browser_navigate`, `browser_fill`, `prompt_for_otp`)
2. Lead calls `browser_save_state` to persist browser state in the container
3. Lead extracts Bearer token from `browser_network_log`
4. Lead passes the token string to downstream agents via `SendMessage`
5. Downstream agents use the token in MCP tool `headers` parameters
6. Agents needing browser state call `browser_restore_state`

## Error Recovery

### Agent Timeout Protocol

After dispatching an agent:
1. Note the dispatch time
2. If no completion message received within max_duration:
   a. Send a status check message to the agent
   b. Wait 2 minutes for response
   c. If no response: agent is stuck
3. Recovery:
   a. Check if partial output files exist (reports/ directory)
   b. Collect any findings already in MCP DB from that agent
   c. Respawn with LEANER prompt:
      - Remove all rule text (agent has CLAUDE.md)
      - Include only: test assignments + targets + auth token + "resume from test X"
      - Pass partial results: "Tests already completed: [list]. Resume from [first incomplete]."
   d. If respawn also fails: run remaining tests yourself (team lead)

### Timeout Thresholds

| Agent | Max Duration | Notes |
|-------|-------------|-------|
| recon-infra | 10 min | Quick scans |
| sast-scan | 10 min | Scanner execution only |
| sast-analysis | 15 min | Code analysis + report writing |
| web-security | 20 min | Many injection tests |
| api-graphql | 20 min | Many API/GraphQL tests |
| chain-analysis | 8 min | Analysis only, no scanning |
| crossval-qa | 15 min | Re-testing + SAST enrichment |
| severity-calibrator | 5 min | Reasoning over already-collected evidence — no scanning |
| compliance | 5 min | Mapping only |
| report-writer | 25 min | Chunked writing (6 chunks to avoid 32K token limit) |
| report-enrichment | 15 min | Validation + targeted edits + optional MCP re-execution |
| pdf-renderer | 3 min | Mechanical PDF calls |

### AUTH_EXPIRED Recovery Protocol

If an agent reports `AUTH_EXPIRED` in its completion message:

1. **Identify which tests were affected** — the agent should list tests that got 401s
2. **Re-authenticate** — run the OTP flow again (prompt user for new code)
3. **Respawn the agent** with:
   - The fresh auth token
   - Only the affected tests (not all tests — the passed ones are already done)
   - Note: "Resume mode — only run these tests: [list]. Previous results are already recorded."
4. **If re-auth fails** (user unavailable, OTP expired), mark the affected tests as BLOCKED with reason: "Authentication expired mid-phase, re-auth unsuccessful"
5. **Update the checkpoint** with the new token and expiry time

The proactive Token Refresh Protocol (re-auth between phases) should prevent most AUTH_EXPIRED events. This recovery protocol is the fallback when it happens anyway.

### Test-Level Recovery
- If a specific test fails (tool error, timeout), retry ONCE with the same parameters
- If retry also fails, mark the test as BLOCKED with:
  - Root cause (e.g., "connection timeout", "tool returned empty response")
  - What was attempted (the exact tool call)
  - Recommended follow-up (e.g., "retry manually with longer timeout")
- NEVER mark a test as SKIPPED — use BLOCKED with details

### Context Loss Recovery — Individual Agents
If an agent loses context mid-execution:
1. Use `load_assessment_context` to recover prior agent results
2. Check the task list for completed test IDs
3. Resume from the first incomplete test

### Context Compaction Recovery — Team Lead

The team lead conversation may hit auto-compaction during long assessments. To survive this gracefully:

**Checkpoint after every phase.** After collecting results from each phase, write a checkpoint file:

```bash
# File: reports/{TARGET_SLUG}-checkpoint.yml
Write to reports/{TARGET_SLUG}-checkpoint.yml after each phase completes
```

```yaml
assessment: {TARGET_SLUG}
timestamp: {ISO8601}
auth_token: "Bearer eyJhbG..."
auth_expires_at: {ISO8601}
completed_phases:
  - phase: "1-auth"
    tests_completed: 8
    finding_ids: ["uuid-1"]
  - phase: "2a-recon-sast-scan"
    tests_completed: 24
    finding_ids: ["uuid-2", "uuid-3"]
pending_phase: "2b-sast-analysis"
total_tests_collected: 32
test_results:
  - test_id: "AUTH-01"
    status: "PASS"
    agent: "lead"
  # ... all results so far
discovered_data:
  endpoints: []
  subdomains: []
  technologies: []
merged_endpoints: []  # Combined recon + SAST entry points (from Step 5.7)
endpoint_discovery_summary:
  total_unique_endpoints: 0
  sources: { crawl: 0, swagger: 0, fuzz: 0, probe: 0, sast: 0 }
```

**Recovery after compaction:**
1. If you lose track of assessment state, read `reports/{TARGET_SLUG}-checkpoint.yml`
2. The checkpoint has everything needed to resume: auth token, completed phases, all test results so far
3. Resume from `pending_phase` — do not re-run completed phases
4. Findings are safe in the MCP SQLite DB regardless of compaction
4. Do NOT re-run already-completed tests (check findings DB for duplicates)

### Context Passing Failure

If the lead cannot extract expected context (e.g., no auth token):

1. Lead documents why (e.g., "OTP flow failed, no Bearer token obtained")
2. Lead spawns downstream agents with a note: "No auth token — run unauthenticated tests only, report auth-dependent tests as BLOCKED with reason 'No auth session available'"
3. Auth-dependent tests (AUTHZ, GQL-04, GQL-05, etc.) are marked BLOCKED, not silently omitted

## Complete Agent-to-Test Assignment

Reference `config/team-assessment.yml` for the authoritative mapping. Summary:

### Team Lead (8 tests)
AUTH-01, AUTH-02, AUTH-03, AUTH-04, AUTH-05, AUTH-06, AUTH-07, AUTH-08

### recon-infra (10 tests)
RECON-01, RECON-02, RECON-03, RECON-04, RECON-05, RECON-06, TLS-01, TLS-02, TLS-03, TLS-04

### sast-scan (14 tests)
SAST-01, SAST-02, SAST-03, SAST-04, SAST-05, SAST-06, SAST-07, SAST-08, SAST-09, SAST-10, SAST-SC-01, SAST-SC-02, SAST-SC-03, SAST-SC-04

### sast-analysis (10 tests)
SAST-DF-01, SAST-DF-02, SAST-DF-03, SAST-DF-04, SAST-DF-05, SAST-DEF-01, SAST-DEF-02, SAST-DEF-03, SAST-DEF-04, SAST-DEF-05

### web-security (28 tests)
AUTHZ-01, AUTHZ-02, AUTHZ-03, AUTHZ-04, HDR-01, HDR-02, HDR-03, HDR-04, CORS-01, CORS-02, CORS-03, INJ-01, INJ-02, INJ-03, INJ-04, INJ-05, INJ-06, INJ-07, INJ-08, SSRF-01, SSRF-02, SSRF-03, CLI-01, CLI-02, CLI-03, CLI-04, CLI-05, CLI-06

### api-graphql (27 tests)
GQL-01, GQL-02, GQL-03, GQL-04, GQL-05, GQL-06, GQL-07, GQL-08, API-01, API-02, API-03, API-04, API-05, API-06, VSCAN-01, VSCAN-02, VSCAN-03, UPLOAD-01, UPLOAD-02, UPLOAD-03, BIZ-01, BIZ-02, BIZ-03, PROTO-01, PROTO-02, PROTO-03, DESER-01

### chain-analysis (8 tests)
CHAIN-01, CHAIN-02, CHAIN-03, CHAIN-04, CHAIN-05, CHAIN-06, CHAIN-07, CHAIN-08

### cloud-recon (15 tests — cloud-only, all N_A on web/API-only runs)
CLOUD-01, CLOUD-02, CLOUD-03, CLOUD-04, CLOUD-05, CLOUD-10, CLOUD-11, CLOUD-12, CLOUD-16, CLOUD-20, CLOUD-21, CLOUD-25, CLOUD-26, CLOUD-27, CLOUD-28

### cloud-exploit (14 tests — cloud-only, all N_A on web/API-only runs)
CLOUD-06, CLOUD-07, CLOUD-08, CLOUD-09, CLOUD-13, CLOUD-14, CLOUD-15, CLOUD-17, CLOUD-18, CLOUD-19, CLOUD-22, CLOUD-23, CLOUD-24, CLOUD-29

### identity-recon (23 tests — identity-only, per-provider gated; N_A when identity_targets out of scope)
IDENTITY-01..05 (AD), IDENTITY-16..20 (Entra), IDENTITY-35..37 (M365/hygiene), IDENTITY-41..45 (Okta), IDENTITY-51..53 (Google Workspace), IDENTITY-57..58 (Ping)

### identity-exploit (37 tests — identity-only, per-provider gated; N_A when identity_targets out of scope)
IDENTITY-06..15 (AD), IDENTITY-21..28 (Entra), IDENTITY-29..34 (M365), IDENTITY-38..40 (hybrid), IDENTITY-46..50 (Okta), IDENTITY-54..56 (Google Workspace), IDENTITY-59..60 (Ping)

### crossval-qa (15 tests; XVAL-12/13 N_A when cloud out of scope, XVAL-14/15 N_A when identity out of scope)
XVAL-01, XVAL-02, XVAL-03, XVAL-04, XVAL-05, XVAL-06, XVAL-07, XVAL-08, XVAL-09, XVAL-10, XVAL-11, XVAL-12, XVAL-13, XVAL-14, XVAL-15

### severity-calibrator (0 tests — calibration only)
### cloud-analysis (0 tests — Cloud Companion Report synthesis only; cloud-only)
### identity-analysis (0 tests — Identity Companion Report synthesis only; identity-only)
### compliance (0 tests — mapping only)
### report-writer (0 tests — report generation only)
### report-enrichment (0 tests — validation and gap fixing only)
### pdf-renderer (0 tests — PDF rendering only)

## Key Principles

1. **Every in-scope test ID accounted for** — the scope-derived set, 0 silently omitted (out-of-scope dimensions go in the N_A appendix)
2. **No SKIPPED status** — PASS, FAIL, N_A, or BLOCKED only
3. **Findings via MCP DB** — `create_finding` stores durably, report reads from DB
4. **Context via messages** — auth tokens, endpoints, recon data passed between agents
5. **Parallel where possible** — Phases 2a and 3 run two agents concurrently
6. **Lead verifies totals** — before report phase, verify every in-scope test (`{IN_SCOPE_TEST_COUNT}`) is accounted for, then pass `{IN_SCOPE_TEST_IDS}` + `{IN_SCOPE_TEST_COUNT}` to the report agents
7. **Error recovery built in** — failed agents get restarted or their tests run by the lead
8. **Agent attribution** — report shows which agent ran which tests
9. **No previous report contamination** — NEVER pass old report paths to agents, never reference prior assessments. Each assessment is a clean, independent snapshot. The only report paths passed between agents are the current run's companion reports: the SAST companion (sast-analysis → crossval-qa → report-writer) and, in cloud scope, the Cloud companion (cloud-analysis → report-writer → pdf-renderer).
10. **Token refresh** — re-authenticate between long phases to prevent JWT expiry
11. **Pre-digest scanner output** — team lead summarizes sast-scan output for sast-analysis (~2K tokens, not 43-80K)
12. **Agent checkpoint files** — every agent saves results to `reports/{agent}-results.json` before completion (see below)

## Agent Checkpoint Files (Session Recovery)

Every agent saves a structured JSON results file to `reports/` before sending its completion message. This ensures assessment data survives session interruptions (terminal crash, token limit, network disconnect).

### Checkpoint Files

**The authoritative list lives in `config/team-assessment.yml` under each agent's `checkpoint_file:` field.** When adding a new agent, set that field in the YAML — the lead's pre-dispatch gate (Step 2.5) and pre-report manifest check (Step 10a.5) will automatically enforce it. The table below is a non-authoritative snapshot of the current set, kept here for quick human reference only.

| Agent | File | Key Data |
|-------|------|----------|
| recon-infra | `reports/recon-infra-results.json` | Endpoints, subdomains, ports, DNS, TLS |
| sast-scan | `reports/sast-scan-results.json` | Scanner counts, entry points, secrets summary |
| sast-analysis | `reports/sast-analysis-results.json` | Data flows, defense verification, SAST report path |
| web-security | `reports/web-security-results.json` | Web test results, endpoint coverage |
| api-graphql | `reports/api-graphql-results.json` | API/GraphQL test results |
| chain-analysis | `reports/chain-analysis-results.json` | Chain hypotheses, confirmed/refuted chains |
| crossval-qa | `reports/crossval-qa-results.json` | Cross-validation, QA scores, secrets validation |
| severity-calibrator | `reports/severity-calibration-results.json` | Per-finding original vs calibrated severity + justifications |
| compliance | `reports/compliance-results.json` | OWASP/NIST/PCI/CVSS mapping |
| report-enrichment | `reports/report-enrichment-results.json` | Validation results, edits made, tools re-executed |

### Recovery Protocol

If a session is interrupted:
1. Read `reports/groovysec-checkpoint.yml` for the team lead's checkpoint (phases completed, finding IDs, test results)
2. Read each `reports/{agent}-results.json` file for agent-specific data
3. Between the checkpoint and the results files, you have complete state for all completed phases
4. Resume from the next incomplete phase — no need to re-run completed agents

### Team Lead Checkpoint Updates

The team lead MUST update `reports/{target}-checkpoint.yml` after EVERY phase completes. The checkpoint includes:
- All finding IDs collected so far
- All test results collected so far
- Phase completion status
- Auth token (for session recovery)
- Discovered data (endpoints, subdomains, technologies)
