# Maestro

**An autonomous penetration testing platform.** An LLM orchestrates a team of
specialized security agents against systems you are authorized to test, driving
**227 security tools** inside a Kali Linux container, and produces a report where
every exploitable finding has been re-proven under a deterministic oracle.

The hard part of automated security testing isn't running scanners. It's not
lying about the results. Maestro's structural answer is that **the LLM supplies
the experiment and never the verdict** — enforced in code, not in a prompt.

> **Open core.** Most of this repository is Apache-2.0. A small, enumerated set
> of paths is proprietary — see [Licensing](#licensing).

---

## Contents

- [Two ways to run it](#two-ways-to-run-it)
- [Install](#install)
- [Quick start](#quick-start)
- [Architecture](#architecture)
- [The five attack surfaces](#the-five-attack-surfaces)
- [The agent team](#the-agent-team)
- [Why you can trust the output](#why-you-can-trust-the-output)
- [Repository layout](#repository-layout)
- [Configuration](#configuration)
- [Development](#development)
- [Authorized use only](#authorized-use-only)
- [Licensing](#licensing)
- [Known limitations](#known-limitations)
- [Documentation](#documentation)
- [Feedback, ideas and bugs](#feedback-ideas-and-bugs)

---

## Two ways to run it

Maestro runs in one of two modes. The assessment engine is **identical** in both
— the same 227 tools, the same agents, the same oracles, the same reports. Only
where the data lives differs.

### Local — everything on this machine

The default. Findings, assessments, reports and projects live in a local SQLite
database at `~/.pentest/data/pentest.db`.

**No AWS account. No Cognito. No terraform. No sign-in. Nothing to provision.**
Clone, build, run.

### Team — your own backend, shared

Postgres + an API deployed into **your** AWS account
([`deploy/terraform/maestro-self-host`](deploy/terraform/maestro-self-host)).
Users sign in against **your** Cognito pool and share one view of the data.
A single unattended `terraform apply`, roughly 15 minutes.

### What each gives you

| | Local | Team |
|---|:---:|:---:|
| Run assessments across all five surfaces | ✅ | ✅ |
| Findings, triage, evidence | ✅ | ✅ |
| Severity calibration | ✅ | ✅ |
| Oracle verification | ✅ | ✅ |
| Reports + PDF rendering | ✅ | ✅ |
| Projects, imports, scan history | ✅ | ✅ |
| In-app documentation | ✅ | ✅ |
| Multi-user shared data | — | ✅ |
| Attack-graph explorer | — | ✅ |
| Post-exploitation footholds | — | ✅ |
| Scheduled DAST | — | ✅ |
| Cross-assessment caching | — | ✅ |
| Users and roles | — | ✅ |

The team-only rows depend on Postgres-native schema the local database has no
equivalent for — the attack graph in particular on an accumulating node/edge
union plus a recursive-CTE pathfinder. Where a feature is unavailable locally
**the UI says so and explains why**, rather than rendering an empty panel.

**Local is a smaller product, not a degraded one.** Switching modes does not
migrate data: the two stores are separate, nothing is deleted, but the other
store's findings aren't visible until you switch back. Decide before you
accumulate work you care about.

Switch any time in **Configuration → Data & Sync**.

---

---

## Install

Maestro is **free to use**. There are two ways in, and the first is why this
repository is public: you can read exactly what you are about to run.

### 1. Vet the source, then install the signed app

This tool executes real attacks with real payloads from your machine. You should
not take that on trust from a binary. Read the code first — the tool handlers in
`mcp-server/`, the container definition in `docker/`, the scope guard in
`mcp-server/src/scope/`, the agent instructions in `.claude/agents/` — then
install the signed build.

**v1.13.0**

| Platform | Download |
|---|---|
| macOS (Apple Silicon) | [Maestro_1.13.0_aarch64.dmg](https://updates.maestro.groovysec.com/maestro/free/macos-aarch64/Maestro_1.13.0_aarch64.dmg) |
| Windows | [Maestro_1.13.0_x64_en-US.msi](https://updates.maestro.groovysec.com/maestro/free/windows-x64/Maestro_1.13.0_x64_en-US.msi) · [setup.exe](https://updates.maestro.groovysec.com/maestro/free/windows-x64/Maestro_1.13.0_x64-setup.exe) |
| Linux | [.deb](https://updates.maestro.groovysec.com/maestro/free/linux-x64/Maestro_1.13.0_amd64.deb) · [.AppImage](https://updates.maestro.groovysec.com/maestro/free/linux-x64/Maestro_1.13.0_amd64.AppImage) |

These are the **free** builds: they default to local mode, so there is no
account, no licence key and no sign-in. (The `latest` channel on the same CDN is
the commercial build, which expects an org login — don't use those links.)

macOS is Apple Silicon only — the Intel build was dropped. Builds are code-signed
(Apple Developer ID on macOS, Azure Trusted Signing on Windows) and ship a signed
updater manifest, so the app verifies its own updates. The current manifest is
always at [update.json](https://updates.maestro.groovysec.com/maestro/free/update.json),
which is also the authoritative list of released artifacts.

You also need **Docker** running, plus the toolkit image:

```bash
docker pull ghcr.io/shmalex405/docker-kali:v1.13.0
```

Roughly 15 GB, a few minutes. The app checks for it during startup and tells you
if it is missing.

The tag must match the app version. Each release pins its toolkit image at build
time and looks it up **by tag**, so pulling `:latest` gives you a byte-identical
image under the wrong name and the app still reports it missing.

### LLM credentials — bring your own

Maestro does not ship an LLM. You connect your own account, and there are two ways
to do it. Both are configured in-app under **Config → Claude** (or **Codex**).

| | Sign in with your account | API key |
|---|---|---|
| How | Browser OAuth — "Sign in with Claude" / "Sign in with ChatGPT" | `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` |
| Uses | Your existing Claude Pro/Max or ChatGPT Plus subscription | Pay-as-you-go API billing |
| Cost of a run | Covered by the subscription you already pay for | **Metered per token, and assessments are token-heavy** |
| Best for | Most people | CI, automation, or if you have no subscription |

**On cost, plainly:** if you sign in with a subscription, running Maestro costs you
nothing beyond that subscription. If you use an API key, you pay per token — and a
full multi-surface assessment can run to hundreds of dollars of usage. Neither
path sends anything to Groovy Security; the credentials live on your machine and
in your container.

Two brains are supported and you pick per assessment: **Claude** (Claude Code) or
**Codex** (OpenAI Codex CLI). Same tools, same agents, same reports — only the
model driving the tool calls differs.

### Request Anthropic Cyber Verification before your first run

**Do this before you start, or exploitation will stall partway through.**

Anthropic applies safeguards to cyber-offensive use of Claude. Maestro's job is
sustained, real exploitation, which is exactly the shape those safeguards look
for — so on an unenrolled account the exploitation agents (`web-security`,
`api-graphql`, `cloud-exploit`, `identity-exploit`, `post-exploit-operator`) may
refuse partway through a run.

It does not look like an error. The agent declines and moves on, so the symptom is
a thinner report rather than a crash — check the agent transcript before assuming
a tool is broken.

**What to do:** apply to Anthropic's **Cyber Verification Program** for your
organization. It is Anthropic's process, granted per-organization, and it does not
transfer with this software — a Groovy Security enrollment does nothing for your
account. Start at [anthropic.com](https://www.anthropic.com/) or via your
Anthropic account contact, and describe your legitimate security-testing use.

If you would rather not wait: recon, SAST, dependency and secret scanning,
compliance mapping and reporting are generally unaffected, so you can run those
immediately and add exploitation once enrolled. The Codex brain is subject to
OpenAI's own policies instead.

### 2. Build it yourself

If you would rather not run anyone else's binary, build from this repository —
see [Quick start](#quick-start). You compile the toolkit image from
`docker/Dockerfile.kali` yourself, so nothing is taken on trust.

### Then

Point it at something you are authorized to test (`config/scope.yml`) and run an
assessment. No account, no licence key, no backend needed — see
[Two ways to run it](#two-ways-to-run-it).

## Quick start

Building from source. To install the packaged app instead, see
[Install](#install).

### Prerequisites

Both modes:

- **Docker**, ~20 GB free. amd64; Apple Silicon works under emulation.
- **Node 20+** and **Rust stable**
- An **Anthropic or OpenAI account** — sign in with your subscription, or use an
  API key. See [LLM credentials](#llm-credentials--bring-your-own).

Team mode additionally:

- An AWS account with a **Route 53 hosted zone** in it
- **Terraform ≥ 1.5**

### Local mode — three commands

```bash
# 1. Build the Kali toolkit image (30–60 min, ~15 GB — one time)
./scripts/build-self-host-toolkit.sh

# 2. Build the desktop app
cd frontend && npm ci
KALI_IMAGE=maestro-toolkit:local \
MAESTRO_DISTRIBUTION=self-host \
  npm run tauri:build -- --config src-tauri/tauri.self-host.conf.json

# 3. Run it — comes up in local mode with no further configuration
```

`MAESTRO_DISTRIBUTION=self-host` is what makes local the default: with it set and
no config file present, the app skips discovery and sign-in entirely. There is no
mode to choose and no file to write.

The toolkit build verifies that `nmap`, `nuclei`, `sqlmap`, `semgrep`, `nikto`,
`gitleaks`, `trivy` and `grype` all landed, and **fails if any are missing** — a
toolkit missing a scanner produces assessments where the affected tests report
BLOCKED rather than PASS.

Then point it at something you're authorized to test:

```bash
$EDITOR config/scope.yml
```

### Team mode

See **[SELF-HOSTING.md](SELF-HOSTING.md)** for the full walkthrough. In outline:
build and push the backend image to your own ECR, `terraform apply`, then paste
`terraform output -raw desktop_self_host_json` into **Configuration → Data &
Sync**. One paste — no transcribing pool IDs.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    LLM Orchestration Layer                      │
│  ┌─────────────────┐              ┌─────────────────────────┐   │
│  │  Claude Code    │      OR      │   OpenAI Codex CLI      │   │
│  │  (Claude tab)   │              │   (Codex tab)           │   │
│  └────────┬────────┘              └────────────┬────────────┘   │
│           └────────────────┬───────────────────┘                │
│                            ▼                                    │
│              ┌──────────────────────────┐                       │
│              │   MCP Server (substrate) │  ← brain-agnostic     │
│              └─────────────┬────────────┘                       │
└────────────────────────────┼────────────────────────────────────┘
                             ▼
        ┌────────────────────────────────────────┐
        │   Kali Linux container (Docker)        │
        │   227 tools · scope-gated execution    │
        └────────────────────┬───────────────────┘
                             │
         ┌───────────────────┴───────────────────┐
         ▼                                       ▼
  ┌──────────────┐                        ┌──────────────┐
  │ Local SQLite │           OR           │ Team backend │
  │ (local mode) │                        │  (Postgres)  │
  └──────────────┘                        └──────────────┘
```

**Everything executes on the operator's machine.** The Kali container and every
scanner are local in both modes. The only thing that ever leaves your machine is
the orchestration prompts to your LLM provider.

**Dual brain.** The MCP server is the universal substrate — neither CLI knows
about the other, and the assessment infrastructure (scanners, container, findings
database, scope validation) is identical between them. Only the model making the
tool calls differs. Selected per assessment via the Claude or Codex terminal tab.

---

## The five attack surfaces

A run's scope determines which surfaces activate. Tests are gated by
`applies_when` in [`config/test-matrix.yml`](config/test-matrix.yml) — **234
tests** in the full matrix. Anything out of scope is accounted for explicitly in
an appendix rather than silently skipped.

| Surface | Activated by | Coverage |
|---|---|---|
| **Web / API / SAST** | always | Authorization boundaries, SQLi, XSS, SSTI, NoSQL, SSRF, cache poisoning, HTTP request smuggling, race conditions, session management, GraphQL (introspection, batching, aliasing, depth), REST fuzzing from OpenAPI, JWT attacks, IDOR, rate limiting, WebSockets, file upload, deserialization, static analysis, secrets, dependencies, IaC |
| **Cloud** | `cloud_accounts` in scope | AWS / Azure / GCP / Kubernetes enumeration, IAM privilege escalation, storage abuse, serverless exploitation, metadata endpoints |
| **Identity** | `identity_targets` in scope | Active Directory (Kerberoast, DCSync, ADCS, delegation), Entra ID, M365, Okta, Google Workspace, Ping — enumeration, lockout-aware spraying, OAuth consent, SAML |
| **AI / LLM** | `ai_targets` in scope | OWASP LLM Top 10 + MITRE ATLAS — prompt injection (direct and indirect), jailbreak, system-prompt extraction, sensitive disclosure, improper output handling, excessive agency, RAG isolation, MCP tool poisoning, model extraction |
| **Post-exploitation** | `post_exploitation` in scope **and** a foothold established | Pivot, loot, escalate — the cross-surface continuation once anything yields access |

---

## The agent team

A full-scope assessment runs up to **25 agents**: a team lead plus 24 specialized
workers. Each worker gets its own context window, which is the point — a single
context runs out partway through and late-phase tests get silently dropped.

Eleven workers are scope-conditional, so the count scales with what's in scope.
Web/API/SAST alone is 14 agents; all five surfaces is 25.

Phases run in parallel where independent and sequentially where they depend on
each other:

```
Phase 1     auth (interactive — the lead handles OTP; workers can't)
Phase 2a    recon-infra ‖ sast-scan ‖ cloud-recon ‖ identity-recon ‖ ai-recon
Phase 2b    sast-analysis
Phase 3     web-security ‖ api-graphql ‖ cloud-exploit ‖ identity-exploit ‖ ai-redteam
Phase 3.5   chain-analysis  (hypothesize)
Phase 4     crossval-qa
Phase 4.5   chain-analysis  (validate against exploit results)
Phase 4.6   post-exploit-operator  (per foothold)
Phase 4.7   verifier  (the oracle gate)
Phase 4.75  severity-calibrator
Phase 4.8+  cloud / identity / AI / post-exploitation companion reports
Phase 5     compliance → report-writer → report-enrichment → pdf-renderer
```

Authoritative list: [`config/team-assessment.yml`](config/team-assessment.yml).
Add a phase there and every future assessment picks it up.

---

## Why you can trust the output

These exist specifically because an LLM left unsupervised produces confident,
plausible, wrong findings.

**Oracle verification.** Every exploitable candidate is re-proven under one of
six deterministic oracles, each with a mandatory control. The LLM supplies the
experiment; the oracle returns the verdict. The model **structurally cannot
write `verified`** — enforced in three places, including a database CHECK
constraint.

**Tool provenance gate.** Before a report is finalized, every test is re-rated
against recorded tool execution. Any PASS or N/A whose backing tool was absent
from the container or never exited 0 is forced to **BLOCKED**. A silently missing
scanner cannot masquerade as clean coverage.

**Severity calibration.** Findings are re-rated against actual exploitation
outcome and reachability rather than intrinsic CVE severity, via deterministic
rules. Reports render both the original and the calibrated severity side by side.

**Attack graph.** An accumulating node/edge graph with a recursive-CTE pathfinder
and per-edge receipts, so a claimed escalation path is *traversable* rather than
asserted. (Team mode.)

**Scope enforcement.** Every tool call is validated against
[`config/scope.yml`](config/scope.yml) before execution, with an exclusion guard
that fails closed.

**SKIPPED is banned.** Every test in the matrix resolves to PASS, FAIL, N_A or
BLOCKED. There is no fifth state that means "we didn't get to it."

---

## Repository layout

| Path | What it is |
|---|---|
| `frontend/` | Tauri 2 + Next.js desktop app — the product |
| `frontend/src-tauri/` | Rust backend: Docker lifecycle, local SQLite, terminal, config |
| `mcp-server/` | TypeScript MCP server (STDIO + HTTP :3001) hosting the tool handlers |
| `backend-rs/` | Rust sync API for team mode — findings, assessments, attack graph |
| `crates/` | Shared Rust wire types |
| `deploy/terraform/` | Self-host deployment: `maestro-self-host` + 6 modules |
| `docker/` | Kali toolkit image definition |
| `config/` | Scope, test matrix, agent-to-test mapping, credentials |
| `docs/user-guide/` | In-app documentation (**compiled into the binary**) |
| `.claude/agents/` | The agent prompt corpus — *commercial* |
| `.claude/commands/` | Slash commands (`/assess`, `/assess-ai`, …) |
| `skills/` | Orchestration protocols and report standards — *commercial* |
| `tests-e2e-assessment/` | Deterministic $0 end-to-end harness vs Juice Shop + NodeGoat |
| `tests-e2e-desktop/` | WebdriverIO desktop suite |

> **Three directories are `include_dir!`-embedded into the Rust binary at compile
> time**: `.claude/commands/`, `.claude/agents/`, and `docs/user-guide/`. They are
> **hard build dependencies** — `include_dir!` on a missing directory is a compile
> error, not a graceful skip. This is also why the in-app docs work on a machine
> with no source repo and no internet.

---

## Configuration

| File | Purpose |
|---|---|
| [`config/scope.yml`](config/scope.yml) | **Allowed targets. Read before every run; nothing executes outside it.** |
| [`config/test-matrix.yml`](config/test-matrix.yml) | The 234-test matrix and its `applies_when` gates |
| [`config/team-assessment.yml`](config/team-assessment.yml) | Agent-to-test mapping and phase order |
| [`config/credentials.yml`](config/credentials.yml) | Auth for authenticated testing |
| [`config/assessment.yml`](config/assessment.yml) | Per-run mode, auth flow, reporting options |

Supported auth types: `session`, `basic`, `bearer`, `api_key`, `oauth2`,
`otp_email` (interactive — the run pauses and prompts), `none`.

Integrations: Jira (ticket creation), Cycode (SCA finding validation),
SharePoint (report storage), email (report distribution).

---

## Development

```bash
# MCP server
cd mcp-server && npm ci && npm run build && npm test

# Rust — Tauri backend
cd frontend/src-tauri && cargo test --bin Maestro

# Frontend
cd frontend && npm ci && npx tsc --noEmit && npx vitest run

# Terraform
cd deploy/terraform/maestro-self-host && terraform init -backend=false && terraform validate

# The open-core license boundary (CI enforces this)
./scripts/check-license-boundary.sh

# Secret scan of the working tree (CI enforces this)
gitleaks dir . --config .gitleaks.toml
```

CI ([`.github/workflows/test.yml`](.github/workflows/test.yml)) runs
`license-boundary`, `secret-scan`, `backend-rs`, `frontend` and `tauri`.

The secret scan deliberately covers the **working tree, not history** — reviewed
non-secrets live in [`.gitleaksignore`](.gitleaksignore), keyed
`file:rule:line` so a moved line comes back for re-review rather than staying
muted forever.

---

## Authorized use only

**Maestro performs real exploitation.** It sends live payloads, forges tokens,
escalates privileges, and reads data in order to prove impact. That is the point
of it, and it is why authorization is not optional.

**You must hold documented authorization for every target you assess.** No
license in this repository conveys permission to test systems you do not own or
are not contractually permitted to test. See [NOTICE](NOTICE).

Built-in guardrails — none of which substitute for authorization:

- **Scope validation** on every tool call, with fail-closed exclusions
- **Non-destructive by default** — DoS, deletion, and resource creation are
  refused and documented rather than executed. Read-only exploitation (IDOR data
  access, token forging, privilege-escalation probes) is expected and required.
- **Lockout mandate** — spray tooling reads the threshold first, stays under it,
  jitters, and aborts on the first lockout
- **Full audit logging** of every command
- **Multi-step exploit protocol** — exploits needing extra infrastructure (rogue
  servers, DNS redirection, MITM position) pause and ask before proceeding

---

## Licensing

Maestro is **open core**. The substrate is Apache-2.0; the assessment craft is
commercial.

### Apache-2.0 — the open core

Fork it, modify it, redistribute it, run it in production. No subscription
needed.

`mcp-server/` (227 tool handlers) · `docker/` · `backend-rs/` · `crates/` ·
`frontend/` · `config/` · `deploy/terraform/` · `docs/` · `tests-e2e-*/`

### Commercial — present, but separately licensed

These paths are **in this repository** because the application does not run
without them: the desktop mounts the agent definitions into its container at
runtime, and two of them are compiled into the binary. Their presence is a
technical necessity, not a license grant.

| Path | What it is |
|---|---|
| `.claude/agents/` | The 23-agent prompt corpus — exploitation mandate, per-surface methodology, evidence standards |
| `.claude/workflows/` | The three-chunk deterministic Workflow path |
| `skills/` | Orchestration protocols, coverage accounting, report standards |
| `mcp-server/src/verification/`, `mcp-server/src/tools/verification.ts` | The oracle verification layer |
| `frontend/lib/customer-registry.ts`, `frontend/app/api/discover/`, `frontend/app/api/license/` | Multi-tenant control plane — unused when self-hosting |

Using them requires an active Maestro subscription or written authorization.
Authoritative list: [COMMERCIAL-COMPONENTS](COMMERCIAL-COMPONENTS). Terms:
[LICENSE-COMMERCIAL](LICENSE-COMMERCIAL). Each listed directory carries its own
`LICENSE`, and CI enforces that via `scripts/check-license-boundary.sh`.

**Your Apache-2.0 rights to the open core are unconditional** and survive
termination of any commercial license. You are free to write your own agent
definitions and skill protocols to replace the commercial ones.

---

## Known limitations

**Anthropic's Cyber Verification Program.** Exploitation agents may refuse
mid-run on an unenrolled account. Enrollment is per-organization and does not
transfer with this software. This is a model-provider policy, not a licensing
restriction — and it is the one limitation with no workaround here, so it is
covered where you will act on it:
[Request Anthropic Cyber Verification](#request-anthropic-cyber-verification-before-your-first-run).

**Blind-vulnerability verification needs a listener.** The `oast` oracle proves
blind SSRF / SQLi / XXE / SSTI, where the target's out-of-band callback is the
only available evidence. Self-hosted deployments must run their own
(`oast_enabled = true`); otherwise the oracle honestly reports `oast_unavailable`
and blind findings stay unverified candidates rather than being guessed at.

**amd64 only.** The Kali image does not build natively on arm64 — Kali's systemd
segfaults under QEMU. Apple Silicon runs the amd64 image under emulation.

**Local mode has no auto-update.** Rebuild from source to upgrade. See
[SELF-HOSTING.md](SELF-HOSTING.md#updates).

Full detail: [SELF-HOSTING.md → Limitations](SELF-HOSTING.md#limitations).

---

## Documentation

The full user guide lives in [`docs/user-guide/`](docs/user-guide/) and is browsable
here without installing anything. It is the **same content compiled into the app**
(embedded at build time via `include_dir!`), so the in-app Docs page and these
files never drift apart.

### Getting started

| | |
|---|---|
| [Overview](docs/user-guide/getting-started/overview.md) | Start here |
| [Black-box pentest](docs/user-guide/getting-started/black-box-pentest.md) | Assessing a target you only have a URL for |
| [Code scan](docs/user-guide/getting-started/code-scan.md) | SAST, secrets and dependencies against a repo |
| [Cycode validation](docs/user-guide/getting-started/cycode-validation.md) | Validating imported SCA findings against a live app |

### Configuration

| | |
|---|---|
| [Overview](docs/user-guide/configuration/overview.md) | What is configurable and where |
| [Scope](docs/user-guide/configuration/scope.md) | **Defining authorized targets — read before your first run** |
| [Connect your LLM](docs/user-guide/configuration/connect-your-llm.md) | Subscription sign-in or API key |
| [Credentials](docs/user-guide/configuration/credentials.md) | Authenticated testing, OTP, test accounts |
| [Tools](docs/user-guide/configuration/tools.md) · [Integrations](docs/user-guide/configuration/integrations.md) · [Cache settings](docs/user-guide/configuration/cache-settings.md) | Tool tuning, Jira/SharePoint/email, caching |

### Working with the app

| | |
|---|---|
| [Projects and assessments](docs/user-guide/projects-and-assessments.md) | Organising work and running assessments |
| [Reports](docs/user-guide/reports.md) | Report structure, evidence standards, PDF output |
| [Code repos and imports](docs/user-guide/code-repos-and-imports/overview.md) | [repos](docs/user-guide/code-repos-and-imports/code-repos.md) · [imports](docs/user-guide/code-repos-and-imports/imports.md) |
| [Audit logs](docs/user-guide/audit-logs.md) | Every command that ran |
| [Users](docs/user-guide/users.md) | Roles and invites *(team mode)* |
| [Architecture](docs/user-guide/architecture.md) | How the pieces fit together |

### Attack surfaces

| Surface | Guides |
|---|---|
| **Cloud** | [Overview](docs/user-guide/cloud-accounts/overview.md) · [AWS](docs/user-guide/cloud-accounts/aws.md) · [Azure](docs/user-guide/cloud-accounts/azure.md) · [GCP](docs/user-guide/cloud-accounts/gcp.md) · [Kubernetes](docs/user-guide/cloud-accounts/kubernetes.md) · [Managed setup](docs/user-guide/cloud-accounts/managed-setup.md) |
| **Identity** | [Overview](docs/user-guide/identity-targets/overview.md) · [Active Directory](docs/user-guide/identity-targets/active-directory.md) · [Entra ID](docs/user-guide/identity-targets/entra-id.md) · [M365](docs/user-guide/identity-targets/m365.md) · [Okta](docs/user-guide/identity-targets/okta.md) · [Google Workspace](docs/user-guide/identity-targets/google-workspace.md) · [Ping](docs/user-guide/identity-targets/ping.md) |
| **AI / LLM** | [Overview](docs/user-guide/ai-targets/overview.md) · [Request shapes](docs/user-guide/ai-targets/request-shapes.md) |
| **Scheduled DAST** | [Overview](docs/user-guide/scheduled-dast/overview.md) · [Attack catalog](docs/user-guide/scheduled-dast/attack-catalog.md) *(team mode)* |

### Operating and deploying

| Document | Description |
|---|---|
| [SELF-HOSTING.md](SELF-HOSTING.md) | Local and team modes, end to end |
| [STEPS.md](STEPS.md) | Setup guide |
| [MODES-COMPARISON.md](MODES-COMPARISON.md) | Operating modes compared |
| [AUTONOMOUS-MODE.md](AUTONOMOUS-MODE.md) · [INTERACTIVE-MODE.md](INTERACTIVE-MODE.md) | Non-interactive vs interactive runs |
| [MULTI-APP-GUIDE.md](MULTI-APP-GUIDE.md) | Testing several applications |
| [CLOUD-ACCOUNTS.md](CLOUD-ACCOUNTS.md) | Cloud credential setup |
| [FRONTEND.md](FRONTEND.md) | Desktop app internals |
| [TESTING.md](TESTING.md) | Running the test suites |
| [CLAUDE.md](CLAUDE.md) | Orchestration instructions and safety rules the agents follow |

---

## Feedback, ideas and bugs

This is actively developed and feedback genuinely shapes it.

| I want to… | Go here |
|---|---|
| **Suggest a feature or share feedback** | [Discussions → Ideas](https://github.com/Shmalex405/maestro/discussions) |
| **Ask a question** | [Discussions → Q&A](https://github.com/Shmalex405/maestro/discussions) |
| **Report a bug** | [Open an issue](https://github.com/Shmalex405/maestro/issues/new/choose) |
| **Report a vulnerability in Maestro itself** | **Privately** to <security@groovysec.com> — see [SECURITY.md](SECURITY.md). Never a public issue. |
| **Ask about commercial licensing or support** | <support@groovysec.com> |

Full detail in [SUPPORT.md](SUPPORT.md). If you are thinking about contributing
code, read [CONTRIBUTING.md](CONTRIBUTING.md) first — some paths in this
repository are commercially licensed and cannot accept contributions.

## Commercial licensing and support

Self-hosted deployments are not covered by Groovy Security support. Open an issue
for bugs in the open core.

For the managed product — including the human-signed pentest attestation, Cyber
Verification Program enrollment, and a hosted OAST listener —
<support@groovysec.com>.
