# Overview

Maestro is your team's automated security assessment platform — run pentests, code scans, and Cycode-style validations from your laptop, and everything you produce lands in your org's shared cloud.

> [!NOTE] At a glance
> - **Where work happens:** a Kali Linux container on *your* machine runs every scan.
> - **Where results live:** your org's cloud — so teammates see the same findings, assessments, and reports.
> - **What you'll do first:** sign in, wait for the one-time toolkit download, then run an assessment.
> - **Time to first scan:** ~5–15 min on first launch (toolkit download), seconds after that.

## Before you start

You'll need three things:

1. **Your work email** — Maestro uses it to find your org's backend automatically. No server URL to type.
2. **Docker Desktop installed and running** — Maestro spins up its Kali container through Docker.
3. **A target you're authorized to test** — a URL, an IP range, or a local repo path.

> [!IMPORTANT] Maestro is a thin client over your org's cloud
> When you sign in, the app shows everything your org has produced — including assessments your teammates ran. When you sign out, it shows nothing. There is no local-only mode.

## Step 1 — Sign in

1. Launch Maestro. On first run it asks for your **work email**.
2. The discovery flow looks up your org's per-org backend from your email domain and walks you through Cognito sign-in.
3. Once you're in, the dashboard loads your org's existing assessments, findings, and reports.

## Step 2 — Wait for the toolkit (first launch only)

The first launch downloads a **~6 GB Kali toolkit image** — the thing that runs nmap, nuclei, sqlmap, semgrep, and the rest.

- On broadband this takes **5–15 minutes**, once per machine.
- Every launch after that starts in seconds.

> [!TIP] Watch progress in the corner
> The **System Status** indicator (bottom-left) shows the container and MCP server coming online. When it reads *All Systems Operational*, you're ready.

## Step 3 — Connect your assessment brain

Assessments are driven by an AI "brain" — **Claude** or **Codex** — running inside the container. You authenticate it once before anything will run.

1. Sidebar → **Config → Claude** (or **Config → Codex**).
2. Pick a credential mode — sign in via browser, paste an **API key**, or use **Bundled** (Groovy-managed) — and connect.
3. The status rows turn green when it's ready.

> [!IMPORTANT] No brain, nothing runs
> If you skip this, an assessment will start but have nothing to drive the tools. Full walkthrough: [Connect your LLM](../configuration/connect-your-llm.md).

## Step 4 — Authorize your target (Scope)

For any live target (a URL or IP), add it to **Config → Scope** first — Maestro refuses to test anything outside your authorized scope. (Skip this for local code scans.) See [Scope](../configuration/scope.md).

## Step 5 — Run your first assessment

1. Click **New Assessment** on the dashboard.
2. Pick a **target** — a URL, an IP, or a repo path.
3. Pick **what to test** — recon, full assessment, code scan, Cycode validation, or a single test class.
4. Give it a **name** and click start.

Findings stream into the **Findings** page as they're discovered. When the run finishes, generate a report — see [Reports](../reports.md).

## What's local vs. what's cloud

| Lives on your machine | Lives in your org's cloud |
| --- | --- |
| Kali Docker container & tool execution | Assessments, findings, reports |
| Live terminal sessions / tmux state | Projects |
| Slash command + agent definitions | Repository entries (metadata only — paths are per-machine) |
| Per-user secrets (Cognito tokens) | Imports (Cycode, CSV) |
| Local repo clone paths | Audit logs |

## Three ways teams use Maestro

Pick the workflow that matches where your work starts — each has its own page:

| Workflow | Best for | Page |
| --- | --- | --- |
| **Black-box pentest** | A deployed app, an internal IP range, an external attack surface | [Black-box Pentest](./black-box-pentest.md) |
| **Code scan (SAST)** | Validating a codebase before deploy; auditing for secrets | [Code Scan](./code-scan.md) |
| **Cycode / CSV validation** | Proving which entries in an existing vuln list are exploitable | [Cycode & CSV Validation](./cycode-validation.md) |

> [!TIP] The power move — combine code scan + pentest
> Run a code scan *and* point an assessment at the deployed app with the same repo selected. Maestro's cross-validation phase proves whether a code flaw is actually exploitable in production. Full walkthrough in [Code Repos and CSV Imports](../code-repos-and-imports/overview.md).

## Where to look next

| If you want to… | Go to |
| --- | --- |
| Finish first-time setup (LLM, scope, credentials) | [Configuration](../configuration/overview.md) |
| Generate and download a PDF report | [Reports](../reports.md) |
| Organize 100s of assessments | [Projects and Assessments](../projects-and-assessments.md) |
| Connect a cloud account (AWS/Azure/GCP/K8s) | [Cloud Accounts](../cloud-accounts/overview.md) |
| Bring in source code or a vuln CSV | [Code Repos and CSV Imports](../code-repos-and-imports/overview.md) |
| Understand what runs where | [Architecture](../architecture.md) |
| See every slash command and agent | the in-app **Help** page |
