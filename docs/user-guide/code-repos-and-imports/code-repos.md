# Code Repos

Register a local repo once, then scan it for code-level vulnerabilities — SQL injection, hardcoded secrets, vulnerable dependencies, IaC issues.

> [!NOTE] At a glance
> - **Register once, scan many times** — a repo entry is stable; assessments against it are point-in-time.
> - **Runs the full SAST suite** — Semgrep, Bandit, njsscan, gitleaks, and dependency audits.
> - **Paths are per-machine** — teammates share the entry, not your local clone path.

## Step 1 — Add a repo

1. Sidebar → **Code Repos** → **Add Repository**.
2. Click **Browse** and pick the local clone path (e.g. `/Users/you/work/myapp`).
3. Maestro detects the languages (TypeScript, Python, Go, …) and registers the repo with your org's cloud.

> [!IMPORTANT] The path is per-machine
> Teammates see the same repo entry (name + description), but **not your path**. Each person re-links the entry to their own local clone. Register once; everyone maps it locally.

## Step 2 — Scan it

| Option | How | When |
| --- | --- | --- |
| **A. Click Scan** | On the repo entry. Runs the full SAST suite. | Quick, standalone code audit. |
| **B. Include in an assessment** | New Assessment → type **Full** or **Code Scan** → pick the repo. | When you also want cross-validation against a live target. |

Findings appear under the repo entry and on the global **Findings** page.

## What the SAST tools catch

| Tool | Catches |
| --- | --- |
| **Semgrep** | SQL injection, command injection, missing auth checks, unsafe deserialization |
| **Bandit** | Python: hardcoded passwords, `eval()`, unsafe `yaml.load`, weak crypto |
| **njsscan** | Node/JS: unsafe regex, prototype pollution, weak JWT handling |
| **Gitleaks / detect-secrets** | Hardcoded credentials in code **and** git history |
| **Trivy / npm audit / pip-audit** | Vulnerable dependencies with known CVEs |
| **Checkov** | Infrastructure-as-Code (Terraform, CloudFormation, K8s manifests) |

> [!TIP] Every scan is auditable
> The full tool list and rule sets live in `mcp-server/src/tools/code-scanning.ts`, and each run logs the exact tool versions and rules it executed.

## Repo entries vs. assessments

A **repository entry** is stable — "this is a thing we scan periodically." An **assessment** is point-in-time — "I scanned this repo on April 30 and got these results." Register the repo once; run many assessments against it over time.

## Where to look next

- [Imports — CSV & Cycode](./imports.md) — bring in external vuln lists.
- [Cross-referencing SAST findings to live targets](./overview.md) — prove which code flaws are exploitable.
