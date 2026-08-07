# Overview

How to bring source code and external vulnerability lists into Maestro — and cross-reference them against live targets.

> [!NOTE] At a glance
> - **[Code Repos](./code-repos.md)** — register a local repo, then run SAST (Semgrep, Bandit, njsscan, gitleaks, dependency audits) on it.
> - **[Imports](./imports.md)** — pull in a Cycode/Snyk/Wiz CSV as "imported findings", then validate which are actually exploitable.
> - **The payoff (below)** — link code findings to a live assessment so Maestro proves whether a flaw is reachable in production.

## The power move — cross-referencing SAST findings to live assessments

This is where Maestro beats running SAST and DAST as two disconnected tools.

```
Code Scan (SAST)              Web App Assessment (DAST)
└── routes/users.py:42        └── https://api.example.com
    SQL injection in `id`         /users?id=...
    parameter
                ↓                          ↓
              ╔═══════════════════════════════╗
              ║ Cross-validation phase        ║
              ║ (Maestro ties them together)  ║
              ╚═══════════════════════════════╝
                              ↓
              FINDING: confirmed exploitable
              + real HTTP request/response
              + source code snippet
              + remediation diff
```

### How to set it up

1. Register the repo (**Code Repos → Add Repository** — see [Code Repos](./code-repos.md)).
2. Run a **Code Scan** to populate SAST findings.
3. Create a **Full** or **Web App** assessment:
   - **Target:** the deployed URL.
   - **Repo:** select it from the dropdown.
4. Maestro runs DAST and SAST in parallel, then a cross-validation phase tries each SAST finding against the live target.
5. Findings sort into three buckets:

| Bucket | Meaning |
| --- | --- |
| **DAST-only** | Found by web app testing; no code reference. |
| **SAST-only** | Found in code; not exploitable in the deployed version. |
| **Cross-validated** | Found in code **and** confirmed exploitable live — fix these first. |

### What it catches that single-tool scans miss

- **False-positive SAST findings** — code that looks vulnerable in isolation but is protected by middleware/auth in production. Maestro runs the real attack and finds out.
- **Real exploits a deps audit can't see** — the dependency is patched, but the wrapper code calling it has the bug.
- **Auth bypasses DAST can't fuzz to** — SAST sees the missing check; cross-validation forges a token to prove it's reachable.

> [!TIP] Remediation includes the fix
> The remediation report ships the source reference — commit + file + line + diff — so the dev team has everything it needs to fix the issue.

## Where to look next

- [Code Repos](./code-repos.md) — register and scan source code.
- [Imports — CSV & Cycode](./imports.md) — bring in and validate external vuln lists.
- [Getting Started](../getting-started/overview.md) — if you're new to Maestro.
