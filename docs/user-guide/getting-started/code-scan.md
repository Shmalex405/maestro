# Code Scan

Run static analysis (SAST) on a repo — catch SQL injection, hardcoded secrets, vulnerable dependencies, and IaC issues before they ship.

> [!NOTE] At a glance
> - **You provide:** a local clone path to the repo.
> - **Maestro runs:** Semgrep, Bandit, njsscan, gitleaks, and dependency audits.
> - **You get:** code-level findings tagged with the repo, ready to cross-reference against a live target.

## Steps

1. Go to **Code Repos** → **Add Repository** → point to a local clone path (e.g. `/Users/you/work/myapp`).
2. Maestro detects the languages and registers the repo (metadata only — your path isn't shared with teammates).
3. Click **Scan** to run the SAST suite.
4. Findings appear under the repo entry and on the global **Findings** page, tagged with the repo.

> [!TIP] Prove it's real, not just present
> A SAST finding tells you a flaw exists in the *code*. To learn whether it's exploitable in the *deployed app*, run a Web App or Full assessment with the same repo selected — see [Code Repos and CSV Imports](../code-repos-and-imports/overview.md).

## Where to look next

- [Code Repos and CSV Imports](../code-repos-and-imports/overview.md) — the full SAST + cross-validation guide.
- [Black-box Pentest](./black-box-pentest.md) — test the deployed version of the same app.
