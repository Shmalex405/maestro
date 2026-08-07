# Cycode & CSV Validation

Already have a Cycode dashboard or CSV export of vulnerabilities? Find out which entries are *actually* exploitable.

> [!NOTE] At a glance
> - **You provide:** a CSV from Cycode, Snyk, Wiz, or a manual checklist.
> - **Maestro runs:** a validation assessment that re-tests each entry against a live target.
> - **You get:** one of three verdicts per finding — **EXPLOITED**, **PARTIAL**, or **NOT EXPLOITABLE** — with real evidence.

## Steps

1. Go to **Import** → paste or upload the CSV.
2. Maestro parses the rows into **imported findings** (kept separate from native findings) and previews them.
3. Click **Validate** on any imported finding to spawn an assessment that re-tests it against a live target.
4. The result writes back to the finding with its verdict and the captured request/response evidence.

| Verdict | Meaning |
| --- | --- |
| **EXPLOITED** | Real evidence — HTTP request + response captured. |
| **PARTIAL** | Got partway, blocked by a control (WAF, RBAC, …). |
| **NOT EXPLOITABLE** | The code path exists, but the runtime app handles it safely. |

> [!TIP] Ground imports in source
> If the CSV references file paths (`routes/users.py:42`), link the import to a registered repo so validation can read the exact code. Details in [Code Repos and CSV Imports](../code-repos-and-imports/imports.md).

## Where to look next

- [Code Repos and CSV Imports](../code-repos-and-imports/overview.md) — full import + validation workflow.
- [Black-box Pentest](./black-box-pentest.md) — the live target your imports validate against.
