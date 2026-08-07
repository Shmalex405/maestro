# Imports — CSV & Cycode

Bring in a vulnerability list from outside Maestro — a Cycode dashboard, a Snyk export, a Wiz CSV, or a manual checklist — then validate which entries are real.

> [!NOTE] At a glance
> - **Imported findings are separate** from native findings, so unverified data never pollutes your main Findings list.
> - **Validate against a live target** to get an EXPLOITED / PARTIAL / NOT EXPLOITABLE verdict with real evidence.
> - **Link to a repo** to ground a finding in a specific commit and file.

## Step 1 — Import the CSV

1. Sidebar → **Import** → paste or upload the CSV.
2. Maestro previews the parsed rows.
3. Confirm the column mapping (Cycode format auto-detects; map custom CSVs manually).
4. Click **Import** — rows become **imported findings**, kept separate from native findings.

> [!NOTE] Why imported findings are kept separate
> Imports often contain duplicates, false positives, or dependency vulns that aren't exploitable in your deployment. Keeping them in their own category lets you triage without polluting the main Findings list with unverified data.

## Step 2 — Validate against a live target

1. Click **Validate** on an imported finding (or select several → **Validate Selected**).
2. Pick the live target to test against.
3. Maestro spawns a validation assessment that:
   - Reads the source at the file/line the finding references.
   - Identifies the live endpoint that exercises that code path.
   - Crafts a real exploit attempt (SQL payload, IDOR enumeration, JWT forgery, …).
   - Captures the live request + response as evidence.
4. Each finding ends with one of three verdicts:

| Verdict | Meaning |
| --- | --- |
| **EXPLOITED** | Real evidence — HTTP request + response captured. |
| **PARTIAL** | Got partway, blocked by a control (WAF, RBAC, …). |
| **NOT EXPLOITABLE** | Code path exists, but the runtime app handles it safely. |

The verdict and evidence write back to the imported finding — no silent re-validation, the trail is auditable.

## Step 3 (optional) — Link an import to a repo

If the import lists vulnerabilities by file path (`routes/users.py:42 — SQL injection`) and you have the repo registered, link them: open the import → **Link to Repository** → pick the repo. Now the finding is grounded in a specific commit, you can grep the source, and validation can read the exact code.

## Where to look next

- [Code Repos](./code-repos.md) — register the source the imports reference.
- [Cross-referencing SAST findings to live targets](./overview.md) — the bigger SAST + DAST picture.
