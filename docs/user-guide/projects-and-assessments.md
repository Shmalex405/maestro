# Projects and Assessments — Filing Structure

How to organize the work as your team scales from a handful of assessments to hundreds.

> [!NOTE] At a glance
> - **Two levels:** a **Project** is a long-running container; an **Assessment** is a single test run inside it.
> - **Assessments can stand alone** — no project required for one-off checks.
> - **Rule of thumb:** group projects by *engagement* (customer/product), name assessments by *date + scope*.

## The shape

```
Project (a customer engagement, a product, a quarter)
└── Assessments (the actual scans you ran)
    ├── Findings
    ├── Reports
    └── Imports (Cycode CSVs, manual imports)
```

- A **Project** is long-running — `Groovy Production`, `ACME Frontend`, `Internal Pentest 2026`. It groups related work.
- An **Assessment** is a single run — `Web app scan of api.acme.com 2026-04-30`. It's the thing that produces findings.

> [!TIP] One-offs don't need a project
> For "let me just check this URL real quick" work, create a standalone assessment. Filing it under a project is overkill.

## How to organize at scale

| Team size | Approach |
| --- | --- |
| ~5 assessments | Skip projects. Name assessments well; the dashboard sorts by date. |
| ~20+ assessments | Start using projects. Group by **engagement**, not by **time**. |
| ~100+ assessments | Projects are essential. Pick one of the two patterns below and stick to it. |

> [!IMPORTANT] Group by engagement, not by time
> Time you can always filter on. Engagement you can't easily reconstruct after the fact. Avoid projects like `Q1 2026 Engagements` — they go stale the moment the quarter ends.

### Pattern A — one project per customer engagement

Best for consultancies and red teams. Projects stay stable; assessments accumulate as the engagement progresses.

```
Groovy Production
├── 2026-04-30 Full assessment
├── 2026-04-15 Recon refresh
└── 2026-03-22 Cycode validation pass

ACME Backend
├── 2026-04-29 Web app scan
└── 2026-04-12 Code scan
```

### Pattern B — one project per product line

Best for in-house security teams with a stable set of products. Projects mirror your product taxonomy.

```
Maestro Desktop App
├── 2026-04-30 SAST + DAST cross-val
└── 2026-04-15 Quarterly health check

Cloud Backend
└── 2026-04-30 Auth flow audit
```

> [!WARNING] Don't mix patterns
> Pick A or B per team. Mixing customer-projects and product-projects in the same workspace gets confusing fast.

## Naming conventions

**Projects** — short, stable, no dates:

| ✓ Good | ✗ Avoid |
| --- | --- |
| `Groovy Production` | `Q1 2026 Engagements` |
| `ACME Backend` | `April work` |

**Assessments** — date prefix + scope. The date sorts naturally; the scope lets you scan the list:

| ✓ Good | ✗ Avoid |
| --- | --- |
| `2026-04-30 Web app scan — staging` | `Test 1` |
| `2026-04-30 SAST cross-val` | `Quick scan`, `Friday's run` |

## New project, or reuse an existing one?

**Create a new project when:**
- The work is for a different customer or product line.
- The authorization scope is different (different `scope.yml` entries).
- The deliverable goes to a different stakeholder.

**Reuse the existing project when:**
- Same customer, same scope, ongoing assessments.
- Re-running a baseline against a new build of the same target.
- Adding follow-up validation runs after remediation.

## Status, search, and filtering

Every assessment carries a status:

| Status | Meaning |
| --- | --- |
| `pending` | Created but not started |
| `running` | In progress |
| `completed` | Finished successfully |
| `paused` | Manually paused — can resume |
| `failed` | Terminated with an error |
| `cancelled` | Manually cancelled |

The Assessments page filters by status, type (full, web app, code scan, …), and project. Filter to `failed` after a busy day to see what needs re-running; filter to `running` to see what's in flight.

> [!NOTE] Search is name-only today
> Search matches assessment names (substring). Tag-based filtering is on the roadmap below.

## What lives where (data model)

| Entity | Created in | Stored in | Visible to teammates |
| --- | --- | --- | --- |
| Project | Desktop UI | Cloud DB | Yes |
| Assessment | Desktop UI or chat panel | Cloud DB | Yes |
| Finding | Cloud DB (via assessment run) | Cloud DB | Yes |
| Report | Generated from findings | Cloud DB | Yes |
| Import (Cycode/CSV) | Desktop UI | Cloud DB | Yes |
| Repository entry | Desktop UI | Cloud metadata + per-machine path | Metadata yes, path no |

> [!IMPORTANT] Live execution is private
> Bob doesn't see Alice's terminal output or the live tool calls of her in-progress assessment — only the persisted artifacts after they land in the cloud.

## Roadmap

Likely additions as customers ask for them:

- **Tags on assessments** — freeform labels (`production`, `urgent`, `pre-merge`) you can filter on.
- **Project archiving** — distinct from delete; hide a finished engagement from the default view but keep it searchable.
- **Saved filters / views** — "all critical findings in Groovy Production from the last 30 days, grouped by target."
- **Bulk operations** — re-run all paused assessments in a project, regenerate all reports.

Have a filing pain the above doesn't solve? File it — the schema is still flexible.
