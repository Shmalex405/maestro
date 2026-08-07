# Audit Logs

The Audit Logs page is a searchable, paginated record of who did what, to what, and when across your Maestro workspace.

> [!NOTE] At a glance
> - Find it in the **Sidebar → Audit Logs**.
> - Every row shows **When**, **Action**, **Resource**, **User**, and **Details**.
> - Filter by action, resource type, or a specific resource; expand any row for the full detail.
> - Destructive actions (deletes, role changes) are highlighted in red.

## What the page records

Each entry captures a single tracked event. The table has five columns plus an expand control:

- **When** — relative time (for example `5m ago`, `2h ago`, `3d ago`). Hover the cell to see the exact local date and time.
- **Action** — the operation, shown as a monospace badge such as `assessment.create`, `finding.delete`, or a tool name. Destructive actions render as a red badge.
- **Resource** — the affected object, shown as `type: id` (for example `assessment: 8f3c1a2b...`).
- **User** — the email or identifier of whoever performed the action, or `system` for automated events.
- **Details** — a short preview of the event payload (a few `key: value` pairs).

Tracked resource types include **assessment**, **finding**, **project**, **repository**, **user**, and **integration**. This gives you traceability for security-sensitive changes — useful for incident review and for demonstrating accountability during a compliance audit.

## Filter and search

The **Filters** card sits above the table. All three controls are searchable dropdowns:

1. **All Actions** — pick a specific action (or tool) to narrow the list. Type in the search box to find one quickly.
2. **All Resources** — restrict to one resource type (assessment, finding, project, repository, user, integration).
3. **Any specific resource** — choose a single resource by ID, name, or email. The choices are drawn from the entries on the current page, and they narrow further once you pick a resource type.

When any filter is active, a **Clear Filters** button appears to reset everything.

> [!TIP]
> The "Hide background updates" switch in the top-right is **on** by default. It suppresses routine progress and status churn (like assessment progress ticks) so you see deliberate actions. Turn it off if you need the full, unfiltered stream.

## Reading and expanding entries

Click any row to expand it. The expanded panel shows the complete `details` payload as formatted JSON — the full record behind the preview.

Maestro also rolls up repeated activity: consecutive same-action, same-resource, same-user `.update` events within a short window collapse into one row with a `×N` badge showing how many were combined. This keeps the log readable without losing the count.

> [!IMPORTANT]
> The page shows logs that already exist; it does not let you edit or delete them. Use **Refresh** (top-right) to pull the latest entries after recent activity.

## Pagination

The list loads 50 entries per page. When there are more, a footer shows the range and total (for example "Showing 1 to 50 of 220 logs") along with **Previous** / **Next** buttons. If background updates are hidden, the footer also notes how many entries were hidden on the current page.

> [!WARNING]
> This page has no built-in export or download button. To preserve audit evidence for an external review, capture it from the table view (for example by expanding the relevant rows) while it is open.

## Where to look next

- [Configuration overview](./configuration/overview.md) — manage projects, repositories, and integrations whose changes appear here.
- [Getting started](./getting-started/overview.md) — orient yourself in the app before reviewing its activity trail.
