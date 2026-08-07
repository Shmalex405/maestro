# Reports

Generate, view, and download the PDF report for an assessment.

> [!NOTE] At a glance
> - Open the page from **Sidebar → Reports** (header reads **Security Reports**).
> - Reports are produced automatically when an assessment finishes — there is no manual "render" button.
> - Each row expands inline: Markdown renders in-app; **PDF** shows an embedded preview with a **Download PDF** button.
> - Search by title and filter by **All / Markdown / PDF**; cloud-assessment reports show a **Cloud** chip.

## Step 1 — Open the Reports page

In the left sidebar, click **Reports**. The page header reads **Security Reports** with the subtitle "View and download assessment reports".

Across the top are four summary cards:

- **Total Reports** — overall count, broken down as "N Markdown, N PDF".
- **Critical** — total Critical findings across all reports.
- **High** — total High findings across all reports.
- **File Reports** — count sourced from the `reports/` directory.

> [!TIP] An empty page is normal before your first run. When no reports exist you'll see "No Reports Yet" with the note "Reports are generated after assessments complete" and a **Start Assessment** button.

## Step 2 — Generate a report from an assessment

Reports are created as the final step of an assessment — you don't build them by hand on this page. To start one, click the **Generate Report** button (top-right of the Reports header) or the **Start Assessment** button on the empty state. Both link to the **Assessments** page, where you launch the run.

When the assessment completes, its report appears automatically in the Reports list. See [./projects-and-assessments.md](./projects-and-assessments.md) for how to configure and run an assessment.

> [!IMPORTANT] If you see a row labelled "Report unavailable" that says the report "pre-dates cloud artifact storage", the PDF bytes were never uploaded for that older row. Re-run the assessment to produce a fresh, cloud-backed copy.

## Step 3 — Find the report you want

Use the controls above the list:

- **Search reports…** — filters the list by title as you type.
- **All / Markdown / PDF** buttons — filter by format. Markdown rows show an **MD** badge; PDF rows show a **PDF** badge.

Each report card shows its title, the date, the source (**Database** or **File**), and — when available — colored finding badges (e.g. `2 C`, `5 H`, `3 M`, `1 L` for Critical / High / Medium / Low). Cloud-related reports also display a **Cloud** chip.

## Step 4 — View a report

Click anywhere on a report card to expand it (the chevron flips from down to up).

- **Markdown reports** render in-app with full formatting — headings, tables, code blocks, links, and (for cloud assessments) a CIS coverage card at the top.
- **PDF reports** show an embedded preview pane inside the card.

Click the card again to collapse it.

## Step 5 — Download the PDF

Expand a **PDF** report. At the top-right of the preview pane, click **Download PDF**. The file is saved to disk and a confirmation toast shows the saved path (e.g. "Saved to …").

> [!WARNING] The PDF preview and download fetch the file from cloud storage using a temporary link (about a 15-minute window). If the preview shows "Failed to load preview", collapse and re-expand the card to request a fresh link.

## What a report contains

Assessment reports follow a consistent structure, including:

- An **executive summary** with finding counts by severity (Critical / High / Medium / Low).
- Per-finding detail: description, evidence, affected component, and remediation guidance.
- An **exploitation summary** and a **coverage checklist** of the tests that ran.
- For cloud assessments, a **CIS coverage** breakdown surfaced as a card at the top of the in-app view.

## Where to look next

- [./projects-and-assessments.md](./projects-and-assessments.md) — run an assessment to generate a report.
- [./getting-started/overview.md](./getting-started/overview.md) — how the app fits together.
- [./configuration/integrations.md](./configuration/integrations.md) — connect Jira/email to route findings out of the report.
