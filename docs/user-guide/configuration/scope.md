# Scope

Authorize the targets Maestro is allowed to test — domains, IP ranges, and exclusions.

> [!NOTE] At a glance
> - Open it from **Sidebar → Config → Scope**.
> - Add allowed targets under three tabs: **Networks** (CIDR ranges), **Domains** (domain patterns), and **Exclusions** (never-test list).
> - Use the **Test Scope Validation** box to check whether a target is in scope before you run an assessment.
> - Anything not explicitly authorized is refused — Maestro will not test it.

## Step 1 — Open the Scope page

In the sidebar, go to **Config**, then choose **Scope**. The page header reads **Scope Configuration** with the subtitle "Define allowed testing targets and exclusions." Use **Back to Configuration** (top-left) to return to the config landing page.

The page has two parts: a **Test Scope Validation** card at the top, and a tabbed editor below with **Networks**, **Domains**, and **Exclusions**. Each tab label shows a live count of entries, e.g. **Domains (3)**.

## Step 2 — Add an allowed domain

Open the **Domains** tab and click **Add Domain**. In the dialog, fill in:

- **Domain Pattern** — the hostname or wildcard you are authorized to test. The placeholder shows the accepted form: `*.staging.example.com`. You can enter a single host (`api-test.example.com`) or a wildcard pattern that covers subdomains (`*.staging.example.com`).
- **Environment** — pick **Development**, **Staging**, or **Production** from the dropdown. This is a label that records what kind of environment the target is.

Click **Add Domain** to save. The new pattern appears in the table with its environment badge. Each row has a trash icon to remove it.

> [!TIP]
> A wildcard like `*.staging.example.com` authorizes every subdomain under `staging.example.com`. Use a single hostname when you want to limit testing to exactly one address.

## Step 3 — Add an allowed network (CIDR range)

Open the **Networks** tab and click **Add Network**. In the dialog, fill in:

- **CIDR Range** — the IP range you are authorized to test, in CIDR notation. The placeholder shows the accepted form: `192.168.100.0/24`. Any IP that falls inside this range is treated as in scope.
- **Environment** — **Development**, **Staging**, or **Production**.
- **Notes (Optional)** — a free-text description, e.g. which system the range belongs to.

Click **Add Network** to save. The range appears in the table in monospace, with its environment badge and notes.

## Step 4 — Add an exclusion (never test)

Exclusions take priority over everything else — a target listed here is never tested, even if it also matches a domain or network you authorized. Use this to fence off production systems, shared infrastructure, or anything off-limits.

Open the **Exclusions** tab and click **Add Exclusion**. In the dialog, fill in:

- **Pattern** — the host or pattern to block. The placeholder shows `production.example.com`.
- **Reason** — why it's excluded (recommended, so the rest of your team understands the boundary).

Click **Add Exclusion** to save.

> [!IMPORTANT]
> Add an exclusion for any production or shared system that happens to sit inside a CIDR range or wildcard you authorized. The exclusion guarantees Maestro skips it.

## Step 5 — Test a target before you run

Before launching an assessment, paste an IP, domain, or URL into the **Test Scope Validation** box at the top of the page and click **Test**. Maestro evaluates it against your current scope and shows one of two results:

- A green banner: **Target is within scope**.
- A red banner: **Target is not in scope** (or a more specific reason).

This is the same check Maestro applies automatically when an assessment runs, so it's the fastest way to confirm a target is authorized before you start.

> [!WARNING]
> Out-of-scope targets are refused. If you point an assessment at something that isn't in your Networks or Domains — or that appears in Exclusions — Maestro will not test it. You'll see the validation fail rather than results coming back. If a target is genuinely authorized, add it to the correct tab first, then re-run the **Test** check to confirm it passes.

## What to expect

- Changes save immediately. After you add or remove an entry, a toast confirms **Scope configuration saved**.
- Removing an entry is instant — click the trash icon on its row.
- Empty tabs show "No networks configured" / "No domains configured" / "No exclusions configured" until you add your first entry.
- Scope is stored per organization in the Maestro cloud backend, so it follows you across machines signed in to the same account.

## Where to look next

- [Configuration overview](./overview.md) — the rest of the Config section.
- [Credentials](./credentials.md) — supply logins so Maestro can test authenticated targets.
- [Connect your LLM](./connect-your-llm.md) — choose the brain that drives your assessments.
- [Run a black-box pentest](../getting-started/black-box-pentest.md) — point an in-scope target at an assessment.
