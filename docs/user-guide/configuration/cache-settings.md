# Cache Settings

Cache Settings controls how aggressively Maestro reuses prior assessment results to speed up repeat runs of the same target.

> [!NOTE] At a glance
> - Find it at **Sidebar → Config → Cache Settings** (page title: **Cache settings**).
> - One master toggle plus five numeric knobs, organized into four cards.
> - Defaults are conservative and safe — most users never need to touch this page.
> - Changes only take effect after you press **Save changes**.

## Where this lives

Open the app, go to **Config** in the sidebar, then **Cache Settings**. The page header reads **Cache settings**, with a **Back** button to return to the previous screen.

A short summary line at the top explains the behavior: every Nth assessment forces a full re-validation, and any code change in a finding's file invalidates that finding's cache entry regardless of these settings.

These settings are per-org and load from your cloud backend. If the page can't load them, an error card appears at the top; while loading you'll see a **Loading…** spinner.

## What caching does

When you re-run an assessment against a target you've tested before, Maestro can reuse earlier results instead of re-scanning everything. That makes repeat runs faster and cheaper. The trade-off is freshness — cached results can lag behind reality, which is why the page includes revalidation cadence, TTLs, and a drift safety net.

> [!TIP]
> Leave the defaults in place unless you have a specific reason to change them. This is an advanced, optional page.

## Caching master switch

The first card, **Caching master switch**, holds a single toggle:

- **Cross-assessment caching enabled / disabled** — turn caching on or off entirely.

When disabled, every assessment runs as if no prior results existed. The card notes that the cost panel still computes counterfactual savings even while caching is off.

> [!WARNING]
> Turning the master switch off means every run is a full scan — slower and more expensive. Use it only when you need a guaranteed clean pass.

## Revalidation cadence

The **Revalidation cadence** card has two numeric fields:

- **Full re-validation interval (assessments)** — range 0–50. Every Nth assessment ignores the cache and re-tests every baseline finding, catching silent drift. Default: 4 (every 4th run is a clean pass). Set to 0 to disable forced revalidation; TTLs and per-severity rules still apply.
- **Baseline max age (days)** — range 1–365. Findings older than this are excluded from baseline reuse. Default: 30.

## Cache TTLs

The **Cache TTLs** card sets how long scanner outputs stay cached. After expiry, the next run does a full scan regardless of whether the cache key matches.

- **SAST cache TTL (days)** — range 1–180. Covers Semgrep / Bandit / gitleaks and similar. Default: 30.
- **Recon cache TTL (days)** — range 1–30. Covers nmap / subdomain / TLS scans. Default: 7 (recon ages faster).

## Drift detection

The **Drift detection** card holds the safety net. When a baseline-trusted finding fails to reproduce during a forced re-validation, that's a drift event. Too many within 30 days and an auto-disable circuit flips your org's caching off until a human reviews it.

- **Auto-disable threshold (alerts / 30 days)** — range 1–100. Default: 3.

Below the threshold field, a summary shows recent activity (when available):

- **Drift events (last 30 days)** — shown as a count against your threshold; if the threshold is breached it turns red and adds a "⚠ threshold breached" note.
- **Unacknowledged** — the count of drift alerts not yet acknowledged.

If no summary is available, the card shows "No drift summary available."

> [!IMPORTANT]
> A breached threshold means caching has been (or is about to be) auto-disabled for your org. Treat it as a signal that cached results stopped matching reality — review before re-enabling.

## Saving your changes

A sticky bar at the bottom of the page has two buttons:

1. **Cancel** — discards changes and returns to the previous screen.
2. **Save changes** — writes your updates. The button is disabled until you change something, and shows **Saved** once there are no pending edits. On success you'll see a "Cache settings saved" confirmation; on failure, a "Save failed" message with the error detail.

## Where to look next

- [Configuration overview](./overview.md)
- [Getting started](../getting-started/overview.md)
