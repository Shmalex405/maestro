# Overview

Scheduled DAST runs the **deterministic** scanning pipeline — nuclei, nikto, sqlmap, plus Maestro's own web/API tests — against your in-scope targets on a recurring cadence or on demand. It is the continuous, no-LLM tier: cheap, repeatable, and safe to leave running on a schedule.

> [!NOTE] At a glance
> - **What it is:** the same scanner fleet a full assessment uses, driven by a deterministic pipeline (no LLM in the loop) so every run is repeatable and inexpensive.
> - **Non-destructive by design:** only GET/HEAD/OPTIONS are fuzzed, sqlmap is risk-capped, and write methods are discovered but never fired. Safe to schedule against production.
> - **You pick the breadth** via a **scan policy** — a named subset of attacks (e.g. *Full web/API*, *Injection focus*).
> - **Results land in Scans** with a full per-scan **Statistics** view: severity breakdown, duration, and the real number of attacks executed.

## Run or schedule a scan

- **Run now:** *Run DAST scan* → pick a target (or a whole application) → pick a scan policy → run. The result appears under **Scans** as it executes.
- **Schedule:** *Schedule a target* → pick target/application, a cadence, and a policy. The scheduler fires the run for you and records each result.

Both honor the target's saved **auth** (authed or anonymous) and **scope**.

## Scan policies — choosing what runs

A **scan policy** is a reusable subset of the attack catalog. Five built-in presets cover the common cases:

| Policy | What it runs |
|---|---|
| **Full assessment** | Every in-scope attack (no filter). |
| **Full web/API (DAST)** | All web/API attacks — recon, TLS, auth, injection, SSRF, GraphQL, API, headers, CORS, upload, business-logic, protocol. |
| **Quick recon + headers** | Fast surface sweep — recon + security headers + TLS. |
| **Injection focus** | SQLi, XSS, command injection, SSTI, SSRF. |
| **API & GraphQL** | Schema fuzzing, GraphQL introspection/abuse, JWT, IDOR, rate-limiting. |

Pick the policy in the *Run* or *Schedule* dialog. Leaving it on **Full assessment** runs everything applicable to the target.

## How many attacks does a scan actually run?

The engine knows **234 attack techniques** (see the [Attack catalog](./attack-catalog.md) for the full list). That count is the *menu*, not the *bill*: each technique fans out at run time into many real requests as its backing tool sweeps every discovered parameter and payload.

> [!TIP] The number that matters
> A typical web-app scan fires **~5,500 HTTP requests** (range ≈ 4,000–7,600, scaling with how many parameters the crawl discovers). nuclei alone runs ~1,600 templates, nikto ~2,500 checks, sqlmap ~100 payloads per injectable parameter. Open a completed scan's **Statistics** view to see the exact **attacks executed** total and the per-tool breakdown for that run.

This is the apples-to-apples figure to compare against other DAST tools that report "N attacks per scan" — those, too, are requests-executed-against-one-app, which scale with the target's surface.

## Where results go

- **Scans** — every run, newest first. Click a row for its **Statistics** view (attacks executed, per-tool breakdown, severity donut, duration, findings).
- **Vulnerabilities** — the dedupe'd, triageable finding queue across all scans.
- **Reports** — generated scan reports.
