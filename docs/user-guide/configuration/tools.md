# Tools

Tune the parameters for Maestro's underlying security tools (Nmap, Nuclei, SQLMap, FFUF, Metasploit, Semgrep) and control how its AI agents behave during a workflow.

> [!NOTE] At a glance
> - Find it at **Sidebar → Config → Tools** (titled **Tools & Agents** in-app).
> - Settings are grouped into six tabs: **Recon**, **Vuln Scan**, **Web App**, **Exploit**, **Code Scan**, and **Agents**.
> - This is advanced and optional — the defaults are sensible, and most assessments never need changes here.
> - Edits aren't live until you click **Save Changes**; an **Unsaved changes** badge appears in the top-right while you have pending edits.

## When you'd touch this page

Leave these alone unless you have a specific reason. You'd come here to scan faster or slower (timing/rate limits), narrow which checks run (template and ruleset selection), or change how aggressively a tool probes a target (SQLMap risk level, Metasploit check mode). Each tab is independent, but the **Recon**, **Vuln Scan**, **Web App**, **Exploit**, and **Code Scan** tabs all save to the same tool configuration — clicking **Save Changes** on any one of them persists every tool tab at once. The **Agents** tab saves separately.

## Recon tab — Nmap

Port scanning and service detection settings:

1. **Default Port Range** — a text field. Enter a range like `1-1000` or a comma list like `22,80,443,8080`.
2. **Timing Template** — a slider from T1 to T5. A badge labels the current value (T1–T2 = *Slow/Stealthy*, T3 = *Normal*, T4 = *Aggressive*, T5 = *Insane*). The default is T4.
3. **Max Packet Rate** — a number field (packets/sec), defaulting to 1000.

> [!TIP]
> Lower the timing template (T1–T2) and packet rate on sensitive or rate-limited targets to stay quiet and avoid tripping defenses.

## Vuln Scan tab — Nuclei

1. **Active Templates** — a grid of clickable cards (CVEs, OWASP Top 10, Vulnerabilities, Misconfigurations, Exposures, Technologies, Default Logins, File Inclusion, Fuzzing). Click a card to toggle it on or off.
2. **Severity Filter** — a dropdown: *All Severities*, *Low and above*, *Medium and above*, *High and Critical only*, or *Critical only*.
3. **Rate Limit** (req/s), **Bulk Size**, and **Concurrency** — three number fields for scan performance.
4. **Custom Templates Path (optional)** — a text field for a path to your own Nuclei templates.

## Web App tab — SQLMap and FFUF

Two cards on this tab.

**SQLMap** (SQL injection testing):
- **Test Level** — a 1–5 slider (badge: *Basic* / *Medium* / *Thorough*). Higher levels test more injection points but take longer.
- **Risk Level** — a 1–3 slider (badge: *Safe* / *Moderate* / *Risky*). The badge turns red at risk 3.
- **Injection Techniques** — clickable badges for Boolean-based blind (B), Error-based (E), Union query-based (U), Stacked queries (S), Time-based blind (T), and Inline queries (Q). Click to add or remove each.
- **Threads** — a number field (1–10).

**FFUF** (directory/endpoint fuzzing):
- **Default Wordlist** — a path field (default `/opt/pentest/wordlists/common.txt`).
- **Request Rate** (req/s) and **Timeout** (seconds) — number fields.

> [!WARNING]
> Raising SQLMap's **Risk Level** to 3 enables payloads that may modify data on the target. Keep risk at 1–2 unless you fully understand the consequences and are authorized for the target.

## Exploit tab — Metasploit

- **Check Mode Only** — a toggle (on by default). When on, Maestro only verifies whether a vulnerability exists and does not exploit it.
- **Threads** — a number field (1–10).

> [!IMPORTANT]
> Turning **Check Mode Only** off enables real exploitation. The page surfaces a red warning when you do this: exploitation may cause service disruption or data modification on target systems. Only disable it for authorized testing.

## Code Scan tab — Semgrep

1. **Active Rule Sets** — clickable cards: Security Audit, OWASP Top 10, Secrets, SQL Injection, XSS, Command Injection, Insecure Transport. Click to toggle.
2. **Minimum Severity** — a dropdown: *Info and above*, *Warning and above*, or *Error only*.
3. **Scan Timeout** — a number field in seconds (default 300).

## Agents tab

Lists Maestro's AI agents — **Recon**, **Vuln Scan**, **Web App**, **Exploit**, **Security Scan**, and **Report** — each in its own row with a one-line description. For every agent:

- A **Switch** enables or disables the agent.
- When enabled, three controls appear: **Timeout (minutes)** (a number field, 5–120), an **Auto-start in workflow** checkbox, and a **Requires approval** checkbox.

The **Exploit** agent defaults to *Requires approval* on, so exploitation steps pause for your confirmation.

## Saving and resetting

Each tab has two buttons at the bottom right:

- **Save Changes** — persists your edits. A toast confirms success.
- **Reset to Defaults** — restores the built-in defaults for that group (tools or agents). This is a local reset; it leaves **unsaved changes** until you click **Save Changes**.

## Where to look next

- [Configuration overview](./overview.md) — the full Config section and what each page does.
- [Scope](./scope.md) — define which targets Maestro is allowed to test before tuning how it tests them.
- [Getting started](../getting-started/overview.md) — first-run setup and your first assessment.
