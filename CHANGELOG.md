# Changelog

Maestro's source became public at **1.13.0**, so this repository's git history begins
there. Entries for earlier versions are reconstructed from the private development
history — those releases are real and shipped to customers, but you will not find
their commits here.

Version numbers are the desktop app's. The Kali toolkit image is tagged to match
(`ghcr.io/shmalex405/docker-kali:v<version>`) and the app resolves it **by tag**, so
the two always move together.

Releases are roughly monthly, with patch releases as needed.

---

## 1.13.0 — 2026-08-08

**Maestro is free, and the source is public.**

- **Open core.** Most of the repository is Apache-2.0. An enumerated set of paths —
  the agent prompt corpus, the orchestration skills, the oracle verification layer,
  and the multi-tenant control plane — remains commercially licensed and is listed in
  [`COMMERCIAL-COMPONENTS`](COMMERCIAL-COMPONENTS). They are present because the
  application does not run without them, not as a licence grant.
- **Local mode.** The free build defaults to running entirely on your machine:
  findings in a local database, no account, no licence key, no backend to provision.
  Bring your own Claude or ChatGPT account; credentials never leave the machine.
- **Team mode** stays available for anyone who wants several people looking at the
  same findings — the deployment terraform is in [`deploy/terraform/`](deploy/terraform/)
  and runs in your own AWS account. Five capabilities need it, and the app names which
  and why rather than showing empty screens: the attack-graph explorer,
  post-exploitation campaigns, scheduled scanning, user roles, and cross-assessment
  caching.
- Signed installers for macOS (Apple Silicon), Windows x64 and Linux x64.

## 1.12.0 — 2026-08-06

**The oracle verification layer** — the release this project's central claim rests on.

- Every finding marked exploitable is re-proven under one of six deterministic
  oracles, each with a mandatory control. The agent supplies the experiment; the
  oracle returns the verdict.
- The model **structurally cannot** write `verified`. That separation is enforced in
  three places, including a database CHECK constraint — it is not a prompt asking the
  model to behave.
- Proven against a live OWASP Juice Shop instance in the end-to-end harness.
- Retired the Groovy-metered credential tier in preparation for the open-core
  release. Credential modes are now OAuth or your own API key.

## 1.11.0 — 2026-07-30

- Graph analytics over the attack-path substrate.
- GCP privilege-escalation coverage alongside the existing AWS and Azure paths.
- Live per-test verdicts in the assessment view, sourced from checkpoints rather than
  inferred from event streams.

## 1.10.0 – 1.10.3 — 2026-06-29 → 2026-07-14

- **Post-exploitation layer.** A plan → execute → deposit → re-plan loop that runs
  from a confirmed foothold, pivoting and escalating across surfaces. It fires only
  when a foothold was actually established, so a campaign starts from proven access
  rather than assumption, and produces its own report with per-edge receipts.
- **Live assessment view** — a structured real-time projection of a running
  assessment over the raw agent terminal.
- Attack-graph explorer visual pass: severity-heat, exploited-path and
  reachable-from-internet lenses.

## 1.9.0 – 1.9.1 — 2026-06-25 → 2026-06-29

- **Attack-graph substrate.** An accumulating node/edge graph with a recursive-CTE
  pathfinder, so multi-step paths are queried rather than narrated.
- Every DAST scan records which attacks were actually executed, not just which were
  planned.

## 1.8.0 — 2026-06-20

- Authenticated and unauthenticated scans per target, with application-level fan-out
  so one application's endpoints are assessed together.

## 1.7.0 — 2026-06-16

- **Non-destructive guarantee** for scheduled DAST, enforced at the execution
  boundary rather than by convention.
- JSON login support for API-first applications.

## 1.6.0 — 2026-06-11

- Assessment completion lifecycle, including an explicit `incomplete` state so a run
  that died is distinguishable from one that finished clean.
- Scheduled DAST runner on an always-on cloud task.

## 1.5.0 — 2026-06-05

- Scheduled DAST: recurring scans, drift detection, alerts on new findings.

## Earlier

The surfaces arrived in this order, each adding its own agents, tests and companion
report:

| Surface | Since | What it covers |
|---|---|---|
| Web + API + SAST | 0.x | OWASP Top 10, injection, authz, GraphQL, REST fuzzing, secrets, dependencies, IaC |
| Cloud | 1.0.x | AWS / Azure / GCP / Kubernetes — IAM privesc, storage abuse, container escape |
| Identity | 1.0.70 | Active Directory, Entra ID, M365, Okta, Google Workspace, Ping — lockout-governed |
| AI / LLM | 1.4.0 | OWASP LLM Top 10 and MITRE ATLAS — prompt injection, excessive agency, RAG isolation |

Two mechanisms that shaped everything after them are worth calling out, because they
exist to stop the tool flattering itself:

- **Tool-provenance gate** — a passing test whose backing tool was absent from the
  container or never exited 0 is forced to BLOCKED. A silently missing scanner cannot
  masquerade as clean coverage.
- **Exploitation-calibrated severity** — severity is re-rated from what actually
  happened during exploitation, not copied from a CVE record.
