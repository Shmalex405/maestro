# End-to-End Assessment Harness

Proves — without the frontend, without the LLM, and at **$0 token cost** — that a
full assessment runs end-to-end and does its job, against **known-vulnerable
targets** where we already know the right answer:

- **OWASP Juice Shop** (web) — the DAST target, scanned **authenticated**.
- **OWASP NodeGoat** (repo) — the SAST target.

The engine is the deterministic sequential pipeline (`run_orchestrator` mode
`sequential`), which drives the **real** Kali scanners (nmap/nuclei/sqlmap/semgrep/…)
by calling tool handlers directly — repeatable and free. The harness syncs the
**working-tree** MCP `dist` into the container, so it tests *this* version, not the
image's baked-in code.

## Run it

```bash
./tests-e2e-assessment/run.sh
```

Requires Docker. It stands up Juice Shop + Kali, provisions two test users,
runs the assessment, asserts, runs the negative-gate proof, and tears everything
down. Exit 0 = proven.

Pin the images for full determinism (defaults track `latest`):

```bash
KALI_IMAGE=ghcr.io/shmalex405/docker-kali:vX.Y.Z \
JUICE_SHOP_IMAGE=bkimminich/juice-shop:vX.Y.Z \
NODEGOAT_COMMIT=<sha> \
./tests-e2e-assessment/run.sh
```

## What each assertion proves (`assert.mjs`)

1. **Coverage completeness** — every test produced a status; **no SKIPPED test
   outside `coverage-spec.json → skipped_ok`** (the genuinely interactive/out-of-band
   ones). A silently-missing handler or test can't hide.
2. **The authenticated path works** — the tests in `must_run_authed`
   (AUTH-02/07, AUTHZ-01/02/03/04) actually executed (not SKIPPED). This is the
   proof that passing a bearer token unlocks the authorization/IDOR/session depth.
   See "Auth model" below.
3. **It found real vulnerabilities** — minimum finding floors (≥1 from a DAST
   scanner, ≥1 from a SAST scanner) plus a `expectations.json` must-find checklist
   (`required:true` entries hard-fail on a miss).
4. **Provenance integrity** — `check_tool_provenance` ran and `0` tests were
   blocked by an absent tool (the full image has them all).
5. **The verdict gate earns AND refuses** — `oracles.mjs` drives `create_finding`
   + `verify_finding` over the real MCP path against live Juice Shop. Three real
   vulnerabilities (cross-user BOLA, SQLi auth bypass, stored payload) must earn a
   verdict; three attempts to obtain one dishonestly must be refused:
   a public endpoint filed as an authorization failure (`mechanism_mismatch`), a
   pattern that also matches the benign control (`pattern_not_discriminating`),
   and an agent choosing its own marker instead of the harness-minted one
   (`placeholder_missing`). Plus the invariant itself: an agent asserting
   `verdict: verified` on `create_finding` gets it stripped and reported back.

   **Both halves are asserted on purpose.** A gate that only ever confirms is not
   a check, and the failure it exists to prevent — an unproven claim reaching a
   customer under a human signature — is invisible unless the refusals are tested.
6. **The provenance gate works live (negative proof)** — a second run with **nuclei
   removed**: every nuclei-backed test is forced `BLOCKED`. A silently-absent
   scanner can no longer pass as clean.

Correlation is **not** asserted here — it needs the cloud backend + promotion and
is covered by `backend-rs/tests/correlation.rs`. This harness owns the
matrix + auth + gate + ground-truth proof.

## Auth model (and its honest boundary)

Juice Shop has plain username/password registration that returns a JWT, so
`provision-creds.mjs` mints two test users with zero human interaction. User A's
token is passed as `options.auth = {type:"bearer", token}` and user B's via
`options.harness.second_user_jwt` (for the cross-user IDOR, AUTHZ-02).

The deterministic pipeline was upgraded so the auth-gated tests run when a token
is present (`sequential-pipeline.ts` `runAuth`/`runAuthz`): AUTH-02 (JWT analysis),
AUTH-07 (token replay), AUTHZ-01 (authenticated IDOR), AUTHZ-02 (cross-user),
AUTHZ-03 (vertical privesc), AUTHZ-04 (function-level). With no token they fall
back to SKIPPED, as before.

**Boundary:** this proves everything reachable with a **bearer token / cookie**
(authorization, IDOR, session, token replay) plus the unauth surface — but NOT
flows that need interactive OTP/SSO or a real browser (AUTH-01/03/05, BIZ-03,
CLI-06) or an out-of-band collaborator (SSRF-03). Those stay in `skipped_ok`.
`API-05`/`API-06` are still hardcoded-skip in the pipeline — flagged there as the
next auth-upgrade candidates.

## Files

| File | Role |
|---|---|
| `run.sh` | Driver — build, stand up, provision, run, assert, verdict-gate, negative-gate, teardown. |
| `docker-compose.yml` | Juice Shop + Kali topology. |
| `scope.yml` | In-scope allowlist for the harness targets (test fixture only). |
| `provision-creds.mjs` | Registers + logs in two Juice Shop users → JWTs, user ids, basket ids. |
| `oracles.mjs` | Drives the verdict gate: creates candidate findings, verifies them through `/tools/call`. |
| `assert.mjs` | The assertions (run / oracles / negative / llm modes). |
| `coverage-spec.json` | `skipped_ok` + `must_run_authed` + `min_total_with_status`. |
| `expectations.json` | Ground-truth must-find checklist (tiered required/informational). |

## Calibration note

The `expectations.json` must-find list is intentionally **conservative** so the
harness is reliable on its first run. After a real run confirms a finding is
produced consistently, flip its `required:false → true` to tighten the gate. The
harness self-checks for teeth: break a `required` expectation and the run must
**fail** (it's not vacuously green).
