# backend-rs Test Layout

This directory houses the cloud-API integration suite. Every file runs
against a freshly-provisioned Postgres database (per-test ephemeral DB via
`common::TestApp` — see `common/mod.rs`).

## Running

```bash
docker run -d --rm --name maestro-test-pg \
  -e POSTGRES_USER=postgres -e POSTGRES_PASSWORD=postgres \
  -p 5433:5432 postgres:16-alpine

cargo test                         # everything
cargo test --test security_contract # one file
```

CI runs the full suite on every PR via `.github/workflows/test.yml`.

## The pyramid

```
                       ▲
                       │ tests-e2e-desktop/  (WebdriverIO + tauri-driver,
                       │                      Linux CI only)
                       │
              security_contract.rs            ← OWASP API1 + API2
              golden_path.rs                  ← end-to-end happy path
              route_contract.rs               ← every route returns sane JSON
              route_registration.rs           ← every module is .merge()'d
              findings.rs / assessments.rs    ← per-resource integration
              category_mapping.rs             ← pure-function unit
                       ▲
                       │
                src/**.rs::tests              ← inline #[cfg(test)] units
                       │
                       └─── (cheap)            (expensive) ───►
```

## What each layer catches (and what it doesn't)

| File | Catches | Misses |
|---|---|---|
| `route_registration.rs` | A handler exists in source but `.merge()` was forgotten in `routes/mod.rs`. A `.route(...)` typo that axum can't match. | Anything about handler *behavior* — only proves the route is reachable. |
| `route_contract.rs` | Handler 500s on a minimal-input probe. Handler returns plaintext where JSON is promised. | Type drift in success-only fields, business-logic bugs. |
| `golden_path.rs` | Cross-layer flow breakage (assessment → finding → snapshot round-trip). | Anything outside the one happy path. |
| `findings.rs`, `assessments.rs` | Per-resource business logic — filter semantics, category derivation, dedup, status transitions. | Behavior of resources without their own test file. |
| `security_contract.rs` | OWASP API1 (Broken Object Level Authorization — cross-org access via guessed IDs). OWASP API2 (Broken Authentication — missing/expired/malformed JWT). | OWASP API3 (mass assignment), API4 (rate limiting), API5 (function-level auth — admin endpoints). Add tests here as those vectors become relevant. |
| Inline `#[cfg(test)]` in `src/**` | Pure-function correctness (e.g., `findings::source_to_category`). | Anything that needs the DB. |

## What's deliberately out of scope here

- **Real Cognito sign-in**, **real Docker container interaction**, **real
  external integrations (Jira, GitHub, SharePoint)**. Those need a staged
  environment + secrets. The desktop e2e suite mocks them via
  `MAESTRO_TEST_BYPASS_AUTH`; the manual checklist in
  `tests-e2e-desktop/MANUAL-CHECKLIST.md` covers the rest.
- **Load / perf tests**. Add when there's actual evidence of scale pain;
  premature perf testing burns capacity on imagined problems.
- **Synthetic monitoring on the deployed cloud env**. Lives in
  `kali-mcp-pentest-infra` (separate repo) — this suite tests the
  *source code* of the cloud backend, not the deployed instances.

## How to add a new test

1. **Per-resource integration test** (the bulk of new tests):
   - One file per resource (`projects.rs`, `repositories.rs`, etc.) using
     the `findings.rs` shape as a template.
   - Include at least one happy-path create-read-update-delete pass.
   - Include cross-org isolation if the resource is per-org.

2. **Security contract addition**:
   - Add to `security_contract.rs` if the test exercises OWASP API1 or
     API2 surfaces.
   - For API3/4/5 (mass assignment, rate limits, role-based auth),
     start a new section in `security_contract.rs` rather than a new
     file — the file is small and benefits from being one navigable
     surface.

3. **A new route**:
   - Add it to `routes/mod.rs::build_router` (caught by
     `route_registration.rs` if you forget).
   - The route auto-inherits the `route_contract.rs` 5xx + JSON-body
     check and the `security_contract.rs` auth-boundary check via
     source-parsing — no per-route test needed for those layers.
