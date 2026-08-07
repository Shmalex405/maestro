# Testing

This repo has 5 test surfaces. Each one runs in its own CI job
(`.github/workflows/test.yml`) and on every PR.

| Layer | Framework | Where | How to run |
|---|---|---|---|
| `backend-rs/` | cargo + sqlx | `backend-rs/tests/`, `#[cfg(test)] mod` blocks | `cd backend-rs && cargo test` |
| `frontend/` | vitest + RTL | `frontend/__tests__/` | `cd frontend && npx vitest run` |
| `frontend/src-tauri/` | cargo | `#[cfg(test)] mod` in source | `cd frontend/src-tauri && cargo test --bin Maestro` |
| `mcp-server/` | vitest | `mcp-server/tests/` | `cd mcp-server && npx vitest run` |
| `proxy/` | vitest | `proxy/__tests__/` (if any) | `cd proxy && npm test` |

## Quick start

```bash
# Backend integration tests need a Postgres on :5433
docker run -d --name backend-rs-test-pg \
  -p 5433:5432 \
  -e POSTGRES_USER=postgres -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=postgres \
  postgres:16-alpine

# Then run anywhere:
cd backend-rs && cargo test
cd frontend  && npx vitest run
cd frontend/src-tauri && cargo test --bin Maestro
cd mcp-server && npx vitest run
```

## Test conventions per layer

### `backend-rs/` — Axum + Postgres

Integration tests live in `backend-rs/tests/*.rs`. Each test gets its
own ephemeral Postgres database via `tests/common::TestApp`:

```rust
mod common;
use common::prelude::*;

#[tokio::test]
async fn lists_findings() {
    let app = TestApp::new().await;
    app.ensure_org("groovy").await;
    let token = app.token_for("u1", Some("groovy"));

    // Create + assert via the real router. No HTTP server, no
    // serialization round-trip — TestApp wires axum::Router::oneshot.
    let (status, json) = app
        .post_json("/api/v1/findings", &token, json!({
            "title": "X", "severity": "high", "target": "t",
            "source": "sqlmap",
        }))
        .await;
    assert!(status.is_success());
    assert_eq!(json["category"], "web_app");
}
```

Pure unit tests for helpers (no DB) live alongside the source as
`#[cfg(test)] mod tests` blocks.

### `frontend/` — vitest + React Testing Library

Component tests live in `frontend/__tests__/components/<name>.test.tsx`.
Mock API + Tauri via `vi.mock('@/lib/tauri-api', …)` BEFORE importing
the component:

```tsx
import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';

vi.mock('@/lib/tauri-api', () => ({
  api: { /* mocked methods */ },
  isTauri: () => false,
}));

import { MyComponent } from '@/components/my-component';

it('does the thing', async () => {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MyComponent />
    </QueryClientProvider>,
  );
  // ...
});
```

The shared setup (`__tests__/setup.ts`) already mocks
`next/navigation`, `matchMedia`, `ResizeObserver`, and `EventSource`.

### `frontend/src-tauri/` — Tauri Rust commands

Inline `#[cfg(test)] mod tests` blocks. The full Tauri runtime
(`AppHandle`, etc.) isn't easily mockable, so we test:
- Pure helpers (path resolution, source parsing, regex)
- Serialization contracts the frontend depends on
- Anything that doesn't need to actually `tauri::Builder::run()`

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn docker_diagnosis_serializes_to_expected_wire_shape() {
        assert_eq!(
            serde_json::to_value(&DockerDiagnosis::NotInstalled).unwrap(),
            serde_json::json!({"state": "not_installed"})
        );
    }
}
```

### `mcp-server/` — vitest

Tool implementations under `tests/tools/`, integrations under
`tests/llm/` and `tests/utils/`. Tools that call `executeInKali` should
mock the docker exec path — set `TEST_REQUIRE_DOCKER=1` if you want to
skip those in CI.

### `proxy/` — vitest (in progress)

No tests yet beyond what publishes already verifies. Add as you touch.

## What we test (and what we don't)

| What | Tested | Why |
|---|---|---|
| API contracts (frontend ↔ backend wire shapes) | ✅ | Highest-blast-radius regression risk. |
| SQL filters / aggregations (findings categories, exploited counts) | ✅ | We've shipped 4 versions of category bugs already; these now have parity tests. |
| React component behavior (modal flow, tab counts, button handlers) | ✅ | Catches "I refactored a hook and the modal stops creating things". |
| State machines (startup gate Docker fan-out) | ✅ | Many user-visible failure modes need precise UI per state. |
| Auth (Cognito, JWT verification, JWKS cache) | partial | Cognito mocking is heavy; rely on the local-JWT path in tests. |
| Tauri runtime invocation flow | ❌ | E2E only; Playwright + Tauri WebDriver is prohibitive cost-for-value. |
| Real Docker / scanner output | ❌ | Slow + flaky; integration testing handled by manual smoke runs. |

## Adding a test

1. Pick the right layer (table at the top).
2. Find an existing test with similar shape and copy its imports.
3. Mock external dependencies (DB, Tauri, fetch, Cognito).
4. Run `cargo test` or `npx vitest run` locally — green BEFORE pushing.
5. CI gates the PR. If CI is red, no merge.

## Running just one test

```bash
# Rust
cargo test --test findings stats_by_category_sums_to_total

# Vitest
npx vitest run -t "creates an assessment with no project"

# Or pick the file
npx vitest run __tests__/components/new-assessment-modal.test.tsx
```

## CI environment

Tests run on every push to `main` and every PR. Required services:

- Postgres on `localhost:5433` (provided by GitHub Actions services for
  the `backend-rs` job; spin one up locally with the Docker command at
  the top)
- No internet access required — all tests use mocks for external APIs

Total CI runtime is currently ~2-3 min. If a layer goes over 5 min we
should think about parallelism.
