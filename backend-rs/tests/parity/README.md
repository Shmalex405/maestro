# Parity soak harness

This directory holds the tooling used to prove the Rust backend is
functionally equivalent to the Python backend before anyone considers
cutover. It is the Phase 5 deliverable described in
`/Users/alex.flowers/.claude/plans/frolicking-drifting-pebble.md`.

**Nothing here publishes anything. Nothing here mutates customer state.**
The harness only exercises the two backends locally against the same
Postgres and diffs responses.

## What this directory contains

| File | Purpose |
|---|---|
| `docker-compose.yml` | Brings up a throwaway Postgres + both backends on ports 8000/8001 |
| `parity_check.sh` | Driver: hits representative endpoints on each backend and diffs the responses |
| `python_tests_conftest.py` | Drop-in replacement for `backend/tests/conftest.py` that retargets the existing pytest suite at a live URL |

## Prereqs

- Docker Desktop running
- Python 3.12 (for the `backend/` test suite — we don't rewrite it)
- `jq` and `diff` on `$PATH`

## Run the stack

```bash
cd backend-rs/tests/parity
docker compose up --build -d
# Python backend on  :8000
# Rust backend   on  :8001
# Postgres       on  :5432 (ephemeral volume)

./parity_check.sh
```

`parity_check.sh` exits non-zero if any endpoint diffs. The script covers:

- `GET /health`, `/health/ready`, `/health/live`
- `GET /api/v1/version`
- `POST /api/v1/auth/register` + `POST /api/v1/auth/login` (local flow)
- `GET /api/v1/auth/me`, `/auth/providers`
- `POST /api/v1/assessments` + list + patch + delete
- `POST /api/v1/findings` + list + `/findings/stats`
- `POST /api/v1/reports` + `GET /reports/{id}/download?format=markdown|html`
  (PDF is byte-for-byte different between WeasyPrint and headless Chromium
  by design — we only parity-check the HTTP headers and content type.)
- `POST /api/v1/sync` round-trip
- `POST /api/v1/projects` + archive
- `POST /api/v1/chat` (placeholder response shape)

## Run the existing pytest suite against either backend

```bash
# Point the existing backend/tests/ suite at Rust:
export PARITY_BASE_URL=http://localhost:8001
pytest backend/tests/ --override-conftest backend-rs/tests/parity/python_tests_conftest.py
```

The shim in `python_tests_conftest.py` replaces the `async_client`
fixture's `ASGITransport(app=app)` with `AsyncClient(base_url=...)` so
pytest hits the live HTTP server instead of importing the FastAPI app
in-process. Every test must pass under both `PARITY_BASE_URL=http://localhost:8000`
(Python) and `:8001` (Rust) before the soak is considered green.

## Exit criteria (per the plan)

- 48 hours of staging traffic with zero semantic diffs on the checked
  endpoints
- `backend/tests/` green against the Rust URL
- No changes to `backend/` (the Python image is untouched)

**The plan ends at "staging-green + parity report artifact."** No customer
tfvars change, no `container_image` promotion, no `:latest` retagging in
the Python ECR repo. Those are separate decisions made outside this
harness.
