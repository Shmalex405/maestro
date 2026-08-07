# maestro-backend (Rust port)

Rust rewrite of `backend/` (Python FastAPI). Same API contract, same
Postgres schema, same JWT auth — but compiled to a single binary instead
of shipping plaintext `.py` files to every customer's ECS cluster.

See `docs/RFC-RUST-BACKEND-MIGRATION.md` for the why and
`/Users/alex.flowers/.claude/plans/frolicking-drifting-pebble.md` for the
executable plan this crate implements.

## Status

**Parallel build — the Python `backend/` is untouched and keeps shipping.**
This crate exists alongside the Python code until the parity soak in
`tests/parity/` proves functional equivalence under live traffic. Customer
cutover (swapping `container_image` in tfvars) is a separate decision made
outside this crate.

## Running locally

```bash
# Start a Postgres:
docker run --rm -d --name pg -p 5432:5432 \
    -e POSTGRES_USER=postgres -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=pentest \
    postgres:16-alpine

# Set env to match backend/app/core/config.py defaults:
export DATABASE_URL=postgresql://postgres:postgres@localhost:5432/pentest
export AUTH_PROVIDER=local
export JWT_SECRET=dev-secret
export DEBUG=true

# Run:
cargo run --bin maestro-backend
```

The server listens on `0.0.0.0:8000` and runs `migrations/0001_initial.sql`
on startup (matching the Python `init_db()` behavior).

## Tests

Unit tests (no DB):

```bash
cargo test
```

Integration parity tests against a live Python backend:

```bash
cd tests/parity
docker compose up --build -d
./parity_check.sh
```

## Layout

```
src/
├── main.rs           — tokio runtime, axum router, CORS layer
├── config.rs         — env var parsing (mirrors backend/app/core/config.py)
├── db.rs             — PgPool + sqlx::migrate
├── state.rs          — shared Arc<AppStateInner>: settings, pool, JWKS cache
├── error.rs          — AppError → {"detail": "..."}  (FastAPI wire shape)
├── pdf.rs            — markdown → HTML → PDF via headless_chrome
├── auth/
│   ├── password.rs   — bcrypt + 72-byte truncation (passlib-compatible)
│   ├── jwt.rs        — HS256 local, RS256 Cognito, RS256 OIDC
│   ├── jwks_cache.rs — moka, 10-min TTL
│   └── middleware.rs — AuthUser FromRequestParts + ALLOWED_ORG_ID guard
├── models/           — sqlx::FromRow structs (one per table)
├── schemas/          — serde request/response types (mirror schemas.py)
└── routes/           — one file per Python router
migrations/
└── 0001_initial.sql  — full schema from backend/app/models/
tests/
└── parity/           — soak harness (docker-compose + diff driver)
```

## What's missing on purpose

- S3 storage backend (`storage_provider=s3`) — not currently used by any
  customer, skipped until it is.
- Non-placeholder LLM integration in `chat.py` — the Python backend's chat
  handler is also a placeholder today; we matched it verbatim.
- WeasyPrint parity for the PDF format option — Chromium renders the same
  source HTML with equivalent CSS; byte-for-byte identical output isn't
  achievable across engines and isn't part of the contract.
