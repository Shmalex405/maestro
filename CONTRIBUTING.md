# Contributing

Contributions are welcome to the Apache-2.0 parts of this repository. Read the
licensing boundary below first, because not all of it can accept them.

## The one thing to check before you start

This repository is **open core**. Most of it is Apache-2.0, but an enumerated set
of paths is commercially licensed and **cannot accept contributions** — a pull
request against them cannot be merged, whatever its quality, so please don't spend
the time.

The authoritative list is [`COMMERCIAL-COMPONENTS`](COMMERCIAL-COMPONENTS). Today
it covers:

```
.claude/agents/                      the agent prompt corpus
.claude/workflows/                   the deterministic Workflow path
skills/                              orchestration protocols and report standards
mcp-server/src/verification/         the oracle verification layer
mcp-server/src/tools/verification.ts
frontend/lib/customer-registry.ts    the multi-tenant control plane
frontend/lib/license-guard.ts
frontend/app/api/discover/
frontend/app/api/license/
```

Those directories carry their own `LICENSE` file, and CI enforces it:

```bash
./scripts/check-license-boundary.sh
```

They are present because the application does not run without them — the desktop
mounts the agent definitions into its container, and `.claude/agents/`,
`.claude/commands/` and `docs/user-guide/` are compiled into the Rust binary via
`include_dir!`, so a missing directory is a compile error. Their presence is a
technical necessity, not a licence grant.

**Everything else is fair game**, including the ~227 tool handlers in
`mcp-server/`, the Kali image in `docker/`, `backend-rs/`, the desktop app in
`frontend/`, `deploy/terraform/`, `config/` and `docs/`.

## Good first contributions

- **A new security tool handler** in `mcp-server/src/tools/` — the highest-value
  contribution and the most self-contained
- **Toolkit additions** in `docker/Dockerfile.kali`
- **A false positive or false negative** you can characterise
- **Documentation** in `docs/user-guide/`, which is also the in-app docs
- **Platform fixes** — Windows and Linux get less real-world use than macOS

## Ground rules

**Every tool call must be scope-validated.** A handler that can reach a target not
permitted by `config/scope.yml` is the most serious class of bug in this codebase.
Route through the existing validator; do not add a bypass, however convenient.

**Never let the model decide a verdict.** If your change touches verification, the
LLM supplies the experiment and the oracle returns the result. That separation is
enforced in three places including a database CHECK constraint, and it is the
product's central claim.

**Non-destructive by default.** Read-only exploitation — data access via IDOR,
token forging, privesc probes — is expected and required. DoS, deletion, and
resource creation are refused and documented rather than executed.

**No real data in tests or fixtures.** No customer names, real account IDs,
production pool or client IDs, or employee addresses. Use `example.com` and
obvious placeholders. `gitleaks` runs in CI; reviewed non-secrets are pinned in
[`.gitleaksignore`](.gitleaksignore) by `file:rule:line`, so a moved line comes
back for re-review rather than staying muted.

## Before you open a PR

```bash
./scripts/check-license-boundary.sh                 # open-core boundary
gitleaks dir . --config .gitleaks.toml              # secret scan
cd mcp-server && npm ci && npm run build && npm test
cd frontend && npm ci && npx tsc --noEmit && npx vitest run
cd frontend/src-tauri && cargo test --bin Maestro
cd deploy/terraform/maestro-self-host && terraform init -backend=false && terraform validate
```

CI runs `license-boundary`, `secret-scan`, `backend-rs`, `frontend` and `tauri`.

Explain **why**, not just what. This codebase leans on comments that record the
reasoning and the failure that motivated a decision — matching that is more
useful than matching the formatting.

## Authorized use

Do not use this project, or develop against it, to test systems you do not own or
are not contractually authorized to test. See [`NOTICE`](NOTICE). If you need a
target while working on it, `tests-e2e-assessment/` stands up OWASP Juice Shop and
NodeGoat locally.

## Questions

Open a [Discussion](https://github.com/Shmalex405/maestro/discussions) — worth
doing before a large change, so you don't build something that turns out to be
headed somewhere else.
