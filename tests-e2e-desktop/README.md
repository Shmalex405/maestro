# Desktop End-to-End Tests

WebdriverIO + tauri-driver suite that drives the real Tauri desktop binary
on Linux. Catches the class of "frontend ↔ Tauri command ↔ backend"
regressions that the in-process tests (vitest/jest/cargo test) can't reach
because they don't render or click the real UI.

## Where it runs

| Platform | Status | Tooling |
|---|---|---|
| Linux | **Primary** | `tauri-driver` + WebKitWebDriver from webkit2gtk-4.1 |
| Windows | Possible | `tauri-driver` + msedgedriver |
| macOS | **Not supported** | `tauri-driver` upstream is Linux/Windows only. macOS devs run the in-process suites + a manual checklist (see `MANUAL-CHECKLIST.md` in this directory) |

CI runs this on the GitHub Actions Linux runner via `desktop-e2e.yml`. The
suite is **never** invoked from `pnpm test` or similar — it's its own job.

## Required Tauri config

`frontend/src-tauri/tauri.conf.json` is already compatible — window is
visible, devtools enabled, no native dialogs block startup. No changes
needed.

## Building the binary

The test runner expects a debug-built Tauri binary at
`frontend/src-tauri/target/debug/Maestro` (override with
`MAESTRO_BINARY_PATH`). Build it from the repo root:

```bash
cd frontend
pnpm install
pnpm tauri build --debug
# binary is now at src-tauri/target/debug/Maestro on macOS/Linux
```

## Running locally on Linux

```bash
# one-time
cargo install tauri-driver
sudo apt-get install -y webkit2gtk-4.1 xvfb

# every run
cd tests-e2e-desktop
pnpm install
xvfb-run tauri-driver &
pnpm test
```

## Running in CI

`.github/workflows/desktop-e2e.yml` builds the binary, brings up
tauri-driver under xvfb in a Docker container (see `Dockerfile`), and runs
the suite. Screenshots from failed tests are uploaded as workflow artifacts.

## Environment variables

| Variable | Purpose |
|---|---|
| `MAESTRO_BINARY_PATH` | Absolute path to the Tauri binary (defaults to debug build location) |
| `MAESTRO_TEST_BYPASS_AUTH` | Set to `1` to skip the Cognito login gate (the test fixture sets this automatically) |
| `TAURI_DRIVER_HOST` / `TAURI_DRIVER_PORT` | Override tauri-driver address |
| `HEADED` | Set to `1` to keep the window visible (default is xvfb-only in CI) |
| `WDIO_LOG_LEVEL` | `info` / `debug` / `trace` |

## What the suite covers

- **Smoke tests** (`specs/routes.smoke.test.ts`) — one test per top-level
  route. Asserts the page loads, the sidebar nav highlight matches, and
  the page header renders. Cheap regression net.
- **Flow tests** (`specs/*.flow.test.ts`) — multi-step user journeys
  (create assessment, view findings, etc.). One per major feature; deep.

## What it does NOT cover

- Real Docker / Kali container interactions (need a running container,
  see the Linux CI runner setup if you want this)
- Real MCP tool output against real targets (need a fixture target)
- The Claude/Codex brain (LLM API calls)
- External integrations (Jira, GitHub, Cognito production)

For those, use the in-process tests or a staged-environment manual run.
