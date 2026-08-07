# Manual Smoke Checklist

What CI cannot reach. Run this before every release on macOS (the primary
end-user platform) and ideally also on Windows. Everything below requires
something the automated suite skips — real Docker, real Cognito,
real LLM tool calls, native macOS chrome, the terminal pty, the updater
dialog, or behavior that diverges by platform.

The automated WebDriver suite (`desktop-e2e.yml`) already covers basic
route loading, sidebar nav, and the assessment-creation form. **Don't
re-check those manually — focus on what's listed here.**

Copy this checklist into the release PR and tick items as you go. If
something fails, file an issue and link the PR; do not silently skip.

---

## A. First-launch + install

- [ ] Fresh install on a clean macOS user account opens to the discovery
      screen (email → org backend lookup) and not a stale prior org
- [ ] Dock icon appears with the Maestro logo (not a generic placeholder)
- [ ] App quits cleanly via Cmd-Q (no stray processes, no "background"
      tmux sessions left running — check with `ps aux | grep tmux`)
- [ ] Re-launching after quit goes straight to the assessments list
      (auth + discovery are remembered)

## B. Authentication

- [ ] Cognito sign-in with a valid account succeeds and lands on the
      dashboard with the user's email visible in the top-right menu
- [ ] Wrong password produces a visible inline error, no Sentry-style
      "internal error" toast
- [ ] "Sign out" from the user menu returns to the login screen and
      clears `~/.kali-mcp-pentest/auth.json` (verify with `cat`)
- [ ] Token refresh works: leave the app open for 16+ minutes, navigate
      to a page that hits the cloud (e.g. Assessments), confirm it
      doesn't bounce back to login

## C. Docker / Kali container management

- [ ] With Docker Desktop NOT running, the startup gate detects it and
      offers "Launch Docker Desktop" — clicking it actually launches it
- [ ] First-launch image pull shows progress (% complete, MB/sec, eta) —
      not just a spinner
- [ ] After the pull, "Start Kali container" succeeds and the container
      shows up in `docker ps`
- [ ] Stopping the container via the Settings → Tools page actually
      stops it (verify with `docker ps`); the UI reflects within ~3s

## D. Code Repositories

- [ ] "Add Repository" via the **GitHub** picker opens an OAuth flow,
      lists the user's repos, and persists the selected one
- [ ] "Add Repository" via the **local directory** picker opens the
      native macOS file dialog, accepts a chosen folder, and saves it
- [ ] Linking a repo to an assessment shows up in the assessment detail
      "Code Repositories" section

## E. Assessment lifecycle

The automated suite covers create + list + detail. Run an actual
assessment by hand:

- [ ] New assessment → pick a real scope target (something local like a
      Vagrant box or a docker-compose stack you control)
- [ ] Pick "Reconnaissance" type, hit start
- [ ] **Claude tab**: the Sparkles tab spawns a tmux session, Claude Code
      prints its banner, runs `scan_ports`, returns within ~2 minutes
- [ ] Findings panel populates as MCP tool calls produce results
- [ ] Phase progress in the right rail advances through Recon → Vuln Scan
      → Web App phases (don't need to wait for the whole 116-test matrix)
- [ ] Cancel the assessment mid-run — UI returns to a sensible state and
      the tmux session is killed (`tmux ls` shows no `assess-*` session)

## F. Codex (parallel brain)

- [ ] **Codex tab** (Bot icon) spawns its own tmux session, prints the
      Codex banner, drives the same MCP tools as Claude
- [ ] Switching tabs mid-assessment doesn't kill the other brain's session
- [ ] Bundled-mode (no personal API key) works for both brains if the
      proxy is healthy
- [ ] Personal-API-key mode shows the right banner in the auth panel
      (Claude OAuth / Codex device-code / API key / Bundled)

## G. Findings + Reports

- [ ] Findings list filters work (severity, status, category, project)
- [ ] Clicking a finding opens the detail page with reproduction steps,
      evidence, and remediation rendered correctly
- [ ] Creating a Jira ticket from a finding actually posts to Jira (test
      project) and the URL in the success toast opens the ticket
- [ ] Generating a PDF report renders a real PDF (open it; check the
      cover page, TOC, and at least one finding section)

## H. Terminal pty

- [ ] In any terminal tab, typing produces output character-by-character
      (not buffered), arrow keys work, Ctrl-C interrupts
- [ ] Cmd-K / clear-screen works
- [ ] Resizing the window resizes the pty (text reflows correctly)
- [ ] Closing the tab cleans up the tmux session within 1-2s

## I. Settings / Config

- [ ] Saving scope.yml from the Scope page writes to the cloud (not
      local) — verify by signing in as another user in the same org and
      seeing the change
- [ ] Adding a cloud account via the Cloud Accounts page validates the
      credential (the "Verify connection" button)
- [ ] Toggling Claude credential mode (OAuth ↔ API key ↔ Bundled) takes
      effect on the next assessment without restart

## J. Updater

- [ ] When a new version is published, the in-app update banner appears
      within 30 minutes of launch
- [ ] "Install update" downloads, prompts for restart, restarts cleanly,
      and lands on the new version (check the About dialog)
- [ ] Cancelling the update doesn't break subsequent prompts

## K. macOS chrome

- [ ] Traffic lights (red/yellow/green) are correctly positioned, don't
      overlap content
- [ ] Cmd-, opens Settings (Config page)
- [ ] Cmd-N opens a new assessment
- [ ] Cmd-W closes the current window (does NOT quit the app)
- [ ] Window state (size, position) is remembered across restarts
- [ ] Dark mode follows the system setting; toggling system appearance
      while the app is open updates the UI within a few seconds

## L. Edge cases

- [ ] Sleeping the laptop mid-assessment and waking it up doesn't crash
      the app; the assessment either resumes or shows a clear error
- [ ] Network drop mid-assessment surfaces a visible "reconnecting"
      indicator, not a silent stall
- [ ] Quitting the app mid-assessment kills the brain's tmux session
      cleanly — re-launching shows the assessment as "interrupted",
      not "running"

---

## How to skip items honestly

Each release covers a subset of these items based on what changed. If a
PR touches none of section X, write `n/a (no changes)` next to that
section in the PR description — don't pretend to have run it. The
checklist is for catching real regressions, not for ceremony.
