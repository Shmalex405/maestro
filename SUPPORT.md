# Support

Where to send what, so it reaches the right place.

| I want to… | Go here |
|---|---|
| Suggest a feature, or tell us what is working and what is not | [Discussions → Ideas](https://github.com/Shmalex405/maestro/discussions) |
| Ask how to do something | [Discussions → Q&A](https://github.com/Shmalex405/maestro/discussions) |
| Report a bug | [Open an issue](https://github.com/Shmalex405/maestro/issues/new/choose) |
| Report a vulnerability **in Maestro** | Privately to <security@groovysec.com> — see [SECURITY.md](SECURITY.md). Not a public issue. |
| Ask about commercial licensing, the signed attestation, or paid support | <support@groovysec.com> |

Feedback is wanted. This is early in the open release and the roadmap is not
fixed — telling us that a surface is thin, a report section is useless, or a
workflow is awkward is more valuable than a polite nothing.

## Before opening an issue

A few checks that resolve most reports faster than we can:

**The app will not finish starting.** The startup gate names the step it failed
on. The two common ones:

- *Check Kali Image* — the toolkit image is missing. Pull the tag matching your
  app version: `docker pull ghcr.io/shmalex405/docker-kali:v<version>`. It must
  match, because the app looks the image up **by tag**.
- *Check Docker* — Docker Desktop is not running, or its daemon is wedged. The
  gate offers a restart button for the second case.

**An assessment produced a thin report, with no error.** Most often this is
Anthropic's cyber safeguards, not a bug: exploitation agents *decline* rather than
crash on an unenrolled account, so coverage silently narrows. See
[Request Anthropic Cyber Verification](README.md#request-anthropic-cyber-verification-before-your-first-run).
Check the agent transcript to tell a refusal from a tool failure.

**Tests report BLOCKED rather than PASS.** That is deliberate. The provenance gate
re-rates any test whose backing tool was absent from the container or never exited
0, so a missing scanner cannot masquerade as clean coverage. Rebuild or re-pull the
toolkit image.

**A feature says "Available in team mode."** Local mode has no Postgres, so the
attack-graph explorer, post-exploitation footholds, scheduled DAST and user roles
are unavailable by design — the page explains which and why. See
[Two ways to run it](README.md#two-ways-to-run-it).

**Findings look wrong.** Include the finding, what you expected, and the target
type. Both directions are worth reporting: a false positive wastes triage time, and
a false negative is worse.

## What helps in a bug report

Your OS and app version, the startup step or page involved, what you expected
versus what happened, and any relevant log. Logs are at
`~/Library/Logs/Maestro/maestro.log` on macOS and
`~/.kali-mcp-pentest/logs/` elsewhere.

**Scrub before posting.** Logs and reports from a real assessment contain target
hostnames, credentials and findings — by design, since reports are written for an
audience that already has that access. A public issue is not that audience. Redact,
or send it privately to <security@groovysec.com> instead.
