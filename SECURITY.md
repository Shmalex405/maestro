# Security Policy

## Reporting a vulnerability in Maestro

**Please report privately. Do not open a public issue.**

Email **<security@groovysec.com>**.

If that bounces, use <support@groovysec.com> with `SECURITY` in the subject
line — but the dedicated address is monitored for this and reaches us faster.

Include what you have: affected version, affected component, reproduction steps,
and impact. A rough report sent privately is far more useful than a polished one
posted publicly.

You will get an acknowledgement, an assessment of severity and scope, a fix or a
documented mitigation, and credit in the release notes if you want it. If we
disagree that something is a vulnerability, you will get the reasoning rather
than silence.

## Why this matters more than usual here

Maestro runs with real privilege on an operator's machine. It drives a Kali
container, holds cloud and identity credentials for authorized assessments, and
executes live exploitation against targets. A vulnerability in Maestro is
therefore not only a risk to the operator — it is a risk to every system they are
authorized to test.

Things we consider particularly serious:

- **Scope-guard bypass.** Anything that causes a tool call to execute against a
  target not permitted by `config/scope.yml`, or that defeats the exclusion guard.
  This is the control that separates an authorized assessment from an unauthorized
  one.
- **Oracle forgery.** Anything that lets the LLM, a target, or injected content
  cause a finding to be marked `verified` without the oracle actually returning
  that verdict. The product's central claim is that the model supplies the
  experiment and never the verdict.
- **Prompt injection with consequences.** Assessment targets are hostile input by
  definition — a scanned application can return content crafted to steer the
  agents. Injection that escalates into tool execution outside scope, credential
  disclosure, or falsified findings is in scope for this policy.
- **Credential exposure.** Cloud, identity or LLM credentials leaking into logs,
  reports, the container filesystem, or anywhere off the operator's machine.
- **Container escape** from the Kali container to the host beyond the documented
  bind mounts.

## Out of scope

- **Maestro doing what it is designed to do.** It sends real payloads, forges
  tokens, and reads data in order to prove impact. That is the product, not a
  vulnerability.
- **Findings you disagree with.** A false positive is a bug — open a normal issue.
- **Vulnerabilities in the third-party tools** the container installs (nmap,
  nuclei, sqlmap, semgrep, metasploit, …). Report those upstream. If our
  *packaging* of one is unsafe, that is ours.
- **Anything requiring an operator to already have root on their own machine.**
- **Missing hardening with no exploit path.** Explain the path and it becomes in
  scope.

## Please do not

Test against systems you are not authorized to test, including ours, while
researching. Reproduce against your own infrastructure or a deliberately
vulnerable target such as OWASP Juice Shop or NodeGoat — both of which the
`tests-e2e-assessment/` harness already stands up locally.

## Supported versions

Fixes land on the latest release. Older versions are not patched — the app
auto-updates from a signed manifest, so staying current is the intended path.
