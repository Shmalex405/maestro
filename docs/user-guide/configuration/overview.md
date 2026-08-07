# Overview

Everything under **Config** in the sidebar — the one-time setup that makes assessments actually run and reach your targets.

> [!NOTE] At a glance
> - **Do this once per machine**, before your first real assessment.
> - **Two things are required:** connect an LLM brain, and authorize your targets in Scope.
> - **The rest is optional** — target credentials, integrations, and cloud accounts — depending on what you're testing.

## The setup checklist

Work top to bottom — the first two are prerequisites, the rest depend on your assessment type.

| # | Setup | Required? | Where |
| --- | --- | --- | --- |
| 1 | **[Connect your LLM](./connect-your-llm.md)** — authenticate the Claude or Codex brain that drives assessments | **Required** | Config → Claude / Codex |
| 2 | **[Scope](./scope.md)** — authorize the domains/IPs you're allowed to test | **Required** for live targets | Config → Scope |
| 3 | **[Target Credentials](./credentials.md)** — how Maestro logs into the app it's testing | If testing authenticated endpoints | Config → Credentials |
| 4 | **[Cloud Accounts](../cloud-accounts/overview.md)** — connect AWS/Azure/GCP/K8s | If running cloud assessments | Config → Cloud Accounts |
| 5 | **[Integrations](./integrations.md)** — GitHub repos + Jira ticketing | Optional | Config → Integrations |
| 6 | **[Tools](./tools.md)** — tune scanner/agent defaults | Optional (advanced) | Config → Tools |
| 7 | **[Cache Settings](./cache-settings.md)** — assessment caching + drift detection | Optional (advanced) | Config → Cache Settings |

> [!IMPORTANT] Without steps 1 and 2, an assessment can't do anything
> The LLM brain is what actually drives the tools — no brain, nothing runs. And Maestro refuses any target that isn't in Scope. Set both up first.

## Where to look next

- [Connect your LLM](./connect-your-llm.md) — start here.
- [Getting Started](../getting-started/overview.md) — the end-to-end first-run walkthrough.
