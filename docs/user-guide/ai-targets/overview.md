# Overview

How to put an AI/LLM system in scope so Maestro can red-team it — a chatbot, a tool-using agent, a RAG app, an MCP server, or a raw model API that you own.

> [!NOTE] At a glance
> - **What it unlocks:** the **AI / LLM** assessment — prompt injection, jailbreak, system-prompt leakage, sensitive disclosure, improper output handling, excessive agency, RAG isolation, and MCP tool-poisoning, mapped to the OWASP Top 10 for LLM Applications (2025) + MITRE ATLAS.
> - **You declare the target; we probe it.** Maestro does not auto-discover AI endpoints — you add an entry under **Config → AI Targets**, and `ai-recon` fingerprints what's actually behind it.
> - **Fail-closed & scope-gated:** no `ai_targets` entry, no AI testing. Only your own systems — never the upstream model provider.
> - **Safe by design:** consumption is probe-only, excessive agency is *capability-not-execution* (we capture the tool call, never fire it), and no persistent poisoning.

## Add a target

**Config → AI Targets → Add AI target.** Each target needs:

| Field | What it is |
|---|---|
| **id** | A short name, e.g. `support-bot`. |
| **kind** | `model_api` · `chat_app` · `agent` · `rag_app` · `mcp_server`. This is your *claim* — see "Cross-kind detection" below. |
| **endpoint** | The HTTP URL. **It must also be in an in-scope `domains`/`networks` entry** — otherwise every AI tool fails closed with an `AI SCOPE VIOLATION`. |
| **Request shape** | The endpoint's JSON request body, with `{{PROMPT}}` where the user message goes. **Required — there is no default.** See [Request shapes](./request-shapes.md). |
| **auth** | The AI assessment **shares your app's real login** — three tiers, most-reliable first: (1) when the AI target is part of an app you also test, the agent forwards the **browser-login session token** it already captured (`{AUTH_TOKEN}`); this is the only path that works against logins that **403 a headless POST** (most real apps). (2) **App credential** — pick a Config → Credentials application and the assessment mints a fresh bearer per run via that app's *programmatic* login; great for apps that accept a headless login. (3) static `credential_ref` + `bearer`/`api_key` as a last resort. You normally just pick the App credential and link the AI target to the same app the web/API assessment authenticates against — the browser-session reuse then happens automatically at run time. |
| **declared_tools** | For `agent` targets — the tool set the agent can call (the excessive-agency blast radius). Required for `agent`. |

## The `kind` decides what runs

The declared `kind` gates which test families apply: a `chat_app` gets injection / jailbreak / output-handling / disclosure; an `agent` adds **excessive agency** and tool-schema tests; a `rag_app` adds **RAG isolation + poisoning**; an `mcp_server` adds **tool-description poisoning + confused-deputy**; `model_api` is the leanest.

## Cross-kind detection — your declared kind is just a claim

`ai-recon` doesn't take `kind` at face value. It **probes the target's true nature** (AI-RECON-05): does a declared chatbot actually *tool-call*, *retrieve and cite documents*, or *answer an MCP `tools/list`*? If it does, the tests for that capability run against it too — **coverage only expands**, and the undeclared capability is itself a finding: *"you said it's a chatbot, but it will act as an agent when pushed."* Turn this off per-target with **cross_kind_probe: false** if you want the declared kind honored strictly.

## Run it

- **AI-only engagement:** `/assess-ai` — the AI report is the primary deliverable.
- **As part of a full assessment:** `/assess` runs the AI surface automatically when `ai_targets` is in scope (it's a conditional surface like Cloud and Identity). The **New Assessment** wizard also lets you opt-in specific AI targets per run.

## Where findings land

AI findings appear under **Surfaces → AI / LLM**, mapped to OWASP LLM Top 10 + MITRE ATLAS, with each probabilistic finding showing its **success-rate (k/N trials)** rather than a bare pass/fail.
