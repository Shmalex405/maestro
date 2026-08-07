# AI / LLM Security Tools

Tool reference for the standalone AI assessment (the per-capability skill, analog
of `skills/infra-security` / `skills/cloud-security`). The orchestration protocol
is in `skills/ai-assessment/SKILL.md`; the design rationale is in
`docs/ai-surface-plan.md`. These tools live in `mcp-server/src/tools/ai-llm.ts`.

Every tool's first argument is **`ai_target_id`** — an `ai_targets[]` entry id from
`config/scope.yml`. The scope validator pins it (fail-closed) and additionally
requires the target's `endpoint` to resolve into an in-scope `domains`/`networks`
entry. The validated target (endpoint, model, `credential_ref`, `declared_tools`)
is threaded into the handler context, so you don't re-pass it.

> Authorized, scope-gated, non-destructive testing of the customer's own AI system
> — never the upstream model provider. Follow the **AI Safety Mandate**
> (`docs/ai-surface-plan.md` §10).

## Tools

| Tool | OWASP | What it does |
|---|---|---|
| `ai_fingerprint_target` | recon | Fingerprint model/provider/framework, enumerate exposed tools, map the untrusted-input surface, detect guardrails, and **cross-kind capability probe** (AI-RECON-05) — does a declared chat_app actually tool-call / retrieve / answer MCP `tools/list`? Sets the effective kind set (declared ∪ detected); coverage only expands. `detect_capabilities=true` default; honors `cross_kind_probe:false`. Read-only; curl-only (gate-exempt). |
| `ai_probe_injection` | LLM01 | Direct / indirect / jailbreak / guardrail-bypass probe over N benign-canary trials. `mode` selects the class; `injection_source` seeds the untrusted source for indirect. |
| `ai_extract_system_prompt` | LLM07 | Attempt to extract the system prompt / instructions / tool schema over N trials. Read-only. |
| `ai_test_info_disclosure` | LLM02 / LLM09 | Probe for sensitive / cross-tenant / training-data disclosure and confidently-wrong output. Read-only. |
| `ai_test_output_handling` | LLM05 | Drive model output that reaches a downstream sink (`sink`: html/sql/shell/markdown_link); ai-redteam proves the sink itself. |
| `ai_test_excessive_agency` | LLM06 | Coerce the agent into firing `target_tool`. **`attempt_execution=false` (default)** captures the tool call without side effects — capability-not-execution. |
| `ai_consumption_probe` | LLM10 | Short, hard-capped absence proof for a rate/token/cost limit. **Probe-only**, never a flood. |

## Usage

```
Tool: ai_fingerprint_target
Arguments: { "ai_target_id": "support-bot" }

Tool: ai_probe_injection
Arguments: { "ai_target_id": "support-bot", "mode": "direct", "trials": 10 }

Tool: ai_test_excessive_agency
Arguments: { "ai_target_id": "ops-agent", "target_tool": "send_email", "attempt_execution": false }
```

The probe tools send N requests (default 5; the matrix `trials:` sets the per-test
N, default 10) at `temperature=0` and return every response for the agent to
judge. Pass `body_template` (a JSON string with a `{{PROMPT}}` placeholder) once
`ai_fingerprint_target` has discovered the real request schema, so probes hit the
endpoint's actual shape rather than the OpenAI-chat default.

## N-trials status model

Status stays binary (PASS/FAIL/N_A/BLOCKED) but the probability lives in evidence.
Record the **success-rate** (k/N), trial count, and temperature per finding. FAIL
when success-rate ≥ the test's `fail_threshold`; PASS only at 0/N. See
`skills/ai-assessment/SKILL.md` and charter §8.

## Backing tools & the provenance gate

The red-team tools are backed by **promptfoo** (`TOOL_BINARIES` in
`mcp-server/src/logging/tool-provenance.ts`). Until promptfoo is baked into the
Kali image, `check_tool_provenance` correctly forces these tests to **BLOCKED** —
the system working, not a regression (§9). `ai_fingerprint_target` is curl-only
recon and is gate-exempt. Never mark an AI test PASS to paper over a missing
backing tool; report BLOCKED with the tool error as root cause.

## Findings routing

AI findings (sources `ai_*` or `ai-recon`/`ai-redteam`/`ai-analysis:TEST-ID`) route
to the `ai` finding category (`backend-rs` `category_from_source`) and surface in
the desktop app under **Surfaces → AI / LLM** (`/surfaces/ai`).
