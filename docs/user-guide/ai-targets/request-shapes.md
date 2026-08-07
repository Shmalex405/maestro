# Request shapes

How to tell Maestro the exact HTTP request your AI endpoint expects. Every AI target **must** declare its request shape — there is no default, because an OpenAI-style guess silently fails against any endpoint that isn't OpenAI-shaped.

> [!NOTE] At a glance
> - **`request_template`** — your endpoint's JSON request body, with `{{PROMPT}}` where the user's message goes. **Required.**
> - **`response_path`** — where the assistant's reply text lives in the response JSON (optional but recommended).
> - Set both under **Config → AI Targets** — pick a preset (OpenAI / Anthropic / Custom) and edit to match. You can paste any JSON; `{{PROMPT}}` is the only magic token.

## Why you set this (and we don't guess)

The probes (`ai-recon` fingerprinting, every `ai-redteam` injection trial) work by POSTing a body to your endpoint with the attack text in place of `{{PROMPT}}`. If the body shape is wrong, the endpoint returns a 4xx and the probe looks "blocked" when really it never landed. So you declare the exact shape once, and every probe uses it.

## The `{{PROMPT}}` placeholder

Put `{{PROMPT}}` exactly where the user message goes. Maestro substitutes the (JSON-escaped) attack string there for each trial. It can appear anywhere in the body — a `messages` array, a top-level field, a nested object.

## `response_path`

The path to the assistant's reply text in the response JSON, using dot/bracket notation (array indexes are numbers): `choices.0.message.content`, `content.0.text`, `data.reply`. Optional — if you leave it blank, the probes read the whole response body and the agent locates the reply itself. Setting it makes evidence cleaner.

## Examples

### OpenAI / Azure OpenAI (Chat Completions)

```json
{"model":"gpt-4o","messages":[{"role":"user","content":"{{PROMPT}}"}]}
```
`response_path`: `choices.0.message.content`

### Anthropic Messages API

```json
{"model":"claude-sonnet-4-6","max_tokens":1024,"messages":[{"role":"user","content":"{{PROMPT}}"}]}
```
`response_path`: `content.0.text`

### A custom app endpoint (the most common real case)

Most customer chatbots wrap a model behind their own API. Use whatever your endpoint actually accepts:

```json
{"message":"{{PROMPT}}","session_id":"maestro-test","stream":false}
```
`response_path`: `reply`  *(or `data.answer`, `output.text`, … — whatever your response uses)*

### LangChain / LlamaIndex "serve" style

```json
{"input":{"question":"{{PROMPT}}"},"config":{}}
```
`response_path`: `output`

### A RAG endpoint that takes a query

```json
{"query":"{{PROMPT}}","top_k":5}
```
`response_path`: `answer`

### `mcp_server` targets

You don't need a chat `request_template` for the MCP-specific probes — those speak JSON-RPC (`tools/list`) directly. Still set a `request_template` if the server also exposes a chat/completion route you want injection-tested; otherwise the MCP probes work without it.

## How to find your shape

If you're not sure what your endpoint expects:

1. **Curl it.** Send the request your app sends and confirm the body:
   ```bash
   curl -sS -X POST https://app.staging.example.com/api/chat \
     -H 'Authorization: Bearer <token>' -H 'Content-Type: application/json' \
     -d '{"message":"hello"}'
   ```
   The `-d` payload *is* your `request_template` (swap the user text for `{{PROMPT}}`); the JSON it returns tells you the `response_path`.
2. **Browser devtools.** Open your chatbot, send a message, and in the Network tab copy the request payload of the POST that carries it.
3. **Your backend code / API docs.** The route handler shows the exact field names.

## Auth goes separately

Don't put your API key in the `request_template`. Set **auth_method** + **credential_ref** on the target; Maestro adds the `Authorization` (or custom) header at runtime from the brokered credential.

## Related

- [AI Targets overview](./overview.md) — kinds, scope rules, cross-kind detection
- Cross-kind detection means a declared `chat_app` that turns out to tool-call gets the agent tests too — see the overview. Set `cross_kind_probe: false` on a target to honor the declared kind only.
