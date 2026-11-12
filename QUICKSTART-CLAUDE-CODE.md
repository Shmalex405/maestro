# Quick start — drive Maestro from Claude Code (no desktop app)

Run Maestro's assessment engine straight from a **Claude Code** terminal session,
the same way the desktop app's Claude tab does, without installing the desktop
app. You get the same ~227 tools, the same agents, the same reports — the desktop
app is just one MCP client; Claude Code is another.

If you'd rather use the packaged desktop app, see
[Install](README.md#install) instead — it works too, and needs no account.

---

## What you need

- **Docker**, running (~30 GB free for the toolkit image)
- **Node 20+**
- **[Claude Code](https://claude.com/claude-code)** and your own Anthropic
  account (sign in with a Claude subscription, or an `ANTHROPIC_API_KEY`). Maestro
  ships no LLM — you bring your own. Nothing is sent to Groovy Security.

---

## The short path

From the repo root, after `git clone`:

```bash
./scripts/claude-code-quickstart.sh
```

That pulls the prebuilt Kali toolkit image, starts the `kali-pentest` container,
builds the MCP server, and prints the two commands below. (Pass `--build` to build
the image from `docker/Dockerfile.kali` yourself instead of pulling it.)

Then:

```bash
export CLAUDE_PROJECT_DIR="$(pwd)"   # required — .mcp.json references it
claude                               # from the repo root
```

Inside Claude Code: it auto-loads `.mcp.json`, exposing the `kali-pentest` tools.
Approve the server when prompted, point `config/scope.yml` at a target you're
authorized to test, and ask it to run an assessment.

---

## What the script does (do it by hand if you prefer)

```bash
# 1. Kali toolkit container — where every tool actually runs.
#    Prebuilt image (fast):
docker compose -f docker/docker-compose.prebuilt.yml up -d
#    …or build it from source (30–60 min):
#    docker compose -f docker/docker-compose.yml up -d --build

# 2. Build the host-side MCP server that Claude Code spawns.
cd mcp-server && npm ci && npm run build && cd ..

# 3. Start Claude Code wired to it.
export CLAUDE_PROJECT_DIR="$(pwd)"
claude
```

`.mcp.json` (already in the repo) registers the server:

```jsonc
"kali-pentest": {
  "command": "node",
  "args": ["${CLAUDE_PROJECT_DIR}/mcp-server/dist/index.js"],
  "env": { "DOCKER_CONTAINER": "kali-pentest", ... }
}
```

The MCP server runs on your host and `docker exec`s into the `kali-pentest`
container for every tool call — so the container name must be exactly
`kali-pentest`, and `CLAUDE_PROJECT_DIR` must be exported before `claude` starts,
or the server fails to connect (`CONNECTION_CLOSED` / `MODULE_NOT_FOUND`).

---

## Before your first real run — read this

- **Scope is enforced, and it's yours to set.** Nothing runs against a target
  until it's in `config/scope.yml`. Only add targets you are authorized to test —
  Maestro sends real payloads, forges tokens and reads data. See [`NOTICE`](NOTICE).

- **Anthropic Cyber Verification Program.** Sustained exploitation is exactly what
  Anthropic's safeguards look for, so on an un-enrolled account the
  exploitation-heavy agents (`web-security`, `api-graphql`, `cloud-exploit`,
  `identity-exploit`, `post-exploit-operator`) may **refuse partway through a
  run** — it looks like a thin report, not an error. Recon, SAST, secret and
  dependency scanning, compliance mapping and reporting are generally unaffected,
  so you can run those immediately. Apply to the programme for your own
  organization to lift it; a Groovy enrollment does not transfer.

- **Commercial components.** `.claude/agents/` and `skills/` are present so the
  tool runs, but are commercially licensed — see
  [`COMMERCIAL-COMPONENTS`](COMMERCIAL-COMPONENTS) and
  [`LICENSE-COMMERCIAL`](LICENSE-COMMERCIAL). Your Apache-2.0 rights to the open
  core are unconditional; you're free to write your own agent and skill
  definitions to replace them.

- **Data lives locally.** Findings, assessments and reports go to a local SQLite
  DB at `~/.pentest/data/pentest.db`. No AWS, no sign-in, nothing to provision.

---

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| Claude Code shows no `kali-pentest` tools | `CLAUDE_PROJECT_DIR` not exported before `claude`, or not launched from the repo root. Export it and relaunch. |
| `kali-pentest` tools error on every call | Container not running: `docker ps` should list `kali-pentest`. Re-run the quickstart. |
| MCP build fails | Node < 20, or `mcp-server` deps not installed — `cd mcp-server && npm ci && npm run build`. |
| Agents decline mid-assessment | Cyber Verification Program (above). Check the agent transcript to tell a model refusal from a tool failure. |

Bugs in the open core: open an issue on the repository. The managed product and
support: <support@groovysec.com>.
