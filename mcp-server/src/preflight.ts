/**
 * MCP preflight.
 *
 * Starts the MCP server exactly as Claude Code will — same command, args,
 * cwd and env, read from the generated MCP config — and checks that it
 * answers `initialize` and lists its tools. The desktop runs this inside the
 * container right before launching claude.
 *
 * Why: Claude Code does not stop when an MCP server fails to start; the
 * session just runs without those tools. That is how an assessment once ran
 * entirely on raw shell commands (no scope validation, no findings recorded)
 * while the status panel showed the HTTP server as healthy.
 *
 * Usage: node dist/preflight.js [config.json | config.toml] [serverName]
 * (Claude's generated maestro-mcp.json, or Codex's generated config.toml)
 * Exit 0 and print the tool count on success; exit 1 with the server's
 * stderr tail on failure.
 */
import { spawn } from "child_process";
import * as fs from "fs";

const configPath = process.argv[2] || "/root/.claude/maestro-mcp.json";
const serverName = process.argv[3] || "kali-pentest";
const TIMEOUT_MS = Number(process.env.MAESTRO_PREFLIGHT_TIMEOUT_MS || 45000);

interface ServerConfig {
  command?: string;
  args?: string[];
  cwd?: string;
  env?: Record<string, string>;
}

let stderrTail = "";

function fail(message: string): never {
  console.error(`MCP preflight FAILED: ${message}`);
  const tail = stderrTail.trim().split("\n").slice(-15).join("\n");
  if (tail) console.error(tail);
  process.exit(1);
}

/**
 * Read one server from Codex's config.toml. Maestro generates that file
 * (terminal.rs ensure_codex_mcp_config) in a fixed shape — string values,
 * string arrays, and numbers under [mcp_servers.<name>] and
 * [mcp_servers.<name>.env] — so this reads exactly that subset rather than
 * pulling in a TOML library.
 */
function readCodexToml(text: string, name: string): ServerConfig | undefined {
  const server: ServerConfig = {};
  let section = "";
  let found = false;
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const header = line.match(/^\[(.+)\]$/);
    if (header) {
      section = header[1].trim();
      continue;
    }
    const kv = line.match(/^([A-Za-z0-9_]+)\s*=\s*(.+)$/);
    if (!kv) continue;
    const [, key, value] = kv;
    const str = value.match(/^"((?:[^"\\]|\\.)*)"$/);
    const unquote = (s: string) => s.replace(/\\(.)/g, "$1");
    if (section === `mcp_servers.${name}`) {
      found = true;
      if (key === "command" && str) server.command = unquote(str[1]);
      if (key === "cwd" && str) server.cwd = unquote(str[1]);
      if (key === "args") {
        server.args = [...value.matchAll(/"((?:[^"\\]|\\.)*)"/g)].map((m) => unquote(m[1]));
      }
    } else if (section === `mcp_servers.${name}.env` && str) {
      server.env = { ...(server.env ?? {}), [key]: unquote(str[1]) };
    }
  }
  return found ? server : undefined;
}

let server: ServerConfig | undefined;
try {
  const text = fs.readFileSync(configPath, "utf8");
  server = configPath.endsWith(".toml")
    ? readCodexToml(text, serverName)
    : JSON.parse(text)?.mcpServers?.[serverName];
} catch (e) {
  fail(`cannot read ${configPath}: ${e instanceof Error ? e.message : String(e)}`);
}
if (!server?.command) fail(`no "${serverName}" server defined in ${configPath}`);

const child = spawn(server.command as string, server.args ?? [], {
  cwd: server.cwd,
  env: { ...process.env, ...(server.env ?? {}) },
  stdio: ["pipe", "pipe", "pipe"],
});

const timer = setTimeout(() => {
  child.removeAllListeners("exit");
  child.kill("SIGKILL");
  fail(`server did not answer within ${TIMEOUT_MS / 1000}s`);
}, TIMEOUT_MS);

function finish(): void {
  clearTimeout(timer);
  child.removeAllListeners("exit");
  child.kill();
}

child.stderr.on("data", (d: Buffer) => {
  stderrTail = (stderrTail + d.toString()).slice(-65536);
});
child.on("error", (e) => {
  finish();
  fail(`could not start ${server?.command}: ${e.message}`);
});
child.on("exit", (code, signal) => {
  clearTimeout(timer);
  fail(`server exited before answering (${code ?? signal})`);
});

const send = (message: object) => child.stdin.write(JSON.stringify(message) + "\n");

let buffer = "";
child.stdout.on("data", (d: Buffer) => {
  buffer += d.toString();
  let newline: number;
  while ((newline = buffer.indexOf("\n")) >= 0) {
    const line = buffer.slice(0, newline).trim();
    buffer = buffer.slice(newline + 1);
    if (!line) continue;
    let message: { id?: number; result?: { tools?: unknown[] }; error?: { message?: string } };
    try {
      message = JSON.parse(line);
    } catch {
      continue; // not a JSON-RPC line
    }
    if (message.id === 1) {
      if (message.error) {
        finish();
        fail(`initialize failed: ${message.error.message ?? "unknown error"}`);
      }
      send({ jsonrpc: "2.0", method: "notifications/initialized" });
      send({ jsonrpc: "2.0", id: 2, method: "tools/list" });
    } else if (message.id === 2) {
      finish();
      const count = message.result?.tools?.length ?? 0;
      if (count === 0) fail("server started but listed no tools");
      console.log(`MCP preflight ok: ${count} tools`);
      process.exit(0);
    }
  }
});

send({
  jsonrpc: "2.0",
  id: 1,
  method: "initialize",
  params: {
    protocolVersion: "2025-06-18",
    capabilities: {},
    clientInfo: { name: "maestro-preflight", version: "1" },
  },
});
