// Out-of-band interaction listener for the `oast` oracle.
//
// Blind vulnerability classes — blind SSRF, blind SQLi, XXE, blind SSTI — put
// nothing in the response. The only evidence that the payload landed is the
// target reaching out to a host we control. That callback is the oracle.
//
// SELF-HOSTED ONLY. We never fall back to a public interactsh instance
// (oast.fun and friends): a callback carries the target's IP, and often headers
// or exfiltrated data, to a third party. For an org whose whole reason for
// running Maestro locally is that assessment data stays theirs, silently
// shipping interactions to a public server would be a breach of that promise.
// If no self-hosted server is configured the oracle reports `oast_unavailable`
// and the finding stays an unverified candidate — a coverage gap we state
// plainly, rather than a proof we obtained by leaking.
//
// Configuration, in precedence order:
//   1. MAESTRO_OAST_SERVER / MAESTRO_OAST_TOKEN — explicit environment override.
//   2. MAESTRO_OAST_CONFIG_PATH — a JSON file {server, token} the desktop app
//      writes from the org's discovery payload. THE NORMAL PATH: the customer
//      configures nothing, and the listener domain + their per-org token arrive
//      with the rest of their org config.
//   3. config/tools.yml → `oast:` — for a deployment that bakes it into the image.
//
// Standing up that server is a deployment task, not something the container can
// do for itself: it needs a public domain with NS records delegating to it, so
// the target can actually resolve and reach it.

import { executeInKaliDetailed } from "../utils/docker-exec";
import { OastSession } from "./oracles";

interface OastConfig {
  server: string;
  token?: string;
}

function readConfig(): OastConfig | null {
  // 1. Explicit environment override — an org pointing at its own listener,
  //    or a harness run. Highest precedence so it can always win.
  const server = process.env.MAESTRO_OAST_SERVER?.trim();
  if (server) {
    return { server, token: process.env.MAESTRO_OAST_TOKEN?.trim() || undefined };
  }

  // 2. The config file the desktop app writes from the org's discovery payload
  //    (commands/cloud.rs::write_oast_config_file). This is the normal path:
  //    the customer does nothing, and the shared listener's domain + their
  //    per-org token arrive with the rest of their org config. A file rather
  //    than env vars so changing the listener doesn't require recreating the
  //    container and the token stays out of `docker inspect`.
  const configPath = process.env.MAESTRO_OAST_CONFIG_PATH?.trim();
  if (configPath) {
    try {
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      const fs = require("fs");
      if (fs.existsSync(configPath)) {
        const doc = JSON.parse(fs.readFileSync(configPath, "utf-8"));
        const s = typeof doc?.server === "string" ? doc.server.trim() : "";
        if (s) return { server: s, token: doc?.token?.trim?.() || undefined };
      }
    } catch {
      /* unreadable or malformed → fall through to unavailable */
    }
  }

  // 3. Static config, for a self-hosted deployment that bakes it into the image.
  try {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const fs = require("fs");
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const yaml = require("js-yaml");
    for (const p of ["/opt/pentest/config/tools.yml", `${process.cwd()}/../config/tools.yml`]) {
      if (!fs.existsSync(p)) continue;
      const doc = yaml.load(fs.readFileSync(p, "utf-8")) as any;
      const s = doc?.oast?.server;
      if (typeof s === "string" && s.trim()) {
        return { server: s.trim(), token: doc?.oast?.token };
      }
    }
  } catch {
    /* fall through to unavailable */
  }
  return null;
}

interface Interaction {
  protocol: string;
  remoteAddress?: string;
  raw?: string;
}

/**
 * Start an interactsh-client against the configured self-hosted server and
 * return a session the oracle can poll. Returns null when OAST is unavailable
 * for any reason — no config, binary missing, or the client failed to register
 * a domain. Never throws: an unavailable listener is a verdict input, not an
 * error condition.
 */
export async function createOastSession(): Promise<OastSession | null> {
  const cfg = readConfig();
  if (!cfg) return null;

  const probe = await executeInKaliDetailed("command -v interactsh-client >/dev/null 2>&1 && echo OK");
  if (!probe.stdout.includes("OK")) return null;

  const id = `${Date.now().toString(36)}${Math.floor(process.hrtime()[1] % 1e6).toString(36)}`;
  const out = `/tmp/oast-${id}.jsonl`;
  const log = `/tmp/oast-${id}.log`;
  const pidFile = `/tmp/oast-${id}.pid`;

  const serverArg = `-s ${cfg.server}${cfg.token ? ` -t ${cfg.token}` : ""}`;
  const start = await executeInKaliDetailed(
    `nohup interactsh-client ${serverArg} -json -o ${out} >${log} 2>&1 & echo $! > ${pidFile}; sleep 3; cat ${log}`
  );

  // The client prints the payload domain it registered on startup.
  const domain = start.stdout.match(/\b[a-z0-9]{10,}\.[a-z0-9.-]*\b/i)?.[0];
  if (!domain) {
    await executeInKaliDetailed(`kill "$(cat ${pidFile} 2>/dev/null)" 2>/dev/null; rm -f ${out} ${log} ${pidFile}`);
    return null;
  }

  return {
    domain,
    poll: async (): Promise<Interaction[]> => {
      const r = await executeInKaliDetailed(`cat ${out} 2>/dev/null || true`);
      return r.stdout
        .split("\n")
        .map((l) => l.trim())
        .filter((l) => l.startsWith("{"))
        .flatMap((l) => {
          try {
            const j = JSON.parse(l);
            return [
              {
                protocol: String(j.protocol ?? "unknown"),
                remoteAddress: j["remote-address"] ?? j.remoteAddress,
                raw: j["raw-request"] ?? j.rawRequest,
              },
            ];
          } catch {
            return [];
          }
        });
    },
    close: async () => {
      await executeInKaliDetailed(
        `kill "$(cat ${pidFile} 2>/dev/null)" 2>/dev/null; rm -f ${out} ${log} ${pidFile}`
      );
    },
  };
}
