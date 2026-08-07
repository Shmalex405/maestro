import { executeInKali } from "../utils/docker-exec";
import { parseNmapOutput, parseSubfinderOutput } from "../utils/parser";
import {
  reconCacheLookup,
  reconCacheUpsert,
  type ReconScanType,
} from "../integrations/cache-client";

/**
 * Recon cache wrapper (Phase 5 of caching plan).
 *
 * Caching is opt-in via `target_id`. When absent, the runner runs
 * uncached. When present, the cache is consulted; on hit, the parsed
 * snapshot is returned along with a `cached: true` marker. On miss,
 * the runner runs and the result is fire-and-forget upserted.
 *
 * Recon cache TTL defaults to 7 days (per org_settings.recon_cache_ttl_days).
 * The cache stores parsed structured output (NOT raw scanner blob)
 * because parsing is deterministic and the parsed form is much smaller.
 */
async function runWithReconCache(opts: {
  target_id?: string;
  scan_type: ReconScanType;
  scanner_version_cmd?: string;
  runner: () => Promise<string>;
}): Promise<string> {
  const { target_id, scan_type, runner } = opts;
  if (!target_id) return runner();

  const lookup = await reconCacheLookup(target_id, scan_type);
  if (lookup.cached && lookup.entry) {
    return JSON.stringify({
      cached: true,
      scan_type,
      scanned_at: lookup.entry.scan_completed_at,
      expires_at: lookup.entry.expires_at,
      snapshot: lookup.entry.snapshot,
      note: `Result loaded from recon cache (${scan_type}) — scanner did not re-run. Snapshot is the parsed scanner output from the prior run.`,
    });
  }

  // Cache miss — run, then write back.
  const scan_completed_at = new Date().toISOString();
  const result = await runner();

  // Try to capture scanner version for cache metadata; failure is
  // non-fatal because the cache key doesn't depend on it (recon scan
  // type is the dominant key).
  let scanner_version: string | undefined;
  if (opts.scanner_version_cmd) {
    try {
      scanner_version = (await executeInKali(opts.scanner_version_cmd)).trim();
    } catch {
      // ignore
    }
  }

  // The runner returns a JSON string. Parse it for storage as the
  // snapshot. If parsing fails (rare — every parser in this file
  // returns JSON), wrap in a raw blob.
  let snapshot: unknown;
  try {
    snapshot = JSON.parse(result);
  } catch {
    snapshot = { raw: result };
  }

  void reconCacheUpsert({
    target_id,
    scan_type,
    snapshot,
    scanner_version,
    scan_completed_at,
  });

  return result;
}

export const reconTools = [
  {
    name: "scan_ports",
    description: "Scan ports on a target using nmap. Returns open ports and service information. When target_id is provided, results are cached and reused on subsequent runs within the recon TTL (Phase 5 of caching plan).",
    inputSchema: {
      type: "object",
      properties: {
        target: { type: "string", description: "Target IP or hostname" },
        ports: { type: "string", description: "Port specification (e.g., '22,80,443' or '1-1000')", default: "1-1000" },
        scan_type: { type: "string", enum: ["quick", "full", "stealth"], default: "quick" },
        target_id: { type: "string", description: "Optional canonical target_id for recon cache lookup" },
      },
      required: ["target"],
    },
  },
  {
    name: "enumerate_subdomains",
    description: "Enumerate subdomains for a given domain using subfinder and amass. When target_id is provided, results are cached (Phase 5 of caching plan).",
    inputSchema: {
      type: "object",
      properties: {
        domain: { type: "string", description: "Target domain" },
        passive_only: { type: "boolean", description: "Use only passive sources", default: true },
        target_id: { type: "string", description: "Optional canonical target_id for recon cache lookup" },
      },
      required: ["domain"],
    },
  },
  {
    name: "fingerprint_services",
    description: "Identify services and versions running on target ports. When target_id is provided, results are cached (Phase 5 of caching plan).",
    inputSchema: {
      type: "object",
      properties: {
        target: { type: "string", description: "Target IP or hostname" },
        ports: { type: "string", description: "Ports to fingerprint" },
        target_id: { type: "string", description: "Optional canonical target_id for recon cache lookup" },
      },
      required: ["target", "ports"],
    },
  },
  {
    name: "discover_hosts",
    description: "Discover live hosts in a CIDR range.",
    inputSchema: {
      type: "object",
      properties: {
        cidr: { type: "string", description: "CIDR range (e.g., '192.168.1.0/24')" },
      },
      required: ["cidr"],
    },
  },
  {
    name: "web_technology_scan",
    description: "Identify web technologies using whatweb and httpx.",
    inputSchema: {
      type: "object",
      properties: {
        target: { type: "string", description: "Target URL" },
      },
      required: ["target"],
    },
  },
];

export const reconHandlers: Record<string, Function> = {
  scan_ports: async (args: {
    target: string;
    ports?: string;
    scan_type?: string;
    target_id?: string;
  }) => {
    const { target, ports = "1-1000", scan_type = "quick", target_id } = args;
    return runWithReconCache({
      target_id,
      scan_type: "ports",
      scanner_version_cmd: "nmap --version 2>&1 | head -1",
      runner: async () => {
        let nmapFlags = "-sV";
        switch (scan_type) {
          case "quick": nmapFlags = "-sV -T4 --top-ports 1000"; break;
          case "full": nmapFlags = "-sV -sC -p-"; break;
          case "stealth": nmapFlags = "-sS -sV -T2"; break;
        }
        const command = `nmap ${nmapFlags} -p ${ports} ${target} -oX -`;
        const output = await executeInKali(command);
        return parseNmapOutput(output);
      },
    });
  },

  enumerate_subdomains: async (args: {
    domain: string;
    passive_only?: boolean;
    target_id?: string;
  }) => {
    const { domain, passive_only = true, target_id } = args;
    return runWithReconCache({
      target_id,
      scan_type: "subdomains",
      scanner_version_cmd: "subfinder -version 2>&1 | head -1",
      runner: async () => {
        const subfinderCmd = `subfinder -d ${domain} -silent`;
        const subfinderOutput = await executeInKali(subfinderCmd);

        let amassOutput = "";
        if (!passive_only) {
          const amassCmd = `amass enum -passive -d ${domain}`;
          amassOutput = await executeInKali(amassCmd);
        }
        return parseSubfinderOutput(subfinderOutput, amassOutput);
      },
    });
  },

  fingerprint_services: async (args: {
    target: string;
    ports: string;
    target_id?: string;
  }) => {
    const { target, ports, target_id } = args;
    return runWithReconCache({
      target_id,
      scan_type: "services",
      scanner_version_cmd: "nmap --version 2>&1 | head -1",
      runner: async () => {
        const command = `nmap -sV -sC -p ${ports} ${target} -oX -`;
        const output = await executeInKali(command);
        return parseNmapOutput(output);
      },
    });
  },

  discover_hosts: async (args: { cidr: string }) => {
    const { cidr } = args;
    const command = `nmap -sn ${cidr} -oG -`;
    const output = await executeInKali(command);
    return output;
  },

  web_technology_scan: async (args: { target: string }) => {
    const { target } = args;
    const whatwebCmd = `whatweb -a 3 ${target} --log-json=-`;
    const httpxCmd = `echo "${target}" | httpx -silent -tech-detect -json`;
    
    const [whatwebOutput, httpxOutput] = await Promise.all([
      executeInKali(whatwebCmd),
      executeInKali(httpxCmd),
    ]);
    
    return JSON.stringify({ whatweb: whatwebOutput, httpx: httpxOutput }, null, 2);
  },
};
