import { executeInKali } from "../utils/docker-exec";
import { reconCacheLookup, reconCacheUpsert } from "../integrations/cache-client";

export const sslTlsTools = [
  {
    name: "scan_ssl_tls",
    description: "Perform comprehensive SSL/TLS analysis using testssl.sh. Tests protocols, ciphers, and vulnerabilities (Heartbleed, ROBOT, POODLE, etc.). When target_id is provided, results are cached (Phase 5 of caching plan).",
    inputSchema: {
      type: "object",
      properties: {
        target: { type: "string", description: "Target hostname:port (e.g., 'example.com:443')" },
        checks: { type: "string", description: "Specific checks: 'all', 'protocols', 'ciphers', 'vulnerabilities'", default: "all" },
        target_id: { type: "string", description: "Optional canonical target_id for recon cache lookup" },
      },
      required: ["target"],
    },
  },
  {
    name: "check_certificate",
    description: "Analyze SSL certificate chain, expiry, algorithm, hostname match, and CT logs.",
    inputSchema: {
      type: "object",
      properties: {
        target: { type: "string", description: "Target hostname:port (e.g., 'example.com:443')" },
      },
      required: ["target"],
    },
  },
  {
    name: "scan_ssl_ciphers",
    description: "Enumerate and grade SSL/TLS cipher suites using nmap ssl-enum-ciphers script.",
    inputSchema: {
      type: "object",
      properties: {
        target: { type: "string", description: "Target hostname" },
        port: { type: "number", description: "Port number", default: 443 },
      },
      required: ["target"],
    },
  },
];

export const sslTlsHandlers: Record<string, Function> = {
  scan_ssl_tls: async (args: { target: string; checks?: string; target_id?: string }) => {
    const { target, checks = "all", target_id } = args;
    const runner = async () => {
      let flags = "--jsonfile /tmp/testssl-output.json";
      if (checks === "protocols") flags += " -p";
      else if (checks === "ciphers") flags += " -E";
      else if (checks === "vulnerabilities") flags += " -U";
      const command = `testssl.sh ${flags} ${target} 2>/dev/null; cat /tmp/testssl-output.json 2>/dev/null || echo '{"error": "testssl.sh failed or produced no output"}'`;
      return await executeInKali(command);
    };

    if (!target_id) return runner();

    const lookup = await reconCacheLookup(target_id, "tls");
    if (lookup.cached && lookup.entry) {
      return JSON.stringify({
        cached: true,
        scan_type: "tls",
        scanned_at: lookup.entry.scan_completed_at,
        expires_at: lookup.entry.expires_at,
        snapshot: lookup.entry.snapshot,
        note: "Result loaded from recon cache (tls).",
      });
    }
    const scan_completed_at = new Date().toISOString();
    const result = await runner();
    let snapshot: unknown;
    try { snapshot = JSON.parse(result); } catch { snapshot = { raw: result }; }
    void reconCacheUpsert({
      target_id,
      scan_type: "tls",
      snapshot,
      scan_completed_at,
    });
    return result;
  },

  check_certificate: async (args: { target: string }) => {
    const { target } = args;
    const hostname = target.split(":")[0];
    const command = `echo | openssl s_client -connect ${target} -servername ${hostname} 2>/dev/null | openssl x509 -noout -text -dates -issuer -subject -serial -fingerprint -ext subjectAltName 2>/dev/null || echo '{"error": "Certificate check failed"}'`;
    return await executeInKali(command);
  },

  scan_ssl_ciphers: async (args: { target: string; port?: number }) => {
    const { target, port = 443 } = args;
    const command = `nmap --script ssl-enum-ciphers -p ${port} ${target} -oX - 2>/dev/null`;
    return await executeInKali(command);
  },
};
