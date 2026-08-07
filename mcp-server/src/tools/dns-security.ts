import { executeInKali } from "../utils/docker-exec";
import { reconCacheLookup, reconCacheUpsert } from "../integrations/cache-client";

export const dnsSecurityTools = [
  {
    name: "test_zone_transfer",
    description: "Attempt DNS zone transfer (AXFR) against all authoritative nameservers for a domain. A successful zone transfer leaks the entire DNS zone.",
    inputSchema: {
      type: "object",
      properties: {
        domain: { type: "string", description: "Target domain to test zone transfer against" },
      },
      required: ["domain"],
    },
  },
  {
    name: "check_dnssec",
    description: "Check DNSSEC deployment and validation for a domain. Verifies RRSIG, DNSKEY, DS, and NSEC/NSEC3 records.",
    inputSchema: {
      type: "object",
      properties: {
        domain: { type: "string", description: "Target domain to check DNSSEC configuration" },
      },
      required: ["domain"],
    },
  },
  {
    name: "check_dns_records",
    description: "Retrieve and analyze all DNS record types for a domain. Checks A, AAAA, MX, TXT, CNAME, NS, SOA, SRV, CAA records and parses SPF, DKIM, and DMARC from TXT records. When target_id is provided, results are cached (Phase 5 of caching plan).",
    inputSchema: {
      type: "object",
      properties: {
        domain: { type: "string", description: "Target domain to query DNS records for" },
        record_types: { type: "string", description: "Comma-separated record types (default: all common types)", default: "A,AAAA,MX,TXT,CNAME,NS,SOA,SRV,CAA" },
        target_id: { type: "string", description: "Optional canonical target_id for recon cache lookup" },
      },
      required: ["domain"],
    },
  },
  {
    name: "detect_subdomain_takeover",
    description: "Detect potential subdomain takeover vulnerabilities by checking for dangling CNAME records pointing to deprovisioned cloud services (S3, Azure, GitHub Pages, Heroku, etc.).",
    inputSchema: {
      type: "object",
      properties: {
        domain: { type: "string", description: "Target domain to check for subdomain takeover" },
        subdomains: {
          type: "array",
          items: { type: "string" },
          description: "List of subdomains to check. If not provided, will enumerate first.",
        },
      },
      required: ["domain"],
    },
  },
];

export const dnsSecurityHandlers: Record<string, Function> = {
  test_zone_transfer: async (args: { domain: string }) => {
    const { domain } = args;
    const command = `echo "=== Nameservers for ${domain} ===" && NS=$(dig +short NS ${domain}) && echo "$NS" && echo "" && echo "=== Zone Transfer Attempts ===" && for ns in $NS; do echo "--- Trying $ns ---"; dig AXFR @$ns ${domain} 2>&1; echo ""; done`;
    return await executeInKali(command);
  },

  check_dnssec: async (args: { domain: string }) => {
    const { domain } = args;
    const command = [
      `echo "=== DNSSEC Check for ${domain} ==="`,
      `echo ""`,
      `echo "--- DNSKEY Records ---"`,
      `dig +dnssec DNSKEY ${domain} +short`,
      `echo ""`,
      `echo "--- DS Records ---"`,
      `dig DS ${domain} +short`,
      `echo ""`,
      `echo "--- RRSIG Records ---"`,
      `dig +dnssec ${domain} | grep -E "(RRSIG|DNSKEY|DS|NSEC)" || echo "No DNSSEC records found"`,
      `echo ""`,
      `echo "--- DNSSEC Validation ---"`,
      `dig +dnssec +cd ${domain} | grep -E "(flags|status|RRSIG)" || echo "Validation check complete"`,
    ].join(" && ");
    return await executeInKali(command);
  },

  check_dns_records: async (args: {
    domain: string;
    record_types?: string;
    target_id?: string;
  }) => {
    const { domain, record_types = "A,AAAA,MX,TXT,CNAME,NS,SOA,SRV,CAA", target_id } = args;

    const runner = async () => {
      const types = record_types.split(",").map((t) => t.trim());
      const commands = [`echo "=== DNS Records for ${domain} ==="`];

      for (const rtype of types) {
        commands.push(`echo ""`);
        commands.push(`echo "--- ${rtype} Records ---"`);
        commands.push(`dig +noall +answer ${rtype} ${domain} || echo "No ${rtype} records found"`);
      }

      commands.push(`echo ""`);
      commands.push(`echo "--- Email Security (SPF/DKIM/DMARC) ---"`);
      commands.push(`echo "SPF:" && dig +short TXT ${domain} | grep -i "v=spf" || echo "No SPF record found"`);
      commands.push(`echo "DMARC:" && dig +short TXT _dmarc.${domain} | grep -i "v=dmarc" || echo "No DMARC record found"`);
      commands.push(`echo "DKIM (default selector):" && dig +short TXT default._domainkey.${domain} || echo "No DKIM record for default selector"`);

      return await executeInKali(commands.join(" && "));
    };

    if (!target_id) return runner();

    const lookup = await reconCacheLookup(target_id, "dns");
    if (lookup.cached && lookup.entry) {
      return JSON.stringify({
        cached: true,
        scan_type: "dns",
        scanned_at: lookup.entry.scan_completed_at,
        expires_at: lookup.entry.expires_at,
        snapshot: lookup.entry.snapshot,
        note: "Result loaded from recon cache (dns).",
      });
    }
    const scan_completed_at = new Date().toISOString();
    const result = await runner();
    // DNS output is plain text, not JSON — store as raw blob.
    void reconCacheUpsert({
      target_id,
      scan_type: "dns",
      snapshot: { raw: result, record_types },
      scan_completed_at,
    });
    return result;
  },

  detect_subdomain_takeover: async (args: { domain: string; subdomains?: string[] }) => {
    const { domain, subdomains } = args;
    const safeArgs = JSON.stringify(args).replace(/'/g, "'\\''");
    const command = `python3 /opt/pentest/scripts/subdomain-takeover.py '${safeArgs}'`;
    return await executeInKali(command);
  },
};
