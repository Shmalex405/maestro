# Recon Agent Skill

## Purpose
The Recon Agent performs initial reconnaissance and asset discovery. It builds a comprehensive map of the attack surface within the defined scope.

## When to Use
- Starting a new assessment
- Adding new targets to scope
- Periodic asset inventory refresh
- Before vulnerability scanning

## Available Tools

### discover_hosts
Discovers live hosts in a CIDR range using nmap ping scan.
```
Arguments:
  - cidr: CIDR range (e.g., "192.168.1.0/24")
```

### scan_ports
Scans ports on a target with configurable depth.
```
Arguments:
  - target: IP or hostname
  - ports: Port specification (default: "1-1000")
  - scan_type: "quick" | "full" | "stealth"
```

### enumerate_subdomains
Finds subdomains using subfinder and amass.
```
Arguments:
  - domain: Target domain
  - passive_only: Boolean (default: true)
```

### fingerprint_services
Identifies service versions on discovered ports.
```
Arguments:
  - target: IP or hostname
  - ports: Ports to fingerprint
```

### web_technology_scan
Identifies web technologies using whatweb and httpx.
```
Arguments:
  - target: URL to scan
```

## Workflow Pattern
1. Validate target is in scope
2. If CIDR: discover_hosts first
3. For each host: scan_ports (quick mode first)
4. For interesting ports: fingerprint_services
5. For web ports (80, 443, 8080, etc.): web_technology_scan
6. If domain: enumerate_subdomains
7. Compile results for downstream agents

## Best Practices
- Always start with quick scans, then deep dive on interesting findings
- Use passive_only for subdomain enumeration to avoid detection
- Document all discovered assets for the report agent
- Pass web services to the web-app-agent for deeper testing

## Output Format

Results MUST be structured and complete. Every discovered asset must be individually listed.

**Host Discovery Output:**
```json
{
  "hosts": [
    {
      "ip": "192.168.1.10",
      "hostname": "web01.example.com",
      "status": "up",
      "latency_ms": 2.5,
      "ports": [
        {"port": 80, "state": "open", "service": "http", "version": "nginx 1.24.0"},
        {"port": 443, "state": "open", "service": "https", "version": "nginx 1.24.0"}
      ]
    }
  ]
}
```

**Subdomain Output:**
```json
{
  "subdomains": [
    {"subdomain": "api.example.com", "ip": "10.0.1.5", "cname": "alb-123.elb.amazonaws.com"},
    {"subdomain": "staging.example.com", "ip": "10.0.2.3", "cname": null}
  ]
}
```

## Completeness Rules (MANDATORY)

1. **Every host discovered must be individually listed** — never say "5 hosts found" without listing all 5 with IPs and hostnames
2. **Every open port must be listed** with port number, protocol, service name, and version (if detected)
3. **Every subdomain must be listed** with its resolved IP and CNAME chain
4. **DNS records must be listed individually** — all A, AAAA, MX, TXT, CNAME, NS records with full values
5. **Never use "various", "multiple", "several", or "etc."** — list every item explicitly
6. **Technology fingerprints must include version numbers** where detected, not just "nginx" but "nginx 1.24.0"
7. **If a scan produces N results, all N must appear in the output** — no partial listings
