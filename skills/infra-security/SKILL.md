# Infrastructure Security Agent Skill

## Purpose

The Infrastructure Security Agent tests the network and transport layer security of targets. It focuses on SSL/TLS configuration, DNS security, cloud metadata exposure, HTTP protocol attacks, and subdomain takeover detection. These tests cover the foundational security layers that underpin all application-level security.

## When to Use

- HTTPS targets need SSL/TLS configuration audit (protocols, ciphers, certificates)
- Domain targets need DNS security assessment (zone transfer, DNSSEC, email security)
- Targets are hosted in cloud environments (AWS, GCP, Azure) and need metadata probing
- Subdomain enumeration revealed potential takeover candidates
- Web targets are behind CDN/proxy and need HTTP smuggling testing
- Infrastructure compliance testing is required (PCI-DSS TLS requirements, etc.)
- After recon agent for deeper infrastructure analysis
- Before vuln-scan agent to identify infrastructure-level weaknesses first

## Available Tools

### SSL/TLS Tools

| Tool | Description |
|------|-------------|
| `scan_ssl_tls` | Comprehensive SSL/TLS analysis via testssl.sh: protocol versions (SSLv2-TLS 1.3), cipher suites, and known vulnerabilities (Heartbleed, ROBOT, POODLE, DROWN, BEAST, CRIME, BREACH, LUCKY13) |
| `check_certificate` | Certificate chain analysis: expiration, algorithm strength, hostname match, SANs, issuer, serial, fingerprint, CT logs |
| `scan_ssl_ciphers` | Cipher suite enumeration and grading via nmap ssl-enum-ciphers: identifies weak ciphers (RC4, DES, NULL), export-grade ciphers, preference order |

### DNS Security Tools

| Tool | Description |
|------|-------------|
| `test_zone_transfer` | DNS zone transfer (AXFR) attempt against all authoritative nameservers: successful transfer leaks the entire DNS zone |
| `check_dnssec` | DNSSEC deployment verification: checks RRSIG, DNSKEY, DS, and NSEC/NSEC3 records |
| `check_dns_records` | Full DNS record enumeration: A, AAAA, MX, TXT, CNAME, NS, SOA, SRV, CAA, plus SPF/DKIM/DMARC email security analysis |
| `detect_subdomain_takeover` | Subdomain takeover detection: checks for dangling CNAME records pointing to deprovisioned cloud services (S3, Azure, GitHub Pages, Heroku, Fastly, Shopify) |

### Cloud Security Tools

| Tool | Description |
|------|-------------|
| `test_cloud_metadata` | Cloud metadata endpoint probing: tests AWS IMDSv1/v2, GCP metadata, Azure IMDS for credential exposure |
| `check_s3_bucket` | S3 bucket permission testing: public listing, read/write access, ACL disclosure, bucket policy exposure |

### Network Tools

| Tool | Description |
|------|-------------|
| `test_http_smuggling` | HTTP request smuggling detection: tests CL.TE, TE.CL, and TE.TE desync techniques between proxies and backends |
| `scan_ports` | Port scanning via nmap: discover services that need infrastructure security testing |
| `fingerprint_services` | Service version identification: determines specific software versions for vulnerability matching |
| `web_technology_scan` | Technology detection: identifies CDN provider, cloud hosting platform, and server software |

## Workflow Pattern

### Phase 1: SSL/TLS Analysis (HTTPS targets)
1. **Full TLS scan** with `scan_ssl_tls` (checks: all)
   - Protocol support (SSLv2, SSLv3, TLS 1.0, TLS 1.1, TLS 1.2, TLS 1.3)
   - Known vulnerabilities (Heartbleed, ROBOT, POODLE, DROWN, etc.)
   - HSTS header presence and configuration
2. **Certificate analysis** with `check_certificate`
   - Expiration date and validity period
   - Algorithm strength (RSA key size, signature algorithm)
   - Hostname match and Subject Alternative Names
   - Certificate chain completeness
3. **Cipher suite audit** with `scan_ssl_ciphers`
   - Weak ciphers (RC4, DES, 3DES, NULL, EXPORT)
   - Cipher preference order (server vs client preference)
   - Forward secrecy support (ECDHE, DHE)

### Phase 2: DNS Security (domain targets)
4. **DNS record enumeration** with `check_dns_records`
   - All record types (A, AAAA, MX, TXT, CNAME, NS, SOA, SRV, CAA)
   - Email security: SPF record, DMARC record, DKIM record
   - CAA records (Certificate Authority Authorization)
   - Information leakage in TXT records
5. **Zone transfer attempt** with `test_zone_transfer`
   - Tests all authoritative nameservers
   - A successful transfer is a high-severity finding
6. **DNSSEC verification** with `check_dnssec`
   - DNSKEY and DS record presence
   - RRSIG validation
   - NSEC/NSEC3 configuration

### Phase 3: Subdomain Takeover
7. **Takeover detection** with `detect_subdomain_takeover`
   - Pass subdomains from recon agent context if available
   - Checks CNAME targets against known vulnerable services
   - Verifies whether the target service has been deprovisioned

### Phase 4: HTTP Protocol Attacks
8. **HTTP smuggling** with `test_http_smuggling`
   - CL.TE: Content-Length vs Transfer-Encoding desync
   - TE.CL: Transfer-Encoding vs Content-Length desync
   - TE.TE: Transfer-Encoding obfuscation desync
   - Only test on targets behind CDN/proxy/load balancer

### Phase 5: Cloud Infrastructure
9. **Cloud metadata probing** with `test_cloud_metadata`
   - AWS IMDSv1 (169.254.169.254) and IMDSv2 (token-based)
   - GCP metadata (metadata.google.internal)
   - Azure IMDS (169.254.169.254 with Metadata: true header)
   - Test via SSRF-vulnerable parameters if applicable
10. **S3 bucket testing** with `check_s3_bucket`
    - Test bucket names found in HTML, JavaScript, DNS, or headers
    - Check public listing, read access, ACL exposure, bucket policy

### Phase 6: Service Analysis
11. **Port scan** with `scan_ports` (if not done by recon)
12. **Service fingerprinting** with `fingerprint_services`
13. **Technology detection** with `web_technology_scan`
    - Identify CDN provider (CloudFront, Cloudflare, Akamai, Fastly)
    - Identify cloud hosting (AWS, GCP, Azure)
    - Identify web server software and version

## SSL/TLS Analysis Methodology

### Protocol Testing
| Protocol | Expected Status | Severity if Enabled |
|----------|----------------|---------------------|
| SSLv2 | Disabled | Critical |
| SSLv3 | Disabled | High (POODLE) |
| TLS 1.0 | Disabled | Medium (PCI-DSS non-compliant) |
| TLS 1.1 | Disabled | Medium (deprecated) |
| TLS 1.2 | Enabled | - |
| TLS 1.3 | Enabled (preferred) | - |

### Vulnerability Checks
| Vulnerability | CVE | Severity |
|--------------|-----|----------|
| Heartbleed | CVE-2014-0160 | Critical |
| ROBOT | CVE-2017-13099 | High |
| POODLE | CVE-2014-3566 | High |
| DROWN | CVE-2016-0800 | High |
| BEAST | CVE-2011-3389 | Medium |
| CRIME | CVE-2012-4929 | Medium |
| BREACH | CVE-2013-3587 | Medium |
| LUCKY13 | CVE-2013-0169 | Low |

### Cipher Suite Classification
| Category | Examples | Severity |
|----------|----------|----------|
| NULL ciphers | TLS_NULL_WITH_NULL_NULL | Critical |
| Export ciphers | TLS_RSA_EXPORT_WITH_RC4_40_MD5 | High |
| DES/3DES | TLS_RSA_WITH_DES_CBC_SHA | High |
| RC4 | TLS_RSA_WITH_RC4_128_SHA | High |
| CBC without AEAD | TLS_RSA_WITH_AES_128_CBC_SHA | Medium |
| AEAD (GCM/CCM) | TLS_AES_128_GCM_SHA256 | OK |
| ChaCha20-Poly1305 | TLS_CHACHA20_POLY1305_SHA256 | OK |

## DNS Security Methodology

### Zone Transfer
- Attempt AXFR against all NS records for the domain
- A successful transfer exposes: all hostnames, IP addresses, mail servers, TXT records, internal naming conventions
- Severity: High (full information disclosure)
- Remediation: Restrict zone transfers to authorized secondary nameservers using allow-transfer ACLs

### DNSSEC
- Verify DNSKEY record presence (public signing key)
- Verify DS record at the registrar (delegation signer)
- Check RRSIG records (signed responses)
- Missing DNSSEC enables: DNS cache poisoning, man-in-the-middle, response spoofing
- Severity: Medium
- Remediation: Enable DNSSEC with the DNS provider and register DS records at the registrar

### Email Security Records
| Record | Purpose | If Missing |
|--------|---------|------------|
| SPF | Specifies authorized senders | Email spoofing possible (Medium) |
| DKIM | Cryptographic email signing | Email integrity not verifiable (Low) |
| DMARC | Policy for SPF/DKIM failures | No enforcement of email auth (Medium) |
| CAA | Restricts which CAs can issue certs | Any CA can issue certificates (Low) |

## Cloud Metadata Probing Methodology

### AWS Instance Metadata Service (IMDS)
- **IMDSv1** (no authentication): `curl http://169.254.169.254/latest/meta-data/`
- **IMDSv2** (token required): `PUT http://169.254.169.254/latest/api/token` with TTL header
- **High-value endpoints**:
  - `/latest/meta-data/iam/security-credentials/` (IAM role credentials)
  - `/latest/user-data` (often contains secrets, scripts, configuration)
  - `/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance`
- Severity: Critical if IAM credentials are exposed

### GCP Metadata
- Requires `Metadata-Flavor: Google` header
- **High-value endpoints**:
  - `/computeMetadata/v1/instance/service-accounts/default/token` (OAuth2 token)
  - `/computeMetadata/v1/project/attributes/` (project-level secrets)

### Azure IMDS
- Requires `Metadata: true` header
- **High-value endpoints**:
  - `/metadata/instance?api-version=2021-02-01` (instance details)
  - `/metadata/identity/oauth2/token` (managed identity token)

## HTTP Smuggling Methodology

### When to Test
- Target is behind a CDN (CloudFront, Cloudflare, Akamai)
- Target uses a reverse proxy (nginx, HAProxy, Apache)
- Multiple `Server` headers are present
- Different HTTP versions between front-end and back-end

### Techniques
| Technique | Description | Detection Method |
|-----------|-------------|-----------------|
| CL.TE | Front-end uses Content-Length, back-end uses Transfer-Encoding | Timing-based response delay |
| TE.CL | Front-end uses Transfer-Encoding, back-end uses Content-Length | Timing-based response delay |
| TE.TE | Both use Transfer-Encoding but one is obfuscated | Obfuscated TE header parsing |

### Impact
- Cache poisoning (serve malicious content to other users)
- Request hijacking (steal other users' requests)
- Access control bypass (reach internal endpoints)
- Severity: High

## Subdomain Takeover Detection

### Vulnerable Services
| Service | CNAME Pattern | Detection Signal |
|---------|--------------|-----------------|
| AWS S3 | *.s3.amazonaws.com | "NoSuchBucket" error |
| GitHub Pages | *.github.io | 404 with "There isn't a GitHub Pages site here" |
| Heroku | *.herokuapp.com | "No such app" error |
| Azure | *.azurewebsites.net | Default Azure page or error |
| Shopify | shops.myshopify.com | Shopify "Sorry, this shop is unavailable" |
| Fastly | *.fastly.net | Fastly "Fastly error: unknown domain" |

### Severity: High
An attacker can claim the deprovisioned service and serve malicious content under your domain, including:
- Phishing pages that pass domain validation
- Cookie theft (if parent domain cookies are accessible)
- Email interception (if MX records point to the subdomain)

## Best Practices

1. **Start with SSL/TLS for HTTPS targets**
   - SSL/TLS issues affect all subsequent testing
   - Certificate problems may indicate larger infrastructure issues

2. **Check DNS for every domain**
   - Zone transfer is a quick check with high impact
   - Email security records are often overlooked
   - CAA records prevent unauthorized certificate issuance

3. **Verify cloud hosting before metadata probing**
   - Use `web_technology_scan` to detect AWS/GCP/Azure
   - Only probe relevant metadata endpoints
   - IMDSv2 enforcement is the primary mitigation for AWS

4. **HTTP smuggling only behind proxies**
   - Look for CDN/proxy indicators before testing
   - Non-destructive detection via timing
   - Document the proxy architecture in findings

5. **Subdomain takeover requires action**
   - High-severity findings that need immediate remediation
   - Document the exact CNAME and target service
   - Recommend either removing the CNAME or re-provisioning the service

6. **Evidence for every finding**
   - Include tool output, not just pass/fail
   - Show specific protocol versions, cipher names, DNS records
   - Provide remediation commands where possible

## Output Format

The Infrastructure Security Agent adds the following to context:

```json
{
  "infraSecurityResults": {
    "sslTls": {
      "protocols": {
        "SSLv2": false,
        "SSLv3": false,
        "TLS1.0": true,
        "TLS1.1": true,
        "TLS1.2": true,
        "TLS1.3": true
      },
      "vulnerabilities": ["TLS 1.0 enabled", "TLS 1.1 enabled"],
      "certificate": {
        "valid": true,
        "expiresIn": "180 days",
        "algorithm": "RSA 2048",
        "issuer": "Let's Encrypt"
      },
      "weakCiphers": ["TLS_RSA_WITH_AES_128_CBC_SHA"]
    },
    "dns": {
      "zoneTransfer": "failed (properly restricted)",
      "dnssec": "not deployed",
      "spf": "present",
      "dmarc": "not present",
      "dkim": "not present",
      "caa": "not present"
    },
    "subdomainTakeover": {
      "tested": 16,
      "vulnerable": 0,
      "candidates": []
    },
    "cloudMetadata": {
      "provider": "AWS",
      "imdsExposed": false,
      "s3Buckets": []
    },
    "httpSmuggling": {
      "tested": true,
      "vulnerable": false
    },
    "findings": []
  }
}
```
