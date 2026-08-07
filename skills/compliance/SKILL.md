# Compliance Agent Skill

## Purpose

The Compliance Agent maps security findings to industry compliance frameworks and calculates CVSS v3.1 scores. It is a read-only analysis agent that does not perform scanning. It receives findings from other agents and produces compliance mappings, coverage matrices, and gap analyses to help organizations understand their security posture in regulatory context.

## When to Use

- After findings are collected from scanning agents (recon, vuln-scan, web-app, security-scan)
- Before or during report generation to enrich findings with compliance metadata
- When the assessment needs to demonstrate compliance coverage (PCI-DSS, NIST, OWASP)
- When CVSS v3.1 base scores are needed for vulnerability prioritization
- When management requires a compliance coverage matrix showing tested vs untested controls
- As part of the full assessment workflow after QA validation

## Input Format

The Compliance Agent receives context containing:
- `findings[]` - All findings from prior agents (with title, severity, target, description, CWE, CVE)
- Standard shared context (assessment info, targets, etc.)

The agent does NOT receive tools for scanning. It uses `create_finding` to persist enriched findings and `generate_report` to produce compliance-focused reports.

## Available Tools

| Tool | Description |
|------|-------------|
| `create_finding` | Persist compliance-enriched findings with CWE, CVSS vector, and framework mappings |
| `generate_report` | Generate compliance-focused report with framework mappings and coverage matrices |

## Methodology

### Step 1: CWE Assignment

Assign the most specific Common Weakness Enumeration identifier to each finding.

#### Common CWE Mappings

| Vulnerability Type | CWE | Name |
|-------------------|-----|------|
| SQL Injection | CWE-89 | Improper Neutralization of Special Elements used in an SQL Command |
| Cross-Site Scripting (XSS) | CWE-79 | Improper Neutralization of Input During Web Page Generation |
| Command Injection | CWE-78 | Improper Neutralization of Special Elements used in an OS Command |
| Path Traversal | CWE-22 | Improper Limitation of a Pathname to a Restricted Directory |
| SSRF | CWE-918 | Server-Side Request Forgery |
| CSRF | CWE-352 | Cross-Site Request Forgery |
| IDOR | CWE-639 | Authorization Bypass Through User-Controlled Key |
| Authentication Bypass | CWE-287 | Improper Authentication |
| Broken Access Control | CWE-284 | Improper Access Control |
| Sensitive Data Exposure | CWE-200 | Exposure of Sensitive Information to an Unauthorized Actor |
| Security Misconfiguration | CWE-16 | Configuration |
| Insecure Deserialization | CWE-502 | Deserialization of Untrusted Data |
| Missing Rate Limiting | CWE-770 | Allocation of Resources Without Limits or Throttling |
| Weak Cryptography | CWE-327 | Use of a Broken or Risky Cryptographic Algorithm |
| Hardcoded Credentials | CWE-798 | Use of Hard-coded Credentials |
| Missing HSTS | CWE-523 | Unprotected Transport of Credentials |
| Open Redirect | CWE-601 | URL Redirection to Untrusted Site |
| Weak Password Policy | CWE-521 | Weak Password Requirements |
| XXE | CWE-611 | Improper Restriction of XML External Entity Reference |
| SSTI | CWE-1336 | Improper Neutralization of Special Elements Used in a Template Engine |
| JWT Issues | CWE-347 | Improper Verification of Cryptographic Signature |
| Race Condition | CWE-362 | Concurrent Execution Using Shared Resource with Improper Synchronization |

#### CWE Assignment Rules
- Use the most specific CWE, not generic parent categories
- If a finding already has a CWE, verify correctness before keeping it
- A finding MUST have at least one CWE assigned

### Step 2: OWASP Top 10 2021 Mapping

Map each finding to the correct OWASP Top 10 2021 category.

| Category | Description | Example Findings |
|----------|-------------|-----------------|
| **A01:2021 - Broken Access Control** | Failures to enforce access restrictions | IDOR, privilege escalation, CORS misconfig, forced browsing, missing function-level access control |
| **A02:2021 - Cryptographic Failures** | Failures related to cryptography | Weak TLS, missing encryption at rest, weak hash algorithms, cleartext secrets, expired certificates |
| **A03:2021 - Injection** | Untrusted data sent to an interpreter | SQLi, XSS, command injection, LDAP injection, SSTI, header injection, NoSQL injection |
| **A04:2021 - Insecure Design** | Missing or ineffective design controls | Missing rate limiting, business logic flaws, missing anti-automation, no account lockout |
| **A05:2021 - Security Misconfiguration** | Insecure default or ad-hoc configurations | Verbose error messages, unnecessary features enabled, default credentials, missing security headers, open cloud storage |
| **A06:2021 - Vulnerable and Outdated Components** | Using components with known vulnerabilities | CVEs in dependencies, outdated libraries, end-of-life frameworks |
| **A07:2021 - Identification and Authentication Failures** | Authentication-related weaknesses | Weak passwords, session fixation, credential stuffing, missing MFA, JWT vulnerabilities |
| **A08:2021 - Software and Data Integrity Failures** | Code and data integrity violations | Insecure deserialization, unsigned updates, CI/CD pipeline vulnerabilities, dependency confusion |
| **A09:2021 - Security Logging and Monitoring Failures** | Insufficient logging and monitoring | Missing audit logs, unmonitored security events, no alerting on suspicious activity |
| **A10:2021 - Server-Side Request Forgery** | SSRF vulnerabilities | SSRF to internal services, cloud metadata access, internal port scanning via SSRF |

### Step 3: OWASP API Top 10 Mapping

Map API-related findings to the OWASP API Security Top 10 2023.

| Category | Description | Example Findings |
|----------|-------------|-----------------|
| **API1:2023 - Broken Object Level Authorization** | Missing object-level access checks | IDOR on API endpoints, accessing other users' resources |
| **API2:2023 - Broken Authentication** | Weak API authentication mechanisms | Missing auth on endpoints, weak API keys, JWT 'none' algorithm |
| **API3:2023 - Broken Object Property Level Authorization** | Exposing/allowing modification of object properties | Mass assignment, excessive data exposure in responses |
| **API4:2023 - Unrestricted Resource Consumption** | No limits on resource usage | Missing rate limiting, no pagination, unbounded queries |
| **API5:2023 - Broken Function Level Authorization** | Missing function-level access control | Admin functions accessible to regular users, privilege escalation |
| **API6:2023 - Unrestricted Access to Sensitive Business Flows** | Business logic abuse | Automated purchase flows, scraping, bulk operations without limits |
| **API7:2023 - Server-Side Request Forgery** | SSRF through API parameters | URL fetch parameters, webhook URLs, file import from URL |
| **API8:2023 - Security Misconfiguration** | API-specific misconfigurations | Overly permissive CORS, verbose API errors, GraphQL introspection enabled |
| **API9:2023 - Improper Inventory Management** | Unmanaged API endpoints | Deprecated API versions, shadow APIs, undocumented endpoints |
| **API10:2023 - Unsafe Consumption of APIs** | Trusting third-party API data | Blind trust of external API responses without validation |

### Step 4: CVSS v3.1 Vector Calculation

Calculate the CVSS v3.1 base score vector for each finding.

#### Vector Format
```
CVSS:3.1/AV:{N|A|L|P}/AC:{L|H}/PR:{N|L|H}/UI:{N|R}/S:{U|C}/C:{N|L|H}/I:{N|L|H}/A:{N|L|H}
```

#### Component Definitions

| Component | Values | Description |
|-----------|--------|-------------|
| **AV** (Attack Vector) | N=Network, A=Adjacent, L=Local, P=Physical | How the vulnerability is exploited |
| **AC** (Attack Complexity) | L=Low, H=High | Conditions beyond attacker control required |
| **PR** (Privileges Required) | N=None, L=Low, H=High | Level of access needed before exploitation |
| **UI** (User Interaction) | N=None, R=Required | Whether a user must take action |
| **S** (Scope) | U=Unchanged, C=Changed | Whether the vulnerability impacts beyond the vulnerable component |
| **C** (Confidentiality) | N=None, L=Low, H=High | Impact on information confidentiality |
| **I** (Integrity) | N=None, L=Low, H=High | Impact on information integrity |
| **A** (Availability) | N=None, L=Low, H=High | Impact on system availability |

#### Common CVSS Vectors

| Vulnerability | Vector | Score |
|--------------|--------|-------|
| SQL Injection (unauth) | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N | 9.1 |
| SQL Injection (auth) | CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N | 8.1 |
| XSS Reflected | CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N | 6.1 |
| XSS Stored | CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N | 5.4 |
| SSRF (internal) | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N | 8.6 |
| SSRF (to cloud metadata) | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N | 10.0 |
| IDOR (data read) | CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N | 6.5 |
| IDOR (data modify) | CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N | 7.1 |
| CSRF | CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N | 6.5 |
| Missing Rate Limiting | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L | 5.3 |
| Missing Rate Limiting (auth) | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N | 5.3 |
| Weak TLS (TLS 1.0) | CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N | 5.9 |
| Heartbleed | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N | 7.5 |
| Zone Transfer | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N | 5.3 |
| Subdomain Takeover | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N | 7.2 |
| Missing HSTS | CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N | 6.8 |
| Hardcoded Credentials | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H | 9.8 |
| S3 Bucket Public Write | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N | 7.5 |

#### Severity-CVSS Consistency Rules
| Severity | Expected CVSS Range |
|----------|-------------------|
| Critical | 9.0 - 10.0 |
| High | 7.0 - 8.9 |
| Medium | 4.0 - 6.9 |
| Low | 0.1 - 3.9 |
| Info | No CVSS required |

If the calculated CVSS contradicts the assigned severity, note the discrepancy in the mapping.

### Step 5: NIST 800-53 Control Family Mapping

Map findings to the relevant NIST 800-53 Rev. 5 control families.

| Control Family | Code | Relevant Finding Types |
|---------------|------|----------------------|
| Access Control | AC | IDOR, broken access control, privilege escalation, missing auth |
| Audit and Accountability | AU | Missing logging, no audit trail, insufficient monitoring |
| Assessment, Authorization, Monitoring | CA | Assessment coverage gaps, untested controls |
| Configuration Management | CM | Misconfigurations, default settings, unnecessary features |
| Identification and Authentication | IA | Auth bypass, weak passwords, session issues, JWT flaws |
| Incident Response | IR | Missing detection, no alerting, insufficient response capability |
| Risk Assessment | RA | Unpatched CVEs, outdated components, unassessed risks |
| System and Communications Protection | SC | TLS issues, missing encryption, CORS, network segmentation |
| System and Information Integrity | SI | Injection flaws, input validation failures, deserialization |
| Media Protection | MP | Sensitive data in S3 buckets, file upload issues |
| Physical and Environmental Protection | PE | Physical access issues (rare in pentests) |

#### Specific Control Mappings

| Finding Type | NIST Control |
|-------------|-------------|
| SQL Injection | SI-10 (Information Input Validation) |
| XSS | SI-10, SC-18 (Mobile Code) |
| CSRF | SC-23 (Session Authenticity) |
| Weak TLS | SC-8 (Transmission Confidentiality and Integrity) |
| Missing Auth | IA-2 (Identification and Authentication) |
| IDOR | AC-3 (Access Enforcement) |
| Hardcoded Credentials | IA-5 (Authenticator Management) |
| Missing Logging | AU-2 (Event Logging), AU-3 (Content of Audit Records) |
| Missing Rate Limiting | SC-5 (Denial of Service Protection) |

### Step 6: PCI-DSS Requirement Mapping

Map findings to PCI-DSS v4.0 requirements.

| PCI-DSS Requirement | Relevant Finding Types |
|--------------------|----------------------|
| **Req 1**: Network security controls | Network segmentation, firewall rules, exposed services |
| **Req 2**: Secure configurations | Default credentials, unnecessary services, vendor defaults |
| **Req 3**: Protect stored account data | Data at rest encryption, key management, data retention |
| **Req 4**: Protect data in transit | Weak TLS, missing HSTS, cleartext transmission |
| **Req 5**: Protect from malicious software | Outdated AV, missing endpoint protection |
| **Req 6**: Develop secure systems | SQLi, XSS, injection flaws, insecure code practices |
| **Req 7**: Restrict access by business need | IDOR, broken access control, excessive permissions |
| **Req 8**: Identify and authenticate access | Weak auth, missing MFA, session management issues |
| **Req 9**: Restrict physical access | Physical security (rarely in scope for pentests) |
| **Req 10**: Log and monitor all access | Missing logging, insufficient monitoring, no alerting |
| **Req 11**: Test security regularly | Assessment coverage, vulnerability scanning gaps |
| **Req 12**: Support security with policies | Organizational policy gaps |

### Step 7: Compliance Coverage Matrix

Generate a matrix showing which framework categories were tested.

```
| Framework | Category | Status | Finding Count |
|-----------|----------|--------|---------------|
| OWASP Top 10 | A01 Broken Access Control | Tested | 2 |
| OWASP Top 10 | A02 Cryptographic Failures | Tested | 1 |
| OWASP Top 10 | A03 Injection | Tested | 3 |
| OWASP Top 10 | A04 Insecure Design | Not Tested | 0 |
| ... | ... | ... | ... |
```

Status values:
- **Tested**: At least one relevant test was executed for this category
- **Tested Clean**: Tests executed, no findings (positive result)
- **Not Tested**: No tests were executed for this category (gap)

### Step 8: Gap Analysis

Identify untested controls and provide actionable recommendations.

For each gap:
1. Which framework category is untested
2. Why it matters (what attack vectors are missed)
3. What tests should be added
4. Priority (high/medium/low)

## Best Practices

1. **Precision Over Breadth**
   - Use the most specific CWE, not generic parents
   - Calculate CVSS accurately, do not estimate
   - Map to the primary OWASP category, not all possible ones

2. **Consistency Across Assessments**
   - Same vulnerability type should always get the same CWE
   - CVSS vectors should be consistent for similar findings
   - Severity ratings must align with CVSS scores

3. **Do Not Change Severity**
   - The compliance agent adds metadata, it does not override severity
   - If CVSS contradicts severity, note the discrepancy but keep original severity
   - Severity changes are the responsibility of the QA agent

4. **Coverage Gaps Are Findings Too**
   - Untested OWASP categories are actionable gaps
   - Missing PCI-DSS controls should be flagged
   - Distinguish "tested clean" from "not tested"

5. **Regulatory Context Matters**
   - PCI-DSS mapping is critical for payment-processing targets
   - NIST mapping is critical for government/regulated targets
   - OWASP mapping is universal and always relevant

## Output Format

The Compliance Agent adds `complianceMapping` to context:

```json
{
  "complianceMapping": {
    "findings": [
      {
        "findingId": "web-app-agent-1234",
        "title": "SQL Injection in User API",
        "severity": "critical",
        "cwe": "CWE-89",
        "cvssVector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "cvssScore": 9.1,
        "owaspTop10": "A03:2021 - Injection",
        "owaspApiTop10": "API8:2023 - Security Misconfiguration",
        "nist80053": "SI-10 (Information Input Validation)",
        "pciDss": "Req 6.2.4 - Prevent common software attacks"
      }
    ],
    "coverageMatrix": {
      "owaspTop10": {
        "A01": { "status": "tested", "findingCount": 2 },
        "A02": { "status": "tested", "findingCount": 1 },
        "A03": { "status": "tested", "findingCount": 3 },
        "A04": { "status": "not_tested", "findingCount": 0 },
        "A05": { "status": "tested", "findingCount": 1 },
        "A06": { "status": "tested_clean", "findingCount": 0 },
        "A07": { "status": "tested", "findingCount": 1 },
        "A08": { "status": "not_tested", "findingCount": 0 },
        "A09": { "status": "not_tested", "findingCount": 0 },
        "A10": { "status": "tested_clean", "findingCount": 0 }
      },
      "nist80053": {
        "AC": { "status": "tested", "findingCount": 2 },
        "IA": { "status": "tested", "findingCount": 1 },
        "SC": { "status": "tested", "findingCount": 2 },
        "SI": { "status": "tested", "findingCount": 3 }
      },
      "pciDss": {
        "Req 4": { "status": "tested", "findingCount": 1 },
        "Req 6": { "status": "tested", "findingCount": 4 },
        "Req 7": { "status": "tested", "findingCount": 2 },
        "Req 8": { "status": "tested", "findingCount": 1 }
      }
    },
    "gaps": [
      {
        "framework": "OWASP Top 10",
        "category": "A04:2021 - Insecure Design",
        "status": "not_tested",
        "recommendation": "Add business logic testing, rate limiting checks, and anti-automation testing",
        "priority": "medium"
      },
      {
        "framework": "OWASP Top 10",
        "category": "A09:2021 - Security Logging and Monitoring Failures",
        "status": "not_tested",
        "recommendation": "Review application logging configuration and monitoring setup",
        "priority": "low"
      }
    ],
    "summary": {
      "totalFindings": 8,
      "mappedToCWE": 8,
      "mappedToOWASP": 8,
      "mappedToNIST": 6,
      "mappedToPCIDSS": 5,
      "averageCVSS": 6.2,
      "owaspCoverage": "70% (7/10 categories tested)",
      "complianceCoverage": "70%"
    }
  }
}
```

The report agent uses this to:
- Include compliance mappings in the findings table
- Show CVSS scores alongside severity ratings
- Include the compliance coverage matrix as a report section
- Highlight gaps as recommendations
