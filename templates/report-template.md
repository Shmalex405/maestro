# Security Assessment Report

**Assessment Date:** {{date}}
**Scope:** {{scope}}
**Prepared By:** Automated Security Testing System

---

## Executive Summary

This report presents the findings from an automated security assessment of the defined scope.

| Severity | Count |
|----------|-------|
| Critical | {{critical_count}} |
| High | {{high_count}} |
| Medium | {{medium_count}} |
| Low | {{low_count}} |
| Info | {{info_count}} |

## Scope

The following targets were included in this assessment:

### Networks
{{#each networks}}
- {{this.cidr}} ({{this.environment}})
{{/each}}

### Domains
{{#each domains}}
- {{this.pattern}} ({{this.environment}})
{{/each}}

## Methodology

The assessment utilized the following tools and techniques:
- **Reconnaissance:** nmap, subfinder, amass, httpx
- **Vulnerability Scanning:** nuclei, nikto, wpscan
- **Web Application Testing:** sqlmap, ffuf, xsstrike
- **Exploitation Validation:** metasploit (check mode), custom scripts

## Findings

{{#each findings}}
### {{this.title}}

**Severity:** {{this.severity}}
**Target:** {{this.target}}
{{#if this.cve}}**CVE:** {{this.cve}}{{/if}}

{{this.description}}

{{#if this.evidence}}
**Evidence:**
```
{{this.evidence}}
```
{{/if}}

**Remediation:**
{{this.remediation}}

---
{{/each}}

## Appendix

### Tool Versions
- nmap: Latest
- nuclei: Latest with updated templates
- sqlmap: Latest

### Disclaimer
This assessment was performed in a controlled environment against test systems only.
