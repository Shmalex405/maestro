#!/usr/bin/env python3
"""Subdomain takeover detection.

Checks CNAME records for subdomains and matches them against known-vulnerable
services. Detects unclaimed/available CNAME targets and NXDOMAIN conditions.

Usage:
    python3 subdomain-takeover.py '{"subdomains": ["old.example.com", "staging.example.com"]}'
"""

import sys
import json
import subprocess
import socket
import requests
import urllib3
from urllib.parse import urlparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TIMEOUT = 10

# Known-vulnerable services and their detection signatures
VULNERABLE_SERVICES = {
    # Service pattern -> (service name, CNAME pattern, detection method, fingerprint)
    "s3.amazonaws.com": {
        "service": "AWS S3",
        "fingerprint": "NoSuchBucket",
        "check_url": True,
    },
    ".s3-website": {
        "service": "AWS S3 Website",
        "fingerprint": "NoSuchBucket",
        "check_url": True,
    },
    "amazonaws.com": {
        "service": "AWS (Generic)",
        "fingerprint": "NoSuchBucket",
        "check_url": True,
    },
    ".herokuapp.com": {
        "service": "Heroku",
        "fingerprint": "no-such-app.html",
        "check_url": True,
    },
    ".herokudns.com": {
        "service": "Heroku DNS",
        "fingerprint": "no-such-app.html",
        "check_url": True,
    },
    "github.io": {
        "service": "GitHub Pages",
        "fingerprint": "There isn't a GitHub Pages site here",
        "check_url": True,
    },
    ".ghost.io": {
        "service": "Ghost",
        "fingerprint": "Domain is not configured",
        "check_url": True,
    },
    ".pantheonsite.io": {
        "service": "Pantheon",
        "fingerprint": "404 error unknown site",
        "check_url": True,
    },
    ".tumblr.com": {
        "service": "Tumblr",
        "fingerprint": "Whatever you were looking for doesn't currently exist",
        "check_url": True,
    },
    ".shopify.com": {
        "service": "Shopify",
        "fingerprint": "Sorry, this shop is currently unavailable",
        "check_url": True,
    },
    ".myshopify.com": {
        "service": "Shopify",
        "fingerprint": "Sorry, this shop is currently unavailable",
        "check_url": True,
    },
    ".surge.sh": {
        "service": "Surge.sh",
        "fingerprint": "project not found",
        "check_url": True,
    },
    ".bitbucket.io": {
        "service": "Bitbucket",
        "fingerprint": "Repository not found",
        "check_url": True,
    },
    ".wordpress.com": {
        "service": "WordPress.com",
        "fingerprint": "Do you want to register",
        "check_url": True,
    },
    ".azurewebsites.net": {
        "service": "Azure Web Apps",
        "fingerprint": "404 Web Site not found",
        "check_url": True,
    },
    ".cloudapp.net": {
        "service": "Azure Cloud App",
        "fingerprint": "",
        "check_url": False,
    },
    ".trafficmanager.net": {
        "service": "Azure Traffic Manager",
        "fingerprint": "",
        "check_url": False,
    },
    ".blob.core.windows.net": {
        "service": "Azure Blob Storage",
        "fingerprint": "BlobNotFound",
        "check_url": True,
    },
    ".cloudfront.net": {
        "service": "AWS CloudFront",
        "fingerprint": "Bad Request",
        "check_url": True,
    },
    ".elasticbeanstalk.com": {
        "service": "AWS Elastic Beanstalk",
        "fingerprint": "",
        "check_url": False,
    },
    ".zendesk.com": {
        "service": "Zendesk",
        "fingerprint": "Help Center Closed",
        "check_url": True,
    },
    ".teamwork.com": {
        "service": "Teamwork",
        "fingerprint": "Oops - We didn't find your site",
        "check_url": True,
    },
    ".helpjuice.com": {
        "service": "Helpjuice",
        "fingerprint": "We could not find what you're looking for",
        "check_url": True,
    },
    ".helpscoutdocs.com": {
        "service": "HelpScout",
        "fingerprint": "No settings were found for this company",
        "check_url": True,
    },
    ".feedpress.me": {
        "service": "FeedPress",
        "fingerprint": "The feed has not been found",
        "check_url": True,
    },
    ".freshdesk.com": {
        "service": "Freshdesk",
        "fingerprint": "May not exist or is no longer available",
        "check_url": True,
    },
    ".fly.dev": {
        "service": "Fly.io",
        "fingerprint": "404 Not Found",
        "check_url": True,
    },
    ".netlify.app": {
        "service": "Netlify",
        "fingerprint": "Not Found",
        "check_url": True,
    },
    ".vercel.app": {
        "service": "Vercel",
        "fingerprint": "404",
        "check_url": True,
    },
    ".render.com": {
        "service": "Render",
        "fingerprint": "not found",
        "check_url": True,
    },
    ".onrender.com": {
        "service": "Render",
        "fingerprint": "not found",
        "check_url": True,
    },
}


def resolve_cname(domain):
    """Resolve CNAME records for a domain using dig/nslookup."""
    cnames = []
    error = None

    # Try using dig first
    try:
        result = subprocess.run(
            ["dig", "+short", "CNAME", domain],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0 and result.stdout.strip():
            for line in result.stdout.strip().split("\n"):
                cname = line.strip().rstrip(".")
                if cname:
                    cnames.append(cname)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    # Fallback to nslookup
    if not cnames:
        try:
            result = subprocess.run(
                ["nslookup", "-type=CNAME", domain],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0:
                for line in result.stdout.split("\n"):
                    if "canonical name" in line.lower():
                        parts = line.split("=")
                        if len(parts) > 1:
                            cname = parts[-1].strip().rstrip(".")
                            if cname:
                                cnames.append(cname)
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

    # Fallback to Python socket
    if not cnames:
        try:
            answers = socket.getaddrinfo(domain, None)
            # getaddrinfo doesn't directly give CNAME, but we can detect if it resolves
        except socket.gaierror as e:
            if "NXDOMAIN" in str(e) or "Name or service not known" in str(e):
                error = "NXDOMAIN"
            else:
                error = str(e)

    return cnames, error


def check_nxdomain(domain):
    """Check if a domain returns NXDOMAIN (does not exist)."""
    try:
        socket.getaddrinfo(domain, None)
        return False
    except socket.gaierror:
        return True


def check_http_fingerprint(domain, fingerprint):
    """Check if a domain's HTTP response matches a known takeover fingerprint."""
    if not fingerprint:
        return {"checked": False, "reason": "No fingerprint defined"}

    for scheme in ["https", "http"]:
        try:
            resp = requests.get(
                f"{scheme}://{domain}",
                timeout=TIMEOUT,
                verify=False,
                allow_redirects=True,
            )
            if fingerprint.lower() in resp.text.lower():
                return {
                    "checked": True,
                    "matched": True,
                    "fingerprint": fingerprint,
                    "scheme": scheme,
                    "status_code": resp.status_code,
                    "response_preview": resp.text[:300],
                }
        except requests.RequestException:
            continue

    return {"checked": True, "matched": False, "fingerprint": fingerprint}


def check_subdomain(subdomain):
    """Full check for a single subdomain."""
    result = {
        "subdomain": subdomain,
        "cnames": [],
        "nxdomain": False,
        "vulnerable_service": None,
        "takeover_possible": False,
        "confidence": "none",
        "details": {},
    }

    # Step 1: Resolve CNAME
    cnames, dns_error = resolve_cname(subdomain)
    result["cnames"] = cnames
    result["dns_error"] = dns_error

    if dns_error == "NXDOMAIN":
        result["nxdomain"] = True
        result["details"]["note"] = "Domain returns NXDOMAIN - may already be unconfigured"

    # Step 2: Check CNAME targets against known vulnerable services
    for cname in cnames:
        cname_lower = cname.lower()

        for pattern, service_info in VULNERABLE_SERVICES.items():
            if pattern.lower() in cname_lower:
                result["vulnerable_service"] = service_info["service"]
                result["details"]["cname_target"] = cname
                result["details"]["matched_pattern"] = pattern

                # Step 3: Check if CNAME target is NXDOMAIN (unclaimed)
                cname_nxdomain = check_nxdomain(cname)
                result["details"]["cname_nxdomain"] = cname_nxdomain

                if cname_nxdomain:
                    result["takeover_possible"] = True
                    result["confidence"] = "high"
                    result["details"]["reason"] = f"CNAME target {cname} returns NXDOMAIN - likely unclaimed"
                elif service_info.get("check_url"):
                    # Step 4: Check HTTP fingerprint
                    http_check = check_http_fingerprint(subdomain, service_info["fingerprint"])
                    result["details"]["http_check"] = http_check

                    if http_check.get("matched"):
                        result["takeover_possible"] = True
                        result["confidence"] = "high"
                        result["details"]["reason"] = f"HTTP response matches {service_info['service']} takeover fingerprint"
                    else:
                        result["confidence"] = "low"
                        result["details"]["reason"] = f"CNAME points to {service_info['service']} but fingerprint not matched"
                else:
                    result["confidence"] = "medium"
                    result["details"]["reason"] = f"CNAME points to {service_info['service']} - manual verification needed"

                break  # Found matching service, stop checking others

    # If no CNAME but domain has NXDOMAIN, check if subdomain itself could be taken over
    if not cnames and result["nxdomain"]:
        result["confidence"] = "low"
        result["details"]["note"] = "No CNAME found but domain is NXDOMAIN - may be a dangling DNS record"

    return result


def main():
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Usage: subdomain-takeover.py '{\"subdomains\": [\"old.example.com\"]}' "}))
        sys.exit(1)

    try:
        args = json.loads(sys.argv[1])
    except json.JSONDecodeError as e:
        print(json.dumps({"error": f"Invalid JSON arguments: {str(e)}"}))
        sys.exit(1)

    subdomains = args.get("subdomains", [])
    if not subdomains:
        print(json.dumps({"error": "Missing required parameter: subdomains (list)"}))
        sys.exit(1)

    results = []
    vulnerable = []

    for subdomain in subdomains:
        # Clean up subdomain
        subdomain = subdomain.strip().lower()
        if subdomain.startswith("http://") or subdomain.startswith("https://"):
            subdomain = urlparse(subdomain).hostname

        result = check_subdomain(subdomain)
        results.append(result)

        if result["takeover_possible"]:
            vulnerable.append({
                "subdomain": subdomain,
                "service": result["vulnerable_service"],
                "confidence": result["confidence"],
                "cnames": result["cnames"],
            })

    # Determine severity
    severity = "info"
    if any(v["confidence"] == "high" for v in vulnerable):
        severity = "critical"
    elif any(v["confidence"] == "medium" for v in vulnerable):
        severity = "high"
    elif vulnerable:
        severity = "medium"

    output = {
        "subdomains_checked": len(subdomains),
        "vulnerable_count": len(vulnerable),
        "severity": severity,
        "vulnerable": vulnerable,
        "results": results,
        "summary": (
            f"Checked {len(subdomains)} subdomains for takeover vulnerabilities. "
            f"Found {len(vulnerable)} potentially vulnerable: "
            f"{[v['subdomain'] for v in vulnerable] if vulnerable else 'none'}."
        ),
    }

    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
