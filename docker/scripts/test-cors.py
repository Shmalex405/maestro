#!/usr/bin/env python3
"""CORS misconfiguration testing.

Tests for Origin reflection, null origin, credentials inclusion,
wildcard check, and subdomain variations.

Usage:
    python3 test-cors.py '{"target": "https://example.com", "origins": ["https://evil.com", "null"]}'
"""

import sys
import json
import requests
import urllib3
from urllib.parse import urlparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_ORIGINS = [
    "https://evil.com",
    "null",
    "https://attacker.example.com",
    "http://localhost",
    "https://example.com.attacker.com",
]

TIMEOUT = 10


def test_origin(target, origin, headers=None):
    """Send a request with a specific Origin header and analyze the response."""
    req_headers = {"Origin": origin}
    if headers:
        req_headers.update(headers)

    try:
        resp = requests.get(target, headers=req_headers, timeout=TIMEOUT, verify=False, allow_redirects=True)
    except requests.RequestException as e:
        return {"origin": origin, "error": str(e)}

    acao = resp.headers.get("Access-Control-Allow-Origin", "")
    acac = resp.headers.get("Access-Control-Allow-Credentials", "")
    acam = resp.headers.get("Access-Control-Allow-Methods", "")
    acah = resp.headers.get("Access-Control-Allow-Headers", "")
    aceh = resp.headers.get("Access-Control-Expose-Headers", "")

    result = {
        "origin_sent": origin,
        "acao": acao,
        "acac": acac,
        "acam": acam,
        "acah": acah,
        "aceh": aceh,
        "status_code": resp.status_code,
        "reflected": acao == origin,
        "wildcard": acao == "*",
        "credentials_with_reflection": (acao == origin and acac.lower() == "true"),
        "credentials_with_wildcard": (acao == "*" and acac.lower() == "true"),
    }

    vulnerabilities = []
    if result["reflected"] and origin not in ("null",):
        vulnerabilities.append("origin_reflection")
    if result["reflected"] and origin == "null":
        vulnerabilities.append("null_origin_reflected")
    if result["credentials_with_reflection"]:
        vulnerabilities.append("credentials_with_reflected_origin")
    if result["credentials_with_wildcard"]:
        vulnerabilities.append("credentials_with_wildcard")

    result["vulnerabilities"] = vulnerabilities
    return result


def test_preflight(target, origin, method="PUT"):
    """Send an OPTIONS preflight request."""
    req_headers = {
        "Origin": origin,
        "Access-Control-Request-Method": method,
        "Access-Control-Request-Headers": "Authorization, Content-Type",
    }

    try:
        resp = requests.options(target, headers=req_headers, timeout=TIMEOUT, verify=False)
    except requests.RequestException as e:
        return {"origin": origin, "preflight": True, "error": str(e)}

    acao = resp.headers.get("Access-Control-Allow-Origin", "")
    acac = resp.headers.get("Access-Control-Allow-Credentials", "")
    acam = resp.headers.get("Access-Control-Allow-Methods", "")

    return {
        "origin_sent": origin,
        "preflight": True,
        "method_requested": method,
        "acao": acao,
        "acac": acac,
        "acam": acam,
        "status_code": resp.status_code,
        "reflected": acao == origin,
        "allows_method": method in acam if acam else False,
    }


def generate_subdomain_origins(target):
    """Generate subdomain-based origin variations for the target domain."""
    parsed = urlparse(target)
    domain = parsed.hostname or ""
    parts = domain.split(".")
    if len(parts) < 2:
        return []

    base = ".".join(parts[-2:])
    return [
        f"https://evil.{base}",
        f"https://sub.evil.{base}",
        f"https://{base}.evil.com",
        f"https://test.{domain}",
        f"http://{domain}",  # HTTP downgrade
    ]


def main():
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Usage: test-cors.py '{\"target\": \"...\"}'"}))
        sys.exit(1)

    try:
        args = json.loads(sys.argv[1])
    except json.JSONDecodeError as e:
        print(json.dumps({"error": f"Invalid JSON arguments: {str(e)}"}))
        sys.exit(1)

    target = args.get("target")
    if not target:
        print(json.dumps({"error": "Missing required parameter: target"}))
        sys.exit(1)

    custom_origins = args.get("origins", [])
    headers = args.get("headers", {})
    test_preflight_flag = args.get("test_preflight", True)

    # Build full origins list
    origins = list(set(DEFAULT_ORIGINS + custom_origins + generate_subdomain_origins(target)))

    results = []
    vulnerabilities_found = []

    for origin in origins:
        result = test_origin(target, origin, headers)
        results.append(result)
        if result.get("vulnerabilities"):
            vulnerabilities_found.extend(result["vulnerabilities"])

        if test_preflight_flag:
            preflight_result = test_preflight(target, origin)
            results.append(preflight_result)

    # Deduplicate vulnerability types
    unique_vulns = list(set(vulnerabilities_found))

    severity = "info"
    if "credentials_with_reflected_origin" in unique_vulns:
        severity = "high"
    elif "credentials_with_wildcard" in unique_vulns:
        severity = "high"
    elif "origin_reflection" in unique_vulns:
        severity = "medium"
    elif "null_origin_reflected" in unique_vulns:
        severity = "medium"

    output = {
        "target": target,
        "tests_run": len(results),
        "origins_tested": len(origins),
        "vulnerabilities": unique_vulns,
        "severity": severity,
        "results": results,
        "summary": f"Tested {len(origins)} origins against {target}. Found {len(unique_vulns)} unique vulnerability types.",
    }

    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
