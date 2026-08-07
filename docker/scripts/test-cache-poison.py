#!/usr/bin/env python3
"""Web cache poisoning detection.

Tests for unkeyed header injection, parameter cloaking, path normalization,
fat GET requests, and cache key manipulation.

Usage:
    python3 test-cache-poison.py '{"target": "https://example.com/page", "headers_to_test": ["X-Forwarded-Host", "X-Original-URL"]}'
"""

import sys
import json
import time
import random
import string
import hashlib
import requests
import urllib3
from urllib.parse import urlparse, urlencode

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TIMEOUT = 10

# Headers commonly used as unkeyed cache inputs
DEFAULT_UNKEYED_HEADERS = [
    "X-Forwarded-Host",
    "X-Host",
    "X-Forwarded-Server",
    "X-Original-URL",
    "X-Rewrite-URL",
    "X-Forwarded-Scheme",
    "X-Forwarded-Proto",
    "X-Original-Host",
    "X-Forwarded-For",
    "X-Real-IP",
    "X-Custom-IP-Authorization",
    "X-Originating-IP",
    "X-Remote-IP",
    "X-Client-IP",
    "X-Remote-Addr",
    "True-Client-IP",
    "CF-Connecting-IP",
    "Fastly-Client-IP",
    "X-Azure-ClientIP",
]


def random_string(length=8):
    """Generate a random string for cache busting."""
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))


def cache_buster_url(url):
    """Add a cache-busting parameter to URL."""
    sep = "&" if "?" in url else "?"
    return f"{url}{sep}cb={random_string()}"


def get_response_fingerprint(resp):
    """Create a fingerprint of the response for comparison."""
    return {
        "status_code": resp.status_code,
        "content_length": len(resp.content),
        "content_hash": hashlib.md5(resp.content).hexdigest()[:16],
        "headers": {
            k.lower(): v for k, v in resp.headers.items()
            if k.lower() in ("cache-control", "x-cache", "age", "vary",
                             "cf-cache-status", "x-cache-status", "x-varnish")
        },
    }


def check_caching(url, headers=None):
    """Check if the URL is being cached by comparing two requests."""
    req_headers = headers or {}
    try:
        resp1 = requests.get(url, headers=req_headers, timeout=TIMEOUT, verify=False)
        time.sleep(0.5)
        resp2 = requests.get(url, headers=req_headers, timeout=TIMEOUT, verify=False)
    except requests.RequestException as e:
        return {"cached": False, "error": str(e)}

    cache_indicators = {}
    for header in ["x-cache", "cf-cache-status", "x-cache-status", "age", "x-varnish"]:
        val1 = resp1.headers.get(header)
        val2 = resp2.headers.get(header)
        if val1 or val2:
            cache_indicators[header] = {"first": val1, "second": val2}

    # Check if Age header increased
    age1 = int(resp1.headers.get("age", 0) or 0)
    age2 = int(resp2.headers.get("age", 0) or 0)
    age_increased = age2 > age1

    # Check for HIT on second request
    cache_hit = False
    for header in ["x-cache", "cf-cache-status", "x-cache-status"]:
        val = (resp2.headers.get(header) or "").upper()
        if "HIT" in val:
            cache_hit = True

    return {
        "cached": cache_hit or age_increased,
        "cache_indicators": cache_indicators,
        "vary_header": resp1.headers.get("vary"),
        "cache_control": resp1.headers.get("cache-control"),
    }


def test_unkeyed_header(target, header_name, canary=None):
    """Test if a header is unkeyed (not part of cache key) and reflected."""
    if canary is None:
        canary = f"evil-{random_string()}.com"

    # Use cache buster to get a fresh cache entry
    test_url = cache_buster_url(target)

    # First request: inject the header
    inject_headers = {header_name: canary}
    try:
        resp1 = requests.get(test_url, headers=inject_headers, timeout=TIMEOUT, verify=False)
    except requests.RequestException as e:
        return {"header": header_name, "error": str(e)}

    body1 = resp1.text

    # Check if canary is reflected in response
    reflected = canary in body1

    # Second request: without the header (should get cached version)
    time.sleep(0.3)
    try:
        resp2 = requests.get(test_url, timeout=TIMEOUT, verify=False)
    except requests.RequestException as e:
        return {"header": header_name, "error": str(e), "reflected_on_inject": reflected}

    body2 = resp2.text

    # If canary appears in second response (without header), cache is poisoned
    poisoned = canary in body2

    return {
        "header": header_name,
        "canary": canary,
        "reflected_on_inject": reflected,
        "reflected_without_header": poisoned,
        "cache_poisoned": poisoned and reflected,
        "status_inject": resp1.status_code,
        "status_clean": resp2.status_code,
        "cache_headers_inject": {
            k: v for k, v in resp1.headers.items()
            if k.lower() in ("x-cache", "cf-cache-status", "age", "cache-control")
        },
        "cache_headers_clean": {
            k: v for k, v in resp2.headers.items()
            if k.lower() in ("x-cache", "cf-cache-status", "age", "cache-control")
        },
    }


def test_parameter_cloaking(target):
    """Test parameter cloaking with different separators."""
    canary = random_string()
    results = []

    # Different parameter separators that may confuse cache/origin
    separators = [
        (";", "semicolon"),
        ("%00", "null_byte"),
        ("%0a", "newline"),
        ("%23", "hash_encoded"),
    ]

    for sep, name in separators:
        test_url = cache_buster_url(target)
        cloak_url = f"{test_url}{sep}injected={canary}"

        try:
            resp = requests.get(cloak_url, timeout=TIMEOUT, verify=False)
            reflected = canary in resp.text
            results.append({
                "separator": name,
                "separator_char": sep,
                "reflected": reflected,
                "status_code": resp.status_code,
            })
        except requests.RequestException as e:
            results.append({"separator": name, "error": str(e)})

    return {
        "test": "parameter_cloaking",
        "results": results,
    }


def test_fat_get(target):
    """Test fat GET request (GET with body)."""
    canary = random_string()
    test_url = cache_buster_url(target)

    try:
        # Send GET with a body
        resp = requests.request(
            "GET", test_url,
            data=f"param={canary}",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=TIMEOUT, verify=False,
        )

        reflected = canary in resp.text

        # Check if cached response includes the body content
        time.sleep(0.3)
        resp2 = requests.get(test_url, timeout=TIMEOUT, verify=False)
        poisoned = canary in resp2.text

        return {
            "test": "fat_get",
            "canary": canary,
            "reflected": reflected,
            "poisoned": poisoned,
            "status_fat": resp.status_code,
            "status_clean": resp2.status_code,
        }
    except requests.RequestException as e:
        return {"test": "fat_get", "error": str(e)}


def test_path_normalization(target):
    """Test path normalization differences between cache and origin."""
    parsed = urlparse(target)
    base_path = parsed.path or "/"

    variations = [
        (f"{base_path}/./", "dot_segment"),
        (f"{base_path}/../{base_path.split('/')[-1]}", "double_dot"),
        (f"{base_path}%2f", "encoded_slash"),
        (f"{base_path}%5c", "encoded_backslash"),
        (f"//{base_path.lstrip('/')}", "double_slash"),
        (f"{base_path}?", "trailing_question"),
        (f"{base_path}#", "trailing_hash"),
    ]

    results = []
    for path_variation, name in variations:
        test_url = f"{parsed.scheme}://{parsed.netloc}{path_variation}"
        try:
            resp = requests.get(test_url, timeout=TIMEOUT, verify=False, allow_redirects=False)
            results.append({
                "variation": name,
                "path": path_variation,
                "status_code": resp.status_code,
                "content_length": len(resp.content),
                "redirects_to": resp.headers.get("location"),
            })
        except requests.RequestException as e:
            results.append({"variation": name, "error": str(e)})

    return {
        "test": "path_normalization",
        "results": results,
    }


def main():
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Usage: test-cache-poison.py '{\"target\": \"...\"}' "}))
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

    custom_headers = args.get("headers_to_test", [])
    test_all = args.get("test_all", True)

    # Merge default and custom headers
    headers_to_test = list(set(DEFAULT_UNKEYED_HEADERS + custom_headers))

    # Step 1: Check if caching is in use
    cache_check = check_caching(target)

    # Step 2: Test unkeyed headers
    header_results = []
    poisoned_headers = []

    for header in headers_to_test:
        result = test_unkeyed_header(target, header)
        header_results.append(result)
        if result.get("cache_poisoned"):
            poisoned_headers.append(header)

    # Step 3: Additional tests
    additional = {}
    if test_all:
        additional["parameter_cloaking"] = test_parameter_cloaking(target)
        additional["fat_get"] = test_fat_get(target)
        additional["path_normalization"] = test_path_normalization(target)

    # Determine severity
    severity = "info"
    if poisoned_headers:
        severity = "high"
    elif any(r.get("reflected_on_inject") for r in header_results):
        severity = "medium"
    elif cache_check.get("cached"):
        severity = "low"

    output = {
        "target": target,
        "cache_detected": cache_check.get("cached", False),
        "cache_info": cache_check,
        "headers_tested": len(header_results),
        "poisoned_headers": poisoned_headers,
        "severity": severity,
        "header_results": header_results,
        "additional_tests": additional,
        "summary": (
            f"Tested {len(header_results)} headers for cache poisoning on {target}. "
            f"Cache detected: {cache_check.get('cached', False)}. "
            f"Poisoned headers: {poisoned_headers if poisoned_headers else 'none'}."
        ),
    }

    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
