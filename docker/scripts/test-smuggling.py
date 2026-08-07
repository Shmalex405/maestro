#!/usr/bin/env python3
"""HTTP request smuggling detection.

Tests for CL.TE, TE.CL, and TE.TE smuggling using raw sockets
with timing-based detection.

Usage:
    python3 test-smuggling.py '{"target": "https://example.com", "technique": "all|cl_te|te_cl|te_te"}'
"""

import sys
import json
import socket
import ssl
import time
from urllib.parse import urlparse

TIMEOUT = 10
DETECTION_DELAY_THRESHOLD = 5  # seconds - delay suggesting smuggling


def create_connection(host, port, use_ssl=False):
    """Create a raw socket connection."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(TIMEOUT)

    if use_ssl:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        sock = context.wrap_socket(sock, server_hostname=host)

    sock.connect((host, port))
    return sock


def send_raw(host, port, use_ssl, raw_request):
    """Send a raw HTTP request and return timing + response."""
    start = time.monotonic()
    response_data = b""
    error = None
    timed_out = False

    try:
        sock = create_connection(host, port, use_ssl)
        sock.sendall(raw_request.encode())

        # Read response
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response_data += chunk
            except socket.timeout:
                timed_out = True
                break
        sock.close()
    except socket.timeout:
        timed_out = True
    except Exception as e:
        error = str(e)

    elapsed = time.monotonic() - start

    return {
        "elapsed": round(elapsed, 3),
        "timed_out": timed_out,
        "response_length": len(response_data),
        "response_preview": response_data[:500].decode("utf-8", errors="replace"),
        "error": error,
    }


def test_cl_te(host, port, use_ssl, path="/"):
    """CL.TE smuggling: Front-end uses Content-Length, back-end uses Transfer-Encoding.

    We send a request where CL says body is short, but TE (chunked) encodes a longer body.
    If the back-end processes the chunked body, the leftover data poisons the next request.
    Detection: timing - if back-end waits for more chunked data, response is delayed.
    """
    # Normal request for baseline
    baseline_req = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: 6\r\n"
        f"\r\n"
        f"normal"
    )
    baseline = send_raw(host, port, use_ssl, baseline_req)

    # CL.TE probe: Content-Length says 4 bytes, but body is chunked with incomplete chunk
    smuggle_req = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: 4\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"\r\n"
        f"1\r\n"
        f"Z\r\n"
        f"Q"
    )
    probe = send_raw(host, port, use_ssl, smuggle_req)

    delay = probe["elapsed"] - baseline["elapsed"]
    vulnerable = delay > DETECTION_DELAY_THRESHOLD or probe["timed_out"]

    return {
        "technique": "CL.TE",
        "description": "Front-end uses Content-Length, back-end uses Transfer-Encoding",
        "baseline_time": baseline["elapsed"],
        "probe_time": probe["elapsed"],
        "delay": round(delay, 3),
        "probe_timed_out": probe["timed_out"],
        "potentially_vulnerable": vulnerable,
        "baseline_response": baseline["response_preview"][:200],
        "probe_response": probe["response_preview"][:200],
        "baseline_error": baseline["error"],
        "probe_error": probe["error"],
    }


def test_te_cl(host, port, use_ssl, path="/"):
    """TE.CL smuggling: Front-end uses Transfer-Encoding, back-end uses Content-Length.

    We send chunked data where CL says body is shorter than the full chunked stream.
    If back-end uses CL, it reads less data and the rest poisons the pipeline.
    Detection: timing-based.
    """
    baseline_req = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: 6\r\n"
        f"\r\n"
        f"normal"
    )
    baseline = send_raw(host, port, use_ssl, baseline_req)

    # TE.CL probe: chunked encoding wraps body, but Content-Length is small
    smuggle_body = "0\r\n\r\n"
    smuggle_req = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: 3\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"\r\n"
        f"8\r\n"
        f"SMUGGLED\r\n"
        f"0\r\n"
        f"\r\n"
    )
    probe = send_raw(host, port, use_ssl, smuggle_req)

    delay = probe["elapsed"] - baseline["elapsed"]
    vulnerable = delay > DETECTION_DELAY_THRESHOLD or probe["timed_out"]

    return {
        "technique": "TE.CL",
        "description": "Front-end uses Transfer-Encoding, back-end uses Content-Length",
        "baseline_time": baseline["elapsed"],
        "probe_time": probe["elapsed"],
        "delay": round(delay, 3),
        "probe_timed_out": probe["timed_out"],
        "potentially_vulnerable": vulnerable,
        "baseline_response": baseline["response_preview"][:200],
        "probe_response": probe["response_preview"][:200],
        "baseline_error": baseline["error"],
        "probe_error": probe["error"],
    }


def test_te_te(host, port, use_ssl, path="/"):
    """TE.TE smuggling: Both use Transfer-Encoding, but obfuscation causes one to ignore it.

    Various obfuscation techniques for the Transfer-Encoding header.
    """
    obfuscations = [
        ("Transfer-Encoding: xchunked", "xchunked"),
        ("Transfer-Encoding : chunked", "space_before_colon"),
        ("Transfer-Encoding: chunked\r\nTransfer-Encoding: x", "duplicate_header"),
        ("Transfer-Encoding:\tchunked", "tab_separator"),
        ("Transfer-Encoding: chunked\x0b", "vertical_tab"),
        ("X: x\r\nTransfer-Encoding: chunked", "header_prefix"),
        ("Transfer-Encoding\r\n: chunked", "newline_in_name"),
    ]

    baseline_req = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: 6\r\n"
        f"\r\n"
        f"normal"
    )
    baseline = send_raw(host, port, use_ssl, baseline_req)

    results = []

    for te_header, technique_name in obfuscations:
        smuggle_req = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 4\r\n"
            f"{te_header}\r\n"
            f"\r\n"
            f"1\r\n"
            f"Z\r\n"
            f"Q"
        )
        probe = send_raw(host, port, use_ssl, smuggle_req)

        delay = probe["elapsed"] - baseline["elapsed"]
        vulnerable = delay > DETECTION_DELAY_THRESHOLD or probe["timed_out"]

        results.append({
            "obfuscation": technique_name,
            "te_header": te_header,
            "probe_time": probe["elapsed"],
            "delay": round(delay, 3),
            "timed_out": probe["timed_out"],
            "potentially_vulnerable": vulnerable,
            "error": probe["error"],
        })

    any_vulnerable = any(r["potentially_vulnerable"] for r in results)

    return {
        "technique": "TE.TE",
        "description": "Both sides use Transfer-Encoding, but obfuscation tricks one into ignoring it",
        "baseline_time": baseline["elapsed"],
        "obfuscation_results": results,
        "potentially_vulnerable": any_vulnerable,
    }


def main():
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Usage: test-smuggling.py '{\"target\": \"https://example.com\"}' "}))
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

    technique = args.get("technique", "all")
    path = args.get("path", "/")

    parsed = urlparse(target)
    host = parsed.hostname
    use_ssl = parsed.scheme == "https"
    port = parsed.port or (443 if use_ssl else 80)

    if not host:
        print(json.dumps({"error": f"Could not parse hostname from target: {target}"}))
        sys.exit(1)

    results = {}

    if technique in ("all", "cl_te"):
        results["cl_te"] = test_cl_te(host, port, use_ssl, path)

    if technique in ("all", "te_cl"):
        results["te_cl"] = test_te_cl(host, port, use_ssl, path)

    if technique in ("all", "te_te"):
        results["te_te"] = test_te_te(host, port, use_ssl, path)

    # Overall assessment
    any_vulnerable = any(
        r.get("potentially_vulnerable", False) for r in results.values()
    )

    severity = "info"
    if any_vulnerable:
        severity = "high"

    output = {
        "target": target,
        "host": host,
        "port": port,
        "ssl": use_ssl,
        "technique": technique,
        "severity": severity,
        "potentially_vulnerable": any_vulnerable,
        "results": results,
        "summary": (
            f"Tested HTTP smuggling techniques against {host}:{port}. "
            f"{'Potential smuggling vulnerability detected!' if any_vulnerable else 'No smuggling indicators found.'}"
        ),
        "note": "These are timing-based heuristics. Manual verification is recommended for any positive results.",
    }

    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
