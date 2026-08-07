#!/usr/bin/env python3
"""Race condition testing using asyncio and aiohttp.

Sends N concurrent identical requests and checks for inconsistencies,
TOCTOU bugs (double-spend, duplicate creation), and timing differences.

Usage:
    python3 test-race.py '{"target": "https://example.com/api/transfer", "method": "POST", "body": "{\"amount\":1}", "concurrency": 10, "headers": {"Authorization": "Bearer ..."}}'
"""

import sys
import json
import time
import asyncio

try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False

# Fallback to synchronous requests + threading if aiohttp not available
import requests
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TIMEOUT = 15


async def send_request_async(session, method, url, headers, body, request_id):
    """Send a single async request and capture timing."""
    start = time.monotonic()
    try:
        kwargs = {
            "headers": headers,
            "ssl": False,
            "timeout": aiohttp.ClientTimeout(total=TIMEOUT),
        }
        if body and method.upper() in ("POST", "PUT", "PATCH"):
            if isinstance(body, str):
                kwargs["data"] = body
                if "Content-Type" not in headers:
                    kwargs["headers"]["Content-Type"] = "application/json"
            else:
                kwargs["json"] = body

        async with session.request(method, url, **kwargs) as resp:
            response_body = await resp.text()
            elapsed = time.monotonic() - start
            return {
                "request_id": request_id,
                "status_code": resp.status,
                "content_length": len(response_body),
                "response_body_preview": response_body[:500],
                "elapsed": round(elapsed, 4),
                "headers": dict(resp.headers),
                "error": None,
            }
    except Exception as e:
        elapsed = time.monotonic() - start
        return {
            "request_id": request_id,
            "status_code": None,
            "content_length": 0,
            "response_body_preview": "",
            "elapsed": round(elapsed, 4),
            "headers": {},
            "error": str(e),
        }


async def run_concurrent_async(target, method, headers, body, concurrency):
    """Run concurrent requests using aiohttp."""
    async with aiohttp.ClientSession() as session:
        tasks = [
            send_request_async(session, method, target, dict(headers), body, i)
            for i in range(concurrency)
        ]
        # Fire all at once
        results = await asyncio.gather(*tasks)
    return list(results)


def send_request_sync(method, url, headers, body, request_id):
    """Send a single synchronous request (fallback)."""
    start = time.monotonic()
    try:
        kwargs = {
            "headers": headers,
            "timeout": TIMEOUT,
            "verify": False,
        }
        if body and method.upper() in ("POST", "PUT", "PATCH"):
            if isinstance(body, str):
                kwargs["data"] = body
                if "Content-Type" not in headers:
                    headers["Content-Type"] = "application/json"
            else:
                kwargs["json"] = body

        resp = requests.request(method, url, **kwargs)
        elapsed = time.monotonic() - start
        return {
            "request_id": request_id,
            "status_code": resp.status_code,
            "content_length": len(resp.content),
            "response_body_preview": resp.text[:500],
            "elapsed": round(elapsed, 4),
            "headers": dict(resp.headers),
            "error": None,
        }
    except Exception as e:
        elapsed = time.monotonic() - start
        return {
            "request_id": request_id,
            "status_code": None,
            "content_length": 0,
            "response_body_preview": "",
            "elapsed": round(elapsed, 4),
            "headers": {},
            "error": str(e),
        }


def run_concurrent_sync(target, method, headers, body, concurrency):
    """Run concurrent requests using ThreadPoolExecutor (fallback)."""
    results = []
    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = {
            executor.submit(send_request_sync, method, target, dict(headers), body, i): i
            for i in range(concurrency)
        }
        for future in as_completed(futures):
            results.append(future.result())
    results.sort(key=lambda r: r["request_id"])
    return results


def analyze_results(results):
    """Analyze race condition test results for anomalies."""
    successful = [r for r in results if r["error"] is None]
    failed = [r for r in results if r["error"] is not None]

    if not successful:
        return {
            "anomalies": [],
            "summary": "All requests failed",
            "potentially_vulnerable": False,
        }

    status_codes = [r["status_code"] for r in successful]
    content_lengths = [r["content_length"] for r in successful]
    timings = [r["elapsed"] for r in successful]

    unique_statuses = set(status_codes)
    unique_lengths = set(content_lengths)

    anomalies = []

    # Different status codes indicate possible race condition
    if len(unique_statuses) > 1:
        anomalies.append({
            "type": "status_code_variance",
            "description": f"Multiple status codes returned: {unique_statuses}",
            "severity": "high",
            "detail": {str(s): status_codes.count(s) for s in unique_statuses},
        })

    # Different content lengths suggest different responses
    if len(unique_lengths) > 1:
        anomalies.append({
            "type": "content_length_variance",
            "description": f"Response sizes varied: {min(content_lengths)}-{max(content_lengths)} bytes",
            "severity": "medium",
        })

    # Check for potential double-spend / duplicate creation
    success_count = sum(1 for s in status_codes if s in (200, 201, 204))
    if success_count > 1:
        anomalies.append({
            "type": "multiple_successes",
            "description": f"{success_count}/{len(successful)} requests returned success status",
            "severity": "high",
            "note": "If this endpoint should only succeed once (e.g., transfer, redeem), this may indicate a race condition",
        })

    # Check response body differences
    bodies = set(r["response_body_preview"] for r in successful)
    if len(bodies) > 1:
        anomalies.append({
            "type": "response_body_variance",
            "description": f"{len(bodies)} unique response bodies detected",
            "severity": "medium",
        })

    # Timing analysis
    if timings:
        avg_time = sum(timings) / len(timings)
        max_time = max(timings)
        min_time = min(timings)
        if max_time - min_time > 1.0:
            anomalies.append({
                "type": "timing_variance",
                "description": f"Timing spread: {min_time:.3f}s - {max_time:.3f}s (delta: {max_time - min_time:.3f}s)",
                "severity": "low",
            })

    potentially_vulnerable = any(a["severity"] in ("high", "critical") for a in anomalies)

    return {
        "anomalies": anomalies,
        "stats": {
            "total_requests": len(results),
            "successful": len(successful),
            "failed": len(failed),
            "unique_status_codes": list(unique_statuses),
            "timing_min": round(min(timings), 4) if timings else None,
            "timing_max": round(max(timings), 4) if timings else None,
            "timing_avg": round(sum(timings) / len(timings), 4) if timings else None,
        },
        "potentially_vulnerable": potentially_vulnerable,
    }


def main():
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Usage: test-race.py '{\"target\": \"...\", \"method\": \"POST\", ...}' "}))
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

    method = args.get("method", "POST")
    body = args.get("body")
    concurrency = args.get("concurrency", 10)
    headers = args.get("headers", {})
    rounds = args.get("rounds", 1)

    # Parse body if it's a JSON string
    if isinstance(body, str):
        try:
            body = json.loads(body)
            body = json.dumps(body)  # Re-serialize for consistency
        except (json.JSONDecodeError, TypeError):
            pass  # Keep as raw string

    all_round_results = []

    for round_num in range(rounds):
        if HAS_AIOHTTP:
            results = asyncio.run(
                run_concurrent_async(target, method, headers, body, concurrency)
            )
            transport = "aiohttp_async"
        else:
            results = run_concurrent_sync(target, method, headers, body, concurrency)
            transport = "requests_threaded"

        analysis = analyze_results(results)
        all_round_results.append({
            "round": round_num + 1,
            "transport": transport,
            "results": results,
            "analysis": analysis,
        })

    # Overall assessment
    any_vulnerable = any(r["analysis"]["potentially_vulnerable"] for r in all_round_results)
    all_anomalies = []
    for r in all_round_results:
        all_anomalies.extend(r["analysis"]["anomalies"])

    if any_vulnerable:
        severity = "high"
    elif all_anomalies:
        severity = "medium"
    else:
        severity = "info"

    output = {
        "target": target,
        "method": method,
        "concurrency": concurrency,
        "rounds": rounds,
        "transport": all_round_results[0]["transport"] if all_round_results else "unknown",
        "severity": severity,
        "potentially_vulnerable": any_vulnerable,
        "total_anomalies": len(all_anomalies),
        "round_results": all_round_results,
        "summary": (
            f"Sent {concurrency * rounds} concurrent requests ({rounds} round(s) of {concurrency}) to {target}. "
            f"{'Potential race condition detected.' if any_vulnerable else 'No race condition indicators found.'}"
        ),
    }

    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
