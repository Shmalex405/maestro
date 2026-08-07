#!/usr/bin/env python3
"""IDOR (Insecure Direct Object Reference) automation testing.

Tests for horizontal privilege escalation by accessing resources with
different user credentials, sequential ID enumeration, and UUID guessing.

Usage:
    python3 test-idor.py '{"target": "https://example.com/api/users/{id}", "ids": ["1", "2", "3"], "auth_headers": [{"Authorization": "Bearer user1_token"}, {"Authorization": "Bearer user2_token"}]}'
"""

import sys
import json
import hashlib
import requests
import urllib3
from urllib.parse import urlparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TIMEOUT = 10


def make_request(url, method="GET", headers=None, body=None):
    """Make an HTTP request and return structured result."""
    req_headers = headers or {}

    try:
        kwargs = {
            "headers": req_headers,
            "timeout": TIMEOUT,
            "verify": False,
        }
        if body:
            if isinstance(body, (dict, list)):
                kwargs["json"] = body
            else:
                kwargs["data"] = body

        resp = requests.request(method, url, **kwargs)

        return {
            "status_code": resp.status_code,
            "content_length": len(resp.content),
            "content_hash": hashlib.md5(resp.content).hexdigest()[:16],
            "response_preview": resp.text[:500],
            "headers": {
                k: v for k, v in resp.headers.items()
                if k.lower() in ("content-type", "x-request-id", "set-cookie")
            },
            "error": None,
        }
    except requests.RequestException as e:
        return {
            "status_code": None,
            "content_length": 0,
            "content_hash": None,
            "response_preview": "",
            "headers": {},
            "error": str(e),
        }


def test_horizontal_access(target, ids, auth_headers, method="GET", body=None):
    """Test if one user can access another user's resources.

    For each ID, make requests with each set of auth headers.
    If user A can access user B's resource, it's an IDOR.
    """
    results = []
    access_matrix = {}

    for user_idx, auth in enumerate(auth_headers):
        user_label = f"user_{user_idx}"
        access_matrix[user_label] = {}

        for resource_id in ids:
            url = target.replace("{id}", str(resource_id))

            resp = make_request(url, method, auth, body)

            access_matrix[user_label][str(resource_id)] = {
                "status_code": resp["status_code"],
                "accessible": resp["status_code"] in (200, 201, 204),
                "content_hash": resp["content_hash"],
                "content_length": resp["content_length"],
            }

            results.append({
                "user": user_label,
                "resource_id": str(resource_id),
                "url": url,
                **resp,
            })

    # Analyze for IDOR vulnerabilities
    idor_findings = []

    if len(auth_headers) >= 2:
        # Compare access patterns between users
        user_keys = list(access_matrix.keys())
        for i in range(len(user_keys)):
            for j in range(i + 1, len(user_keys)):
                user_a = user_keys[i]
                user_b = user_keys[j]

                for resource_id in ids:
                    rid = str(resource_id)
                    a_access = access_matrix[user_a][rid]
                    b_access = access_matrix[user_b][rid]

                    # Both users can access the same resource with same content
                    if (a_access["accessible"] and b_access["accessible"] and
                            a_access["content_hash"] == b_access["content_hash"]):
                        # This could be a shared/public resource or IDOR
                        idor_findings.append({
                            "type": "shared_access",
                            "resource_id": rid,
                            "users": [user_a, user_b],
                            "note": "Both users can access this resource with identical content. May be intentional (public) or IDOR.",
                            "severity": "medium",
                        })

                    # Different content for same resource = user-specific data
                    if (a_access["accessible"] and b_access["accessible"] and
                            a_access["content_hash"] != b_access["content_hash"]):
                        idor_findings.append({
                            "type": "different_content",
                            "resource_id": rid,
                            "users": [user_a, user_b],
                            "note": "Both users get different content for the same resource ID. This is expected if IDs are user-scoped.",
                            "severity": "info",
                        })

    return {
        "test_type": "horizontal_access",
        "results": results,
        "access_matrix": access_matrix,
        "idor_findings": idor_findings,
    }


def test_unauthenticated_access(target, ids, method="GET"):
    """Test if resources are accessible without authentication."""
    results = []

    for resource_id in ids:
        url = target.replace("{id}", str(resource_id))
        resp = make_request(url, method)

        results.append({
            "resource_id": str(resource_id),
            "url": url,
            "accessible": resp["status_code"] in (200, 201, 204),
            **resp,
        })

    accessible = [r for r in results if r["accessible"]]

    return {
        "test_type": "unauthenticated_access",
        "results": results,
        "accessible_count": len(accessible),
        "vulnerable": len(accessible) > 0,
    }


def test_sequential_enumeration(target, start_id, count, auth_headers=None, method="GET"):
    """Test sequential ID enumeration."""
    results = []
    headers = auth_headers[0] if auth_headers else {}

    accessible_ids = []

    for i in range(start_id, start_id + count):
        url = target.replace("{id}", str(i))
        resp = make_request(url, method, headers)

        is_accessible = resp["status_code"] in (200, 201, 204)
        results.append({
            "id": i,
            "url": url,
            "accessible": is_accessible,
            "status_code": resp["status_code"],
            "content_length": resp["content_length"],
        })

        if is_accessible:
            accessible_ids.append(i)

    return {
        "test_type": "sequential_enumeration",
        "range": f"{start_id}-{start_id + count - 1}",
        "total_tested": count,
        "accessible_count": len(accessible_ids),
        "accessible_ids": accessible_ids,
        "results": results,
        "pattern_detected": len(accessible_ids) > count * 0.5,
    }


def test_method_tampering(target, resource_id, auth_headers=None):
    """Test if different HTTP methods expose IDOR."""
    methods = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]
    headers = auth_headers[0] if auth_headers else {}
    url = target.replace("{id}", str(resource_id))

    results = []

    for method in methods:
        resp = make_request(url, method, headers)
        results.append({
            "method": method,
            "status_code": resp["status_code"],
            "content_length": resp["content_length"],
            "accessible": resp["status_code"] in (200, 201, 204),
        })

    return {
        "test_type": "method_tampering",
        "resource_id": str(resource_id),
        "url": url,
        "results": results,
        "accessible_methods": [r["method"] for r in results if r["accessible"]],
    }


def test_parameter_pollution(target, resource_id, auth_headers=None):
    """Test parameter pollution for IDOR bypass."""
    headers = auth_headers[0] if auth_headers else {}
    base_url = target.replace("{id}", str(resource_id))

    # Different pollution techniques
    techniques = [
        ("array_notation", base_url.replace(str(resource_id), f"{resource_id}&id=admin")),
        ("duplicate_param", f"{base_url}&id=admin" if "?" in base_url else f"{base_url}?id=admin"),
        ("json_injection", None),  # Will be POST with JSON body
        ("dot_notation", base_url.replace(str(resource_id), f"{resource_id}.")),
        ("encoded_slash", base_url.replace(str(resource_id), f"{resource_id}%2f..")),
    ]

    results = []

    for name, url in techniques:
        if name == "json_injection":
            url = base_url
            resp = make_request(url, "POST", headers, {"id": resource_id, "admin": True})
        else:
            resp = make_request(url, "GET", headers)

        results.append({
            "technique": name,
            "url": url or base_url,
            "status_code": resp["status_code"],
            "content_length": resp["content_length"],
            "accessible": resp["status_code"] in (200, 201, 204),
        })

    return {
        "test_type": "parameter_pollution",
        "resource_id": str(resource_id),
        "results": results,
    }


def main():
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Usage: test-idor.py '{\"target\": \"...\", \"ids\": [...]}' "}))
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

    ids = args.get("ids", ["1", "2", "3"])
    auth_headers = args.get("auth_headers", [])
    method = args.get("method", "GET")
    body = args.get("body")
    tests = args.get("tests", ["horizontal", "unauthenticated", "enumeration", "methods", "pollution"])

    # Ensure {id} placeholder exists
    if "{id}" not in target:
        print(json.dumps({"error": "Target URL must contain {id} placeholder, e.g., /api/users/{id}"}))
        sys.exit(1)

    all_results = {}
    vulnerabilities = []

    # Horizontal access test
    if "horizontal" in tests and len(auth_headers) >= 2:
        horizontal = test_horizontal_access(target, ids, auth_headers, method, body)
        all_results["horizontal_access"] = horizontal
        if horizontal["idor_findings"]:
            vulnerabilities.extend(horizontal["idor_findings"])

    # Unauthenticated access test
    if "unauthenticated" in tests:
        unauth = test_unauthenticated_access(target, ids, method)
        all_results["unauthenticated_access"] = unauth
        if unauth["vulnerable"]:
            vulnerabilities.append({
                "type": "unauthenticated_access",
                "severity": "high",
                "note": f"{unauth['accessible_count']} resources accessible without authentication",
            })

    # Sequential enumeration
    if "enumeration" in tests:
        start_id = int(ids[0]) if ids and ids[0].isdigit() else 1
        enum_count = args.get("enum_count", 20)
        enumeration = test_sequential_enumeration(target, start_id, enum_count, auth_headers, method)
        all_results["sequential_enumeration"] = enumeration
        if enumeration["pattern_detected"]:
            vulnerabilities.append({
                "type": "sequential_enumeration",
                "severity": "medium",
                "note": f"{enumeration['accessible_count']}/{enumeration['total_tested']} sequential IDs accessible",
            })

    # Method tampering
    if "methods" in tests and ids:
        methods_result = test_method_tampering(target, ids[0], auth_headers)
        all_results["method_tampering"] = methods_result

    # Parameter pollution
    if "pollution" in tests and ids:
        pollution = test_parameter_pollution(target, ids[0], auth_headers)
        all_results["parameter_pollution"] = pollution

    # Determine severity
    severity = "info"
    if any(v.get("severity") == "high" for v in vulnerabilities):
        severity = "high"
    elif any(v.get("severity") == "medium" for v in vulnerabilities):
        severity = "medium"
    elif vulnerabilities:
        severity = "low"

    output = {
        "target": target,
        "ids_tested": ids,
        "auth_users": len(auth_headers),
        "tests_run": list(all_results.keys()),
        "severity": severity,
        "vulnerabilities": vulnerabilities,
        "results": all_results,
        "summary": (
            f"Tested IDOR on {target} with {len(ids)} resource IDs and {len(auth_headers)} user credentials. "
            f"Found {len(vulnerabilities)} potential issues."
        ),
    }

    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
