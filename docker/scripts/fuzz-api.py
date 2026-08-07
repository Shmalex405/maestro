#!/usr/bin/env python3
"""OpenAPI/Swagger schema-based API fuzzing.

Parses an OpenAPI/Swagger spec and generates fuzz values per parameter type.
Tests each endpoint with malformed inputs and checks for 500 errors,
stack traces, and verbose errors.

Usage:
    python3 fuzz-api.py '{"spec_url": "https://example.com/swagger.json", "base_url": "https://example.com", "auth_header": "Bearer ..."}'
"""

import sys
import json
import random
import string
import requests
import urllib3
from urllib.parse import urljoin

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TIMEOUT = 10

# Methods that only READ — safe to fuzz against a live target. Any other method
# (POST/PUT/PATCH/DELETE) can create, modify, or delete real data, so in
# non-destructive mode (the default) we DISCOVER those endpoints but never send a
# request to them. This is the hard guarantee that a scheduled scan cannot delete
# or mutate target data.
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}

# Fuzz values by parameter type
FUZZ_VALUES = {
    "string": [
        "",
        " ",
        "null",
        "undefined",
        "NaN",
        "true",
        "false",
        "<script>alert(1)</script>",
        "' OR 1=1 --",
        '" OR 1=1 --',
        "{{7*7}}",
        "${7*7}",
        "../../../etc/passwd",
        "A" * 10000,
        "\x00",
        "\n\r\n",
        "{{constructor.constructor('return this')()}}",
        '{"$gt":""}',
        "-1",
        "0",
        "9999999999",
        "%00",
        "%0a%0d",
        "admin",
        "test@test.com'; DROP TABLE users;--",
    ],
    "integer": [
        0, -1, 1, -999999999, 999999999,
        2147483647,     # INT_MAX
        -2147483648,    # INT_MIN
        2147483648,     # INT_MAX + 1
        9999999999999999999,  # Long overflow
        None,           # null
        "abc",          # Type confusion
        1.5,            # Float
        True,           # Boolean
        "",
    ],
    "number": [
        0.0, -1.0, 1.1,
        float("inf"),
        float("-inf"),
        1e308,          # Near max double
        -1e308,
        0.0000000001,
        None,
        "NaN",
        "Infinity",
        "",
        "abc",
    ],
    "boolean": [
        True, False,
        "true", "false",
        "1", "0",
        "yes", "no",
        None, "",
        2, -1,
    ],
    "array": [
        [],
        [None],
        ["" for _ in range(1000)],
        [{"$gt": ""}],
        "not_an_array",
        None,
    ],
    "object": [
        {},
        {"__proto__": {"admin": True}},
        {"constructor": {"prototype": {"admin": True}}},
        None,
        "not_an_object",
        [],
    ],
}

# Error indicators in responses
ERROR_INDICATORS = [
    "traceback", "stacktrace", "stack trace",
    "exception", "error", "internal server error",
    "syntax error", "parse error",
    "unexpected", "undefined", "null reference",
    "segfault", "core dump", "panic",
    "java.lang", "system.nullreferenceexception",
    "sqlstate", "mysql", "postgresql", "sqlite",
    "orm", "sequelize", "mongoose", "prisma",
    "at module", "at function", "at object",
    "node_modules", "site-packages",
    "debug", "verbose",
    "file \"", "line ",
]


def fetch_spec(spec_url, headers=None):
    """Fetch and parse OpenAPI/Swagger spec."""
    req_headers = headers or {}
    try:
        resp = requests.get(spec_url, headers=req_headers, timeout=TIMEOUT, verify=False)
        resp.raise_for_status()
        return resp.json()
    except requests.RequestException as e:
        return {"error": f"Failed to fetch spec: {str(e)}"}
    except json.JSONDecodeError as e:
        return {"error": f"Failed to parse spec JSON: {str(e)}"}


def extract_endpoints(spec):
    """Extract endpoints from OpenAPI/Swagger spec."""
    endpoints = []
    paths = spec.get("paths", {})
    base_path = spec.get("basePath", "")

    for path, methods in paths.items():
        full_path = base_path + path if base_path else path

        for method, details in methods.items():
            if method.lower() in ("get", "post", "put", "patch", "delete", "options", "head"):
                parameters = details.get("parameters", [])

                # Also check for requestBody (OpenAPI 3)
                request_body = details.get("requestBody", {})
                body_schema = None
                if request_body:
                    content = request_body.get("content", {})
                    for ct, ct_details in content.items():
                        body_schema = ct_details.get("schema", {})
                        break

                endpoints.append({
                    "path": full_path,
                    "method": method.upper(),
                    "operation_id": details.get("operationId", ""),
                    "parameters": parameters,
                    "body_schema": body_schema,
                    "summary": details.get("summary", ""),
                    "consumes": details.get("consumes", spec.get("consumes", ["application/json"])),
                })

    return endpoints


def get_param_type(param):
    """Determine the type of a parameter."""
    schema = param.get("schema", {})
    return param.get("type") or schema.get("type", "string")


def generate_fuzz_body(schema, fuzz_index=0):
    """Generate a fuzzed request body from schema."""
    if not schema:
        return None

    schema_type = schema.get("type", "object")

    if schema_type == "object":
        properties = schema.get("properties", {})
        body = {}
        for prop_name, prop_schema in properties.items():
            prop_type = prop_schema.get("type", "string")
            fuzz_list = FUZZ_VALUES.get(prop_type, FUZZ_VALUES["string"])
            idx = fuzz_index % len(fuzz_list)
            body[prop_name] = fuzz_list[idx]
        return body
    elif schema_type == "array":
        return FUZZ_VALUES["array"][fuzz_index % len(FUZZ_VALUES["array"])]
    else:
        fuzz_list = FUZZ_VALUES.get(schema_type, FUZZ_VALUES["string"])
        return fuzz_list[fuzz_index % len(fuzz_list)]


def fuzz_endpoint(base_url, endpoint, headers=None, max_fuzz=10):
    """Fuzz a single endpoint with various payloads."""
    results = []
    path = endpoint["path"]
    method = endpoint["method"]
    parameters = endpoint["parameters"]
    body_schema = endpoint["body_schema"]

    for fuzz_index in range(max_fuzz):
        # Build URL with fuzzed path/query parameters
        fuzzed_path = path
        query_params = {}
        fuzzed_headers = dict(headers or {})

        for param in parameters:
            param_name = param.get("name", "")
            param_in = param.get("in", "query")
            param_type = get_param_type(param)

            fuzz_list = FUZZ_VALUES.get(param_type, FUZZ_VALUES["string"])
            fuzz_value = fuzz_list[fuzz_index % len(fuzz_list)]

            if fuzz_value is None:
                fuzz_value = "null"
            fuzz_str = str(fuzz_value)

            if param_in == "path":
                fuzzed_path = fuzzed_path.replace(f"{{{param_name}}}", fuzz_str)
            elif param_in == "query":
                query_params[param_name] = fuzz_str
            elif param_in == "header":
                fuzzed_headers[param_name] = fuzz_str

        url = urljoin(base_url, fuzzed_path)

        # Build request body
        body = None
        if body_schema and method in ("POST", "PUT", "PATCH"):
            body = generate_fuzz_body(body_schema, fuzz_index)

        try:
            kwargs = {
                "headers": fuzzed_headers,
                "params": query_params if query_params else None,
                "timeout": TIMEOUT,
                "verify": False,
            }

            if body is not None:
                if isinstance(body, (dict, list)):
                    kwargs["json"] = body
                else:
                    kwargs["data"] = str(body)

            resp = requests.request(method, url, **kwargs)

            response_body = resp.text[:1000]
            body_lower = response_body.lower()

            indicators = []
            for indicator in ERROR_INDICATORS:
                if indicator in body_lower:
                    indicators.append(indicator)

            result = {
                "fuzz_index": fuzz_index,
                "url": url,
                "method": method,
                "params": query_params,
                "body": body if body is not None else None,
                "status_code": resp.status_code,
                "content_length": len(resp.content),
                "error_indicators": indicators,
                "server_error": resp.status_code >= 500,
                "response_preview": response_body[:300] if indicators or resp.status_code >= 500 else None,
            }

            results.append(result)

        except requests.RequestException as e:
            results.append({
                "fuzz_index": fuzz_index,
                "url": url,
                "method": method,
                "error": str(e),
            })

    return results


def main():
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Usage: fuzz-api.py '{\"spec_url\": \"...\", \"base_url\": \"...\"}' "}))
        sys.exit(1)

    try:
        args = json.loads(sys.argv[1])
    except json.JSONDecodeError as e:
        print(json.dumps({"error": f"Invalid JSON arguments: {str(e)}"}))
        sys.exit(1)

    spec_url = args.get("spec_url")
    spec_content = args.get("spec_content")
    base_url = args.get("base_url")
    auth_header = args.get("auth_header")
    max_fuzz = args.get("max_fuzz", 10)
    # Default ON: never fire write methods. Only an explicit non_destructive:false
    # (which the scheduled-DAST path never sends) re-enables them.
    non_destructive = args.get("non_destructive", True)

    if not spec_url and not spec_content:
        print(json.dumps({"error": "Either spec_url or spec_content is required"}))
        sys.exit(1)

    headers = args.get("headers", {})
    if auth_header:
        headers["Authorization"] = auth_header

    # Fetch or parse spec
    if spec_content:
        if isinstance(spec_content, str):
            try:
                spec = json.loads(spec_content)
            except json.JSONDecodeError:
                print(json.dumps({"error": "Invalid spec_content JSON"}))
                sys.exit(1)
        else:
            spec = spec_content
    else:
        spec = fetch_spec(spec_url, headers)

    if "error" in spec:
        print(json.dumps(spec))
        sys.exit(1)

    # Determine base URL
    if not base_url:
        # Try to extract from spec
        servers = spec.get("servers", [])
        if servers:
            base_url = servers[0].get("url", "")
        else:
            host = spec.get("host", "")
            schemes = spec.get("schemes", ["https"])
            base_path = spec.get("basePath", "")
            if host:
                base_url = f"{schemes[0]}://{host}{base_path}"

    if not base_url:
        print(json.dumps({"error": "Could not determine base URL. Provide base_url parameter."}))
        sys.exit(1)

    # Extract endpoints
    endpoints = extract_endpoints(spec)

    if not endpoints:
        print(json.dumps({
            "error": "No endpoints found in spec",
            "spec_keys": list(spec.keys()),
        }))
        sys.exit(1)

    # Fuzz each endpoint
    all_results = []
    server_errors = []
    info_leaks = []
    discovered_write_endpoints = []  # write methods enumerated but NOT exercised

    for endpoint in endpoints:
        # Non-destructive guarantee: write methods are recorded as DISCOVERED for
        # the report, but no request is ever sent to them. Impossible to mutate
        # or delete target data.
        if non_destructive and endpoint["method"] not in SAFE_METHODS:
            discovered_write_endpoints.append({
                "path": endpoint["path"],
                "method": endpoint["method"],
                "operation_id": endpoint["operation_id"],
                "summary": endpoint.get("summary", ""),
                "note": "discovered only — not fuzzed (non-destructive mode)",
            })
            continue
        fuzz_results = fuzz_endpoint(base_url, endpoint, headers, max_fuzz)
        endpoint_summary = {
            "path": endpoint["path"],
            "method": endpoint["method"],
            "operation_id": endpoint["operation_id"],
            "fuzz_results": fuzz_results,
        }

        for r in fuzz_results:
            if r.get("server_error"):
                server_errors.append({
                    "path": endpoint["path"],
                    "method": endpoint["method"],
                    "status_code": r["status_code"],
                    "fuzz_index": r["fuzz_index"],
                })
            if r.get("error_indicators"):
                info_leaks.append({
                    "path": endpoint["path"],
                    "method": endpoint["method"],
                    "indicators": r["error_indicators"],
                    "fuzz_index": r["fuzz_index"],
                })

        all_results.append(endpoint_summary)

    # Determine severity
    severity = "info"
    if info_leaks:
        severity = "medium"
    if server_errors:
        severity = "medium"
    if len(server_errors) > 5:
        severity = "high"

    output = {
        "spec_url": spec_url,
        "base_url": base_url,
        "non_destructive": non_destructive,
        "endpoints_found": len(endpoints),
        "endpoints_fuzzed": len(all_results),
        "write_endpoints_discovered_not_fuzzed": len(discovered_write_endpoints),
        "total_requests": sum(len(r["fuzz_results"]) for r in all_results),
        "server_errors": len(server_errors),
        "info_leaks": len(info_leaks),
        "severity": severity,
        "server_error_details": server_errors[:20],
        "info_leak_details": info_leaks[:20],
        "discovered_write_endpoints": discovered_write_endpoints,
        "results": all_results,
        "summary": (
            f"Fuzzed {len(all_results)} read-only endpoints from API spec. "
            + (f"Discovered (not fuzzed) {len(discovered_write_endpoints)} write endpoints in non-destructive mode. " if non_destructive else "")
            + f"Server errors: {len(server_errors)}. "
            f"Information leaks: {len(info_leaks)}."
        ),
    }

    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
