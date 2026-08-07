import * as crypto from "crypto";

export interface FingerprintInput {
  target: string;
  title: string;
  cve?: string;
  cwe?: string;
  description?: string;
  file_path?: string;
  line_start?: number;
}

/**
 * Generate a unique fingerprint for a finding based on key attributes.
 * Same vulnerability on same target = same fingerprint.
 * Different targets or different vulnerability types = different fingerprints.
 */
export function generateFingerprint(input: FingerprintInput): string {
  const normalizedTarget = normalizeTarget(input.target);
  const vulnType = extractVulnerabilityType(input.title, input.cve, input.cwe);
  const endpointPath = extractEndpointPath(normalizedTarget);
  const parameter = extractParameter(input.title, input.description);

  const components = [
    normalizedTarget,
    vulnType,
    input.cve || "",
    endpointPath,
    parameter || "",
    input.file_path || "",
    input.line_start != null ? String(input.line_start) : "",
  ];

  return crypto
    .createHash("sha256")
    .update(components.join("|"))
    .digest("hex");
}

/**
 * Normalize a target URL/IP for consistent fingerprinting.
 * - Lowercase hostname
 * - Remove default ports (80 for http, 443 for https)
 * - Remove trailing slashes
 * - Sort query parameters
 */
export function normalizeTarget(target: string): string {
  try {
    const url = new URL(target);

    // Lowercase hostname
    url.hostname = url.hostname.toLowerCase();

    // Remove default ports
    if (
      (url.protocol === "http:" && url.port === "80") ||
      (url.protocol === "https:" && url.port === "443")
    ) {
      url.port = "";
    }

    // Normalize pathname - remove trailing slash except for root
    url.pathname = url.pathname.replace(/\/+$/, "") || "/";

    // Sort query parameters for consistency
    url.searchParams.sort();

    return url.toString();
  } catch {
    // Not a URL, treat as hostname/IP - just lowercase and trim
    return target.toLowerCase().trim();
  }
}

/**
 * Extract a canonical vulnerability type from the finding title and identifiers.
 * Maps various tool-specific names to canonical types.
 */
export function extractVulnerabilityType(
  title: string,
  cve?: string,
  cwe?: string
): string {
  const titleLower = title.toLowerCase();

  // CWE-based mapping (most specific)
  const cweMap: Record<string, string> = {
    "CWE-89": "sql_injection",
    "CWE-79": "xss",
    "CWE-22": "path_traversal",
    "CWE-78": "command_injection",
    "CWE-94": "code_injection",
    "CWE-918": "ssrf",
    "CWE-601": "open_redirect",
    "CWE-352": "csrf",
    "CWE-639": "idor",
    "CWE-98": "lfi",
    "CWE-611": "xxe",
    "CWE-1336": "ssti",
    "CWE-287": "auth_bypass",
    "CWE-284": "access_control",
    "CWE-200": "info_disclosure",
    "CWE-311": "missing_encryption",
    "CWE-502": "deserialization",
    "CWE-434": "file_upload",
    "CWE-306": "missing_auth",
    "CWE-798": "hardcoded_credentials",
    "CWE-532": "log_injection",
    "CWE-319": "cleartext_transmission",
  };

  if (cwe && cweMap[cwe]) {
    return cweMap[cwe];
  }

  // Title-based pattern matching
  const patterns: [RegExp, string][] = [
    [/sql\s*injection|sqli/i, "sql_injection"],
    [/xss|cross[\-\s]*site[\-\s]*script/i, "xss"],
    [/ssrf|server[\-\s]*side[\-\s]*request/i, "ssrf"],
    [/rce|remote[\-\s]*code[\-\s]*exec|command[\-\s]*injection/i, "rce"],
    [/open[\-\s]*redirect/i, "open_redirect"],
    [/csrf|cross[\-\s]*site[\-\s]*request[\-\s]*forgery/i, "csrf"],
    [/idor|insecure[\-\s]*direct[\-\s]*object/i, "idor"],
    [/lfi|local[\-\s]*file[\-\s]*inclusion/i, "lfi"],
    [/rfi|remote[\-\s]*file[\-\s]*inclusion/i, "rfi"],
    [/xxe|xml[\-\s]*external[\-\s]*entity/i, "xxe"],
    [/ssti|server[\-\s]*side[\-\s]*template[\-\s]*injection/i, "ssti"],
    [/path[\-\s]*traversal|directory[\-\s]*traversal|\.\.\/|\.\.\\/, "path_traversal"],
    [/auth(entication)?[\-\s]*bypass/i, "auth_bypass"],
    [/broken[\-\s]*access[\-\s]*control/i, "access_control"],
    [/info(rmation)?[\-\s]*(disclosure|leak|exposure)/i, "info_disclosure"],
    [/deserialization|pickle|unserialize/i, "deserialization"],
    [/(arbitrary[\-\s]*)?file[\-\s]*upload/i, "file_upload"],
    [/missing[\-\s]*auth|unauthenticated/i, "missing_auth"],
    [/hardcoded[\-\s]*(credential|password|secret|key|token)/i, "hardcoded_credentials"],
    [/log[\-\s]*(injection|forging)/i, "log_injection"],
    [/cleartext|unencrypted[\-\s]*transmission/i, "cleartext_transmission"],
    [/weak[\-\s]*password/i, "weak_password"],
    [/default[\-\s]*(credential|password)/i, "default_credentials"],
    [/exposed[\-\s]*(api|endpoint|admin)/i, "exposed_endpoint"],
    [/misconfiguration|misconfig/i, "misconfiguration"],
    [/cors/i, "cors_misconfiguration"],
    [/clickjack/i, "clickjacking"],
    [/host[\-\s]*header[\-\s]*injection/i, "host_header_injection"],
    [/http[\-\s]*request[\-\s]*smuggling/i, "http_smuggling"],
    [/prototype[\-\s]*pollution/i, "prototype_pollution"],
    [/denial[\-\s]*of[\-\s]*service|dos\b/i, "dos"],
    [/buffer[\-\s]*overflow/i, "buffer_overflow"],
    [/insecure[\-\s]*cookie/i, "insecure_cookie"],
    [/session[\-\s]*(fixation|hijack)/i, "session_vulnerability"],
    [/crlf[\-\s]*injection/i, "crlf_injection"],
    [/header[\-\s]*injection/i, "header_injection"],
    [/nosql[\-\s]*injection/i, "nosql_injection"],
    [/ldap[\-\s]*injection/i, "ldap_injection"],
    [/xml[\-\s]*injection/i, "xml_injection"],
    [/xpath[\-\s]*injection/i, "xpath_injection"],
  ];

  for (const [pattern, type] of patterns) {
    if (pattern.test(titleLower)) {
      return type;
    }
  }

  // If CVE present but no pattern match, use CVE as type identifier
  if (cve) {
    return `cve:${cve.toLowerCase()}`;
  }

  // Fallback: normalize title to create a type
  return titleLower
    .replace(/[^a-z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "")
    .substring(0, 50);
}

/**
 * Extract the endpoint path from a target URL.
 */
export function extractEndpointPath(target: string): string {
  try {
    const url = new URL(target);
    return url.pathname || "/";
  } catch {
    // Not a URL, return as-is
    return "/";
  }
}

/**
 * Extract affected parameter from title or description.
 * Used for injection vulnerabilities to differentiate findings.
 */
export function extractParameter(
  title: string,
  description?: string
): string | null {
  const text = `${title} ${description || ""}`;

  // Common patterns for parameter identification
  const patterns = [
    /parameter[:\s]+['"`]?(\w+)['"`]?/i,
    /param[:\s]+['"`]?(\w+)['"`]?/i,
    /\?(\w+)=/,
    /['"`](\w+)['"`]\s+parameter/i,
    /in\s+['"`]?(\w+)['"`]?\s+(param|field|input)/i,
    /via\s+['"`]?(\w+)['"`]?\s+(param|field|input|parameter)/i,
  ];

  for (const pattern of patterns) {
    const match = text.match(pattern);
    if (match && match[1]) {
      return match[1].toLowerCase();
    }
  }

  return null;
}
