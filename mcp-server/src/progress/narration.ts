// Fully-templated plain-English narration. No LLM — deterministic, instant, and
// hallucination-free. Maps a tool call to a human action line for the live
// ticker. The ProgressEvent.status drives colour/icon in the UI, so narrate()
// returns the present-tense action and only overrides phrasing for the handful
// of tools where a distinct done/failed line reads better.
//
// Coverage strategy: an explicit verb for the high-traffic tools, plus a
// prefix-based humanizer ("test_cors" → "Testing cors policy") for the long
// tail of ~160 tools. Extend TOOL_TEMPLATES freely as phrasing is tuned.

import { ProgressStatus } from "./types";

interface Template {
  /** Present-tense action; {t} is replaced with the pretty target. */
  started: string;
  /** Optional override when status === "ok". */
  ok?: string;
  /** Optional override when status === "error". */
  error?: string;
}

const TOOL_TEMPLATES: Record<string, Template> = {
  // Recon
  scan_ports: { started: "Scanning ports on {t}", ok: "Finished port scan of {t}", error: "Port scan of {t} failed" },
  discover_hosts: { started: "Discovering live hosts on {t}", ok: "Host discovery complete" },
  enumerate_subdomains: { started: "Enumerating subdomains of {t}", ok: "Subdomain enumeration complete" },

  // Vuln scanning
  run_nuclei: { started: "Running Nuclei CVE templates against {t}", ok: "Nuclei scan of {t} complete" },
  run_nikto: { started: "Scanning {t}'s web server with Nikto", ok: "Nikto scan of {t} complete" },
  search_exploits: { started: "Searching exploit databases" },

  // Web app
  run_sqlmap: { started: "Probing {t} for SQL injection with sqlmap", ok: "sqlmap run against {t} complete" },
  test_xss: { started: "Testing {t} for cross-site scripting", ok: "XSS testing of {t} complete" },
  fuzz_endpoints: { started: "Fuzzing endpoints on {t}" },
  crawl_site: { started: "Crawling {t}" },
  test_cors: { started: "Testing the CORS policy on {t}" },
  test_ssrf: { started: "Testing {t} for server-side request forgery" },
  test_ssti: { started: "Testing {t} for template injection" },
  test_http_smuggling: { started: "Testing {t} for HTTP request smuggling" },
  test_race_condition: { started: "Testing {t} for race conditions" },
  test_cache_poisoning: { started: "Testing {t} for cache poisoning" },
  test_websocket: { started: "Testing WebSocket security on {t}" },
  generate_waf_bypass: { started: "Generating WAF-bypass payloads for {t}" },

  // API
  test_graphql_security: { started: "Testing GraphQL security on {t}" },
  fuzz_api_schema: { started: "Fuzzing the API schema on {t}" },
  test_api_rate_limiting: { started: "Testing API rate limiting on {t}" },
  test_idor: { started: "Testing {t} for IDOR / broken object-level auth" },

  // SSL/DNS
  scan_ssl_tls: { started: "Analyzing the SSL/TLS configuration on {t}" },
  check_certificate: { started: "Validating the certificate chain for {t}" },
  scan_ssl_ciphers: { started: "Enumerating SSL/TLS cipher suites on {t}" },
  test_zone_transfer: { started: "Attempting a DNS zone transfer for {t}" },
  check_dnssec: { started: "Checking DNSSEC for {t}" },
  detect_subdomain_takeover: { started: "Checking {t} for subdomain takeover" },

  // Token/session
  analyze_jwt: { started: "Analyzing JWT structure and signing" },
  test_token_replay: { started: "Testing token replay on {t}" },
  test_session_fixation: { started: "Testing {t} for session fixation" },

  // Cloud
  test_cloud_metadata: { started: "Probing the cloud metadata endpoint" },
  check_s3_bucket: { started: "Checking S3 bucket permissions" },

  // SAST
  scan_repository: { started: "Scanning the repository", ok: "Repository scan complete" },
  scan_semgrep: { started: "Running Semgrep over the codebase" },
  scan_bandit: { started: "Running Bandit over the Python code" },
  scan_secrets: { started: "Scanning the codebase for secrets" },
  scan_dependencies: { started: "Scanning dependencies for known CVEs" },
  analyze_code_context: { started: "Analyzing code context around a finding" },

  // Findings
  create_finding: { started: "Recording a finding", ok: "Finding recorded" },
  generate_report: { started: "Generating the report" },
  complete_assessment: { started: "Finalizing the assessment", ok: "Assessment finalized" },
};

// Prefix → leading verb for the humanizer fallback.
const PREFIX_VERB: Array<[RegExp, string]> = [
  [/^run_/, "Running"],
  [/^scan_/, "Scanning"],
  [/^test_/, "Testing"],
  [/^check_/, "Checking"],
  [/^analyze_/, "Analyzing"],
  [/^enumerate_/, "Enumerating"],
  [/^discover_/, "Discovering"],
  [/^fuzz_/, "Fuzzing"],
  [/^detect_/, "Detecting"],
  [/^correlate_/, "Correlating"],
  [/^import_/, "Importing"],
  [/^generate_/, "Generating"],
  [/^ai_/, "Probing AI surface:"],
];

/** Strip scheme + trailing slash so "https://api.x.com/" → "api.x.com". */
function prettyTarget(target: string): string {
  return target.replace(/^[a-z]+:\/\//i, "").replace(/\/+$/, "");
}

function humanize(tool: string, target?: string): string {
  let phrase: string | null = null;
  for (const [re, verb] of PREFIX_VERB) {
    if (re.test(tool)) {
      const rest = tool.replace(re, "").replace(/_/g, " ").trim();
      phrase = `${verb} ${rest}`.trim();
      break;
    }
  }
  if (!phrase) phrase = `Running ${tool.replace(/_/g, " ")}`;
  if (target) phrase += ` on ${prettyTarget(target)}`;
  return phrase;
}

/**
 * Turn one tool dispatch into a plain-English line.
 *
 * The returned string is the action ("Scanning ports on api.x.com"); the
 * caller pairs it with status for colour/icon. Done/failed phrasing is only
 * substituted for tools that declare an explicit ok/error template.
 */
export function narrate(params: {
  tool: string;
  status: ProgressStatus;
  target?: string;
}): string {
  const { tool, status, target } = params;
  const tpl = TOOL_TEMPLATES[tool];

  if (tpl) {
    let base =
      status === "ok" && tpl.ok
        ? tpl.ok
        : status === "error" && tpl.error
        ? tpl.error
        : tpl.started;
    const t = target ? prettyTarget(target) : "the target";
    return base.replace(/\{t\}/g, t);
  }

  return humanize(tool, target);
}
