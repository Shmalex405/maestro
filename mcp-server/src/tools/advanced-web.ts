import { executeInKali } from "../utils/docker-exec";
import { ToolEvidence } from "../utils/evidence-wrapper";

export const advancedWebTools = [
  {
    name: "test_cors",
    description: "Test Cross-Origin Resource Sharing (CORS) misconfigurations. Checks for wildcard origins, null origin reflection, credential leakage, and subdomain trust issues.",
    inputSchema: {
      type: "object",
      properties: {
        target: { type: "string", description: "Target URL to test CORS policy against" },
        origins: {
          type: "array",
          items: { type: "string" },
          description: "List of origins to test (e.g., ['https://evil.com', 'null', 'https://subdomain.target.com']). Defaults to common malicious origins.",
        },
        methods: {
          type: "array",
          items: { type: "string" },
          description: "HTTP methods to test in preflight requests",
        },
      },
      required: ["target"],
    },
  },
  {
    name: "test_ssrf",
    description: "Test for Server-Side Request Forgery (SSRF) vulnerabilities. Sends payloads targeting internal services, cloud metadata endpoints, and internal network ranges.",
    inputSchema: {
      type: "object",
      properties: {
        target: { type: "string", description: "Target URL with parameter to inject into (e.g., 'https://app.com/fetch?url=FUZZ')" },
        parameter: { type: "string", description: "Parameter name to inject SSRF payloads into" },
        method: { type: "string", description: "HTTP method (GET or POST)", default: "GET" },
        payloads: {
          type: "array",
          items: { type: "string" },
          description: "Custom SSRF payloads. Defaults to common internal targets (169.254.169.254, localhost, etc.)",
        },
        callback_url: { type: "string", description: "External callback URL to detect blind SSRF (e.g., Burp Collaborator or interactsh URL)" },
      },
      required: ["target"],
    },
  },
  {
    name: "test_ssti",
    description: "Test for Server-Side Template Injection (SSTI) across multiple template engines (Jinja2, Twig, Freemarker, Velocity, Pug, ERB, Smarty, Mako).",
    inputSchema: {
      type: "object",
      properties: {
        target: { type: "string", description: "Target URL with injectable parameter" },
        parameter: { type: "string", description: "Parameter name to inject SSTI payloads into" },
        method: { type: "string", description: "HTTP method (GET or POST)", default: "GET" },
        engine: { type: "string", description: "Specific template engine to test (auto-detects if not specified)" },
      },
      required: ["target"],
    },
  },
  {
    name: "test_http_smuggling",
    description: "Test for HTTP request smuggling vulnerabilities (CL.TE, TE.CL, TE.TE). NON-DESTRUCTIVE detection only.",
    inputSchema: {
      type: "object",
      properties: {
        target: { type: "string", description: "Target URL to test for HTTP smuggling" },
        technique: {
          type: "string",
          description: "Smuggling technique to test: 'cl_te', 'te_cl', 'te_te', or 'all'",
          default: "all",
        },
        timeout: { type: "number", description: "Request timeout in seconds for timing-based detection", default: 10 },
      },
      required: ["target"],
    },
  },
  {
    name: "test_race_condition",
    description: "Test for race condition vulnerabilities by sending concurrent requests to an endpoint. Tests for TOCTOU issues, double-spend, and parallel execution flaws.",
    inputSchema: {
      type: "object",
      properties: {
        target: { type: "string", description: "Target URL to test for race conditions" },
        method: { type: "string", description: "HTTP method", default: "POST" },
        data: { type: "string", description: "Request body data (for POST requests)" },
        headers: { type: "object", description: "Custom headers to include in requests" },
        concurrency: { type: "number", description: "Number of concurrent requests to send", default: 10 },
        iterations: { type: "number", description: "Number of times to repeat the concurrent batch", default: 3 },
      },
      required: ["target"],
    },
  },
  {
    name: "test_cache_poisoning",
    description: "Test for web cache poisoning vulnerabilities by injecting unkeyed headers (X-Forwarded-Host, X-Original-URL, etc.) and checking if poisoned responses are cached.",
    inputSchema: {
      type: "object",
      properties: {
        target: { type: "string", description: "Target URL to test for cache poisoning" },
        headers_to_test: {
          type: "array",
          items: { type: "string" },
          description: "Custom unkeyed headers to test. Defaults to common cache poisoning headers.",
        },
        cache_buster: { type: "string", description: "Cache buster parameter name to isolate tests", default: "cb" },
      },
      required: ["target"],
    },
  },
  {
    name: "test_websocket",
    description: "Test WebSocket endpoint security. Checks for missing authentication, origin validation, message injection, and cross-site WebSocket hijacking.",
    inputSchema: {
      type: "object",
      properties: {
        target: { type: "string", description: "WebSocket URL (ws:// or wss://)" },
        origin: { type: "string", description: "Origin header to send (for cross-origin tests)" },
        messages: {
          type: "array",
          items: { type: "string" },
          description: "Messages to send after connection is established",
        },
        auth_token: { type: "string", description: "Authentication token to include" },
        timeout: { type: "number", description: "Connection timeout in seconds", default: 10 },
      },
      required: ["target"],
    },
  },
  {
    name: "generate_waf_bypass",
    description: "Generate WAF bypass payloads for a specific attack type. Produces encoding-based, syntax-based, and protocol-based evasion payloads for SQL injection, XSS, command injection, and path traversal.",
    inputSchema: {
      type: "object",
      properties: {
        attack_type: {
          type: "string",
          description: "Type of attack to generate bypass payloads for: 'sqli', 'xss', 'cmdi', 'path_traversal', 'ssti'",
        },
        waf: { type: "string", description: "Specific WAF to target bypasses for (e.g., 'cloudflare', 'akamai', 'aws_waf', 'modsecurity')" },
        context: { type: "string", description: "Injection context: 'html', 'javascript', 'attribute', 'url', 'sql_string', 'sql_numeric'" },
        base_payload: { type: "string", description: "Base payload to encode/obfuscate for WAF bypass" },
      },
      required: ["attack_type"],
    },
  },
];

export const advancedWebHandlers: Record<string, Function> = {
  test_cors: async (args: { target: string; origins?: string[]; methods?: string[] }) => {
    const safeArgs = JSON.stringify(args).replace(/'/g, "'\\''");
    const command = `python3 /opt/pentest/scripts/test-cors.py '${safeArgs}'`;
    const result = await executeInKali(command);
    return JSON.stringify({
      raw_output: result,
      evidence: {
        tool_name: "test_cors",
        evidence_captures: (args.origins || ["https://evil.com", "null"]).map((origin) => ({
          curl_command: `curl -s -H "Origin: ${origin}" "${args.target}"`,
          method: "GET",
          url: args.target,
          request_headers: { Origin: origin },
          timestamp: new Date().toISOString(),
        })),
      },
    });
  },

  test_ssrf: async (args: { target: string; parameter?: string; method?: string; payloads?: string[]; callback_url?: string }) => {
    const safeArgs = JSON.stringify(args).replace(/'/g, "'\\''");
    const command = `python3 /opt/pentest/scripts/test-ssrf.py '${safeArgs}'`;
    const result = await executeInKali(command);
    return JSON.stringify({
      raw_output: result,
      evidence: {
        tool_name: "test_ssrf",
        evidence_captures: [{
          curl_command: `python3 /opt/pentest/scripts/test-ssrf.py '${safeArgs}'`,
          method: args.method || "GET",
          url: args.target,
          request_headers: {},
          timestamp: new Date().toISOString(),
        }],
      },
    });
  },

  test_ssti: async (args: { target: string; parameter?: string; method?: string; engine?: string }) => {
    const safeArgs = JSON.stringify(args).replace(/'/g, "'\\''");
    const command = `python3 /opt/pentest/scripts/test-ssti.py '${safeArgs}'`;
    const result = await executeInKali(command);
    return JSON.stringify({
      raw_output: result,
      evidence: {
        tool_name: "test_ssti",
        evidence_captures: [{
          curl_command: `python3 /opt/pentest/scripts/test-ssti.py '${safeArgs}'`,
          method: args.method || "GET",
          url: args.target,
          request_headers: {},
          timestamp: new Date().toISOString(),
        }],
      },
    });
  },

  test_http_smuggling: async (args: { target: string; technique?: string; timeout?: number }) => {
    const safeArgs = JSON.stringify(args).replace(/'/g, "'\\''");
    const command = `python3 /opt/pentest/scripts/test-smuggling.py '${safeArgs}'`;
    return await executeInKali(command);
  },

  test_race_condition: async (args: {
    target: string;
    method?: string;
    data?: string;
    headers?: Record<string, string>;
    concurrency?: number;
    iterations?: number;
  }) => {
    const safeArgs = JSON.stringify(args).replace(/'/g, "'\\''");
    const command = `python3 /opt/pentest/scripts/test-race.py '${safeArgs}'`;
    return await executeInKali(command);
  },

  test_cache_poisoning: async (args: { target: string; headers_to_test?: string[]; cache_buster?: string }) => {
    const safeArgs = JSON.stringify(args).replace(/'/g, "'\\''");
    const command = `python3 /opt/pentest/scripts/test-cache-poison.py '${safeArgs}'`;
    return await executeInKali(command);
  },

  test_websocket: async (args: {
    target: string;
    origin?: string;
    messages?: string[];
    auth_token?: string;
    timeout?: number;
  }) => {
    const safeArgs = JSON.stringify(args).replace(/'/g, "'\\''");
    const command = `node /opt/pentest/scripts/test-websocket.js '${safeArgs}'`;
    return await executeInKali(command);
  },

  generate_waf_bypass: async (args: {
    attack_type: string;
    waf?: string;
    context?: string;
    base_payload?: string;
  }) => {
    const safeArgs = JSON.stringify(args).replace(/'/g, "'\\''");
    const command = `python3 /opt/pentest/scripts/generate-waf-bypass.py '${safeArgs}'`;
    return await executeInKali(command);
  },
};
