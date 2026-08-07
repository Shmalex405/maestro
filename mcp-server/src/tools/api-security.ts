import { executeInKali } from "../utils/docker-exec";
import { ToolEvidence, HttpEvidence } from "../utils/evidence-wrapper";

export const apiSecurityTools = [
  {
    name: "test_graphql_security",
    description: "Test GraphQL endpoint for security misconfigurations: introspection enabled, query batching, field suggestion leakage, depth limiting, alias-based DoS, and mutation discovery.",
    inputSchema: {
      type: "object",
      properties: {
        target: { type: "string", description: "GraphQL endpoint URL (e.g., 'https://app.com/graphql')" },
        headers: { type: "object", description: "Custom headers (e.g., authentication tokens)" },
        tests: {
          type: "array",
          items: { type: "string" },
          description: "Specific tests to run: 'introspection', 'batching', 'field_suggestions', 'depth_limit', 'aliasing'. Defaults to all.",
        },
      },
      required: ["target"],
    },
  },
  {
    name: "fuzz_api_schema",
    description: "Fuzz API endpoints by sending malformed, unexpected, or boundary-value inputs based on an OpenAPI/Swagger schema or parameter descriptions. Tests type confusion, missing fields, oversized payloads, and special characters.",
    inputSchema: {
      type: "object",
      properties: {
        target: { type: "string", description: "Base API URL" },
        schema_url: { type: "string", description: "OpenAPI/Swagger schema URL (e.g., '/api/docs/swagger.json')" },
        endpoints: {
          type: "array",
          items: { type: "string" },
          description: "Specific endpoint paths to fuzz (if no schema provided)",
        },
        headers: { type: "object", description: "Custom headers for authenticated fuzzing" },
        method: { type: "string", description: "HTTP method for endpoints without schema", default: "POST" },
      },
      required: ["target"],
    },
  },
  {
    name: "test_api_rate_limiting",
    description: "Test API rate limiting by sending rapid concurrent requests to an endpoint. Measures response codes (429), rate limit headers (X-RateLimit-*), and response time degradation.",
    inputSchema: {
      type: "object",
      properties: {
        target: { type: "string", description: "Target API endpoint URL" },
        method: { type: "string", description: "HTTP method", default: "GET" },
        requests: { type: "number", description: "Number of requests to send in rapid succession", default: 50 },
        headers: { type: "object", description: "Custom headers (e.g., authentication)" },
        data: { type: "string", description: "Request body for POST/PUT requests" },
      },
      required: ["target"],
    },
  },
  {
    name: "test_idor",
    description: "Test for Insecure Direct Object Reference (IDOR) vulnerabilities by accessing resources with different user contexts or sequential/predictable IDs.",
    inputSchema: {
      type: "object",
      properties: {
        target: { type: "string", description: "Target URL pattern with ID placeholder (e.g., 'https://app.com/api/users/{id}/profile')" },
        valid_id: { type: "string", description: "A known valid resource ID for the authenticated user" },
        test_ids: {
          type: "array",
          items: { type: "string" },
          description: "IDs to attempt access with (other users' IDs, sequential IDs, etc.)",
        },
        auth_token: { type: "string", description: "Authentication token for the test user" },
        auth_header: { type: "string", description: "Authentication header name", default: "Authorization" },
        method: { type: "string", description: "HTTP method", default: "GET" },
      },
      required: ["target"],
    },
  },
];

export const apiSecurityHandlers: Record<string, Function> = {
  test_graphql_security: async (args: { target: string; headers?: Record<string, string>; tests?: string[] }) => {
    const { target, headers = {}, tests = ["introspection", "batching", "field_suggestions", "depth_limit", "aliasing"] } = args;

    const headerFlags = Object.entries(headers)
      .map(([k, v]) => `-H "${k}: ${v}"`)
      .join(" ");

    const commands: string[] = [`echo "=== GraphQL Security Tests for ${target} ==="`];

    if (tests.includes("introspection")) {
      commands.push(`echo ""`);
      commands.push(`echo "--- 1. Introspection Query ---"`);
      commands.push(
        `curl -s -X POST ${headerFlags} -H "Content-Type: application/json" -d '{"query":"{__schema{types{name,fields{name,type{name}}}}}"}' "${target}" | head -c 5000`
      );
    }

    if (tests.includes("batching")) {
      commands.push(`echo ""`);
      commands.push(`echo "--- 2. Query Batching ---"`);
      commands.push(
        `curl -s -X POST ${headerFlags} -H "Content-Type: application/json" -d '[{"query":"{__typename}"},{"query":"{__typename}"},{"query":"{__typename}"}]' "${target}" | head -c 2000`
      );
    }

    if (tests.includes("field_suggestions")) {
      commands.push(`echo ""`);
      commands.push(`echo "--- 3. Field Suggestions (Information Leakage) ---"`);
      commands.push(
        `curl -s -X POST ${headerFlags} -H "Content-Type: application/json" -d '{"query":"{user{passwor}}"}' "${target}" | head -c 2000`
      );
      commands.push(
        `curl -s -X POST ${headerFlags} -H "Content-Type: application/json" -d '{"query":"{use}"}' "${target}" | head -c 2000`
      );
    }

    if (tests.includes("depth_limit")) {
      commands.push(`echo ""`);
      commands.push(`echo "--- 4. Query Depth Limit ---"`);
      const deepQuery = "{__schema{types{fields{type{fields{type{fields{type{fields{type{name}}}}}}}}}}";
      commands.push(
        `curl -s -X POST ${headerFlags} -H "Content-Type: application/json" -d '{"query":"${deepQuery}"}' "${target}" | head -c 2000`
      );
    }

    if (tests.includes("aliasing")) {
      commands.push(`echo ""`);
      commands.push(`echo "--- 5. Alias-Based Resource Exhaustion ---"`);
      const aliasQuery = Array.from({ length: 20 }, (_, i) => `a${i}:__typename`).join(" ");
      commands.push(
        `curl -s -X POST ${headerFlags} -H "Content-Type: application/json" -d '{"query":"{${aliasQuery}}"}' "${target}" | head -c 2000`
      );
    }

    const result = await executeInKali(commands.join(" && "));
    const evidence: ToolEvidence = {
      tool_name: "test_graphql_security",
      evidence_captures: tests.map((test) => ({
        curl_command: `curl -s -X POST ${headerFlags} -H "Content-Type: application/json" -d '...' "${target}"`,
        method: "POST",
        url: target,
        request_headers: { "Content-Type": "application/json", ...headers },
        timestamp: new Date().toISOString(),
      })),
    };
    return JSON.stringify({ raw_output: result, evidence });
  },

  fuzz_api_schema: async (args: {
    target?: string;
    base_url?: string;
    schema_url?: string;
    spec_url?: string;
    endpoints?: string[];
    headers?: Record<string, string>;
    method?: string;
    max_fuzz?: number;
    /** Default ON: write methods (POST/PUT/PATCH/DELETE) are discovered but never
     *  fired. Only an explicit false re-enables them — the deterministic pipeline
     *  never sends false, so scheduled scans cannot mutate/delete target data. */
    non_destructive?: boolean;
  }) => {
    // Map the pipeline's arg names (target / schema_url) to what fuzz-api.py
    // expects (base_url / spec_url). headers (incl. Authorization injected by the
    // pipeline) and non_destructive pass straight through.
    const payload: Record<string, unknown> = {
      spec_url: args.spec_url ?? args.schema_url,
      base_url: args.base_url ?? args.target,
      non_destructive: args.non_destructive !== false,
    };
    if (args.headers) payload.headers = args.headers;
    if (args.max_fuzz) payload.max_fuzz = args.max_fuzz;
    const safeArgs = JSON.stringify(payload).replace(/'/g, "'\\''");
    const command = `python3 /opt/pentest/scripts/fuzz-api.py '${safeArgs}'`;
    return await executeInKali(command);
  },

  test_api_rate_limiting: async (args: {
    target: string;
    method?: string;
    requests?: number;
    headers?: Record<string, string>;
    data?: string;
  }) => {
    const { target, method = "GET", requests = 50, headers = {}, data } = args;

    const headerFlags = Object.entries(headers)
      .map(([k, v]) => `-H "${k}: ${v}"`)
      .join(" ");
    const dataFlag = data ? `-d '${data}'` : "";

    const command = [
      `echo "=== Rate Limiting Test ==="`,
      `echo "Target: ${target}"`,
      `echo "Method: ${method}"`,
      `echo "Requests: ${requests}"`,
      `echo ""`,
      `RATE_LIMITED=0`,
      `SUCCESSFUL=0`,
      `ERRORS=0`,
      `echo "--- Sending ${requests} rapid requests ---"`,
      `for i in $(seq 1 ${requests}); do`,
      `  STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X ${method} ${headerFlags} ${dataFlag} "${target}")`,
      `  if [ "$STATUS" = "429" ]; then RATE_LIMITED=$((RATE_LIMITED + 1))`,
      `  elif [ "$STATUS" -ge 200 ] && [ "$STATUS" -lt 300 ]; then SUCCESSFUL=$((SUCCESSFUL + 1))`,
      `  else ERRORS=$((ERRORS + 1))`,
      `  fi`,
      `done`,
      `echo ""`,
      `echo "--- Results ---"`,
      `echo "Successful (2xx): $SUCCESSFUL"`,
      `echo "Rate Limited (429): $RATE_LIMITED"`,
      `echo "Other Errors: $ERRORS"`,
      `echo ""`,
      `echo "--- Rate Limit Headers (last response) ---"`,
      `curl -s -D - -o /dev/null -X ${method} ${headerFlags} ${dataFlag} "${target}" | grep -iE "(rate|limit|retry|x-ratelimit)" || echo "No rate limit headers found"`,
      `echo ""`,
      `if [ "$RATE_LIMITED" = "0" ]; then echo "WARNING: No rate limiting detected after ${requests} requests."; else echo "OK: Rate limiting detected ($RATE_LIMITED / ${requests} requests were throttled)."; fi`,
    ].join("\n");
    const result = await executeInKali(command);
    return JSON.stringify({
      raw_output: result,
      evidence: {
        tool_name: "test_api_rate_limiting",
        evidence_captures: [{
          curl_command: `curl -s -o /dev/null -w "%{http_code}" -X ${method} ${headerFlags} ${dataFlag} "${target}"`,
          method,
          url: target,
          request_headers: headers,
          timestamp: new Date().toISOString(),
        }],
      },
    });
  },

  test_idor: async (args: {
    target: string;
    valid_id?: string;
    test_ids?: string[];
    auth_token?: string;
    auth_header?: string;
    method?: string;
  }) => {
    const safeArgs = JSON.stringify(args).replace(/'/g, "'\\''");
    const command = `python3 /opt/pentest/scripts/test-idor.py '${safeArgs}'`;
    const result = await executeInKali(command);
    return JSON.stringify({
      raw_output: result,
      evidence: {
        tool_name: "test_idor",
        evidence_captures: [{
          curl_command: `python3 /opt/pentest/scripts/test-idor.py '${safeArgs}'`,
          method: args.method || "GET",
          url: args.target,
          request_headers: {},
          timestamp: new Date().toISOString(),
        }],
      },
    });
  },
};
