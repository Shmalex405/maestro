/**
 * API Security Agent Implementation
 *
 * Specialized agent for deep API security testing across REST, GraphQL, and
 * WebSocket protocols. Focuses on authentication/authorization bypasses,
 * injection attacks, IDOR, rate limiting, and protocol-specific vulnerabilities.
 */

import {
  BaseAgent,
  AgentConfig,
  AgentInput,
  ToolDefinition,
  ProgressCallback,
} from "../base-agent";
import { advancedWebHandlers } from "../../tools/advanced-web";
import { apiSecurityHandlers } from "../../tools/api-security";
import { tokenSecurityHandlers } from "../../tools/token-security";
import { webAppHandlers } from "../../tools/web-app";
import { browserHandlers } from "../../tools/browser";

// API Security agent configuration
const API_SECURITY_AGENT_CONFIG: AgentConfig = {
  name: "api-security-agent",
  description: "API security testing agent for REST, GraphQL, and WebSocket APIs",
  maxIterations: 30,
  timeoutMs: 900000, // 15 minutes
  requiresScopeValidation: true,
  tools: [
    "test_graphql_security",
    "fuzz_api_schema",
    "test_api_rate_limiting",
    "test_idor",
    "test_websocket",
    "test_cors",
    "analyze_jwt",
    "test_token_replay",
    "crawl_site",
    "fuzz_endpoints",
    "run_sqlmap",
    "browser_navigate",
    "browser_evaluate",
    "browser_network_log",
  ],
};

// Tool definitions for Claude API
const API_SECURITY_TOOL_DEFINITIONS: ToolDefinition[] = [
  {
    name: "test_graphql_security",
    description:
      "Test a GraphQL endpoint for security misconfigurations. Checks for introspection " +
      "enabled, query batching, field suggestion leakage, depth limiting, and alias-based " +
      "resource exhaustion. Use this when a GraphQL endpoint is detected.",
    input_schema: {
      type: "object",
      properties: {
        target: {
          type: "string",
          description: "GraphQL endpoint URL (e.g., 'https://app.com/graphql')",
        },
        headers: {
          type: "object",
          description: "Custom headers for authentication (e.g., {'Authorization': 'Bearer token'})",
        },
        tests: {
          type: "array",
          items: { type: "string" },
          description:
            "Specific tests to run: 'introspection', 'batching', 'field_suggestions', 'depth_limit', 'aliasing'. Defaults to all.",
        },
      },
      required: ["target"],
    },
  },
  {
    name: "fuzz_api_schema",
    description:
      "Fuzz API endpoints using OpenAPI/Swagger schema or manual endpoint definitions. " +
      "Sends malformed, unexpected, and boundary-value inputs to discover input validation " +
      "weaknesses, type confusion, and error disclosure.",
    input_schema: {
      type: "object",
      properties: {
        target: {
          type: "string",
          description: "Base API URL",
        },
        schema_url: {
          type: "string",
          description: "OpenAPI/Swagger schema URL (e.g., '/api/docs/swagger.json')",
        },
        endpoints: {
          type: "array",
          items: { type: "string" },
          description: "Specific endpoint paths to fuzz (if no schema provided)",
        },
        headers: {
          type: "object",
          description: "Custom headers for authenticated fuzzing",
        },
        method: {
          type: "string",
          description: "HTTP method for endpoints without schema (default: POST)",
        },
      },
      required: ["target"],
    },
  },
  {
    name: "test_api_rate_limiting",
    description:
      "Test API rate limiting by sending rapid concurrent requests. Measures whether " +
      "the API returns 429 responses, includes X-RateLimit-* headers, or degrades gracefully. " +
      "Use on authentication endpoints, sensitive operations, and data endpoints.",
    input_schema: {
      type: "object",
      properties: {
        target: {
          type: "string",
          description: "Target API endpoint URL",
        },
        method: {
          type: "string",
          description: "HTTP method (default: GET)",
        },
        requests: {
          type: "number",
          description: "Number of requests to send in rapid succession (default: 50)",
        },
        headers: {
          type: "object",
          description: "Custom headers (e.g., authentication)",
        },
        data: {
          type: "string",
          description: "Request body for POST/PUT requests",
        },
      },
      required: ["target"],
    },
  },
  {
    name: "test_idor",
    description:
      "Test for Insecure Direct Object Reference (IDOR) by accessing resources with " +
      "different user IDs or sequential/predictable identifiers. Compares responses to " +
      "detect unauthorized access to other users' data.",
    input_schema: {
      type: "object",
      properties: {
        target: {
          type: "string",
          description:
            "Target URL pattern with ID (e.g., 'https://app.com/api/users/{id}/profile')",
        },
        valid_id: {
          type: "string",
          description: "A known valid resource ID for the authenticated user",
        },
        test_ids: {
          type: "array",
          items: { type: "string" },
          description: "IDs to attempt access with (other users' IDs, sequential IDs, etc.)",
        },
        auth_token: {
          type: "string",
          description: "Authentication token for the test user",
        },
        auth_header: {
          type: "string",
          description: "Authentication header name (default: Authorization)",
        },
        method: {
          type: "string",
          description: "HTTP method (default: GET)",
        },
      },
      required: ["target"],
    },
  },
  {
    name: "test_websocket",
    description:
      "Test WebSocket endpoint security. Checks for missing authentication on the " +
      "upgrade request, origin validation, message injection, and cross-site WebSocket " +
      "hijacking (CSWSH). Use when WS or WSS endpoints are discovered.",
    input_schema: {
      type: "object",
      properties: {
        target: {
          type: "string",
          description: "WebSocket URL (ws:// or wss://)",
        },
        origin: {
          type: "string",
          description: "Origin header to send for cross-origin tests",
        },
        messages: {
          type: "array",
          items: { type: "string" },
          description: "Messages to send after connection (e.g., injection payloads)",
        },
        auth_token: {
          type: "string",
          description: "Authentication token to include",
        },
      },
      required: ["target"],
    },
  },
  {
    name: "test_cors",
    description:
      "Test CORS configuration for overly permissive Access-Control-Allow-Origin, " +
      "credential reflection, null origin acceptance, and wildcard origins. Use on every " +
      "API endpoint to detect cross-origin data leakage risks.",
    input_schema: {
      type: "object",
      properties: {
        target: {
          type: "string",
          description: "Target URL to test CORS policy on",
        },
        origins: {
          type: "array",
          items: { type: "string" },
          description: "Custom origin values to test (default: evil.com, null, target subdomain)",
        },
      },
      required: ["target"],
    },
  },
  {
    name: "analyze_jwt",
    description:
      "Analyze a JWT token for security weaknesses. Decodes header/payload, checks for " +
      "'none' algorithm bypass, algorithm confusion (RS256 to HS256), weak secrets, " +
      "expiration handling, and known JWT vulnerabilities.",
    input_schema: {
      type: "object",
      properties: {
        token: {
          type: "string",
          description: "The JWT token string to analyze",
        },
        secret: {
          type: "string",
          description: "Optional secret/key to test signature verification",
        },
        test_none_alg: {
          type: "boolean",
          description: "Test 'none' algorithm bypass (default: true)",
        },
        test_alg_confusion: {
          type: "boolean",
          description: "Test algorithm confusion attacks (default: true)",
        },
      },
      required: ["token"],
    },
  },
  {
    name: "test_token_replay",
    description:
      "Test if expired, revoked, or logged-out tokens are still accepted by the server. " +
      "Sends requests with the provided token and compares against unauthenticated baseline " +
      "to detect improper token invalidation.",
    input_schema: {
      type: "object",
      properties: {
        target: {
          type: "string",
          description: "Target API endpoint to test token replay against",
        },
        token: {
          type: "string",
          description: "The token to replay (e.g., expired JWT, old session token)",
        },
        token_header: {
          type: "string",
          description: "HTTP header name for the token (default: Authorization)",
        },
        token_prefix: {
          type: "string",
          description: "Prefix before the token value (default: Bearer)",
        },
        method: {
          type: "string",
          description: "HTTP method to use (default: GET)",
        },
      },
      required: ["target", "token"],
    },
  },
  {
    name: "crawl_site",
    description:
      "Crawl a website to discover all API endpoints, forms, and parameters. Use this " +
      "first to build a map of the application. Especially useful for finding /api/ paths, " +
      "OpenAPI schema endpoints, and GraphQL endpoints.",
    input_schema: {
      type: "object",
      properties: {
        target: {
          type: "string",
          description: "Base URL to crawl",
        },
        depth: {
          type: "number",
          description: "Crawl depth (default: 2)",
        },
      },
      required: ["target"],
    },
  },
  {
    name: "fuzz_endpoints",
    description:
      "Discover hidden API endpoints, documentation, and admin paths using wordlist fuzzing. " +
      "Use with the 'api' wordlist to find /swagger.json, /openapi.json, /graphql, /api-docs, etc.",
    input_schema: {
      type: "object",
      properties: {
        target: {
          type: "string",
          description: "Base URL with FUZZ placeholder (e.g., 'https://app.com/FUZZ')",
        },
        wordlist: {
          type: "string",
          description: "Wordlist: common, big, api, admin (default: api)",
        },
        extensions: {
          type: "string",
          description: "File extensions to try (e.g., 'json,yaml,yml')",
        },
      },
      required: ["target"],
    },
  },
  {
    name: "run_sqlmap",
    description:
      "Test API parameters for SQL injection. NON-DESTRUCTIVE mode only. Use on REST " +
      "endpoints with query parameters or JSON body fields that interact with a database.",
    input_schema: {
      type: "object",
      properties: {
        target: {
          type: "string",
          description: "Target URL with parameters (e.g., /api/users?id=1)",
        },
        method: {
          type: "string",
          enum: ["GET", "POST"],
          description: "HTTP method",
        },
        data: {
          type: "string",
          description: "POST data / JSON body for injection testing",
        },
        level: {
          type: "number",
          description: "Test level 1-5 (default: 2)",
        },
        risk: {
          type: "number",
          description: "Risk level 1-3 (default: 1, NEVER exceed 2)",
        },
      },
      required: ["target"],
    },
  },
];

// Browser tool definitions for API testing
const API_BROWSER_TOOL_DEFINITIONS: ToolDefinition[] = [
  {
    name: "browser_navigate",
    description:
      "Navigate to a URL in the browser. Use for SPA-based APIs that require JavaScript " +
      "execution, or to load API documentation pages.",
    input_schema: {
      type: "object",
      properties: {
        url: { type: "string", description: "URL to navigate to" },
        wait_for: { type: "string", description: "CSS selector to wait for" },
      },
      required: ["url"],
    },
  },
  {
    name: "browser_evaluate",
    description:
      "Execute JavaScript in the browser to interact with APIs directly. Use to make " +
      "fetch() calls from the browser context (subject to CORS), extract tokens from " +
      "localStorage/sessionStorage, or inspect SPA state.",
    input_schema: {
      type: "object",
      properties: {
        script: {
          type: "string",
          description: "JavaScript code to evaluate in browser context",
        },
      },
      required: ["script"],
    },
  },
  {
    name: "browser_network_log",
    description:
      "Get captured network requests from the browser. Essential for discovering hidden " +
      "API calls made by SPAs, including authentication flows, GraphQL queries, and " +
      "WebSocket connections.",
    input_schema: {
      type: "object",
      properties: {
        filter: {
          type: "string",
          description: "URL pattern regex to filter (e.g., '/api/', '/graphql')",
        },
      },
    },
  },
];

/**
 * API Security Agent Implementation
 */
export class ApiSecurityAgentImpl extends BaseAgent {
  constructor(onProgress?: ProgressCallback) {
    super(
      API_SECURITY_AGENT_CONFIG,
      {
        ...advancedWebHandlers,
        ...apiSecurityHandlers,
        ...tokenSecurityHandlers,
        ...webAppHandlers,
        ...browserHandlers,
      },
      onProgress
    );
  }

  /**
   * Get tool definitions for Claude
   */
  getToolDefinitions(): ToolDefinition[] {
    return [...API_SECURITY_TOOL_DEFINITIONS, ...API_BROWSER_TOOL_DEFINITIONS];
  }

  /**
   * Build the initial prompt for Claude
   */
  buildInitialPrompt(input: AgentInput): string {
    let prompt = `# API Security Testing Task

You are the API Security Agent. Your mission is to perform deep security testing of REST, GraphQL, and WebSocket APIs on the provided targets.

## Targets to Test:
`;

    if (input.targets && input.targets.length > 0) {
      for (const target of input.targets) {
        prompt += `- ${target}\n`;
      }
    } else {
      prompt += "No targets provided. Please indicate an error.\n";
    }

    // Include context from previous agents
    if (input.context?.discoveredEndpoints) {
      prompt += `\n## Discovered Endpoints (from prior agents):\n`;
      for (const ep of input.context.discoveredEndpoints.slice(0, 30)) {
        prompt += `- ${typeof ep === "string" ? ep : JSON.stringify(ep)}\n`;
      }
    }

    if (input.context?.webTechnologies) {
      prompt += `\n## Detected Technologies:\n`;
      for (const [host, techs] of Object.entries(input.context.webTechnologies)) {
        prompt += `- ${host}: ${JSON.stringify(techs)}\n`;
      }
    }

    if (input.context?.attackSurface) {
      const as = input.context.attackSurface;
      prompt += `\n## Attack Surface Intelligence (from Code Analysis):\n`;
      if (as.prioritizedAttackVectors?.length) {
        for (const v of as.prioritizedAttackVectors.slice(0, 15)) {
          prompt += `- [${v.confidence?.toUpperCase() || "MEDIUM"}] ${v.type} -> ${v.target} (${v.reason})\n`;
        }
      }
      if (as.entryPoints?.length) {
        prompt += `\n### API Entry Points (${as.entryPoints.length} total):\n`;
        for (const ep of as.entryPoints.slice(0, 20)) {
          const auth = ep.auth === "none" ? " [NO AUTH]" : "";
          prompt += `- ${ep.method || "GET"} ${ep.route}${auth}\n`;
        }
      }
    }

    prompt += `
## Your Workflow:

### Phase 1: API Discovery
1. **Crawl the target** with \`crawl_site\` to discover all endpoints
2. **Fuzz for API documentation** with \`fuzz_endpoints\` using the 'api' wordlist
   - Look for: /swagger.json, /openapi.json, /api-docs, /graphql, /graphiql, /playground
3. **Check browser network log** with \`browser_navigate\` + \`browser_network_log\` to discover
   client-side API calls in SPAs

### Phase 2: API Classification
4. **Classify the API type** based on discovery results:
   - REST API: standard HTTP endpoints with JSON responses
   - GraphQL: /graphql endpoint, JSON requests with "query" field
   - WebSocket: ws:// or wss:// endpoints in network log

### Phase 3: GraphQL Testing (if detected)
5. **Run GraphQL security tests** with \`test_graphql_security\`:
   - Introspection: can the full schema be dumped?
   - Batching: can multiple queries be sent in one request?
   - Depth limit: does the server prevent deeply nested queries?
   - Aliasing: can resource exhaustion occur via aliases?
   - Field suggestions: does the server leak field names in errors?

### Phase 4: REST / Schema-Based Testing
6. **Schema-based fuzzing** with \`fuzz_api_schema\` if OpenAPI schema is available
7. **SQL injection testing** with \`run_sqlmap\` on all parameterized endpoints

### Phase 5: Authentication & Authorization
8. **JWT analysis** with \`analyze_jwt\` on any tokens found
   - Extract tokens from browser localStorage/cookies via \`browser_evaluate\`
9. **Token replay** with \`test_token_replay\` to verify token invalidation
10. **IDOR testing** with \`test_idor\` on resource endpoints with numeric/UUID IDs
    - Test accessing other users' resources with your authenticated token

### Phase 6: Rate Limiting & CORS
11. **Rate limiting** with \`test_api_rate_limiting\` on:
    - Authentication endpoints (login, password reset)
    - Sensitive data endpoints
    - Resource-intensive operations
12. **CORS testing** with \`test_cors\` on all API endpoints

### Phase 7: Injection & WebSocket
13. **SQL injection** with \`run_sqlmap\` on all remaining parameterized endpoints
14. **WebSocket testing** with \`test_websocket\` if WS endpoints were discovered

## CRITICAL SAFETY RULES:
- NEVER use sqlmap with risk > 2
- NEVER execute destructive operations
- Stay non-destructive at all times
- If unsure about safety, err on the side of caution

## Output Requirements:

Provide a summary with:
- API type detected (REST / GraphQL / WebSocket / mixed)
- OpenAPI/schema availability
- Authentication mechanism identified
- Vulnerabilities found by category
- Evidence for each finding
- Recommendations for remediation

Begin API security testing now.`;

    return prompt;
  }

  /**
   * Get the system prompt for this agent
   */
  getSystemPrompt(): string {
    return `You are the API Security Agent, specializing in REST, GraphQL, and WebSocket API testing.

## Your Capabilities:
- GraphQL security testing (introspection, batching, depth, aliasing, field suggestions)
- REST API schema-based fuzzing
- JWT token analysis and attack testing
- IDOR and authorization bypass testing
- Rate limiting verification
- CORS misconfiguration detection
- WebSocket security testing
- SQL injection on API parameters
- Token replay and session management testing

## Decision Guidelines:

### When to use test_graphql_security:
- Target has a /graphql endpoint
- Response content-type is application/json with "data" key
- Network log shows GraphQL queries
- Always test ALL five checks: introspection, batching, field_suggestions, depth_limit, aliasing

### When to use fuzz_api_schema:
- OpenAPI/Swagger schema is available
- You want to test input validation across all endpoints
- Use after discovering the API documentation URL

### When to use analyze_jwt:
- Any Bearer token is discovered in headers/cookies/localStorage
- Tokens appear to be JWT format (xxx.yyy.zzz base64-encoded)
- Authentication uses token-based sessions

### When to use test_token_replay:
- After finding a JWT or session token
- To verify that tokens are properly invalidated on logout/expiration
- To test if old tokens are still accepted

### When to use test_idor:
- API endpoints include resource IDs in the path or query
- Different users should have isolated data
- Look for patterns like /api/users/{id}, /api/orders/{id}, /api/documents/{id}

### When to use test_api_rate_limiting:
- On login/authentication endpoints (brute-force protection)
- On password reset endpoints
- On any endpoint that accesses sensitive data
- On resource-intensive operations (search, export, report generation)

### When to use test_cors:
- On every API endpoint, especially those that return sensitive data
- Focus on endpoints that use credentials (cookies, Authorization headers)

### When to use test_websocket:
- WebSocket URLs discovered in network log (ws:// or wss://)
- Chat or real-time features detected
- Test with and without authentication

### When to use browser_evaluate:
- To extract tokens from localStorage/sessionStorage
- To inspect SPA application state
- To make fetch() calls from the browser context

### When to use browser_network_log:
- After browser_navigate, to discover hidden API calls
- To find API patterns, authentication flows, and WebSocket connections

## Important Rules:
1. Be systematic: discover first, then classify, then test each category
2. Test both authenticated and unauthenticated access on every endpoint
3. Document every finding with clear evidence
4. For GraphQL, always check all five security aspects
5. For REST, prioritize endpoints that handle sensitive data
6. NEVER use sqlmap risk > 2 or destructive techniques`;
  }

  /**
   * Override extractFindings for API-specific finding extraction
   */
  protected extractFindings(result: string, toolName: string, target?: string): void {
    // Call parent implementation first
    super.extractFindings(result, toolName, target);

    try {
      const parsed = JSON.parse(result);

      // GraphQL-specific extraction
      if (toolName === "test_graphql_security") {
        if (parsed.introspection_enabled || (typeof result === "string" && result.includes("__schema"))) {
          this.addFinding({
            title: "GraphQL Introspection Enabled",
            severity: "medium",
            target: target || "unknown",
            description:
              "GraphQL introspection is enabled, allowing attackers to dump the full schema " +
              "including types, fields, queries, and mutations. This reveals the entire API surface.",
            evidence: typeof parsed === "string" ? parsed.slice(0, 1000) : JSON.stringify(parsed).slice(0, 1000),
            remediation: "Disable introspection in production. Most GraphQL servers support an introspection toggle.",
            source: toolName,
          });
        }

        if (parsed.batching_allowed) {
          this.addFinding({
            title: "GraphQL Query Batching Allowed",
            severity: "low",
            target: target || "unknown",
            description:
              "GraphQL query batching is enabled, allowing multiple queries in a single request. " +
              "This can be used for brute-force attacks and resource exhaustion.",
            source: toolName,
          });
        }
      }

      // JWT analysis extraction
      if (toolName === "analyze_jwt") {
        if (parsed.none_algorithm_accepted) {
          this.addFinding({
            title: "JWT 'none' Algorithm Bypass Accepted",
            severity: "critical",
            target: target || "unknown",
            description:
              "The server accepts JWTs with the 'none' algorithm, allowing complete authentication bypass.",
            evidence: parsed.none_algorithm_response,
            remediation: "Explicitly whitelist allowed algorithms in JWT verification. Never accept 'none'.",
            source: toolName,
          });
        }

        if (parsed.algorithm_confusion) {
          this.addFinding({
            title: "JWT Algorithm Confusion Vulnerability",
            severity: "high",
            target: target || "unknown",
            description:
              "The server is vulnerable to JWT algorithm confusion (RS256 to HS256 downgrade), " +
              "allowing an attacker to forge tokens using the public key as HMAC secret.",
            evidence: parsed.confusion_response,
            remediation: "Use asymmetric algorithms only and verify the algorithm in the JWT header matches expected.",
            source: toolName,
          });
        }
      }

      // IDOR extraction
      if (toolName === "test_idor") {
        if (parsed.vulnerable || parsed.idor_found) {
          this.addFinding({
            title: "Insecure Direct Object Reference (IDOR)",
            severity: "high",
            target: target || "unknown",
            description:
              "The API allows accessing other users' resources by changing the object ID in the request. " +
              "This is an authorization bypass vulnerability.",
            evidence: parsed.evidence || JSON.stringify(parsed.results || parsed).slice(0, 1000),
            remediation: "Implement server-side authorization checks. Verify the requesting user owns the resource.",
            source: toolName,
          });
        }
      }

      // Rate limiting extraction
      if (toolName === "test_api_rate_limiting") {
        const resultStr = typeof result === "string" ? result : JSON.stringify(result);
        if (resultStr.includes("No rate limiting detected") || resultStr.includes("WARNING")) {
          this.addFinding({
            title: "Missing API Rate Limiting",
            severity: "medium",
            target: target || "unknown",
            description:
              "No rate limiting was detected on the API endpoint after sending rapid requests. " +
              "This enables brute-force attacks, credential stuffing, and denial of service.",
            evidence: resultStr.slice(0, 1000),
            remediation:
              "Implement rate limiting on all API endpoints. Use 429 status codes and X-RateLimit-* headers.",
            source: toolName,
          });
        }
      }

      // CORS extraction
      if (toolName === "test_cors") {
        const resultStr = typeof result === "string" ? result : JSON.stringify(result);
        if (
          resultStr.includes("VULNERABLE") ||
          resultStr.includes("Access-Control-Allow-Origin: *") ||
          resultStr.includes("reflects origin")
        ) {
          this.addFinding({
            title: "CORS Misconfiguration",
            severity: "medium",
            target: target || "unknown",
            description:
              "The API has an overly permissive CORS policy, potentially allowing cross-origin " +
              "data theft from authenticated users.",
            evidence: resultStr.slice(0, 1000),
            remediation:
              "Restrict Access-Control-Allow-Origin to trusted domains. Never use wildcards with credentials.",
            source: toolName,
          });
        }
      }

      // Token replay extraction
      if (toolName === "test_token_replay") {
        const resultStr = typeof result === "string" ? result : JSON.stringify(result);
        if (resultStr.includes("Token was ACCEPTED") || resultStr.includes("replay is possible")) {
          this.addFinding({
            title: "Token Replay Vulnerability",
            severity: "high",
            target: target || "unknown",
            description:
              "The server accepts expired or previously revoked tokens, indicating improper " +
              "token invalidation. An attacker with a stolen token can maintain access indefinitely.",
            evidence: resultStr.slice(0, 1000),
            remediation:
              "Implement server-side token revocation. Use short-lived tokens with refresh mechanisms.",
            source: toolName,
          });
        }
      }

      // Store discovered API patterns in context
      if (toolName === "crawl_site") {
        this.state.context.apiEndpoints = parsed.endpoints || parsed.urls || [];
      }

      if (toolName === "browser_network_log") {
        if (!this.state.context.networkApiCalls) {
          this.state.context.networkApiCalls = [];
        }
        const apiCalls = (parsed.requests || parsed || []).filter(
          (r: any) =>
            typeof r === "object" &&
            r.url &&
            (r.url.includes("/api/") ||
              r.url.includes("/graphql") ||
              r.url.includes("/v1/") ||
              r.url.includes("/v2/"))
        );
        this.state.context.networkApiCalls.push(...apiCalls);
      }
    } catch {
      // Not JSON, try text-based extraction
      const resultStr = typeof result === "string" ? result : "";

      if (toolName === "test_cors" && resultStr.includes("VULNERABLE")) {
        this.addFinding({
          title: "CORS Misconfiguration",
          severity: "medium",
          target: target || "unknown",
          description: "Overly permissive CORS policy detected.",
          evidence: resultStr.slice(0, 1000),
          source: toolName,
        });
      }

      if (toolName === "test_api_rate_limiting" && resultStr.includes("No rate limiting detected")) {
        this.addFinding({
          title: "Missing API Rate Limiting",
          severity: "medium",
          target: target || "unknown",
          description: "No rate limiting detected on the API endpoint.",
          evidence: resultStr.slice(0, 1000),
          source: toolName,
        });
      }
    }
  }
}
