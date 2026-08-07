import { executeInKali } from "../utils/docker-exec";
import { ToolEvidence } from "../utils/evidence-wrapper";

export const tokenSecurityTools = [
  {
    name: "analyze_jwt",
    description: "Analyze a JWT token for security weaknesses. Decodes header/payload, checks algorithm confusion (none/HS256 vs RS256), expiration, signature validation, and known vulnerabilities.",
    inputSchema: {
      type: "object",
      properties: {
        token: { type: "string", description: "The JWT token string to analyze" },
        secret: { type: "string", description: "Optional secret/key to test signature verification" },
        test_none_alg: { type: "boolean", description: "Test 'none' algorithm bypass", default: true },
        test_alg_confusion: { type: "boolean", description: "Test algorithm confusion attacks (RS256 to HS256)", default: true },
      },
      required: ["token"],
    },
  },
  {
    name: "test_token_replay",
    description: "Test if expired, revoked, or logged-out tokens are still accepted by the server. Sends requests with the provided token and checks for valid responses.",
    inputSchema: {
      type: "object",
      properties: {
        target: { type: "string", description: "Target URL (API endpoint) to test token replay against" },
        token: { type: "string", description: "The token to replay (e.g., expired JWT, old session token)" },
        token_header: { type: "string", description: "HTTP header name for the token", default: "Authorization" },
        token_prefix: { type: "string", description: "Prefix before the token value (e.g., 'Bearer')", default: "Bearer" },
        method: { type: "string", description: "HTTP method to use", default: "GET" },
      },
      required: ["target", "token"],
    },
  },
];

export const tokenSecurityHandlers: Record<string, Function> = {
  analyze_jwt: async (args: { token: string; secret?: string; test_none_alg?: boolean; test_alg_confusion?: boolean }) => {
    const safeArgs = JSON.stringify(args).replace(/'/g, "'\\''");
    const command = `python3 /opt/pentest/scripts/test-jwt.py '${safeArgs}'`;
    return await executeInKali(command);
  },

  test_token_replay: async (args: {
    target: string;
    token: string;
    token_header?: string;
    token_prefix?: string;
    method?: string;
  }) => {
    const { target, token, token_header = "Authorization", token_prefix = "Bearer", method = "GET" } = args;
    const headerValue = token_prefix ? `${token_prefix} ${token}` : token;
    const command = [
      `echo "=== Token Replay Test ==="`,
      `echo "Target: ${target}"`,
      `echo "Method: ${method}"`,
      `echo "Header: ${token_header}"`,
      `echo ""`,
      `echo "--- Request with token ---"`,
      `STATUS=$(curl -s -o /tmp/token-replay-body.txt -w "%{http_code}" -X ${method} -H "${token_header}: ${headerValue}" "${target}")`,
      `echo "HTTP Status: $STATUS"`,
      `echo "Response Body:"`,
      `cat /tmp/token-replay-body.txt`,
      `echo ""`,
      `echo ""`,
      `echo "--- Request without token (baseline) ---"`,
      `BASELINE=$(curl -s -o /tmp/token-baseline-body.txt -w "%{http_code}" -X ${method} "${target}")`,
      `echo "HTTP Status: $BASELINE"`,
      `echo "Response Body:"`,
      `cat /tmp/token-baseline-body.txt`,
      `echo ""`,
      `echo ""`,
      `echo "--- Analysis ---"`,
      `if [ "$STATUS" = "200" ] || [ "$STATUS" = "201" ]; then echo "WARNING: Token was ACCEPTED (HTTP $STATUS). Token may still be valid or replay is possible."; elif [ "$STATUS" = "401" ] || [ "$STATUS" = "403" ]; then echo "OK: Token was REJECTED (HTTP $STATUS). Server properly invalidates tokens."; else echo "INCONCLUSIVE: Received HTTP $STATUS. Manual review recommended."; fi`,
    ].join(" && ");
    const result = await executeInKali(command);
    return JSON.stringify({
      raw_output: result,
      evidence: {
        tool_name: "test_token_replay",
        evidence_captures: [{
          curl_command: `curl -s -X ${method} -H "${token_header}: ${headerValue}" "${target}"`,
          method,
          url: target,
          request_headers: { [token_header]: headerValue },
          timestamp: new Date().toISOString(),
        }],
      },
    });
  },
};
