# API Security Agent Skill

## Purpose

The API Security Agent performs deep security testing of REST, GraphQL, and WebSocket APIs. It goes beyond generic web application testing to focus on API-specific attack vectors: authentication/authorization bypasses, injection through API parameters, IDOR, rate limiting gaps, token security weaknesses, and protocol-specific vulnerabilities.

## When to Use

- The target is a REST API (JSON endpoints, OpenAPI/Swagger documentation available)
- A GraphQL endpoint is detected (/graphql, /graphiql, /playground)
- WebSocket connections are discovered in network traffic
- The target is a single-page application (SPA) backed by API endpoints
- You need to test API authentication mechanisms (JWT, OAuth, API keys)
- You need to verify authorization boundaries between users/roles
- After the web-app agent for deeper API-specific testing

## Available Tools

### API-Specific Tools

| Tool | Description |
|------|-------------|
| `test_graphql_security` | Tests GraphQL endpoints for introspection, batching, field suggestions, depth limiting, and alias-based resource exhaustion |
| `fuzz_api_schema` | Fuzzes API endpoints using OpenAPI/Swagger schema or manual endpoint definitions with malformed, boundary-value, and type-confused inputs |
| `test_api_rate_limiting` | Sends rapid concurrent requests to measure rate limiting enforcement (429 responses, X-RateLimit headers, response degradation) |
| `test_idor` | Tests Insecure Direct Object Reference by accessing resources with different user IDs or predictable identifiers |

### Token & Authentication Tools

| Tool | Description |
|------|-------------|
| `analyze_jwt` | Analyzes JWT tokens for 'none' algorithm bypass, algorithm confusion (RS256 to HS256), weak secrets, expiration handling |
| `test_token_replay` | Tests if expired, revoked, or logged-out tokens are still accepted by the server |

### Web Testing Tools

| Tool | Description |
|------|-------------|
| `test_cors` | Tests CORS configuration for overly permissive origins, credential reflection, null origin acceptance |
| `test_websocket` | Tests WebSocket endpoint security for missing auth, origin validation, message injection, CSWSH |
| `crawl_site` | Crawls the application to discover API endpoints, forms, and parameters |
| `fuzz_endpoints` | Discovers hidden API endpoints, documentation paths, and admin interfaces |
| `run_sqlmap` | Tests API parameters for SQL injection (NON-DESTRUCTIVE mode) |

### Browser Tools

| Tool | Description |
|------|-------------|
| `browser_navigate` | Navigates browser for SPA-based API testing and documentation discovery |
| `browser_evaluate` | Executes JavaScript to extract tokens from localStorage/sessionStorage, make fetch() calls |
| `browser_network_log` | Captures network requests to discover hidden API calls, auth flows, and WebSocket connections |

## Workflow Pattern

### Phase 1: API Discovery
1. **Crawl** the target with `crawl_site` to discover all endpoints
2. **Fuzz for documentation** with `fuzz_endpoints` using the `api` wordlist
   - Target paths: /swagger.json, /openapi.json, /api-docs, /graphql, /graphiql, /playground, /api/schema
3. **Capture network traffic** with `browser_navigate` + `browser_network_log` to discover SPA API calls

### Phase 2: API Classification
4. **Classify the API type**:
   - **REST**: Standard HTTP endpoints with JSON responses, versioned paths (/v1/, /v2/)
   - **GraphQL**: Single /graphql endpoint, POST requests with "query" field
   - **WebSocket**: ws:// or wss:// URLs in network log
   - **Mixed**: Applications may use multiple API types

### Phase 3: GraphQL Testing
5. **Run full GraphQL security suite** with `test_graphql_security`:
   - **Introspection**: Can the full schema be dumped? (exposes types, fields, queries, mutations)
   - **Batching**: Are multiple queries accepted in one request? (brute-force amplification)
   - **Field suggestions**: Do errors leak field names? ("Did you mean: password, passwordHash?")
   - **Depth limiting**: Does the server prevent deeply nested queries? (DoS vector)
   - **Aliasing**: Can resource exhaustion occur via alias repetition?

### Phase 4: REST / Schema-Based Testing
6. **Schema-based fuzzing** with `fuzz_api_schema` if OpenAPI spec is available
   - Tests: type confusion, missing required fields, oversized payloads, special characters, boundary values
7. **SQL injection** with `run_sqlmap` on parameterized endpoints (level 2, risk 1)

### Phase 5: Authentication & Authorization
8. **JWT analysis** with `analyze_jwt` on tokens found in:
   - Browser localStorage/sessionStorage (extracted via `browser_evaluate`)
   - Authorization headers
   - Cookies
9. **Token replay** with `test_token_replay`:
   - Log out and replay the old token
   - Wait for expiration and replay
   - Use token from different IP context
10. **IDOR testing** with `test_idor`:
    - Replace user IDs with other users' IDs
    - Try sequential enumeration (id=1, id=2, ...)
    - Try UUID guessing or enumeration
    - Test both read (GET) and write (PUT/PATCH/DELETE) operations

### Phase 6: Rate Limiting & CORS
11. **Rate limiting** with `test_api_rate_limiting` on:
    - Authentication endpoints (login, password reset, OTP verification)
    - Sensitive data retrieval endpoints
    - Resource-intensive operations (search, export, report generation)
    - File upload endpoints
12. **CORS testing** with `test_cors` on all API endpoints

### Phase 7: Injection & WebSocket
13. **Injection testing** with `run_sqlmap` on remaining parameterized endpoints
14. **WebSocket testing** with `test_websocket` if WS endpoints were discovered:
    - Connection without authentication
    - Cross-origin connection (CSWSH)
    - Message injection payloads

## GraphQL Testing Methodology

### Introspection
- Send the standard introspection query: `{__schema{types{name,fields{name,type{name}}}}}`
- If successful, the full schema is exposed (types, queries, mutations, subscriptions)
- Severity: Medium (information disclosure that enables further attacks)
- Remediation: Disable introspection in production

### Query Batching
- Send an array of queries: `[{"query":"{__typename}"},{"query":"{__typename}"}]`
- If the server processes all queries, it enables:
  - Authentication brute-force (batch login attempts)
  - Rate limit bypass (one HTTP request, many operations)
- Severity: Low-Medium depending on what operations are batchable

### Field Suggestions
- Send a query with a deliberately misspelled field: `{user{passwor}}`
- Check if the error response includes "Did you mean: password?"
- This leaks the schema even when introspection is disabled
- Severity: Low-Medium (schema enumeration without introspection)

### Depth Limiting
- Send a deeply nested query: `{a{b{c{d{e{f{g{h{name}}}}}}}}}`
- If the server executes it without error, resource exhaustion is possible
- Severity: Medium (denial of service vector)

### Alias-Based Resource Exhaustion
- Send many aliases in one query: `{a0:__typename a1:__typename ... a999:__typename}`
- If the server resolves all aliases, it processes N times more work per request
- Severity: Low-Medium (rate limit bypass, potential DoS)

## IDOR Testing Methodology

1. **Identify resource endpoints**: Look for patterns like `/api/users/{id}`, `/api/orders/{id}/details`
2. **Authenticate as User A**: Get a valid token/session
3. **Access User A's resources**: Confirm baseline access (200 OK)
4. **Access User B's resources**: Replace the ID with another user's ID
5. **Compare responses**: If 200 OK with different user's data, IDOR confirmed
6. **Test all CRUD operations**: GET, PUT, PATCH, DELETE on each resource
7. **Test with no auth**: Remove authentication entirely to check for auth bypass
8. **Test horizontal and vertical**: Same-role access (horizontal) and admin-to-user (vertical)

## JWT Analysis Methodology

1. **Decode the token**: Extract header and payload (base64 decode)
2. **Check the algorithm**: RS256 (asymmetric) vs HS256 (symmetric) vs none
3. **Test 'none' algorithm**: Replace alg with "none", remove signature, send request
4. **Test algorithm confusion**: If RS256, try HS256 with the public key as secret
5. **Check expiration**: Is "exp" claim present? Is it reasonable? (hours, not years)
6. **Check claims**: Are sensitive fields in the payload? (role, permissions, PII)
7. **Test signature**: Modify a claim, keep original signature, send request
8. **Brute-force secret**: For HS256, try common weak secrets (if time permits)

## Best Practices

1. **Discovery Before Testing**
   - Always crawl and fuzz before testing specific vulnerabilities
   - Use browser network log to find APIs that crawlers miss

2. **Test Both Authenticated and Unauthenticated**
   - Every endpoint should be tested without auth first
   - Then test with valid auth to find authorization issues
   - Then test with a different user's auth to find IDOR

3. **GraphQL Requires Special Attention**
   - Standard web scanners miss GraphQL-specific issues
   - Always run all five GraphQL tests
   - Check if introspection is disabled but field suggestions are enabled

4. **Token Security is Critical**
   - JWT analysis should be done on every token found
   - Token replay testing reveals session management flaws
   - Check token storage location (localStorage vs httpOnly cookies)

5. **Rate Limiting Matters Most on Auth Endpoints**
   - Login, password reset, and OTP verification are priority targets
   - Missing rate limiting on auth = brute-force is possible

6. **Document Every Finding with REAL Evidence**
   - Include the ACTUAL request (with real tokens, real URLs — no `$TOKEN` or `<PASSWORD>` placeholders)
   - Include the ACTUAL response body (paste it — never write `# Returns HTTP 200`)
   - This is a confidential internal report — show real data, real PII, real secrets
   - Note the tool used and parameters tested
   - Provide specific remediation guidance

## Output Format

The API Security Agent adds the following to context:

```json
{
  "apiSecurityResults": {
    "apiType": "REST | GraphQL | WebSocket | mixed",
    "schemaAvailable": true,
    "schemaUrl": "/api/docs/swagger.json",
    "authMechanism": "JWT | session | API key | OAuth2",
    "endpointsDiscovered": 47,
    "endpointsTested": 35,
    "graphqlTests": {
      "introspection": "enabled",
      "batching": "allowed",
      "fieldSuggestions": "enabled",
      "depthLimit": "not enforced",
      "aliasing": "not limited"
    },
    "findings": [
      {
        "title": "GraphQL Introspection Enabled",
        "severity": "medium",
        "category": "information-disclosure",
        "evidence": "REQUEST: curl -s -X POST https://api.example.com/graphql -H 'Content-Type: application/json' -d '{\"query\":\"{__schema{types{name fields{name type{name}}}}}\"}'\\nRESPONSE (HTTP 200): {\"data\":{\"__schema\":{\"types\":[{\"name\":\"User\",\"fields\":[{\"name\":\"id\"},{\"name\":\"email\"},{\"name\":\"ssn\"}]},...]}}}"
      }
    ],
    "rateLimitingResults": {
      "/api/auth/login": "not enforced (50/50 requests succeeded)",
      "/api/users": "enforced (429 after 30 requests)"
    },
    "corsResults": {
      "/api/data": "vulnerable (reflects arbitrary origin with credentials)"
    }
  }
}
```
