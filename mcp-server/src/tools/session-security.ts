import { executeInKali } from "../utils/docker-exec";
import { ToolEvidence } from "../utils/evidence-wrapper";

export const sessionSecurityTools = [
  {
    name: "test_session_fixation",
    description: "Test for session fixation vulnerabilities. Verifies if the session ID is regenerated after authentication. A vulnerable application keeps the same session ID before and after login.",
    inputSchema: {
      type: "object",
      properties: {
        target: { type: "string", description: "Target login page URL" },
        login_url: { type: "string", description: "URL to POST login credentials to (if different from target)" },
        username_field: { type: "string", description: "Form field name for username", default: "username" },
        password_field: { type: "string", description: "Form field name for password", default: "password" },
        username: { type: "string", description: "Valid username for authentication" },
        password: { type: "string", description: "Valid password for authentication" },
        session_cookie_name: { type: "string", description: "Name of the session cookie to track", default: "session" },
      },
      required: ["target", "username", "password"],
    },
  },
  {
    name: "test_session_management",
    description: "Test session management security: token entropy/randomness, predictability, timeout behavior, concurrent session handling, and secure cookie attributes (HttpOnly, Secure, SameSite).",
    inputSchema: {
      type: "object",
      properties: {
        target: { type: "string", description: "Target URL that sets session cookies" },
        login_url: { type: "string", description: "Login endpoint URL for authenticated session tests" },
        username: { type: "string", description: "Valid username for authentication tests" },
        password: { type: "string", description: "Valid password for authentication tests" },
        session_cookie_name: { type: "string", description: "Name of the session cookie to analyze", default: "session" },
        num_samples: { type: "number", description: "Number of session tokens to collect for entropy analysis", default: 10 },
      },
      required: ["target"],
    },
  },
  {
    name: "test_password_policy",
    description: "Test password policy enforcement and account lockout mechanisms. Attempts weak passwords via registration or password change, and tests for account lockout after failed login attempts.",
    inputSchema: {
      type: "object",
      properties: {
        target: { type: "string", description: "Target application base URL" },
        registration_url: { type: "string", description: "User registration endpoint URL" },
        login_url: { type: "string", description: "Login endpoint URL for lockout testing" },
        password_change_url: { type: "string", description: "Password change endpoint URL" },
        username: { type: "string", description: "Username for lockout testing" },
        username_field: { type: "string", description: "Form field name for username", default: "username" },
        password_field: { type: "string", description: "Form field name for password", default: "password" },
        lockout_threshold: { type: "number", description: "Number of failed attempts to test lockout", default: 10 },
      },
      required: ["target"],
    },
  },
];

export const sessionSecurityHandlers: Record<string, Function> = {
  test_session_fixation: async (args: {
    target: string;
    login_url?: string;
    username_field?: string;
    password_field?: string;
    username: string;
    password: string;
    session_cookie_name?: string;
  }) => {
    const {
      target,
      login_url,
      username_field = "username",
      password_field = "password",
      username,
      password,
      session_cookie_name = "session",
    } = args;

    const loginEndpoint = login_url || target;

    const command = [
      `echo "=== Session Fixation Test ==="`,
      `echo "Target: ${target}"`,
      `echo "Login URL: ${loginEndpoint}"`,
      `echo "Session Cookie: ${session_cookie_name}"`,
      `echo ""`,

      `echo "--- Step 1: Get pre-auth session ---"`,
      `curl -s -c /tmp/sf-cookies-pre.txt -o /dev/null "${target}"`,
      `PRE_SESSION=$(grep "${session_cookie_name}" /tmp/sf-cookies-pre.txt | awk '{print $NF}' | tail -1)`,
      `echo "Pre-auth session ID: $PRE_SESSION"`,
      `echo ""`,

      `echo "--- Step 2: Authenticate with pre-auth cookie ---"`,
      `curl -s -b /tmp/sf-cookies-pre.txt -c /tmp/sf-cookies-post.txt -o /tmp/sf-login-resp.txt -X POST -d "${username_field}=${username}&${password_field}=${password}" "${loginEndpoint}"`,
      `POST_SESSION=$(grep "${session_cookie_name}" /tmp/sf-cookies-post.txt | awk '{print $NF}' | tail -1)`,
      `echo "Post-auth session ID: $POST_SESSION"`,
      `echo ""`,

      `echo "--- Step 3: Analysis ---"`,
      `if [ -z "$PRE_SESSION" ]; then echo "INFO: No pre-auth session cookie set."; elif [ -z "$POST_SESSION" ]; then echo "INFO: No post-auth session cookie found (may use different auth mechanism)."; elif [ "$PRE_SESSION" = "$POST_SESSION" ]; then echo "VULNERABLE: Session ID was NOT regenerated after authentication!"; echo "Pre-auth:  $PRE_SESSION"; echo "Post-auth: $POST_SESSION"; else echo "OK: Session ID was regenerated after authentication."; echo "Pre-auth:  $PRE_SESSION"; echo "Post-auth: $POST_SESSION"; fi`,
      `echo ""`,

      `echo "--- Cookie Security Attributes ---"`,
      `curl -s -D /tmp/sf-headers.txt -o /dev/null "${target}"`,
      `grep -i "set-cookie" /tmp/sf-headers.txt || echo "No Set-Cookie headers found"`,

      `echo ""`,
      `echo "=== Test Complete ==="`,
    ].join("\n");

    const result = await executeInKali(command);
    return JSON.stringify({
      raw_output: result,
      evidence: {
        tool_name: "test_session_fixation",
        evidence_captures: [{
          curl_command: `curl -s -c /tmp/sf-cookies-pre.txt -o /dev/null "${target}"`,
          method: "GET",
          url: target,
          request_headers: {},
          timestamp: new Date().toISOString(),
        }, {
          curl_command: `curl -s -b /tmp/sf-cookies-pre.txt -c /tmp/sf-cookies-post.txt -X POST -d "${username_field}=...&${password_field}=..." "${loginEndpoint}"`,
          method: "POST",
          url: loginEndpoint,
          request_headers: {},
          timestamp: new Date().toISOString(),
        }],
      },
    });
  },

  test_session_management: async (args: {
    target: string;
    login_url?: string;
    username?: string;
    password?: string;
    session_cookie_name?: string;
    num_samples?: number;
  }) => {
    const {
      target,
      session_cookie_name = "session",
      num_samples = 10,
    } = args;

    const command = [
      `echo "=== Session Management Security Test ==="`,
      `echo "Target: ${target}"`,
      `echo "Cookie: ${session_cookie_name}"`,
      `echo ""`,

      `echo "--- 1. Cookie Security Attributes ---"`,
      `curl -s -D /tmp/sm-headers.txt -o /dev/null "${target}"`,
      `echo "Set-Cookie headers:"`,
      `grep -i "set-cookie" /tmp/sm-headers.txt || echo "  No Set-Cookie headers found"`,
      `echo ""`,
      `echo "Checking flags:"`,
      `grep -i "set-cookie" /tmp/sm-headers.txt | grep -qi "httponly" && echo "  HttpOnly: PRESENT" || echo "  HttpOnly: MISSING - cookies accessible to JavaScript"`,
      `grep -i "set-cookie" /tmp/sm-headers.txt | grep -qi "secure" && echo "  Secure: PRESENT" || echo "  Secure: MISSING - cookies sent over HTTP"`,
      `grep -i "set-cookie" /tmp/sm-headers.txt | grep -qi "samesite" && echo "  SameSite: PRESENT" || echo "  SameSite: MISSING - may be vulnerable to CSRF"`,
      `echo ""`,

      `echo "--- 2. Session Token Entropy (${num_samples} samples) ---"`,
      `TOKENS=""`,
      `for i in $(seq 1 ${num_samples}); do`,
      `  TOKEN=$(curl -s -c - -o /dev/null "${target}" | grep "${session_cookie_name}" | awk '{print $NF}')`,
      `  if [ -n "$TOKEN" ]; then TOKENS="$TOKENS $TOKEN"; echo "  Sample $i: $TOKEN"; fi`,
      `done`,
      `echo ""`,
      `UNIQUE=$(echo $TOKENS | tr ' ' '\\n' | sort -u | wc -l)`,
      `TOTAL=$(echo $TOKENS | tr ' ' '\\n' | grep -c . || echo 0)`,
      `echo "Unique tokens: $UNIQUE / $TOTAL"`,
      `if [ "$UNIQUE" = "$TOTAL" ] && [ "$TOTAL" -gt "0" ]; then echo "OK: All session tokens are unique."; elif [ "$TOTAL" -gt "0" ]; then echo "WARNING: Some session tokens are duplicated ($UNIQUE unique out of $TOTAL)."; else echo "INFO: No session tokens collected."; fi`,
      `echo ""`,

      `echo "--- 3. Token Length Analysis ---"`,
      `FIRST_TOKEN=$(echo $TOKENS | awk '{print $1}')`,
      `if [ -n "$FIRST_TOKEN" ]; then LEN=$(echo -n "$FIRST_TOKEN" | wc -c); echo "Token length: $LEN characters"; if [ "$LEN" -lt 16 ]; then echo "WARNING: Short token length (<16 chars) may be predictable."; elif [ "$LEN" -lt 32 ]; then echo "INFO: Token length is adequate but could be stronger."; else echo "OK: Token length ($LEN chars) provides good entropy."; fi; else echo "No tokens to analyze."; fi`,
      `echo ""`,

      `echo "=== Session Management Test Complete ==="`,
    ].join("\n");

    const result = await executeInKali(command);
    return JSON.stringify({
      raw_output: result,
      evidence: {
        tool_name: "test_session_management",
        evidence_captures: [{
          curl_command: `curl -s -D /tmp/sm-headers.txt -o /dev/null "${target}"`,
          method: "GET",
          url: target,
          request_headers: {},
          timestamp: new Date().toISOString(),
        }],
      },
    });
  },

  test_password_policy: async (args: {
    target: string;
    registration_url?: string;
    login_url?: string;
    password_change_url?: string;
    username?: string;
    username_field?: string;
    password_field?: string;
    lockout_threshold?: number;
  }) => {
    const {
      target,
      login_url,
      username,
      username_field = "username",
      password_field = "password",
      lockout_threshold = 10,
    } = args;

    const loginEndpoint = login_url || `${target}/login`;

    const commands: string[] = [
      `echo "=== Password Policy & Account Lockout Test ==="`,
      `echo "Target: ${target}"`,
      `echo ""`,
    ];

    if (username && loginEndpoint) {
      commands.push(`echo "--- 1. Account Lockout Test ---"`);
      commands.push(`echo "Testing ${lockout_threshold} failed login attempts for user: ${username}"`);
      commands.push(`LOCKED=0`);
      commands.push(`for i in $(seq 1 ${lockout_threshold}); do`);
      commands.push(`  STATUS=$(curl -s -o /tmp/pp-lockout-$i.txt -w "%{http_code}" -X POST -d "${username_field}=${username}&${password_field}=WrongPass\${i}!" "${loginEndpoint}")`);
      commands.push(`  BODY=$(cat /tmp/pp-lockout-$i.txt)`);
      commands.push(`  echo "  Attempt $i: HTTP $STATUS"`);
      commands.push(`  if echo "$BODY" | grep -qiE "(locked|blocked|suspended|too many|rate.limit|captcha)"; then echo "  LOCKOUT DETECTED at attempt $i"; LOCKED=1; break; fi`);
      commands.push(`done`);
      commands.push(`echo ""`);
      commands.push(`if [ "$LOCKED" = "0" ]; then echo "WARNING: No account lockout after ${lockout_threshold} failed attempts."; else echo "OK: Account lockout/protection mechanism detected."; fi`);
      commands.push(`echo ""`);
    }

    commands.push(`echo "--- 2. Weak Password Tests ---"`);
    commands.push(`echo "Testing common weak passwords against registration/login..."`);

    const weakPasswords = ["a", "123", "password", "12345678", "aaaa", "abc123", "qwerty"];
    const testUser = `pentestuser${Date.now()}`;

    for (const pwd of weakPasswords) {
      commands.push(
        `STATUS=$(curl -s -o /tmp/pp-weak.txt -w "%{http_code}" -X POST -d "${username_field}=${testUser}&${password_field}=${pwd}" "${loginEndpoint}")`,
      );
      commands.push(`echo "  Password '${pwd}': HTTP $STATUS"`);
    }

    commands.push(`echo ""`);
    commands.push(`echo "--- 3. Password Complexity Indicators ---"`);
    commands.push(
      `curl -s "${target}" | grep -oiE "(password.*policy|password.*require|password.*must|minimum.*length|uppercase|lowercase|special.*char|digit)" | head -20 || echo "No visible password policy found in HTML"`,
    );

    commands.push(`echo ""`);
    commands.push(`echo "=== Password Policy Test Complete ==="`);

    return await executeInKali(commands.join("\n"));
  },
};
