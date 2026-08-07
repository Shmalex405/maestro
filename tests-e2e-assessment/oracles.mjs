#!/usr/bin/env node
// Oracle verdict-gate driver.
//
// Proves the verification layer (docs/oracle-verification-layer.md) against a
// REAL vulnerable target, through the REAL MCP path — create_finding and
// verify_finding over POST /tools/call, the same route the verifier agent uses.
// Nothing here reaches into the oracle engine directly; if the tool dispatch,
// scope validation, container exec or SQLite write is broken, this fails.
//
// The point is not "the oracles verify things". It is that they REFUSE to
// verify things that look like findings but aren't:
//
//   * a real vulnerability with a lazy pattern that also matches the control
//   * a public endpoint filed as an authorization failure
//   * an agent choosing its own marker instead of the harness-minted one
//   * an agent asserting a verdict directly on create_finding
//
// Usage: node oracles.mjs <mcp-url> <creds.json> <juice-url-in-container> <out.json>

import { readFileSync, writeFileSync } from "node:fs";

const [, , MCP, CREDS_PATH, TARGET, OUT] = process.argv;
if (!MCP || !CREDS_PATH || !TARGET || !OUT) {
  console.error("usage: oracles.mjs <mcp-url> <creds.json> <target-url> <out.json>");
  process.exit(2);
}

const creds = JSON.parse(readFileSync(CREDS_PATH, "utf-8"));
const A = creds.userA;
const B = creds.userB;

async function callTool(name, args) {
  const res = await fetch(`${MCP}/tools/call`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name, arguments: args }),
  });
  const text = await res.text();
  // Handlers return stringified JSON, sometimes wrapped in an MCP content envelope.
  let payload;
  try {
    payload = JSON.parse(text);
  } catch {
    return { _raw: text };
  }
  const inner = payload?.content?.[0]?.text;
  if (typeof inner === "string") {
    try {
      return JSON.parse(inner);
    } catch {
      return { _raw: inner };
    }
  }
  return payload;
}

// findings dedupe on (normalized target + vulnerability type) — NOT on title
// (see integrations/finding-fingerprint.ts). Two fixtures describing the same
// vuln class on the same URL therefore collapse into one row, and the second
// would inherit the first's verdict. Each scenario passes its own target path so
// the fixtures stay distinct; that is a harness concern, not a product one.
async function createCandidate(title, findingTarget, extra = {}) {
  const r = await callTool("create_finding", {
    title,
    severity: "high",
    description: "Oracle harness fixture.",
    target: findingTarget,
    source: "e2e-oracle-harness",
    exploitable: "true",
    ...extra,
  });
  if (!r.finding_id) throw new Error(`create_finding returned no finding_id: ${JSON.stringify(r)}`);
  return r;
}

const curl = (s) => `curl -s ${s}`;
const authed = (jwt, path) => curl(`-H 'Authorization: Bearer ${jwt}' '${TARGET}${path}'`);
const anon = (path) => curl(`'${TARGET}${path}'`);

const scenarios = [
  {
    name: "differential verifies a real cross-user BOLA",
    why: "User A reads user B's basket; anonymous is rejected, so the boundary that failed really is object-level authorization.",
    expect: { verdict: "verified" },
    finding: {
      title: "BOLA: any user can read another user's basket",
      target: `${TARGET}/rest/basket/${B.basketId}`,
    },
    oracle: {
      oracle_kind: "differential",
      authorized_command: authed(B.jwt, `/rest/basket/${B.basketId}`),
      attacker_command: authed(A.jwt, `/rest/basket/${B.basketId}`),
      unauthenticated_command: anon(`/rest/basket/${B.basketId}`),
      marker: `"UserId":${B.userId}`,
    },
  },
  {
    name: "differential REFUSES a public endpoint filed as an authz failure",
    why:
      "Product reviews need no credentials at all. The attacker experiment 'reproduces' perfectly, " +
      "so only the unauthenticated control can tell us the finding names the wrong bug.",
    expect: { verdict: "refuted", reason: "mechanism_mismatch" },
    finding: {
      title: "IDOR: product reviews readable by any user",
      target: `${TARGET}/rest/products/1/reviews`,
    },
    oracle: {
      oracle_kind: "differential",
      authorized_command: authed(B.jwt, "/rest/products/1/reviews"),
      attacker_command: authed(A.jwt, "/rest/products/1/reviews"),
      unauthenticated_command: anon("/rest/products/1/reviews"),
      marker: "One of my favorites!",
    },
  },
  {
    name: "idempotent_replay verifies a real SQLi auth bypass",
    why: "The payload returns a token; the benign login attempt does not.",
    expect: { verdict: "verified" },
    finding: {
      title: "SQL injection in the login form allows authentication bypass",
      target: `${TARGET}/rest/user/login`,
    },
    oracle: {
      oracle_kind: "idempotent_replay",
      command: `curl -s -X POST '${TARGET}/rest/user/login' -H 'Content-Type: application/json' -d '{"email":"'"'"' OR 1=1--","password":"x"}'`,
      control_command: `curl -s -X POST '${TARGET}/rest/user/login' -H 'Content-Type: application/json' -d '{"email":"nobody@e2e.local","password":"wrong"}'`,
      success_pattern: '"token":"ey',
    },
  },
  {
    name: "idempotent_replay REFUSES a self-certifying pattern",
    why:
      "Same real vulnerability, but the pattern matches any HTTP response. It reproduces every " +
      "replay — and must still be refused, because the benign control matches too.",
    expect: { verdict: "refuted", reason: "pattern_not_discriminating" },
    // Distinct target path so this does not fingerprint onto the scenario above —
    // same vuln class, same endpoint, and dedupe would otherwise merge them.
    finding: {
      title: "SQL injection in the login form (lazy verification recipe)",
      target: `${TARGET}/rest/user/login?fixture=lazy-recipe`,
    },
    oracle: {
      oracle_kind: "idempotent_replay",
      command: `curl -si -X POST '${TARGET}/rest/user/login' -H 'Content-Type: application/json' -d '{"email":"'"'"' OR 1=1--","password":"x"}'`,
      control_command: `curl -si -X POST '${TARGET}/rest/user/login' -H 'Content-Type: application/json' -d '{"email":"nobody@e2e.local","password":"wrong"}'`,
      success_pattern: "Content-Type",
    },
  },
  {
    name: "artifact verifies a stored payload read back on another channel",
    why:
      "The harness mints the marker, checks it is absent first, deposits it through the authenticated " +
      "API and reads it back through the public one — proving the payload reaches a consumer.",
    expect: { verdict: "verified" },
    finding: {
      title: "Stored payload persists in product reviews",
      target: `${TARGET}/rest/products/1/reviews?fixture=artifact`,
    },
    oracle: {
      oracle_kind: "artifact",
      deposit_command: `curl -s -X PUT '${TARGET}/rest/products/1/reviews' -H 'Content-Type: application/json' -H 'Authorization: Bearer ${A.jwt}' -d '{"message":"{{TOKEN}}","author":"${A.email}"}'`,
      read_command: `curl -s '${TARGET}/rest/products/1/reviews' | grep -o '{{TOKEN}}'`,
    },
  },
  {
    name: "artifact REFUSES a marker the agent chose itself",
    why: "Without the harness-minted {{TOKEN}} an agent could 'find' a value it planted. Refused before any request goes out.",
    expect: { verdict: "refuted", reason: "placeholder_missing" },
    finding: {
      title: "Stored payload persists in product reviews (agent-chosen marker)",
      target: `${TARGET}/rest/products/1/reviews?fixture=artifact-selfmarked`,
    },
    oracle: {
      oracle_kind: "artifact",
      deposit_command: `curl -s -X PUT '${TARGET}/rest/products/1/reviews' -H 'Content-Type: application/json' -H 'Authorization: Bearer ${A.jwt}' -d '{"message":"agent-picked-marker","author":"${A.email}"}'`,
      read_command: `curl -s '${TARGET}/rest/products/1/reviews' | grep -o 'agent-picked-marker'`,
    },
  },
];

async function main() {
  const out = { target: TARGET, ranAt: new Date().toISOString(), scenarios: [], selfCertification: null };

  // --- The invariant, straight through the tool boundary --------------------
  // An agent asserting a verdict on create_finding must get it stripped.
  const selfCert = await createCandidate("Self-certified finding (invariant probe)", `${TARGET}/invariant-probe`, {
    verdict: "verified",
    oracle_kind: "differential",
    receipt_json: '{"fabricated":true}',
    replay_n: 5,
    replay_successes: 5,
  });
  out.selfCertification = {
    finding_id: selfCert.finding_id,
    verdict: selfCert.verdict,
    rejected_fields: selfCert.rejected_fields || [],
  };
  console.log(
    `[oracles] self-certification probe → verdict=${selfCert.verdict} rejected=${JSON.stringify(selfCert.rejected_fields || [])}`
  );

  // --- Each oracle scenario, end to end -------------------------------------
  for (const s of scenarios) {
    const created = await createCandidate(s.finding.title, s.finding.target);
    const res = await callTool("verify_finding", {
      finding_id: created.finding_id,
      target: TARGET,
      intensity: "safe",
      ...s.oracle,
    });

    const row = {
      name: s.name,
      why: s.why,
      expect: s.expect,
      finding_id: created.finding_id,
      created_verdict: created.verdict,
      ok: res.ok !== false,
      error: res.error || null,
      verdict: res.verdict ?? null,
      reason: res.reason ?? null,
      oracle_kind: res.oracle_kind ?? null,
      oracle_strength: res.oracle_strength ?? null,
      replays: res.replays ?? null,
      explanation: res.explanation ?? null,
    };
    out.scenarios.push(row);
    console.log(
      `[oracles] ${s.name}\n           → verdict=${row.verdict} reason=${row.reason ?? "none"} replays=${row.replays ?? "-"}${row.error ? ` error=${row.error}` : ""}`
    );
  }

  writeFileSync(OUT, JSON.stringify(out, null, 2));
  console.log(`[oracles] wrote ${OUT}`);
}

main().catch((e) => {
  console.error(`[oracles] FAILED: ${e.message}`);
  process.exit(1);
});
