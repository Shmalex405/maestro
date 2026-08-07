#!/usr/bin/env node
// Provision two Juice Shop test users (register + login) and write their JWTs to
// creds.json. Zero human interaction — Juice Shop has a plain username/password
// registration API that returns a bearer token.
//
// Two users so the authenticated run can prove a CROSS-USER IDOR (user A's token
// reading user B's data), not merely "I'm logged in".
//
// Usage: node provision-creds.mjs <base-url> [out-file]
//   node provision-creds.mjs http://localhost:3000 creds.json
//
// Fails loudly (non-zero exit) if the Juice Shop API shape changed — we never
// want the harness to silently fall back to an UNauthenticated run and then
// claim the auth path was proven.

import { writeFileSync } from "node:fs";

const baseUrl = (process.argv[2] || "http://localhost:3000").replace(/\/$/, "");
const outFile = process.argv[3] || new URL("./creds.json", import.meta.url).pathname;

const PASSWORD = "Harness-Passw0rd!"; // Juice Shop enforces a password policy
const SECURITY_ANSWER = "harness"; // required by the registration form

async function http(method, path, body) {
  const res = await fetch(`${baseUrl}${path}`, {
    method,
    headers: { "Content-Type": "application/json" },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  let json;
  try {
    json = JSON.parse(text);
  } catch {
    json = { raw: text };
  }
  return { status: res.status, json };
}

async function getSecurityQuestionId() {
  // The registration payload references a security question by id; any one works.
  const { status, json } = await http("GET", "/api/SecurityQuestions");
  const first = json?.data?.[0]?.id;
  if (status >= 400 || !first) {
    throw new Error(`could not load SecurityQuestions (status ${status}) — Juice Shop API shape changed`);
  }
  return first;
}

async function register(email, securityQuestionId) {
  const { status, json } = await http("POST", "/api/Users", {
    email,
    password: PASSWORD,
    passwordRepeat: PASSWORD,
    securityQuestion: { id: securityQuestionId },
    securityAnswer: SECURITY_ANSWER,
  });
  // 201 on create; 400 if the user already exists from a prior run (fine).
  if (status !== 201 && status !== 400) {
    throw new Error(`register ${email} failed (status ${status}): ${JSON.stringify(json)}`);
  }
}

async function login(email) {
  const { status, json } = await http("POST", "/rest/user/login", {
    email,
    password: PASSWORD,
  });
  const token = json?.authentication?.token;
  if (status !== 200 || !token) {
    throw new Error(`login ${email} failed (status ${status}): ${JSON.stringify(json)} — Juice Shop login API shape changed`);
  }
  // `bid` is this user's basket id. The oracle harness needs it to build a
  // differential recipe: user A reading user B's basket is a real BOLA, and the
  // oracle's verdict depends on naming the RIGHT object, not just any id.
  return { token, basketId: json.authentication.bid };
}

/** The user id lives in the JWT payload — needed as the differential marker. */
function userIdFromJwt(jwt) {
  const payload = JSON.parse(Buffer.from(jwt.split(".")[1], "base64").toString("utf-8"));
  const id = payload?.data?.id;
  if (!id) throw new Error("could not read data.id from the Juice Shop JWT — token shape changed");
  return id;
}

async function provisionUser(label, securityQuestionId) {
  const email = `harness-${label}-${Date.now()}@e2e.local`;
  await register(email, securityQuestionId);
  const { token, basketId } = await login(email);
  if (!basketId) {
    throw new Error(`login ${email} returned no basket id — Juice Shop login API shape changed`);
  }
  return { email, jwt: token, basketId, userId: userIdFromJwt(token) };
}

async function main() {
  // Wait for Juice Shop to actually answer (compose healthcheck should already gate this).
  const version = await http("GET", "/rest/admin/application-version");
  if (version.status >= 500) {
    throw new Error(`Juice Shop not ready at ${baseUrl} (status ${version.status})`);
  }

  const sqId = await getSecurityQuestionId();
  const userA = await provisionUser("a", sqId);
  const userB = await provisionUser("b", sqId);

  const creds = { baseUrl, userA, userB, provisionedAt: new Date().toISOString() };
  writeFileSync(outFile, JSON.stringify(creds, null, 2));
  console.log(`[provision] wrote 2 users to ${outFile}`);
  console.log(`[provision]   userA: ${userA.email} (id ${userA.userId}, basket ${userA.basketId})`);
  console.log(`[provision]   userB: ${userB.email} (id ${userB.userId}, basket ${userB.basketId})`);
}

main().catch((e) => {
  console.error(`[provision] FAILED: ${e.message}`);
  process.exit(1);
});
