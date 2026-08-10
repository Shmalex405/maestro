#!/usr/bin/env node
//
// Emit the public facts about this Maestro build as JSON.
//
// These four numbers appear on groovysec.com, and every one of them has been
// wrong there at some point — the website carried "21 agents / 213 tools / 232
// tests" for several releases while the real figures were 24 / 227 / 234. The
// copy was written by hand from whatever was true at the time and then nothing
// re-derived it, so drift was silent and permanent until someone happened to read
// the page closely.
//
// So: one script, derived from the same files the product actually uses, and the
// website consumes its output rather than restating it. If a number here is
// wrong, it is wrong because the config is wrong, which is a much easier bug to
// notice.
//
// Usage:
//   node scripts/maestro-facts.mjs              # JSON to stdout
//   node scripts/maestro-facts.mjs --check FILE # compare against a facts file
//
// Requires mcp-server/dist to be built, because the tool count is read from the
// assembled allTools array rather than parsed out of source. Static counting was
// tried and rejected: `name:` appears inside nested option objects too, which
// over-counts (235 against a true 227) in a way that looks plausible.

import { readFileSync, existsSync } from "node:fs";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import path from "node:path";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const require = createRequire(import.meta.url);

function fail(msg) {
  console.error(`error: ${msg}`);
  process.exit(1);
}

// ── version ─────────────────────────────────────────────────────────────────
// tauri.conf.json is canonical; the tag and the CDN paths are both derived from
// it, so anything else would be a second source of truth for the same number.
const tauriConf = path.join(ROOT, "frontend/src-tauri/tauri.conf.json");
if (!existsSync(tauriConf)) fail(`${tauriConf} not found — run from the repo root.`);
const version = JSON.parse(readFileSync(tauriConf, "utf8")).version;
if (!/^\d+\.\d+\.\d+$/.test(version)) fail(`unexpected version "${version}"`);

// ── agents ──────────────────────────────────────────────────────────────────
// The `agents:` map in team-assessment.yml includes team-lead, which is the
// orchestrator rather than a worker. The site advertises workers, so both are
// emitted and the caller picks — conflating them is how "24 agents" and "25
// agents" both ended up in circulation.
const teamYml = path.join(ROOT, "config/team-assessment.yml");
if (!existsSync(teamYml)) fail(`${teamYml} not found`);
const teamSrc = readFileSync(teamYml, "utf8");
const agentsBlock = teamSrc.split(/\nagents:/)[1];
if (!agentsBlock) fail("no `agents:` key in config/team-assessment.yml");
const agentNames = [...agentsBlock.split(/\n(?=[a-z_]+:)/)[0].matchAll(/^ {2}([a-z0-9_-]+):/gm)].map(
  (m) => m[1],
);
if (agentNames.length < 2) fail(`parsed only ${agentNames.length} agents — the yml shape changed`);
const agentsTotal = agentNames.length;
const agentsWorkers = agentNames.filter((n) => n !== "team-lead").length;
if (agentsWorkers === agentsTotal) fail("no team-lead in the agents map — check the parse");

// ── tools ───────────────────────────────────────────────────────────────────
const dist = path.join(ROOT, "mcp-server/dist/server.js");
if (!existsSync(dist)) {
  fail(
    "mcp-server/dist/server.js not found. Build it first:\n" +
      "  cd mcp-server && npm ci && npm run build",
  );
}
let tools;
try {
  const mod = require(dist);
  tools = mod.allTools?.length;
} catch (e) {
  fail(`could not load ${dist}: ${e.message}`);
}
if (!tools) fail("allTools was empty or absent — the server export shape changed");

// ── tests ───────────────────────────────────────────────────────────────────
// The matrix is the superset; a given run executes the scope-derived subset. The
// site quotes the superset, which is the stable, comparable number.
const matrixYml = path.join(ROOT, "config/test-matrix.yml");
if (!existsSync(matrixYml)) fail(`${matrixYml} not found`);
const tests = (readFileSync(matrixYml, "utf8").match(/^\s*-?\s*test_id:/gm) || []).length;
if (!tests) fail("no test_id entries found in config/test-matrix.yml");

const facts = { version, agents: agentsWorkers, agentsTotal, tools, tests };

// ── --check ─────────────────────────────────────────────────────────────────
// Exits non-zero on drift, listing each field that disagrees, so this can be a CI
// gate as well as a generator.
const checkIdx = process.argv.indexOf("--check");
if (checkIdx !== -1) {
  const target = process.argv[checkIdx + 1];
  if (!target) fail("--check needs a path to a facts JSON file");
  if (!existsSync(target)) fail(`${target} not found`);
  const have = JSON.parse(readFileSync(target, "utf8"));
  const drift = Object.entries(facts).filter(([k, v]) => have[k] !== v);
  if (drift.length === 0) {
    console.log(`ok  ${target} matches this build (${version})`);
    process.exit(0);
  }
  console.error(`DRIFT  ${target} disagrees with this build:`);
  for (const [k, v] of drift) console.error(`  ${k}: file says ${JSON.stringify(have[k])}, build says ${JSON.stringify(v)}`);
  console.error("\nRegenerate it:  node scripts/maestro-facts.mjs > <file>");
  process.exit(1);
}

console.log(JSON.stringify(facts, null, 2));
