/**
 * Tests for the deterministic vuln → capability lookup (post-ex Layer A §4.2).
 *
 * Two halves:
 *  - a SMOKE test against the real config/chain-patterns.yml, so the loader stays
 *    in sync with the catalog's actual shape (catches a renamed section / field).
 *  - the normalization + alias logic, so human finding labels ("SQL Injection",
 *    "BOLA") resolve to the catalog's short keys ("sqli", "idor").
 */

import * as path from "path";
import {
  capabilitiesFor,
  loadVulnCapabilityMap,
  normalizeVulnType,
  _resetCache,
} from "../../src/tools/chain-capabilities";

const REAL_CATALOG = path.resolve(__dirname, "../../../config/chain-patterns.yml");

beforeEach(() => _resetCache());

describe("loadVulnCapabilityMap — against the real catalog", () => {
  it("loads vuln_capability_map with grants/requires for known vulns", () => {
    const map = loadVulnCapabilityMap(REAL_CATALOG);
    expect(Object.keys(map).length).toBeGreaterThan(10);
    expect(map.sqli?.grants).toEqual(expect.arrayContaining(["sql_execution"]));
    expect(map.ssrf?.grants).toEqual(expect.arrayContaining(["cloud_metadata_access"]));
    expect(map.idor).toBeDefined();
  });
});

describe("capabilitiesFor — resolves vuln types to capabilities", () => {
  it("matches exact catalog keys", () => {
    expect(capabilitiesFor("sqli", REAL_CATALOG)?.grants).toContain("sql_execution");
    expect(capabilitiesFor("ssrf", REAL_CATALOG)?.requires).toContain("unauthenticated_access");
  });

  it("normalizes human finding labels to catalog keys", () => {
    // "SQL Injection" → sql_injection → alias → sqli
    expect(capabilitiesFor("SQL Injection", REAL_CATALOG)?.grants).toContain("sql_execution");
    // "Reflected XSS" → reflected_xss → alias → xss_reflected
    expect(capabilitiesFor("Reflected XSS", REAL_CATALOG)?.grants).toContain("javascript_execution");
  });

  it("resolves the Wiz-case alias: BOLA → idor", () => {
    const bola = capabilitiesFor("BOLA", REAL_CATALOG);
    const idor = capabilitiesFor("idor", REAL_CATALOG);
    expect(bola).not.toBeNull();
    expect(bola).toEqual(idor);
  });

  it("returns null for an unknown vuln type (caller falls back to the LLM)", () => {
    expect(capabilitiesFor("some_novel_zero_day", REAL_CATALOG)).toBeNull();
    expect(capabilitiesFor("", REAL_CATALOG)).toBeNull();
  });
});

describe("normalizeVulnType", () => {
  it.each([
    ["SQL Injection", "sql_injection"],
    ["Reflected XSS", "reflected_xss"],
    ["Server-Side Request Forgery", "server_side_request_forgery"],
    ["OS Command Injection!", "os_command_injection"],
    ["  IDOR  ", "idor"],
  ])("%s → %s", (input, expected) => {
    expect(normalizeVulnType(input)).toBe(expected);
  });
});
