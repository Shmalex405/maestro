/**
 * Tests for the cross-cutting scope-exclusion guard.
 *
 * Like the non-destructive backstop, the two halves matter equally:
 *  - BLOCK: a documented never-touch / excluded target is refused no matter which
 *    arg name it arrives under (the gap this guard closes — identity/AI/cloud-ARN
 *    exclusions were previously enforced nowhere).
 *  - ALLOW (never false-positive): a legitimate in-scope target that merely
 *    *resembles* an excluded value (shares a substring, lives under a different
 *    arg) is NEVER blocked. A fence that breaks live assessments is worse than no
 *    fence.
 *
 * The guard's core is pure, so these test it directly with no config mocking.
 */

import {
  collectExclusionPatterns,
  matchesExclusion,
  screenExclusions,
  TARGET_ARG_KEYS,
} from "../../src/scope/exclusion-guard";

// A scope config exercising every exclusion shape that appears in scope.yml:
// bare-string (network/AD/Entra/cloud-ARN-glob) and object-form (M365 mailbox/site).
const CONFIG = {
  exclusions: ["*.prod.example.com", "10.0.0.53"], // network flat list
  cloud_accounts: [
    { id: "aws-dev", provider: "aws", exclusions: ["arn:aws:s3:::production-*", "arn:aws:lambda:*:*:function:prod-*"] },
  ],
  identity_targets: [
    { id: "ad-staging", provider: "ad", exclusions: ["krbtgt", "svc-backup-prod"] },
    { id: "entra-dev", provider: "entra", exclusions: ["breakglass@corp.onmicrosoft.com"] },
    { id: "m365-dev", provider: "m365", exclusions: [{ mailbox: "ceo@corp.com" }, { site: "/sites/Legal" }] },
  ],
  ai_targets: [{ id: "bot", exclusions: [] }],
  kubernetes: [{ id: "k1", cluster: "k1", namespaces_excluded: ["kube-system", "prod"] }],
};

const PATTERNS = collectExclusionPatterns(CONFIG);

describe("collectExclusionPatterns — gathers every dimension's exclusions", () => {
  it("flattens bare-string and object-form exclusions from all sources", () => {
    expect(PATTERNS).toEqual(
      expect.arrayContaining([
        "*.prod.example.com",
        "10.0.0.53",
        "arn:aws:s3:::production-*",
        "arn:aws:lambda:*:*:function:prod-*",
        "krbtgt",
        "svc-backup-prod",
        "breakglass@corp.onmicrosoft.com",
        "ceo@corp.com", // extracted from { mailbox: ... }
        "/sites/Legal", // extracted from { site: ... }
        "kube-system",
        "prod",
      ])
    );
  });

  it("returns an empty list when no exclusions are configured", () => {
    expect(collectExclusionPatterns({})).toEqual([]);
    expect(collectExclusionPatterns({ exclusions: [], cloud_accounts: [] })).toEqual([]);
  });
});

describe("matchesExclusion — matching semantics", () => {
  it("matches exact bare patterns", () => {
    expect(matchesExclusion("krbtgt", "krbtgt")).toBe(true);
    expect(matchesExclusion("ceo@corp.com", "ceo@corp.com")).toBe(true);
  });

  it("matches domain/hierarchy suffixes", () => {
    expect(matchesExclusion("host.prod.example.com", "prod.example.com")).toBe(true);
    expect(matchesExclusion("10.0.0.53", "10.0.0.53")).toBe(true);
  });

  it("matches glob patterns (ARN / resource globs)", () => {
    expect(matchesExclusion("arn:aws:s3:::production-data", "arn:aws:s3:::production-*")).toBe(true);
    expect(matchesExclusion("api.prod.example.com", "*.prod.example.com")).toBe(true);
    expect(matchesExclusion("api.staging.example.com", "*.prod.example.com")).toBe(false);
  });

  it("NEVER false-positives on substrings or near-misses", () => {
    // "krbtgt" must not match a benign service principal that contains it.
    expect(matchesExclusion("krbtgt-svc-readonly", "krbtgt")).toBe(false);
    // suffix match is dot-anchored — "admin" must not match "superadmin".
    expect(matchesExclusion("superadmin", "admin")).toBe(false);
    // a different prod function is not the excluded one.
    expect(matchesExclusion("arn:aws:lambda:us-east-1:1:function:dev-handler", "arn:aws:lambda:*:*:function:prod-*")).toBe(false);
    expect(matchesExclusion("", "krbtgt")).toBe(false);
    expect(matchesExclusion("krbtgt", "")).toBe(false);
  });
});

describe("screenExclusions — BLOCK: excluded targets are refused", () => {
  const BLOCKED: Array<[string, Record<string, unknown>, string]> = [
    ["network host glob (target arg)", { target: "api.prod.example.com" }, "*.prod.example.com"],
    ["network host glob (url normalized)", { url: "https://api.prod.example.com/login" }, "*.prod.example.com"],
    ["network ip (cidr arg)", { cidr: "10.0.0.53" }, "10.0.0.53"],
    ["cloud ARN glob (arn arg)", { arn: "arn:aws:s3:::production-data" }, "arn:aws:s3:::production-*"],
    ["cloud ARN glob (resource_arn arg)", { resource_arn: "arn:aws:lambda:us-east-1:1:function:prod-billing" }, "arn:aws:lambda:*:*:function:prod-*"],
    ["AD principal (principal arg)", { principal: "krbtgt" }, "krbtgt"],
    ["AD principal (username arg)", { username: "svc-backup-prod" }, "svc-backup-prod"],
    ["Entra breakglass (upn arg)", { upn: "breakglass@corp.onmicrosoft.com" }, "breakglass@corp.onmicrosoft.com"],
    ["M365 mailbox object-form (mailbox arg)", { mailbox: "ceo@corp.com" }, "ceo@corp.com"],
    ["M365 site object-form (site arg)", { site: "/sites/Legal" }, "/sites/Legal"],
    ["k8s excluded namespace (namespace arg)", { cluster_id: "k1", namespace: "kube-system" }, "kube-system"],
  ];

  it.each(BLOCKED)("blocks [%s]", (_label, args, pattern) => {
    const res = screenExclusions(args, PATTERNS);
    expect(res.blocked).toBe(true);
    expect(res.pattern).toBe(pattern);
    expect(res.reason).toBeTruthy();
  });
});

describe("screenExclusions — ALLOW: never false-positive on legitimate targets", () => {
  const ALLOWED: Array<[string, Record<string, unknown>]> = [
    ["in-scope staging host", { target: "api.staging.example.com" }],
    ["in-scope ip outside the excluded one", { target: "10.0.0.54" }],
    ["a dev lambda (not the excluded prod glob)", { arn: "arn:aws:lambda:us-east-1:1:function:dev-handler" }],
    ["a non-excluded bucket", { arn: "arn:aws:s3:::staging-assets" }],
    ["a service principal that merely contains 'krbtgt'", { principal: "krbtgt-svc-readonly" }],
    ["a non-excluded namespace", { cluster_id: "k1", namespace: "staging" }],
    ["a non-excluded mailbox", { mailbox: "support@corp.com" }],
    ["an excluded value under a NON-target arg key (e.g. a note/description)", { description: "krbtgt", notes: "ceo@corp.com" }],
  ];

  it.each(ALLOWED)("allows [%s]", (_label, args) => {
    expect(screenExclusions(args, PATTERNS).blocked).toBe(false);
  });

  it("allows everything when no exclusion patterns are configured", () => {
    expect(screenExclusions({ target: "krbtgt", arn: "arn:aws:s3:::production-data" }, []).blocked).toBe(false);
  });

  it("ignores non-string arg values", () => {
    expect(screenExclusions({ target: 123 as unknown as string, namespace: null as unknown as string }, PATTERNS).blocked).toBe(false);
  });
});

describe("TARGET_ARG_KEYS — covers the surfaces that carry a target", () => {
  it("includes the network, cloud, identity, and M365 arg names", () => {
    for (const k of ["target", "cidr", "arn", "namespace", "principal", "upn", "mailbox", "site", "ai_target_id"]) {
      expect(TARGET_ARG_KEYS).toContain(k);
    }
  });
});
