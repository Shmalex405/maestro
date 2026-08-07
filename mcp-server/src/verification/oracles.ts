// The oracle verification layer — earned verdicts.
//
// One principle, from docs/oracle-verification-layer.md:
//
//   A finding's verdict must be EARNED IN CODE by a named oracle, and the LLM
//   must be structurally unable to write `verified` itself.
//
// The split that makes this work: the LLM supplies the RECIPE (what request to
// send, what string identifies success), the code supplies the VERDICT. That
// keeps Maestro's edge — LLM-driven detection finds bespoke authz/business-logic
// bugs no frozen probe library encodes — while making the proof deterministic.
// Non-deterministic search, deterministic verdict.
//
// The obvious attack on that split is a degenerate recipe: an agent that supplies
// `success_pattern: "HTTP"` gets 5/5 against any live endpoint and self-certifies.
// Reproducibility alone cannot distinguish "the vulnerability is real" from "the
// response always looks like this". So every oracle here is built around a
// CONTROL — an execution that should NOT exhibit the vulnerability. A pattern
// that matches the control too is not discriminating, and the oracle refutes.
//
// The decision core (decideReplay / decideDifferential) is PURE over observed
// outputs, so it is reproducible and unit-testable without a container.

export type Verdict = "candidate" | "verified" | "refuted";
export type OracleKind =
  | "idempotent_replay"
  | "differential"
  | "artifact"
  | "canary"
  | "credential_use"
  | "oast";

/**
 * Oracle strength, strongest first. `verify_finding` reports this so the
 * verifier agent can tell when it settled for a weaker proof than the finding
 * could have earned. Ordering rationale:
 *
 *   artifact / oast — the harness controls a nonce the agent cannot predict, so
 *                     observing it come back is causally tied to the attack.
 *   credential_use  — a recovered secret actually authenticates; the negative
 *                     control (same request, no credential) is unambiguous.
 *   canary          — planted value surfaces where only an attacker could reach.
 *   differential    — divergence between two identities, computed by the harness.
 *   idempotent_replay — reproduction plus a benign control. Weakest, but universal.
 */
export const ORACLE_STRENGTH: Record<OracleKind, number> = {
  artifact: 6,
  oast: 5,
  credential_use: 4,
  canary: 3,
  differential: 2,
  idempotent_replay: 1,
};

/** safe = 2 replays, aggressive = 5. Per docs/oracle-verification-layer.md. */
export type Intensity = "safe" | "aggressive";

export function replayCountFor(intensity: Intensity): number {
  return intensity === "aggressive" ? 5 : 2;
}

// ---------------------------------------------------------------------------
// Specs — the recipe an agent supplies. Stored verbatim as the replay capsule.
// ---------------------------------------------------------------------------

export interface ReplaySpec {
  kind: "idempotent_replay";
  /** The attack, run in the Kali container. */
  command: string;
  /** Regex that must match the attack output for the attempt to count. */
  success_pattern: string;
  /**
   * The negative control: the same request WITHOUT the thing that makes it an
   * attack (payload removed, benign value substituted). Required — see the
   * module header. If `success_pattern` matches this too, it proves nothing.
   */
  control_command: string;
}

export interface DifferentialSpec {
  kind: "differential";
  /** The request in the attacker's context (their token, someone else's object). */
  attacker_command: string;
  /** The same resource fetched by the party legitimately entitled to it. */
  authorized_command: string;
  /** A literal string from the protected resource that identifies it uniquely. */
  marker: string;
  /**
   * The same request with NO credentials at all. This is the mechanism control:
   * if an unauthenticated caller also gets the marker, the finding is missing
   * authentication, not a broken object-level authorization check, and a
   * `differential` receipt would be attributing impact to the wrong bug.
   */
  unauthenticated_command?: string;
}

export interface ArtifactSpec {
  kind: "artifact";
  /**
   * The attack that deposits the marker. MUST contain the literal `{{TOKEN}}`
   * placeholder — the harness generates the nonce, not the agent. That is the
   * whole strength of this oracle: an agent that cannot predict the value it
   * will be asked to find cannot manufacture the observation.
   */
  deposit_command: string;
  /** Reads the deposited marker back, ideally through a different channel. */
  read_command: string;
}

export interface CanarySpec {
  kind: "canary";
  /** The attack that should surface a value only an attacker could reach. */
  exploit_command: string;
  /** The planted value that must not be reachable through legitimate use. */
  canary_value: string;
  /**
   * The legitimate interface. If the canary is visible here, the data is simply
   * public and no boundary was crossed.
   */
  legitimate_command: string;
}

export interface CredentialUseSpec {
  kind: "credential_use";
  /**
   * A protected action performed WITH the recovered/forged credential — a
   * cracked hash, a forged JWT, an assumed cloud role, a replayed token.
   */
  authenticated_command: string;
  /** Content that appears only on a genuinely authenticated response. */
  success_pattern: string;
  /**
   * The same request with the credential removed. If this succeeds too, the
   * route was never protected and the credential proved nothing.
   */
  unauthenticated_command: string;
}

export interface OastSpec {
  kind: "oast";
  /**
   * The payload that should cause the target to call out to us. MUST contain
   * the literal `{{OAST_DOMAIN}}` placeholder — the harness owns the listener
   * and the domain, so an interaction is proof the target reached out.
   */
  command: string;
  /** Which interaction protocol counts as proof. */
  protocol?: "dns" | "http" | "any";
}

export type OracleSpec =
  | ReplaySpec
  | DifferentialSpec
  | ArtifactSpec
  | CanarySpec
  | CredentialUseSpec
  | OastSpec;

// ---------------------------------------------------------------------------
// Observations + receipt — the machine evidence a verdict is built from.
// ---------------------------------------------------------------------------

export interface Observation {
  label: string;
  command: string;
  exit_code: number | null;
  matched: boolean;
  /** Captured output, truncated. This is the evidence a human replays against. */
  excerpt: string;
}

export interface OracleReceipt {
  oracle_kind: OracleKind;
  verdict: Verdict;
  /** Machine-readable reason code. `null` when verified. */
  reason:
    | null
    | "pattern_degenerate"
    | "pattern_not_discriminating"
    | "marker_too_weak"
    | "recipe_invalid"
    | "mechanism_mismatch"
    | "not_reproducible"
    | "execution_failed"
    /** The spec omitted the harness-controlled placeholder it must contain. */
    | "placeholder_missing"
    /** The nonce was already present before the attack ran — read-back proves nothing. */
    | "artifact_preexisting"
    /** The canary is visible through the legitimate interface; nothing was crossed. */
    | "canary_not_protected"
    /** The out-of-band listener is unavailable, so no verdict can be earned. */
    | "oast_unavailable";
  explanation: string;
  n: number;
  successes: number;
  observations: Observation[];
  decided_at: string;
}

export interface OracleOutcome {
  receipt: OracleReceipt;
  capsule: { spec: OracleSpec; n: number };
}

const EXCERPT_LIMIT = 4000;

export function excerpt(s: string): string {
  return s.length > EXCERPT_LIMIT ? `${s.slice(0, EXCERPT_LIMIT)}\n…[truncated]` : s;
}

// ---------------------------------------------------------------------------
// Recipe guards — reject specs that cannot discriminate before spending requests.
// ---------------------------------------------------------------------------

/**
 * A pattern that matches essentially any output can't earn a verdict. This
 * catches the structurally-degenerate cases; the negative control catches the
 * merely-weak ones (`HTTP`, `200`), which is why the control is not optional.
 */
export function isDegeneratePattern(pattern: string): boolean {
  const p = pattern.trim();
  if (p.length < 3) return true;
  if (/^[.^$\s*+?()\[\]{}|\\]*$/.test(p)) return true; // only regex metacharacters
  const universal = new Set([".*", ".+", "^.*$", "^.+$", "[\\s\\S]*", "(.|\\n)*"]);
  if (universal.has(p)) return true;
  // A pattern whose only literal content is a single repeated wildcard class.
  const literals = p.replace(/[.^$*+?()\[\]{}|\\]/g, "").trim();
  return literals.length < 3;
}

/** A marker must be specific enough to identify one protected resource. */
export function isWeakMarker(marker: string): boolean {
  const m = marker.trim();
  if (m.length < 8) return true;
  // Needs some entropy — an id, email, token or name, not a bare field label.
  return !/[0-9@._-]/.test(m) && !/[A-Z]/.test(m);
}

function safeMatch(pattern: string, text: string): boolean {
  try {
    return new RegExp(pattern, "i").test(text);
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Execution shim — injected so the decision core stays pure and testable.
// ---------------------------------------------------------------------------

export interface RunResult {
  stdout: string;
  stderr: string;
  exitCode: number | null;
}
export type Runner = (command: string) => Promise<RunResult>;

/**
 * The default nonce for the `artifact` oracle. Unpredictable by construction —
 * an agent cannot pre-compute what it will be asked to find. The `maestro-`
 * prefix makes a stray marker traceable if one survives in a target.
 */
export function defaultMintToken(): string {
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const { randomBytes } = require("crypto");
  return `maestro-oracle-${randomBytes(12).toString("hex")}`;
}

function observe(label: string, command: string, r: RunResult, matched: boolean): Observation {
  return {
    label,
    command,
    exit_code: r.exitCode,
    matched,
    excerpt: excerpt(`${r.stdout}${r.stderr ? `\n[stderr] ${r.stderr}` : ""}`),
  };
}

function receipt(
  oracle_kind: OracleKind,
  verdict: Verdict,
  reason: OracleReceipt["reason"],
  explanation: string,
  n: number,
  successes: number,
  observations: Observation[]
): OracleReceipt {
  return {
    oracle_kind,
    verdict,
    reason,
    explanation,
    n,
    successes,
    observations,
    decided_at: new Date().toISOString(),
  };
}

// ---------------------------------------------------------------------------
// Oracle 1 — idempotent_replay.
//
// Universal fallback. Kills single-shot luck and flaky reflection: the attack
// must reproduce N/N, and the negative control must NOT reproduce.
// ---------------------------------------------------------------------------

export async function runIdempotentReplay(
  spec: ReplaySpec,
  n: number,
  run: Runner
): Promise<OracleOutcome> {
  const capsule = { spec, n };

  if (isDegeneratePattern(spec.success_pattern)) {
    return {
      capsule,
      receipt: receipt(
        "idempotent_replay",
        "refuted",
        "pattern_degenerate",
        `success_pattern ${JSON.stringify(spec.success_pattern)} matches essentially any output, so it cannot demonstrate anything. Supply a pattern containing content unique to the vulnerable response.`,
        n,
        0,
        []
      ),
    };
  }

  const observations: Observation[] = [];

  // Negative control first — if the pattern isn't discriminating, we've spent one
  // request instead of N to find out.
  const control = await run(spec.control_command);
  const controlMatched = safeMatch(spec.success_pattern, `${control.stdout}\n${control.stderr}`);
  observations.push(observe("control", spec.control_command, control, controlMatched));

  if (controlMatched) {
    return {
      capsule,
      receipt: receipt(
        "idempotent_replay",
        "refuted",
        "pattern_not_discriminating",
        `The success pattern also matches the negative control, so a match against the attack proves nothing about the attack. Either the pattern is too broad or the control is not actually benign.`,
        n,
        0,
        observations
      ),
    };
  }

  let successes = 0;
  for (let i = 0; i < n; i++) {
    const attempt = await run(spec.command);
    const matched = safeMatch(spec.success_pattern, `${attempt.stdout}\n${attempt.stderr}`);
    if (matched) successes++;
    observations.push(observe(`attack_${i + 1}`, spec.command, attempt, matched));
  }

  if (successes === n) {
    return {
      capsule,
      receipt: receipt(
        "idempotent_replay",
        "verified",
        null,
        `Attack reproduced ${successes}/${n} and the negative control did not exhibit the pattern.`,
        n,
        successes,
        observations
      ),
    };
  }

  return {
    capsule,
    receipt: receipt(
      "idempotent_replay",
      "refuted",
      "not_reproducible",
      `Attack reproduced only ${successes}/${n}. A verdict requires every replay to succeed — intermittent success is indistinguishable from coincidence.`,
      n,
      successes,
      observations
    ),
  };
}

// ---------------------------------------------------------------------------
// Oracle 2 — differential.
//
// The authorization oracle: IDOR / BOLA / broken access control. The proof is
// DIVERGENCE that the code computes itself — the attacker context obtains a
// marker that only the authorized context should be able to see.
//
// The mechanism control is what makes this honest. If an unauthenticated caller
// also gets the marker, the impact is real but the CLAIM is wrong: that is
// missing authentication, not a broken object-level authorization check.
// ExploitGym found 69 of 226 successful exploits landing on a vulnerability
// other than the intended one; this is that check, in code.
// ---------------------------------------------------------------------------

export async function runDifferential(
  spec: DifferentialSpec,
  n: number,
  run: Runner
): Promise<OracleOutcome> {
  const capsule = { spec, n };

  if (isWeakMarker(spec.marker)) {
    return {
      capsule,
      receipt: receipt(
        "differential",
        "refuted",
        "marker_too_weak",
        `marker ${JSON.stringify(spec.marker)} is too generic to identify one protected resource. Use a value unique to the victim record (an id, email, token, or account name).`,
        n,
        0,
        []
      ),
    };
  }

  const observations: Observation[] = [];
  const hasMarker = (r: RunResult) => `${r.stdout}\n${r.stderr}`.includes(spec.marker);

  // Sanity: the authorized context must actually be able to see the resource.
  // If it can't, the recipe does not demonstrate the boundary it claims to.
  const authorized = await run(spec.authorized_command);
  const authorizedMatched = hasMarker(authorized);
  observations.push(observe("authorized", spec.authorized_command, authorized, authorizedMatched));

  if (!authorizedMatched) {
    return {
      capsule,
      receipt: receipt(
        "differential",
        "refuted",
        "recipe_invalid",
        `The authorized context did not return the marker, so there is no established baseline that this resource is protected-but-visible-to-its-owner. Without it, an attacker-context match cannot be attributed to an authorization failure.`,
        n,
        0,
        observations
      ),
    };
  }

  // Mechanism control: does this need credentials at all?
  if (spec.unauthenticated_command) {
    const anon = await run(spec.unauthenticated_command);
    const anonMatched = hasMarker(anon);
    observations.push(observe("unauthenticated", spec.unauthenticated_command, anon, anonMatched));

    if (anonMatched) {
      return {
        capsule,
        receipt: receipt(
          "differential",
          "refuted",
          "mechanism_mismatch",
          `An unauthenticated request also returned the marker. The exposure is real, but it is MISSING AUTHENTICATION, not a broken object-level authorization check — re-file the finding against the correct mechanism and re-verify. A differential receipt here would attribute the impact to the wrong vulnerability.`,
          n,
          0,
          observations
        ),
      };
    }
  }

  let successes = 0;
  for (let i = 0; i < n; i++) {
    const attempt = await run(spec.attacker_command);
    const matched = hasMarker(attempt);
    if (matched) successes++;
    observations.push(observe(`attacker_${i + 1}`, spec.attacker_command, attempt, matched));
  }

  if (successes === n) {
    return {
      capsule,
      receipt: receipt(
        "differential",
        "verified",
        null,
        `The attacker context obtained the authorized party's marker ${successes}/${n} times${
          spec.unauthenticated_command
            ? ", while an unauthenticated request did not — the boundary that failed is object-level authorization, as claimed."
            : ". No unauthenticated control was supplied, so this receipt does not rule out that the endpoint requires no authentication at all."
        }`,
        n,
        successes,
        observations
      ),
    };
  }

  return {
    capsule,
    receipt: receipt(
      "differential",
      "refuted",
      "not_reproducible",
      `The attacker context obtained the marker only ${successes}/${n} times. A verdict requires every replay to succeed.`,
      n,
      successes,
      observations
    ),
  };
}

// ---------------------------------------------------------------------------
// Oracle 3 — artifact.
//
// The strongest oracle available, because the harness owns the nonce. The agent
// writes commands containing `{{TOKEN}}`; the harness substitutes a value the
// agent has never seen, then checks that the value comes back out. There is no
// way to fabricate an observation of a secret you were not told.
//
// The pre-read is the control: if the nonce is somehow already present before
// the deposit ran, the read-back is not caused by the attack.
// ---------------------------------------------------------------------------

export const TOKEN_PLACEHOLDER = "{{TOKEN}}";

export async function runArtifact(
  spec: ArtifactSpec,
  n: number,
  run: Runner,
  mintToken: () => string
): Promise<OracleOutcome> {
  const capsule = { spec, n };

  if (!spec.deposit_command.includes(TOKEN_PLACEHOLDER)) {
    return {
      capsule,
      receipt: receipt(
        "artifact",
        "refuted",
        "placeholder_missing",
        `deposit_command must contain the literal ${TOKEN_PLACEHOLDER}. The harness mints the marker so that observing it prove the deposit happened — a marker you chose yourself proves nothing.`,
        n,
        0,
        []
      ),
    };
  }

  const observations: Observation[] = [];
  let successes = 0;

  for (let i = 0; i < n; i++) {
    // A fresh nonce per round, so round 2 cannot pass on round 1's residue.
    const token = mintToken();
    const deposit = spec.deposit_command.split(TOKEN_PLACEHOLDER).join(token);
    const read = spec.read_command.split(TOKEN_PLACEHOLDER).join(token);

    const pre = await run(read);
    const preHas = `${pre.stdout}\n${pre.stderr}`.includes(token);
    observations.push(observe(`pre_read_${i + 1}`, read, pre, preHas));

    if (preHas) {
      return {
        capsule,
        receipt: receipt(
          "artifact",
          "refuted",
          "artifact_preexisting",
          `The marker was already present before the deposit ran, so reading it back does not demonstrate the attack had any effect.`,
          n,
          successes,
          observations
        ),
      };
    }

    const dep = await run(deposit);
    observations.push(observe(`deposit_${i + 1}`, deposit, dep, true));

    const post = await run(read);
    const postHas = `${post.stdout}\n${post.stderr}`.includes(token);
    if (postHas) successes++;
    observations.push(observe(`post_read_${i + 1}`, read, post, postHas));
  }

  return successes === n
    ? {
        capsule,
        receipt: receipt(
          "artifact",
          "verified",
          null,
          `A harness-minted marker was deposited by the attack and read back ${successes}/${n} times, absent from the read channel beforehand each round.`,
          n,
          successes,
          observations
        ),
      }
    : {
        capsule,
        receipt: receipt(
          "artifact",
          "refuted",
          "not_reproducible",
          `The deposited marker was read back only ${successes}/${n} times.`,
          n,
          successes,
          observations
        ),
      };
}

// ---------------------------------------------------------------------------
// Oracle 4 — canary.
//
// A value planted where only a successful attack should reach. The control asks
// the question that matters: can the legitimate interface see it too? If yes,
// the data was public and no boundary was crossed.
// ---------------------------------------------------------------------------

export async function runCanary(
  spec: CanarySpec,
  n: number,
  run: Runner
): Promise<OracleOutcome> {
  const capsule = { spec, n };

  if (isWeakMarker(spec.canary_value)) {
    return {
      capsule,
      receipt: receipt(
        "canary",
        "refuted",
        "marker_too_weak",
        `canary_value ${JSON.stringify(spec.canary_value)} is too generic — a value that could occur incidentally cannot demonstrate it was reached by the attack.`,
        n,
        0,
        []
      ),
    };
  }

  const observations: Observation[] = [];
  const has = (r: RunResult) => `${r.stdout}\n${r.stderr}`.includes(spec.canary_value);

  const legit = await run(spec.legitimate_command);
  const legitHas = has(legit);
  observations.push(observe("legitimate", spec.legitimate_command, legit, legitHas));

  if (legitHas) {
    return {
      capsule,
      receipt: receipt(
        "canary",
        "refuted",
        "canary_not_protected",
        `The canary is visible through the legitimate interface, so surfacing it via the attack path does not demonstrate a boundary was crossed. This data is public.`,
        n,
        0,
        observations
      ),
    };
  }

  let successes = 0;
  for (let i = 0; i < n; i++) {
    const attempt = await run(spec.exploit_command);
    const matched = has(attempt);
    if (matched) successes++;
    observations.push(observe(`exploit_${i + 1}`, spec.exploit_command, attempt, matched));
  }

  return successes === n
    ? {
        capsule,
        receipt: receipt(
          "canary",
          "verified",
          null,
          `The attack surfaced the planted canary ${successes}/${n} times, while the legitimate interface did not expose it.`,
          n,
          successes,
          observations
        ),
      }
    : {
        capsule,
        receipt: receipt(
          "canary",
          "refuted",
          "not_reproducible",
          `The attack surfaced the canary only ${successes}/${n} times.`,
          n,
          successes,
          observations
        ),
      };
}

// ---------------------------------------------------------------------------
// Oracle 5 — credential_use.
//
// "TruffleHog finds the key; we log in with it." A recovered or forged
// credential is only a finding if it actually authenticates. The control — the
// same request without the credential — separates "this key works" from "this
// route was never protected in the first place".
// ---------------------------------------------------------------------------

export async function runCredentialUse(
  spec: CredentialUseSpec,
  n: number,
  run: Runner
): Promise<OracleOutcome> {
  const capsule = { spec, n };

  if (isDegeneratePattern(spec.success_pattern)) {
    return {
      capsule,
      receipt: receipt(
        "credential_use",
        "refuted",
        "pattern_degenerate",
        `success_pattern ${JSON.stringify(spec.success_pattern)} matches essentially any response. Use content that appears only on a genuinely authenticated one.`,
        n,
        0,
        []
      ),
    };
  }

  const observations: Observation[] = [];
  const matches = (r: RunResult) => safeMatch(spec.success_pattern, `${r.stdout}\n${r.stderr}`);

  const anon = await run(spec.unauthenticated_command);
  const anonMatched = matches(anon);
  observations.push(observe("unauthenticated", spec.unauthenticated_command, anon, anonMatched));

  if (anonMatched) {
    return {
      capsule,
      receipt: receipt(
        "credential_use",
        "refuted",
        "mechanism_mismatch",
        `The same request succeeds with NO credential, so the credential did not grant this access. The real finding is that the route is unauthenticated — re-file it against that mechanism.`,
        n,
        0,
        observations
      ),
    };
  }

  let successes = 0;
  for (let i = 0; i < n; i++) {
    const attempt = await run(spec.authenticated_command);
    const matched = matches(attempt);
    if (matched) successes++;
    observations.push(observe(`authenticated_${i + 1}`, spec.authenticated_command, attempt, matched));
  }

  return successes === n
    ? {
        capsule,
        receipt: receipt(
          "credential_use",
          "verified",
          null,
          `The recovered credential authenticated ${successes}/${n} times against a route that rejects the same request without it.`,
          n,
          successes,
          observations
        ),
      }
    : {
        capsule,
        receipt: receipt(
          "credential_use",
          "refuted",
          "not_reproducible",
          `The credential authenticated only ${successes}/${n} times.`,
          n,
          successes,
          observations
        ),
      };
}

// ---------------------------------------------------------------------------
// Oracle 6 — oast.
//
// The only oracle for blind classes: blind SSRF/SQLi/XXE/SSTI, where nothing
// comes back in the response and the sole evidence is the target reaching out.
// The harness owns the listener and the domain, so an interaction bearing our
// correlation id is proof the target made the request.
//
// Self-hosted only: the listener runs inside the org's own Kali container, so
// no target data leaves it. Never a public interactsh instance.
// ---------------------------------------------------------------------------

export const OAST_PLACEHOLDER = "{{OAST_DOMAIN}}";

/** Injected so the oracle stays testable without a live listener. */
export interface OastSession {
  domain: string;
  /** Interactions observed since the session started, newest last. */
  poll: () => Promise<{ protocol: string; remoteAddress?: string; raw?: string }[]>;
  close: () => Promise<void>;
}
export type OastProvider = () => Promise<OastSession | null>;

export async function runOast(
  spec: OastSpec,
  n: number,
  run: Runner,
  provider: OastProvider
): Promise<OracleOutcome> {
  const capsule = { spec, n };

  if (!spec.command.includes(OAST_PLACEHOLDER)) {
    return {
      capsule,
      receipt: receipt(
        "oast",
        "refuted",
        "placeholder_missing",
        `command must contain the literal ${OAST_PLACEHOLDER}. The harness owns the listener, so only a domain it minted can prove the target called out.`,
        n,
        0,
        []
      ),
    };
  }

  const session = await provider();
  if (!session) {
    return {
      capsule,
      receipt: receipt(
        "oast",
        "refuted",
        "oast_unavailable",
        `No out-of-band listener is available in this container (interactsh-client absent or failed to start), so no verdict can be earned for a blind finding. This is a coverage gap, NOT evidence the finding is false — report it as an unverified candidate and state that OAST was unavailable.`,
        n,
        0,
        []
      ),
    };
  }

  const observations: Observation[] = [];
  let successes = 0;

  try {
    // Baseline: the listener must be quiet before we send anything, otherwise a
    // noisy shared listener could be mistaken for our callback.
    const before = await session.poll();
    observations.push(
      observe(
        "listener_baseline",
        `poll ${session.domain}`,
        { stdout: `${before.length} pre-existing interaction(s)`, stderr: "", exitCode: 0 },
        before.length > 0
      )
    );

    for (let i = 0; i < n; i++) {
      const cmd = spec.command.split(OAST_PLACEHOLDER).join(session.domain);
      const attempt = await run(cmd);
      observations.push(observe(`payload_${i + 1}`, cmd, attempt, true));

      const seen = await session.poll();
      const fresh = seen.slice(before.length + successes);
      const wanted = spec.protocol && spec.protocol !== "any" ? spec.protocol : null;
      const hit = fresh.find((x) => !wanted || x.protocol.toLowerCase() === wanted);
      if (hit) successes++;
      observations.push(
        observe(
          `callback_${i + 1}`,
          `poll ${session.domain}`,
          {
            stdout: hit
              ? `${hit.protocol} interaction from ${hit.remoteAddress ?? "unknown"}\n${hit.raw ?? ""}`
              : "no interaction",
            stderr: "",
            exitCode: 0,
          },
          !!hit
        )
      );
    }
  } finally {
    await session.close().catch(() => undefined);
  }

  return successes === n
    ? {
        capsule,
        receipt: receipt(
          "oast",
          "verified",
          null,
          `The target called back to our self-hosted listener ${successes}/${n} times on a domain the harness minted. For a blind class this is the callback itself, not an inference from response content.`,
          n,
          successes,
          observations
        ),
      }
    : {
        capsule,
        receipt: receipt(
          "oast",
          "refuted",
          "not_reproducible",
          `The target called back only ${successes}/${n} times.`,
          n,
          successes,
          observations
        ),
      };
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

export interface OracleDeps {
  run: Runner;
  /** Mints the unpredictable marker for the `artifact` oracle. */
  mintToken?: () => string;
  /** Provides a self-hosted out-of-band listener for the `oast` oracle. */
  oast?: OastProvider;
}

export async function runOracle(
  spec: OracleSpec,
  intensity: Intensity,
  deps: Runner | OracleDeps
): Promise<OracleOutcome> {
  const n = replayCountFor(intensity);
  const d: OracleDeps = typeof deps === "function" ? { run: deps } : deps;
  const run = d.run;
  try {
    switch (spec.kind) {
      case "idempotent_replay":
        return await runIdempotentReplay(spec, n, run);
      case "differential":
        return await runDifferential(spec, n, run);
      case "artifact":
        return await runArtifact(spec, n, run, d.mintToken ?? defaultMintToken);
      case "canary":
        return await runCanary(spec, n, run);
      case "credential_use":
        return await runCredentialUse(spec, n, run);
      case "oast":
        return await runOast(spec, n, run, d.oast ?? (async () => null));
    }
  } catch (err) {
    return {
      capsule: { spec, n },
      receipt: receipt(
        spec.kind,
        "refuted",
        "execution_failed",
        `Oracle execution failed: ${String(err)}. No verdict can be earned from a failed run — the finding stays a candidate.`,
        n,
        0,
        []
      ),
    };
  }
}

/**
 * The invariant, in one function. Nothing may write `verified` to a finding
 * unless a receipt actually earned it. Mirrors the CHECK constraint added in
 * backend migration 0049 so the MCP server and the database agree.
 */
export function verdictIsEarned(r: OracleReceipt | null | undefined): boolean {
  if (!r) return false;
  return (
    r.verdict === "verified" &&
    !!r.oracle_kind &&
    r.n > 0 &&
    r.successes === r.n &&
    r.reason === null
  );
}
