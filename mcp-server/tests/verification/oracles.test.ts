/**
 * Oracle decision-core tests.
 *
 * These are the tests that matter most in the verification layer: they assert
 * that an agent CANNOT talk its way to a `verified` verdict. Every case here is
 * a self-certification attempt that must fail, or a genuine proof that must
 * succeed. The runner is faked, so the whole decision core is exercised without
 * a container.
 */

import {
  DifferentialSpec,
  OracleReceipt,
  ReplaySpec,
  RunResult,
  isDegeneratePattern,
  isWeakMarker,
  replayCountFor,
  runDifferential,
  runIdempotentReplay,
  runOracle,
  verdictIsEarned,
} from '../../src/verification/oracles';

/** Fake runner: maps a command substring to the output it should produce. */
function fakeRunner(responses: Record<string, string>, exitCode = 0) {
  return async (command: string): Promise<RunResult> => {
    const key = Object.keys(responses).find(k => command.includes(k));
    return { stdout: key ? responses[key] : '', stderr: '', exitCode };
  };
}

const replaySpec = (over: Partial<ReplaySpec> = {}): ReplaySpec => ({
  kind: 'idempotent_replay',
  command: 'curl ATTACK',
  success_pattern: 'root:x:0:0',
  control_command: 'curl CONTROL',
  ...over,
});

const diffSpec = (over: Partial<DifferentialSpec> = {}): DifferentialSpec => ({
  kind: 'differential',
  attacker_command: 'curl ATTACKER',
  authorized_command: 'curl AUTHORIZED',
  unauthenticated_command: 'curl ANON',
  marker: 'victim-4821@example.com',
  ...over,
});

describe('recipe guards', () => {
  it.each(['.*', '.+', '^.*$', '', '  ', 'ab', '^$', '[\\s\\S]*'])(
    'rejects degenerate pattern %j',
    p => expect(isDegeneratePattern(p)).toBe(true)
  );

  it('accepts a pattern with real literal content', () => {
    expect(isDegeneratePattern('root:x:0:0')).toBe(false);
    expect(isDegeneratePattern('SQL syntax.*MySQL')).toBe(false);
  });

  it('rejects markers too generic to identify one resource', () => {
    expect(isWeakMarker('id')).toBe(true);
    expect(isWeakMarker('email')).toBe(true);
    expect(isWeakMarker('username')).toBe(true);
  });

  it('accepts a marker with identifying content', () => {
    expect(isWeakMarker('victim-4821@example.com')).toBe(false);
    expect(isWeakMarker('acct_9f2c1b77')).toBe(false);
  });

  it('maps intensity to replay count', () => {
    expect(replayCountFor('safe')).toBe(2);
    expect(replayCountFor('aggressive')).toBe(5);
  });
});

describe('idempotent_replay', () => {
  it('verifies when the attack reproduces N/N and the control stays clean', async () => {
    const { receipt } = await runIdempotentReplay(
      replaySpec(),
      2,
      fakeRunner({ ATTACK: 'root:x:0:0:root:/root:/bin/bash', CONTROL: 'Not Found' })
    );

    expect(receipt.verdict).toBe('verified');
    expect(receipt.reason).toBeNull();
    expect(receipt.successes).toBe(2);
    expect(verdictIsEarned(receipt)).toBe(true);
    // The control result is part of the evidence, not just an internal step.
    expect(receipt.observations.find(o => o.label === 'control')?.matched).toBe(false);
  });

  it('REFUTES when the success pattern also matches the control', async () => {
    // The self-certification attack: pick a pattern that always matches. The
    // attack "reproduces" 2/2, but so does a benign request, so it proves nothing.
    const { receipt } = await runIdempotentReplay(
      replaySpec({ success_pattern: 'HTTP' }),
      2,
      fakeRunner({ ATTACK: 'HTTP/1.1 200 OK', CONTROL: 'HTTP/1.1 404 Not Found' })
    );

    expect(receipt.verdict).toBe('refuted');
    expect(receipt.reason).toBe('pattern_not_discriminating');
    expect(verdictIsEarned(receipt)).toBe(false);
  });

  it('refuses a degenerate pattern without spending any requests', async () => {
    const runner = jest.fn(fakeRunner({}));
    const { receipt } = await runIdempotentReplay(replaySpec({ success_pattern: '.*' }), 2, runner);

    expect(receipt.verdict).toBe('refuted');
    expect(receipt.reason).toBe('pattern_degenerate');
    expect(runner).not.toHaveBeenCalled();
  });

  it('refutes an intermittent result rather than rounding it up', async () => {
    let call = 0;
    const flaky = async (command: string): Promise<RunResult> => {
      if (command.includes('CONTROL')) return { stdout: 'Not Found', stderr: '', exitCode: 0 };
      call++;
      return { stdout: call === 1 ? 'root:x:0:0' : 'Not Found', stderr: '', exitCode: 0 };
    };

    const { receipt } = await runIdempotentReplay(replaySpec(), 2, flaky);

    expect(receipt.verdict).toBe('refuted');
    expect(receipt.reason).toBe('not_reproducible');
    expect(receipt.successes).toBe(1);
  });

  it('stores a capsule that carries the whole recipe', async () => {
    const spec = replaySpec();
    const { capsule } = await runIdempotentReplay(
      spec,
      2,
      fakeRunner({ ATTACK: 'root:x:0:0', CONTROL: 'Not Found' })
    );

    expect(capsule.spec).toEqual(spec);
    expect(capsule.n).toBe(2);
  });
});

describe('differential', () => {
  it('verifies when the attacker obtains what only the authorized party should see', async () => {
    const { receipt } = await runDifferential(
      diffSpec(),
      2,
      fakeRunner({
        AUTHORIZED: '{"email":"victim-4821@example.com"}',
        ATTACKER: '{"email":"victim-4821@example.com"}',
        ANON: '{"error":"unauthorized"}',
      })
    );

    expect(receipt.verdict).toBe('verified');
    expect(receipt.reason).toBeNull();
    expect(verdictIsEarned(receipt)).toBe(true);
  });

  it('REFUTES with mechanism_mismatch when an unauthenticated caller also gets the marker', async () => {
    // ExploitGym measured 69 of 226 successful exploits landing on a bug other
    // than the intended one. This is that check: the exposure is real, but it is
    // missing authentication, not the broken object-level authorization claimed.
    const { receipt } = await runDifferential(
      diffSpec(),
      2,
      fakeRunner({
        AUTHORIZED: '{"email":"victim-4821@example.com"}',
        ATTACKER: '{"email":"victim-4821@example.com"}',
        ANON: '{"email":"victim-4821@example.com"}',
      })
    );

    expect(receipt.verdict).toBe('refuted');
    expect(receipt.reason).toBe('mechanism_mismatch');
    expect(receipt.explanation).toMatch(/MISSING AUTHENTICATION/);
    expect(verdictIsEarned(receipt)).toBe(false);
  });

  it('refutes when the authorized context cannot see the resource either', async () => {
    const { receipt } = await runDifferential(
      diffSpec(),
      2,
      fakeRunner({ AUTHORIZED: '{"error":"not found"}', ATTACKER: 'victim-4821@example.com' })
    );

    expect(receipt.verdict).toBe('refuted');
    expect(receipt.reason).toBe('recipe_invalid');
  });

  it('refuses a marker too weak to identify one resource', async () => {
    const runner = jest.fn(fakeRunner({}));
    const { receipt } = await runDifferential(diffSpec({ marker: 'id' }), 2, runner);

    expect(receipt.verdict).toBe('refuted');
    expect(receipt.reason).toBe('marker_too_weak');
    expect(runner).not.toHaveBeenCalled();
  });

  it('notes the gap when no unauthenticated control was supplied', async () => {
    const { receipt } = await runDifferential(
      diffSpec({ unauthenticated_command: undefined }),
      2,
      fakeRunner({
        AUTHORIZED: 'victim-4821@example.com',
        ATTACKER: 'victim-4821@example.com',
      })
    );

    expect(receipt.verdict).toBe('verified');
    expect(receipt.explanation).toMatch(/no unauthenticated control/i);
  });
});

describe('runOracle', () => {
  it('refutes rather than throwing when execution fails', async () => {
    const exploding = async (): Promise<RunResult> => {
      throw new Error('container gone');
    };

    const { receipt } = await runOracle(replaySpec(), 'safe', exploding);

    expect(receipt.verdict).toBe('refuted');
    expect(receipt.reason).toBe('execution_failed');
    expect(verdictIsEarned(receipt)).toBe(false);
  });

  it('honours aggressive intensity', async () => {
    const { receipt } = await runOracle(
      replaySpec(),
      'aggressive',
      fakeRunner({ ATTACK: 'root:x:0:0', CONTROL: 'Not Found' })
    );

    expect(receipt.n).toBe(5);
    expect(receipt.successes).toBe(5);
  });
});

describe('verdictIsEarned — the invariant', () => {
  const base: OracleReceipt = {
    oracle_kind: 'idempotent_replay',
    verdict: 'verified',
    reason: null,
    explanation: '',
    n: 2,
    successes: 2,
    observations: [],
    decided_at: '2026-07-28T00:00:00.000Z',
  };

  it('accepts a receipt that genuinely earned it', () => {
    expect(verdictIsEarned(base)).toBe(true);
  });

  it('rejects a hand-built receipt whose replays did not all succeed', () => {
    expect(verdictIsEarned({ ...base, successes: 1 })).toBe(false);
  });

  it('rejects a receipt with zero replays', () => {
    expect(verdictIsEarned({ ...base, n: 0, successes: 0 })).toBe(false);
  });

  it('rejects a receipt that carries a refusal reason', () => {
    expect(verdictIsEarned({ ...base, reason: 'not_reproducible' })).toBe(false);
  });

  it('rejects null/undefined', () => {
    expect(verdictIsEarned(null)).toBe(false);
    expect(verdictIsEarned(undefined)).toBe(false);
  });
});

// ─────────────────────────────────────────────────────────────────────────
// Rollout steps 3–4 oracles. Same standard as above: every case is either a
// self-certification attempt that must fail, or a genuine proof that must pass.
// ─────────────────────────────────────────────────────────────────────────

import {
  ArtifactSpec,
  CanarySpec,
  CredentialUseSpec,
  OastSpec,
  OastSession,
  ORACLE_STRENGTH,
  TOKEN_PLACEHOLDER,
  OAST_PLACEHOLDER,
  defaultMintToken,
  runArtifact,
  runCanary,
  runCredentialUse,
  runOast,
} from '../../src/verification/oracles';

describe('artifact', () => {
  const spec = (over: Partial<ArtifactSpec> = {}): ArtifactSpec => ({
    kind: 'artifact',
    deposit_command: `curl -d "comment=${TOKEN_PLACEHOLDER}" POST_URL`,
    read_command: `curl GET_URL | grep ${TOKEN_PLACEHOLDER}`,
    ...over,
  });

  /** Simulates a store: the deposit makes the token readable afterwards. */
  function statefulRunner() {
    const stored = new Set<string>();
    return async (command: string) => {
      const token = command.match(/maestro-oracle-[0-9a-f]+/)?.[0];
      if (command.startsWith('curl -d')) {
        if (token) stored.add(token);
        return { stdout: 'created', stderr: '', exitCode: 0 };
      }
      const hit = token && stored.has(token);
      return { stdout: hit ? `<p>${token}</p>` : '<p>empty</p>', stderr: '', exitCode: 0 };
    };
  }

  it('verifies a deposit that is read back, with a fresh nonce each round', async () => {
    const { receipt } = await runArtifact(spec(), 2, statefulRunner(), defaultMintToken);

    expect(receipt.verdict).toBe('verified');
    expect(receipt.successes).toBe(2);
    // Pre-read control ran each round and found nothing.
    const preReads = receipt.observations.filter(o => o.label.startsWith('pre_read'));
    expect(preReads).toHaveLength(2);
    expect(preReads.every(o => !o.matched)).toBe(true);
  });

  it('REFUSES a spec without the harness placeholder', async () => {
    // The self-certification attack: choose your own marker, then "find" it.
    const runner = jest.fn();
    const { receipt } = await runArtifact(
      spec({ deposit_command: 'curl -d "comment=hello" POST_URL' }),
      2,
      runner,
      defaultMintToken
    );

    expect(receipt.verdict).toBe('refuted');
    expect(receipt.reason).toBe('placeholder_missing');
    expect(runner).not.toHaveBeenCalled();
  });

  it('refutes when the marker is already present before the deposit', async () => {
    // A read channel that echoes everything would otherwise "verify" anything.
    const echo = async (command: string) => ({
      stdout: command,
      stderr: '',
      exitCode: 0,
    });
    const { receipt } = await runArtifact(spec(), 2, echo, defaultMintToken);

    expect(receipt.verdict).toBe('refuted');
    expect(receipt.reason).toBe('artifact_preexisting');
  });

  it('mints unpredictable, distinct tokens', () => {
    const a = defaultMintToken();
    const b = defaultMintToken();
    expect(a).not.toBe(b);
    expect(a).toMatch(/^maestro-oracle-[0-9a-f]{24}$/);
  });
});

describe('canary', () => {
  const spec = (over: Partial<CanarySpec> = {}): CanarySpec => ({
    kind: 'canary',
    exploit_command: 'curl EXPLOIT',
    legitimate_command: 'curl LEGIT',
    canary_value: 'canary-a91f-a0d3e2',
    ...over,
  });

  it('verifies when only the attack path surfaces the canary', async () => {
    const { receipt } = await runCanary(
      spec(),
      2,
      fakeRunner({ EXPLOIT: 'secret=canary-a91f-a0d3e2', LEGIT: 'forbidden' })
    );

    expect(receipt.verdict).toBe('verified');
    expect(receipt.successes).toBe(2);
  });

  it('REFUTES when the legitimate interface exposes it too', async () => {
    const { receipt } = await runCanary(
      spec(),
      2,
      fakeRunner({ EXPLOIT: 'canary-a91f-a0d3e2', LEGIT: 'canary-a91f-a0d3e2' })
    );

    expect(receipt.verdict).toBe('refuted');
    expect(receipt.reason).toBe('canary_not_protected');
  });

  it('refuses a canary value generic enough to occur by accident', async () => {
    const runner = jest.fn();
    const { receipt } = await runCanary(spec({ canary_value: 'secret' }), 2, runner);

    expect(receipt.reason).toBe('marker_too_weak');
    expect(runner).not.toHaveBeenCalled();
  });
});

describe('credential_use', () => {
  const spec = (over: Partial<CredentialUseSpec> = {}): CredentialUseSpec => ({
    kind: 'credential_use',
    authenticated_command: 'curl -H "Authorization: Bearer FORGED" AUTHED',
    unauthenticated_command: 'curl ANON',
    success_pattern: '"role"\\s*:\\s*"admin"',
    ...over,
  });

  it('verifies when a forged credential authenticates and anonymous does not', async () => {
    const { receipt } = await runCredentialUse(
      spec(),
      2,
      fakeRunner({ AUTHED: '{"role":"admin"}', ANON: '{"error":"401"}' })
    );

    expect(receipt.verdict).toBe('verified');
    expect(verdictIsEarned(receipt)).toBe(true);
  });

  it('REFUTES with mechanism_mismatch when the route needs no credential at all', async () => {
    // The credential proved nothing — the route was simply never protected.
    const { receipt } = await runCredentialUse(
      spec(),
      2,
      fakeRunner({ AUTHED: '{"role":"admin"}', ANON: '{"role":"admin"}' })
    );

    expect(receipt.verdict).toBe('refuted');
    expect(receipt.reason).toBe('mechanism_mismatch');
  });
});

describe('oast', () => {
  const spec = (over: Partial<OastSpec> = {}): OastSpec => ({
    kind: 'oast',
    command: `curl -d "url=http://${OAST_PLACEHOLDER}/x" TARGET`,
    ...over,
  });

  function session(hits: number, protocol = 'dns'): OastSession {
    const seen: { protocol: string }[] = [];
    let fired = 0;
    return {
      domain: 'abc123def456.oast.internal',
      poll: async () => {
        if (fired < hits) {
          seen.push({ protocol });
          fired++;
        }
        return [...seen];
      },
      close: async () => undefined,
    };
  }

  it('verifies when the target calls back every round', async () => {
    const { receipt } = await runOast(
      spec(),
      2,
      fakeRunner({ TARGET: 'accepted' }),
      async () => session(99)
    );

    expect(receipt.verdict).toBe('verified');
    expect(receipt.successes).toBe(2);
  });

  it('REFUSES a spec without the harness-minted domain placeholder', async () => {
    const { receipt } = await runOast(
      spec({ command: 'curl -d "url=http://attacker.com/x" TARGET' }),
      2,
      fakeRunner({}),
      async () => session(99)
    );

    expect(receipt.verdict).toBe('refuted');
    expect(receipt.reason).toBe('placeholder_missing');
  });

  it('reports oast_unavailable as a coverage gap, not as evidence of absence', async () => {
    const { receipt } = await runOast(spec(), 2, fakeRunner({}), async () => null);

    expect(receipt.verdict).toBe('refuted');
    expect(receipt.reason).toBe('oast_unavailable');
    expect(receipt.explanation).toMatch(/NOT evidence the finding is false/);
  });

  it('refutes when no callback arrives', async () => {
    const { receipt } = await runOast(
      spec(),
      2,
      fakeRunner({ TARGET: 'accepted' }),
      async () => session(0)
    );

    expect(receipt.verdict).toBe('refuted');
    expect(receipt.reason).toBe('not_reproducible');
    expect(receipt.successes).toBe(0);
  });
});

describe('oracle strength ordering', () => {
  it('ranks harness-controlled-nonce oracles above pattern matching', () => {
    expect(ORACLE_STRENGTH.artifact).toBeGreaterThan(ORACLE_STRENGTH.differential);
    expect(ORACLE_STRENGTH.oast).toBeGreaterThan(ORACLE_STRENGTH.canary);
    expect(ORACLE_STRENGTH.credential_use).toBeGreaterThan(ORACLE_STRENGTH.idempotent_replay);
    // idempotent_replay is the universal fallback and therefore the weakest.
    expect(Math.min(...Object.values(ORACLE_STRENGTH))).toBe(ORACLE_STRENGTH.idempotent_replay);
  });
});
