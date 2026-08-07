/**
 * Self-hosted bootstrap synthesis.
 *
 * A self-hosted install has no /api/discover to ask, so the startup gate builds
 * a Bootstrap from the operator's local config instead. The contract that
 * matters: whatever bootstrapFromSelfHost produces must satisfy
 * isValidBootstrap — otherwise the gate would treat the install as
 * un-bootstrapped, fall through to managed discovery, and point the operator at
 * a Groovy endpoint they have no account on.
 */

import { describe, it, expect } from 'vitest';
import { bootstrapFromSelfHost, type SelfHostConfig } from '@/lib/self-host';
import { isValidBootstrap, BOOTSTRAP_SCHEMA_VERSION } from '@/lib/desktop-bootstrap';

const CONFIG: SelfHostConfig = {
  mode: 'team',
  orgId: 'acme',
  customerName: 'Acme Security',
  backendUrl: 'https://maestro.security.acme.test',
  cognitoRegion: 'us-west-2',
  cognitoUserPoolId: 'us-west-2_AbC123',
  cognitoClientId: '1a2b3c4d5e6f7g8h9i0j',
  cognitoDomain: 'maestro-acme-prod.auth.us-west-2.amazoncognito.com',
  oastServer: 'oast.security.acme.test',
  oastToken: 'poll-token',
};

describe('bootstrapFromSelfHost', () => {
  it('produces a bootstrap the startup gate accepts as valid', () => {
    // The whole point: if this ever returns false, self-hosted installs
    // silently fall back to managed discovery.
    expect(isValidBootstrap(bootstrapFromSelfHost(CONFIG))).toBe(true);
  });

  it('carries the routing and identity fields through unchanged', () => {
    const b = bootstrapFromSelfHost(CONFIG);
    expect(b.backendUrl).toBe('https://maestro.security.acme.test');
    expect(b.cognitoRegion).toBe('us-west-2');
    expect(b.cognitoUserPoolId).toBe('us-west-2_AbC123');
    expect(b.cognitoClientId).toBe('1a2b3c4d5e6f7g8h9i0j');
    expect(b.orgId).toBe('acme');
    expect(b.customerName).toBe('Acme Security');
  });

  it('stamps the current schema version so it is not re-discovered', () => {
    // A bootstrap stamped below BOOTSTRAP_SCHEMA_VERSION triggers
    // bootstrapNeedsRefresh(), which in a managed install re-runs discovery.
    // Self-hosted has nothing to re-discover against.
    expect(bootstrapFromSelfHost(CONFIG).schemaVersion).toBe(BOOTSTRAP_SCHEMA_VERSION);
  });

  it('records the email when supplied, and tolerates its absence', () => {
    expect(bootstrapFromSelfHost(CONFIG, 'ops@acme.test').email).toBe('ops@acme.test');
    // No email is normal on a first launch before sign-in — it must not make
    // the bootstrap invalid, since nothing self-hosted resolves anything from
    // it (there is no email-to-org mapping to do).
    const b = bootstrapFromSelfHost(CONFIG);
    expect(b.email).toBe('');
    expect(isValidBootstrap(b)).toBe(true);
  });

  it('passes the OAST server and token through together', () => {
    // Unlike the managed path — where the token deliberately never rides the
    // unauthenticated discovery response — a self-hoster's token comes off
    // their own disk, so it travels with the server.
    expect(bootstrapFromSelfHost(CONFIG).oast).toEqual({
      server: 'oast.security.acme.test',
      token: 'poll-token',
    });
  });

  it('omits oast entirely when no listener is configured', () => {
    // Absent (not an empty object) is what makes the oracle report
    // oast_unavailable and keep blind findings as honest candidates.
    const b = bootstrapFromSelfHost({ ...CONFIG, oastServer: '', oastToken: '' });
    expect(b.oast).toBeUndefined();
  });

  it('keeps the server when a listener needs no token', () => {
    const b = bootstrapFromSelfHost({ ...CONFIG, oastToken: '' });
    expect(b.oast).toEqual({ server: 'oast.security.acme.test', token: undefined });
  });

  it('refuses to build a bootstrap from a local-mode config', () => {
    // Local mode has no backendUrl or Cognito settings, so the result would fail
    // isValidBootstrap. A stored INVALID bootstrap is worse than none: the gate
    // would treat the install as bootstrapped, skip discovery, and then fail
    // every cloudRequest. Throwing makes a mis-wired caller loud.
    expect(() => bootstrapFromSelfHost({ ...CONFIG, mode: 'local' })).toThrow(
      /local-mode config/i,
    );
  });

  it('normalizes an empty cognito domain to undefined', () => {
    // Empty string and undefined mean the same thing downstream (browser
    // sign-in off, SRP password login still available); undefined keeps the
    // stored shape identical to a discovered bootstrap.
    expect(bootstrapFromSelfHost({ ...CONFIG, cognitoDomain: '' }).cognitoDomain)
      .toBeUndefined();
  });
});
