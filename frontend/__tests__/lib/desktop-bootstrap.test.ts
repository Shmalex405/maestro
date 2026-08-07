/**
 * Bootstrap validation. `isBootstrapped()` must reject a partial/corrupt
 * bootstrap (e.g. one missing `backendUrl`, as could be left by an older app
 * version) so the startup gate re-runs discovery and self-heals — rather than
 * accepting it, skipping discovery, and leaving every cloudRequest throwing
 * "No cloud backend configured" (blank data panels, no server error).
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { isValidBootstrap, isBootstrapped, saveBootstrap, type Bootstrap } from '@/lib/desktop-bootstrap';

const COMPLETE: Bootstrap = {
  orgId: 'example-org',
  customerName: 'Groovy Security',
  backendUrl: 'https://maestro.example.com',
  cognitoRegion: 'us-west-2',
  cognitoUserPoolId: 'us-west-2_EXAMPLE01',
  cognitoClientId: 'exampleclientid0000000000',
  discoveredAt: '2026-06-15T00:00:00.000Z',
  email: 'tester@example.com',
};

// The test env's global localStorage (Node's experimental impl) is
// non-functional here, so back it with a simple in-memory Map.
beforeEach(() => {
  const store = new Map<string, string>();
  vi.stubGlobal('localStorage', {
    getItem: (k: string) => (store.has(k) ? store.get(k)! : null),
    setItem: (k: string, v: string) => void store.set(k, v),
    removeItem: (k: string) => void store.delete(k),
    clear: () => store.clear(),
  });
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('isValidBootstrap', () => {
  it('accepts a complete bootstrap', () => {
    expect(isValidBootstrap(COMPLETE)).toBe(true);
  });

  it('rejects null', () => {
    expect(isValidBootstrap(null)).toBe(false);
  });

  it('rejects a bootstrap missing backendUrl', () => {
    expect(isValidBootstrap({ ...COMPLETE, backendUrl: '' })).toBe(false);
    const { backendUrl: _omit, ...withoutUrl } = COMPLETE;
    expect(isValidBootstrap(withoutUrl as Bootstrap)).toBe(false);
  });

  it('rejects a bootstrap missing Cognito config', () => {
    expect(isValidBootstrap({ ...COMPLETE, cognitoUserPoolId: '' })).toBe(false);
    expect(isValidBootstrap({ ...COMPLETE, cognitoClientId: '   ' })).toBe(false);
    expect(isValidBootstrap({ ...COMPLETE, cognitoRegion: '' })).toBe(false);
  });
});

describe('isBootstrapped', () => {
  it('is false when nothing is stored', () => {
    expect(isBootstrapped()).toBe(false);
  });

  it('is true after a complete bootstrap is saved', () => {
    saveBootstrap(COMPLETE);
    expect(isBootstrapped()).toBe(true);
  });

  it('is false for a partial bootstrap left in storage (triggers re-discovery)', () => {
    localStorage.setItem('maestro-bootstrap', JSON.stringify({ orgId: 'example-org', email: 'x@y' }));
    expect(isBootstrapped()).toBe(false);
  });
});
