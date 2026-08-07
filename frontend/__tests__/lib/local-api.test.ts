/**
 * Local-mode shape adapter and mode defaults.
 *
 * The local SQLite row and the TS/cloud Finding are NOT the same shape: two
 * fields are named differently and one is a list where the UI expects a scalar.
 * A mistake here doesn't fail to compile — it renders a blank CVSS column or an
 * empty CVE cell — so the mapping is pinned explicitly.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { toFinding } from '@/lib/local-api';
import {
  getDataMode,
  setDataMode,
  clearDataMode,
  isLocalMode,
  isFeatureAvailable,
  featureUnavailableReason,
  dataModeLabel,
} from '@/lib/deployment-mode';

// The test env's localStorage is non-functional; back it with a Map.
beforeEach(() => {
  const store = new Map<string, string>();
  vi.stubGlobal('localStorage', {
    getItem: (k: string) => (store.has(k) ? store.get(k)! : null),
    setItem: (k: string, v: string) => void store.set(k, v),
    removeItem: (k: string) => void store.delete(k),
    clear: () => store.clear(),
  });
});
afterEach(() => vi.unstubAllGlobals());

// Minimal local row — only the non-nullable columns.
const localRow = {
  id: 'f1',
  title: 'SQL injection in /login',
  severity: 'critical',
  status: 'open',
  target: 'https://app.example.com',
  description: 'Unparameterized query',
  created_at: '2026-07-29T00:00:00Z',
  updated_at: '2026-07-29T01:00:00Z',
};

describe('toFinding', () => {
  it('renames cvss_score to cvss', () => {
    // The UI reads `cvss`; the local column is `cvss_score`. Getting this wrong
    // shows an empty CVSS column with no error anywhere.
    expect(toFinding({ ...localRow, cvss_score: 9.8 }).cvss).toBe(9.8);
  });

  it('joins cve_ids into the single cve field rather than dropping extras', () => {
    // Local stores a list, the UI shows one string. Taking [0] would silently
    // lose the rest of a multi-CVE finding.
    expect(toFinding({ ...localRow, cve_ids: ['CVE-2024-1', 'CVE-2024-2'] }).cve)
      .toBe('CVE-2024-1, CVE-2024-2');
  });

  it('leaves cve undefined for an empty or absent list', () => {
    expect(toFinding({ ...localRow, cve_ids: [] }).cve).toBeUndefined();
    expect(toFinding(localRow).cve).toBeUndefined();
  });

  it('carries the parity fields through', () => {
    // These are the columns added specifically so local mode keeps calibration
    // and triage metadata. If the adapter drops them the migration was pointless.
    const f = toFinding({
      ...localRow,
      exploitable: 'TRUE',
      original_severity: 'critical',
      calibrated_severity: 'medium',
      calibration_rule: 'Rule 1',
      calibration_justification: 'not internet-reachable',
      tags: ['triaged'],
      jira_ticket: 'SEC-42',
      source_tool: 'semgrep',
    });
    expect(f.exploitable).toBe('TRUE');
    expect(f.original_severity).toBe('critical');
    expect(f.calibrated_severity).toBe('medium');
    expect(f.calibration_rule).toBe('Rule 1');
    expect(f.calibration_justification).toBe('not internet-reachable');
    expect(f.tags).toEqual(['triaged']);
    expect(f.jira_ticket).toBe('SEC-42');
    expect(f.source_tool).toBe('semgrep');
  });

  it('converts SQLite nulls to undefined', () => {
    // Optional TS fields are `?: T`, not `T | null`. Leaking null makes
    // `field ?? fallback` behave but `'field' in obj` and JSON diffs lie.
    const f = toFinding({ ...localRow, evidence: null, cwe: null, tags: null });
    expect(f.evidence).toBeUndefined();
    expect(f.cwe).toBeUndefined();
    expect(f.tags).toBeUndefined();
  });

  it('preserves the required fields verbatim', () => {
    const f = toFinding(localRow);
    expect(f.id).toBe('f1');
    expect(f.severity).toBe('critical');
    expect(f.status).toBe('open');
    expect(f.created_at).toBe('2026-07-29T00:00:00Z');
  });
});

describe('data mode', () => {
  it('defaults to cloud, never local', () => {
    // Critical: every install predating local mode has no stored value.
    // Defaulting to local would repoint them at an empty SQLite DB and their
    // findings would appear deleted.
    expect(getDataMode()).toBe('cloud');
    expect(isLocalMode()).toBe(false);
  });

  it('round-trips an explicit mode', () => {
    setDataMode('local');
    expect(getDataMode()).toBe('local');
    expect(isLocalMode()).toBe(true);
    setDataMode('cloud');
    expect(isLocalMode()).toBe(false);
  });

  it('falls back to cloud after the mode is cleared', () => {
    setDataMode('local');
    clearDataMode();
    expect(getDataMode()).toBe('cloud');
  });

  it('ignores a garbage stored value', () => {
    localStorage.setItem('maestro-data-mode', 'banana');
    expect(getDataMode()).toBe('cloud');
  });

  it('labels the modes for status surfaces', () => {
    expect(dataModeLabel('local')).toBe('Local');
    expect(dataModeLabel('cloud')).toBe('Team');
  });
});

describe('team-only features', () => {
  it('are available in cloud mode', () => {
    setDataMode('cloud');
    expect(isFeatureAvailable('attack-graph')).toBe(true);
    expect(featureUnavailableReason('attack-graph')).toBeNull();
  });

  it('are unavailable in local mode, with a reason to render', () => {
    // The reason exists so the UI can explain itself instead of showing an
    // empty panel that looks like a bug.
    setDataMode('local');
    expect(isFeatureAvailable('attack-graph')).toBe(false);
    expect(featureUnavailableReason('attack-graph')).toMatch(/Postgres|team backend/i);
    expect(featureUnavailableReason('post-exploitation')).toMatch(/team backend/i);
    expect(featureUnavailableReason('scheduled-dast')).toMatch(/team backend/i);
    expect(featureUnavailableReason('user-management')).toMatch(/team backend/i);
  });
});
