/**
 * Tests for the deterministic provenance gate — the "teeth" of P1.
 *
 * gateTestResults is a pure function, so these assert the enforcement rules
 * directly without any container, DB, or network.
 */

import { gateTestResults, GateInputs } from '../../src/logging/provenance-gate';

// RECON-01 → scan_ports (nmap); SAST-01 → scan_semgrep (semgrep);
// TOK-01 → analyze_jwt (pure-API, no binary). Mirrors test-matrix.yml mappings.
const toolMap = {
  'RECON-01': 'scan_ports',
  'SAST-01': 'scan_semgrep',
  'TOK-01': 'analyze_jwt',
};

function inputs(over: Partial<GateInputs> = {}): GateInputs {
  return {
    toolMap,
    availability: [
      { binary: 'nmap', installed: true, version: 'Nmap 7.94' },
      { binary: 'semgrep', installed: true, version: '1.0' },
    ],
    execSummary: [
      { tool_name: 'scan_ports', run_count: 2, ok_count: 2, fail_count: 0, last_exit_code: 0 },
      { tool_name: 'scan_semgrep', run_count: 1, ok_count: 1, fail_count: 0, last_exit_code: 0 },
    ],
    ...over,
  };
}

describe('gateTestResults', () => {
  it('leaves PASS untouched when the tool ran and the binary is present', () => {
    const [r] = gateTestResults([{ test_id: 'RECON-01', status: 'PASS' }], inputs());
    expect(r.enforced_status).toBe('PASS');
    expect(r.changed).toBe(false);
  });

  it('forces PASS → BLOCKED when the backing binary is absent', () => {
    const [r] = gateTestResults(
      [{ test_id: 'RECON-01', status: 'PASS' }],
      inputs({ availability: [{ binary: 'nmap', installed: false, version: null }] })
    );
    expect(r.enforced_status).toBe('BLOCKED');
    expect(r.changed).toBe(true);
    expect(r.reason).toMatch(/nmap.*not present/);
  });

  it('forces N_A → BLOCKED when the backing binary is absent', () => {
    const [r] = gateTestResults(
      [{ test_id: 'RECON-01', status: 'N_A' }],
      inputs({ availability: [{ binary: 'nmap', installed: false, version: null }] })
    );
    expect(r.enforced_status).toBe('BLOCKED');
  });

  it('WARNS (does not block) when the tool ran but never exited 0 — exit codes are unreliable', () => {
    const [r] = gateTestResults(
      [{ test_id: 'RECON-01', status: 'PASS' }],
      inputs({
        execSummary: [
          { tool_name: 'scan_ports', run_count: 3, ok_count: 0, fail_count: 3, last_exit_code: 1 },
        ],
      })
    );
    expect(r.enforced_status).toBe('PASS'); // NOT blocked — whatweb/fuzzers exit non-zero benignly
    expect(r.changed).toBe(false);
    expect(r.warning).toMatch(/never exited 0/);
  });

  it('forces PASS → BLOCKED when a scanner-backed tool was never invoked', () => {
    const [r] = gateTestResults(
      [{ test_id: 'RECON-01', status: 'PASS' }],
      inputs({ execSummary: [] })
    );
    expect(r.enforced_status).toBe('BLOCKED');
    expect(r.reason).toMatch(/never invoked/);
  });

  it('does NOT touch pure-API tools with no known binary', () => {
    const [r] = gateTestResults(
      [{ test_id: 'TOK-01', status: 'PASS' }],
      inputs({ execSummary: [] })
    );
    expect(r.enforced_status).toBe('PASS');
    expect(r.changed).toBe(false);
  });

  it('never downgrades an existing FAIL', () => {
    const [r] = gateTestResults(
      [{ test_id: 'RECON-01', status: 'FAIL' }],
      inputs({ availability: [{ binary: 'nmap', installed: false, version: null }] })
    );
    expect(r.enforced_status).toBe('FAIL');
    expect(r.changed).toBe(false);
  });

  it('leaves tests with no matrix mapping untouched', () => {
    const [r] = gateTestResults([{ test_id: 'UNKNOWN-99', status: 'PASS' }], inputs());
    expect(r.enforced_status).toBe('PASS');
    expect(r.tool).toBeNull();
  });
});
