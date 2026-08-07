// Static manifest of the assessment test matrix, by category.
//
// Derived from config/test-matrix.yml (the authoritative source). The desktop app
// is cloud-backed and does not ship that YAML, so this manifest carries just the
// per-category shape the Execution Overview needs to explain coverage: how many
// tests a category has, and which scope dimension it REQUIRES. That lets the UI
// distinguish "ran and passed" from "never ran because that scope dimension was
// off" (e.g. 29 cloud tests excluded because no cloud account was in scope).
//
// Counts track config/test-matrix.yml (dast 73, sast 24, cross_validation 15,
// chain_analysis 8, cloud 29, identity 60 = 209 leaf tests). If the matrix grows,
// update the counts here — they are summary denominators, not load-bearing.

import type { Assessment, ExecutionTestResult, TestOutcome } from './types';

export type ScopeDimension = 'cloud' | 'identity' | 'repo' | null;

export interface TestCategory {
  key: string;
  label: string;
  /** test_id prefixes belonging to this category (the part before the first '-'). */
  prefixes: string[];
  /** Number of tests in config/test-matrix.yml for this category. */
  count: number;
  /** The scope dimension this category needs; null = always applicable. */
  requiresScope: ScopeDimension;
  /** Human reason shown when the whole category was excluded (never recorded). */
  excludedReason: string;
}

export const TEST_MATRIX_CATEGORIES: TestCategory[] = [
  {
    key: 'dast',
    label: 'Web & API (DAST)',
    prefixes: ['RECON', 'TLS', 'AUTH', 'AUTHZ', 'HDR', 'CORS', 'INJ', 'SSRF', 'GQL', 'API', 'CLI', 'VSCAN', 'UPLOAD', 'BIZ', 'PROTO', 'DESER'],
    count: 73,
    requiresScope: null,
    excludedReason: 'No live web/API target was reachable',
  },
  {
    key: 'sast',
    label: 'Static Analysis (SAST)',
    prefixes: ['SAST'],
    count: 24,
    requiresScope: 'repo',
    excludedReason: 'No repository was provided to scan',
  },
  {
    key: 'cross_validation',
    label: 'Cross-Validation',
    prefixes: ['XVAL'],
    count: 15,
    requiresScope: 'repo',
    excludedReason: 'No repository was provided (cross-validation correlates SAST findings against live endpoints)',
  },
  {
    key: 'chain_analysis',
    label: 'Attack Chains',
    prefixes: ['CHAIN'],
    count: 8,
    requiresScope: null,
    excludedReason: 'No findings were available to chain',
  },
  {
    key: 'cloud',
    label: 'Cloud',
    prefixes: ['CLOUD'],
    count: 29,
    requiresScope: 'cloud',
    excludedReason: 'No cloud account or Kubernetes cluster was in scope',
  },
  {
    key: 'identity',
    label: 'Identity / IdP',
    prefixes: ['IDENTITY'],
    count: 60,
    requiresScope: 'identity',
    excludedReason: 'No identity target (AD / Entra / M365 / Okta / Google / Ping) was in scope',
  },
];

export const TOTAL_MATRIX_TESTS = TEST_MATRIX_CATEGORIES.reduce((n, c) => n + c.count, 0);

const PREFIX_TO_CATEGORY = new Map<string, TestCategory>();
for (const cat of TEST_MATRIX_CATEGORIES) {
  for (const p of cat.prefixes) PREFIX_TO_CATEGORY.set(p, cat);
}

/** Map a test_id (e.g. "CLOUD-06", "SAST-SC-01") to its category. */
export function categoryForTestId(testId: string): TestCategory | null {
  const prefix = testId.split('-')[0];
  return PREFIX_TO_CATEGORY.get(prefix) ?? null;
}

export interface CategoryCoverage {
  key: string;
  label: string;
  matrixCount: number;
  recorded: number;
  ran: number; // PASS + FAIL — actually executed
  pass: number;
  fail: number;
  n_a: number;
  blocked: number;
  skipped: number;
  /** Tests had recorded results → the category was actually assessed. */
  assessed: boolean;
  /** Scope-gated category with zero recorded results → deliberately not run. */
  excluded: boolean;
  excludedReason: string | null;
}

export interface CoverageBreakdown {
  categories: CategoryCoverage[];
  excludedCategories: CategoryCoverage[];
  totals: {
    matrixTotal: number;
    recordedTotal: number;
    ran: number;
    n_a: number;
    blocked: number;
    skipped: number;
    excludedByScope: number; // sum of matrixCount across excluded categories
  };
  /** True once any per-test results exist (Option-B promotion happened). */
  hasData: boolean;
}

/**
 * Bucket recorded per-test results by category, and flag scope-gated categories
 * with zero recorded results as "excluded" (with the reason). For `repo`-gated
 * categories, the assessment's repo_paths refines exclusion-vs-gap.
 */
export function computeCoverage(
  testResults: ExecutionTestResult[],
  assessment: Assessment | null,
): CoverageBreakdown {
  const hasRepo = !!(assessment?.repo_paths && assessment.repo_paths.length > 0);

  const byCat = new Map<string, ExecutionTestResult[]>();
  for (const t of testResults) {
    const cat = categoryForTestId(t.test_id);
    const key = cat?.key ?? '_uncategorized';
    if (!byCat.has(key)) byCat.set(key, []);
    byCat.get(key)!.push(t);
  }

  const tally = (rows: ExecutionTestResult[]) => {
    const c = { pass: 0, fail: 0, n_a: 0, blocked: 0, skipped: 0 };
    for (const r of rows) {
      const s = r.status as TestOutcome | 'SKIPPED';
      if (s === 'PASS') c.pass++;
      else if (s === 'FAIL') c.fail++;
      else if (s === 'N_A') c.n_a++;
      else if (s === 'BLOCKED') c.blocked++;
      else if (s === 'SKIPPED') c.skipped++;
    }
    return c;
  };

  const categories: CategoryCoverage[] = TEST_MATRIX_CATEGORIES.map((cat) => {
    const rows = byCat.get(cat.key) ?? [];
    const c = tally(rows);
    const recorded = rows.length;
    const assessed = recorded > 0;

    // Excluded = scope-gated category that produced no results. For repo-gated
    // categories, only call it "excluded" when no repo was provided at all;
    // a provided repo with no results is a gap, not a scope exclusion.
    let excluded = false;
    if (!assessed && cat.requiresScope) {
      if (cat.requiresScope === 'repo') excluded = !hasRepo;
      else excluded = true;
    }

    return {
      key: cat.key,
      label: cat.label,
      matrixCount: cat.count,
      recorded,
      ran: c.pass + c.fail,
      pass: c.pass,
      fail: c.fail,
      n_a: c.n_a,
      blocked: c.blocked,
      skipped: c.skipped,
      assessed,
      excluded,
      excludedReason: excluded ? cat.excludedReason : null,
    };
  });

  const excludedCategories = categories.filter((c) => c.excluded);
  const totals = {
    matrixTotal: TOTAL_MATRIX_TESTS,
    recordedTotal: categories.reduce((n, c) => n + c.recorded, 0),
    ran: categories.reduce((n, c) => n + c.ran, 0),
    n_a: categories.reduce((n, c) => n + c.n_a, 0),
    blocked: categories.reduce((n, c) => n + c.blocked, 0),
    skipped: categories.reduce((n, c) => n + c.skipped, 0),
    excludedByScope: excludedCategories.reduce((n, c) => n + c.matrixCount, 0),
  };

  return {
    categories,
    excludedCategories,
    totals,
    hasData: testResults.length > 0,
  };
}
