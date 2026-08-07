// =============================================================================
// SURFACE — the shared "surface" lens over the single findings store.
//
// Per docs/ui-coverage-dashboard-plan.md §1.1, a surface is a LENS derived from
// a finding's `source` + its target's `target_type`, NOT a separate data silo:
//   - web/API   — recon / web-app / api / vuln-scan / exploitation sources
//   - cloud     — cloud-* sources PLUS the network/DNS/TLS infrastructure layer
//                 (one "Cloud / Infra" tile; see SURFACE_CATEGORIES below)
//   - identity  — identity-* sources (future; no data yet)
//
// The Coverage Dashboard's surface filter and the surface-health strip share
// this derivation. Until a first-class `surface` column lands server-side, the
// dashboard approximates per-surface counts from the existing /findings/stats
// `by_category` rollup via SURFACE_CATEGORIES below.
// =============================================================================

import type { FindingCategory } from './types';
import type { Surface } from './stores/dashboard-filter-store';

/**
 * Which finding categories roll up into each surface. `web` covers the
 * application testing category; `cloud` is the "Cloud / Infra" surface — cloud
 * config findings PLUS the network/DNS/TLS `infrastructure` category. They
 * share one tile so infrastructure findings aren't orphaned: when `cloud` was
 * split out into its own first-class category (commit 12721c84), no surface
 * owned `infrastructure` anymore, so it vanished from the Coverage strip.
 * Folding it back under cloud keeps it visible. The Findings page still keeps
 * Cloud and Infrastructure as separate filter tabs (a finer lens).
 *
 * Note: a finding can appear under more than one surface lens (e.g. an
 * exploited cloud finding), which mirrors the "lens, not partition" model in
 * findings/page.tsx. For the surface-health tiles we keep the mapping
 * disjoint-enough to give meaningful per-surface counts without double
 * counting the big buckets.
 */
export const SURFACE_CATEGORIES: Record<Exclude<Surface, 'all'>, FindingCategory[]> = {
  web: ['web_app'],
  cloud: ['cloud', 'infrastructure'],
  identity: ['identity'],
  code: ['code_security'],
  ai: ['ai'],
};

/**
 * The surfaces rendered as health tiles / heatmap columns, in display order.
 * Excludes the 'all' lens. Single source of truth so the dashboard strip, the
 * coverage heatmap, and any per-surface loop stay in lockstep — add a surface
 * here and it shows up everywhere.
 */
export const SURFACE_ORDER: Exclude<Surface, 'all'>[] = [
  'web',
  'cloud',
  'identity',
  'ai',
  'code',
];

/** Human label for a surface. */
export const SURFACE_LABELS: Record<Surface, string> = {
  all: 'All surfaces',
  web: 'Web & API',
  cloud: 'Cloud / Infra',
  identity: 'Identity / IDP',
  code: 'Code Security',
  ai: 'AI / LLM',
};

/** Sum a `by_category` rollup down to a single surface's finding count. */
export function surfaceCount(
  byCategory: Partial<Record<FindingCategory, number>> | undefined,
  surface: Exclude<Surface, 'all'>,
): number {
  if (!byCategory) return 0;
  return SURFACE_CATEGORIES[surface].reduce((acc, cat) => acc + (byCategory[cat] || 0), 0);
}

/**
 * The backend `category` query param for a surface lens — the comma-separated
 * union of the surface's categories (the backend's `category_clause` unions
 * their source-pattern sets). Returns `undefined` for the 'all' lens (no
 * filter). Used by every surface-scoped query (donut / table / board) so a
 * multi-category surface like Cloud / Infra filters to the same set its tile
 * counts.
 */
export function surfaceCategoryParam(surface: Surface): string | undefined {
  if (surface === 'all') return undefined;
  const cats = SURFACE_CATEGORIES[surface];
  return cats && cats.length > 0 ? cats.join(',') : undefined;
}
