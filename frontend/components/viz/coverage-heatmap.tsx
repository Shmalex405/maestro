'use client';

// Coverage Dashboard W3 — coverage heatmap. A category × surface cell grid
// colored by worst severity found in each cell. Rows are the canonical finding
// categories (so categories with no findings render as gaps), cols are the
// surfaces. Finding-density coverage (where issues are), per the W3 design note.
//
// Surface placement: we trust the backend's web/cloud/identity derivation
// (which it gets right from source/target_type, so an exploited cloud workload
// still lands in the Cloud column), but override AI and Code-Security findings
// to their own columns — the backend's coverage_surface_of() has no ai/code
// branch yet, so those would otherwise be mis-bucketed into Web.

import { Fragment } from 'react';
import { severityStyle } from '@/lib/severity';
import { SURFACE_ORDER } from '@/lib/surface';
import type { CoverageCell } from '@/lib/types';

// Canonical categories (match backend category_from_source) + friendly labels.
const CATEGORY_ROWS: { key: string; label: string }[] = [
  { key: 'web_app', label: 'Web / API' },
  { key: 'code_security', label: 'Code security (SAST)' },
  { key: 'cloud', label: 'Cloud (IAM / storage / K8s / serverless)' },
  { key: 'infrastructure', label: 'Infrastructure (network / DNS / TLS)' },
  { key: 'identity', label: 'Identity / IDP' },
  { key: 'ai', label: 'AI / LLM' },
  { key: 'other', label: 'Other' },
];

// Columns = the canonical surface lenses (shared SURFACE_ORDER). Short labels
// keep the dense grid readable at ~92px/column.
const SURFACE_SHORT: Record<string, string> = {
  web: 'Web & API',
  cloud: 'Cloud',
  identity: 'Identity',
  ai: 'AI / LLM',
  code: 'Code',
};
const SURFACE_COLS: { key: string; label: string }[] = SURFACE_ORDER.map((k) => ({
  key: k,
  label: SURFACE_SHORT[k] ?? k,
}));

const SEV_RANK: Record<string, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };

function worseSeverity(a: string | null, b: string | null): string | null {
  if (!a) return b;
  if (!b) return a;
  return (SEV_RANK[a] ?? 0) >= (SEV_RANK[b] ?? 0) ? a : b;
}

// Which heatmap column a backend cell belongs in. AI / Code findings carry the
// right `category` but a stale `surface` (backend defaults them to "web"), so
// re-route them here; everything else trusts the backend's surface.
function columnKeyOf(cell: CoverageCell): string {
  if (cell.category === 'ai') return 'ai';
  if (cell.category === 'code_security') return 'code';
  if (cell.category === 'cloud') return 'cloud';
  if (cell.category === 'identity') return 'identity';
  return cell.surface;
}

interface MergedCell {
  count: number;
  worst: string | null;
}

function HeatCell({
  cell,
  category,
  surface,
}: {
  cell?: MergedCell;
  category: string;
  surface: string;
}) {
  if (!cell || cell.count === 0) {
    return (
      <div
        className="m-0.5 flex h-9 items-center justify-center rounded border border-border/30 bg-muted/20 text-[10px] text-muted-foreground/40"
        title={`${category} · ${surface}: no findings`}
      >
        —
      </div>
    );
  }
  const hex = cell.worst ? severityStyle(cell.worst).hex : '#475569';
  return (
    <div
      className="m-0.5 flex h-9 items-center justify-center rounded border text-xs font-semibold"
      style={{ backgroundColor: `${hex}26`, borderColor: `${hex}80`, color: hex }}
      title={`${category} · ${surface}: ${cell.count} finding${cell.count === 1 ? '' : 's'}${
        cell.worst ? ` · worst: ${cell.worst}` : ''
      }`}
    >
      {cell.count}
    </div>
  );
}

export function CoverageHeatmap({ cells }: { cells: CoverageCell[] }) {
  // Re-aggregate by (category, derived-surface) — the override can collapse two
  // backend rows into one cell, so sum counts and keep the worst severity.
  const byKey = new Map<string, MergedCell>();
  for (const c of cells) {
    const key = `${c.category}:${columnKeyOf(c)}`;
    const prev = byKey.get(key);
    byKey.set(key, {
      count: (prev?.count ?? 0) + c.count,
      worst: worseSeverity(prev?.worst ?? null, c.worst_severity ?? null),
    });
  }

  return (
    <div className="overflow-x-auto">
      <div
        className="inline-grid"
        style={{
          gridTemplateColumns: `minmax(200px, 1fr) repeat(${SURFACE_COLS.length}, 92px)`,
        }}
      >
        {/* Header row */}
        <div className="px-2 py-1.5" />
        {SURFACE_COLS.map((s) => (
          <div
            key={s.key}
            className="px-2 py-1.5 text-center text-[11px] font-medium text-muted-foreground"
          >
            {s.label}
          </div>
        ))}

        {/* Body */}
        {CATEGORY_ROWS.map((row) => (
          <Fragment key={row.key}>
            <div
              className="truncate border-t border-border/30 px-2 py-2 text-xs text-foreground/80"
              title={row.label}
            >
              {row.label}
            </div>
            {SURFACE_COLS.map((col) => (
              <HeatCell
                key={col.key}
                cell={byKey.get(`${row.key}:${col.key}`)}
                category={row.label}
                surface={col.label}
              />
            ))}
          </Fragment>
        ))}
      </div>
    </div>
  );
}
