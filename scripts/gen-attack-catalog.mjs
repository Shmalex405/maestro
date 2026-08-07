#!/usr/bin/env node
// Generate the attack-catalog artifacts from config/test-matrix.yml:
//   1. frontend/lib/attack-catalog.ts        — typed snapshot (kept as a stable
//                                               artifact; no longer rendered in
//                                               the product UI)
//   2. docs/user-guide/scheduled-dast/attack-catalog.md — the read-only
//                                               reference shown under Docs
//                                               (the Attack Library moved here)
//
// Re-run whenever test-matrix.yml changes to keep both in sync:
//
//   node scripts/gen-attack-catalog.mjs   (run from repo root)
//
// The pipeline still validates against the real matrix — this is display data.

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
// js-yaml lives in frontend/ (and mcp-server/) node_modules, not at repo root —
// resolve it from there so the script runs from any cwd.
const require = createRequire(path.join(root, 'frontend', 'package.json'));
const yaml = require('js-yaml');
const matrixPath = path.join(root, 'config', 'test-matrix.yml');
const outPath = path.join(root, 'frontend', 'lib', 'attack-catalog.ts');
const docPath = path.join(root, 'docs', 'user-guide', 'scheduled-dast', 'attack-catalog.md');

const doc = yaml.load(fs.readFileSync(matrixPath, 'utf-8'));

// Phase = top-level key (dast, sast, cross_validation, chain_analysis, cloud, identity).
// Walk each phase's tree collecting every node with a test_id.
const PHASE_LABELS = {
  dast: 'Web & API (DAST)',
  sast: 'Code (SAST)',
  cross_validation: 'Cross-Validation',
  chain_analysis: 'Chain Analysis',
  cloud: 'Cloud',
  identity: 'Identity / IDP',
  ai: 'AI / LLM',
};

const entries = [];
function walk(node, phase) {
  if (!node || typeof node !== 'object') return;
  if (Array.isArray(node)) {
    for (const n of node) walk(n, phase);
    return;
  }
  if (typeof node.test_id === 'string') {
    entries.push({
      id: node.test_id,
      name: node.name ?? node.test_id,
      // Category = the test_id prefix (RECON-01 -> RECON), matches the manifest.
      category: String(node.test_id).split('-')[0],
      phase,
      tool: node.tool ?? null,
      description: node.description ?? '',
      applies_when: node.applies_when ?? null,
    });
    return;
  }
  for (const v of Object.values(node)) walk(v, phase);
}

for (const [phase, sub] of Object.entries(doc ?? {})) {
  walk(sub, phase);
}
entries.sort((a, b) => a.id.localeCompare(b.id, undefined, { numeric: true }));

const header = `// AUTO-GENERATED from config/test-matrix.yml by scripts/gen-attack-catalog.mjs.
// Do NOT edit by hand — re-run the generator. ${entries.length} attacks.

export interface AttackCatalogEntry {
  id: string;
  name: string;
  /** test_id prefix, e.g. RECON / INJ / GQL. */
  category: string;
  /** top-level phase: dast | sast | cross_validation | chain_analysis | cloud | identity | ai. */
  phase: string;
  /** MCP tool that backs the attack (null if orchestrated). */
  tool: string | null;
  description: string;
  /** Scope gate from the matrix (null = always-on). */
  applies_when: string | null;
}

export const PHASE_LABELS: Record<string, string> = ${JSON.stringify(PHASE_LABELS, null, 2)};

export const ATTACK_CATALOG: AttackCatalogEntry[] = ${JSON.stringify(entries, null, 2)};

/** Distinct categories in catalog order (first-seen). */
export const ATTACK_CATEGORIES: string[] = Array.from(new Set(ATTACK_CATALOG.map((a) => a.category)));
`;

fs.writeFileSync(outPath, header);
console.log(`Wrote ${entries.length} attacks → ${path.relative(root, outPath)}`);

// ---------------------------------------------------------------------------
// Markdown reference (Docs → Scheduled DAST → Attack catalog).
// Grouped by phase, then a table per category, so the 234 read as a browsable
// reference rather than a flat dump. AUTO-GENERATED — see the doc header.
// ---------------------------------------------------------------------------
const esc = (s) => String(s ?? '').replace(/\|/g, '\\|').replace(/\n+/g, ' ').trim();
const phaseOrder = Object.keys(PHASE_LABELS);
const byPhase = new Map();
for (const e of entries) {
  if (!byPhase.has(e.phase)) byPhase.set(e.phase, []);
  byPhase.get(e.phase).push(e);
}
// Stable phase ordering: known phases first (in PHASE_LABELS order), then any extras.
const orderedPhases = [
  ...phaseOrder.filter((p) => byPhase.has(p)),
  ...[...byPhase.keys()].filter((p) => !phaseOrder.includes(p)),
];

const phaseCounts = orderedPhases
  .map((p) => `**${PHASE_LABELS[p] ?? p}** ${byPhase.get(p).length}`)
  .join(' · ');

let md = `# Attack catalog

> [!NOTE] Auto-generated — do not edit by hand
> This page is generated from \`config/test-matrix.yml\` by \`scripts/gen-attack-catalog.mjs\`. It is a reference, not a control surface — you select what runs via **scan policies** when you schedule or run a scan.

The deterministic DAST engine knows **${entries.length} attack techniques** across ${orderedPhases.length} surfaces. Each row below is a *technique*, not a single request — at run time one technique fans out into hundreds-to-thousands of real HTTP requests as its backing tool sweeps every discovered parameter and payload. A typical web scan fires **~5,500 requests**; see the per-scan **Statistics** view for the exact count your scan executed.

> [!TIP] Techniques vs. requests
> Counting techniques (234) and counting requests-sent (thousands) are different units. The number that matters for "how much did this scan actually attack my app" is the per-scan **attacks executed** stat, not this catalog's length.

**By surface:** ${phaseCounts}

`;

for (const phase of orderedPhases) {
  const rows = byPhase.get(phase);
  md += `## ${PHASE_LABELS[phase] ?? phase}\n\n`;
  // Group by category within the phase.
  const cats = new Map();
  for (const e of rows) {
    if (!cats.has(e.category)) cats.set(e.category, []);
    cats.get(e.category).push(e);
  }
  for (const [cat, items] of cats) {
    md += `### ${cat}\n\n`;
    md += `| ID | Attack | Backing tool | Applies when |\n`;
    md += `|---|---|---|---|\n`;
    for (const e of items) {
      const tool = e.tool ? `\`${esc(e.tool)}\`` : 'orchestrated';
      const when = e.applies_when ? esc(e.applies_when) : 'Always';
      md += `| ${esc(e.id)} | **${esc(e.name)}** — ${esc(e.description)} | ${tool} | ${when} |\n`;
    }
    md += `\n`;
  }
}

fs.mkdirSync(path.dirname(docPath), { recursive: true });
fs.writeFileSync(docPath, md);
console.log(`Wrote ${entries.length} attacks → ${path.relative(root, docPath)}`);
