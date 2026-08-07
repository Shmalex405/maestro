// Server component that pre-declares which doc slugs Next.js should emit at
// build time. Required because tauri.conf.json's frontendDist uses Next's
// static export (`output: export`), which can't resolve params at runtime —
// the build needs the full set up front.
//
// We walk `docs/user-guide/` recursively, the same source of truth the Tauri
// `include_dir!` bundles into the binary. A top-level file becomes a
// single-segment slug (`getting-started`); a file in a subfolder becomes a
// multi-segment slug (`cloud-accounts/aws`). Adding a new markdown file —
// nested or not — gets a route on the next build with no other code change.

import { promises as fs } from 'fs';
import path from 'path';
import { DocViewer } from './doc-viewer';

// process.cwd() during `next build` is `frontend/`. The user-guide lives one
// level up under `docs/user-guide/`.
const DOCS_DIR = path.join(process.cwd(), '..', 'docs', 'user-guide');

async function walkSlugs(dir: string, prefix: string[] = []): Promise<string[][]> {
  const out: string[][] = [];
  const entries = await fs.readdir(dir, { withFileTypes: true });
  for (const entry of entries) {
    if (entry.isDirectory()) {
      out.push(...(await walkSlugs(path.join(dir, entry.name), [...prefix, entry.name])));
    } else if (entry.name.endsWith('.md')) {
      out.push([...prefix, entry.name.replace(/\.md$/, '')]);
    }
  }
  return out;
}

export async function generateStaticParams() {
  try {
    const slugs = await walkSlugs(DOCS_DIR);
    return slugs.map((slug) => ({ slug }));
  } catch {
    // Defensive: if the docs directory isn't reachable from the build
    // context (shouldn't happen in CI), at least emit the known top-level
    // set so the routes exist.
    return [
      { slug: ['architecture'] },
      { slug: ['projects-and-assessments'] },
      { slug: ['getting-started', 'overview'] },
      { slug: ['cloud-accounts', 'overview'] },
      { slug: ['code-repos-and-imports', 'overview'] },
    ];
  }
}

export default async function DocPage({ params }: { params: Promise<{ slug: string[] }> }) {
  const { slug } = await params;
  // Catch-all params arrive as an array; the loader keys on a `/`-joined slug.
  return <DocViewer slug={slug.join('/')} />;
}
