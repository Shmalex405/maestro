/**
 * Frontend ↔ Tauri bridge wiring test.
 *
 * The frontend calls Rust commands via `invoke<T>('<name>', args)`. Each
 * `<name>` must exist in the Rust `invoke_handler!` macro in `main.rs` —
 * otherwise the user gets a "command not found" runtime error.
 *
 * This test:
 *   1. Walks `lib/` and `components/` and extracts every `invoke<...>(name, ...)`
 *      call site.
 *   2. Parses `src-tauri/src/main.rs` and extracts the leaf names from
 *      `generate_handler![...]`.
 *   3. Asserts the frontend never invokes a name that isn't registered.
 *
 * Catches the class of bug where a Tauri command is renamed/removed but
 * the frontend still calls the old name, or where a new feature wires up
 * the frontend before the Rust side.
 */

import { describe, expect, it } from 'vitest';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';

const REPO_ROOT = path.resolve(__dirname, '../..');
const TAURI_MAIN = path.join(REPO_ROOT, 'src-tauri/src/main.rs');

function walkSrcDirs(roots: string[]): string[] {
  const out: string[] = [];
  function recurse(dir: string) {
    let entries: string[];
    try { entries = readdirSync(dir); } catch { return; }
    for (const name of entries) {
      if (name === 'node_modules' || name === '.next' || name === 'src-tauri') continue;
      const p = path.join(dir, name);
      let stat;
      try { stat = statSync(p); } catch { continue; }
      if (stat.isDirectory()) recurse(p);
      else if (/\.(ts|tsx)$/.test(name) && !/\.test\.tsx?$/.test(name)) {
        out.push(p);
      }
    }
  }
  for (const root of roots) recurse(root);
  return out;
}

/**
 * Extract every `invoke...(<name>, ...)` call site. We're tolerant of the
 * type parameter and arg shape — we only care about the literal name.
 * Accepts both single and double-quoted names.
 */
function extractInvokeTargets(source: string): string[] {
  // Match `invoke` followed by optional `<...>`, then `(`, then a string literal.
  // We anchor on the dot or word boundary to avoid matching `myInvoke(`.
  const re = /\binvoke\s*(?:<[^>]+>)?\s*\(\s*['"]([a-zA-Z0-9_]+)['"]/g;
  const out: string[] = [];
  for (const match of source.matchAll(re)) {
    out.push(match[1]);
  }
  return out;
}

/**
 * Parse `src-tauri/src/main.rs` and return the leaf names inside the
 * `generate_handler![...]` block (e.g. `commands::system::get_system_status`
 * → `get_system_status`).
 */
function registeredCommands(mainRs: string): Set<string> {
  const startIdx = mainRs.indexOf('generate_handler!');
  if (startIdx < 0) throw new Error('generate_handler! block not found in main.rs');
  const bracketOpen = mainRs.indexOf('[', startIdx);
  const bracketClose = mainRs.indexOf(']', bracketOpen);
  const body = mainRs.slice(bracketOpen + 1, bracketClose);

  // Strip line comments line-by-line so commas inside comments don't split entries.
  const cleaned = body
    .split('\n')
    .map(l => l.split('//')[0].trim())
    .filter(Boolean)
    .join(' ');

  const out = new Set<string>();
  for (const raw of cleaned.split(',')) {
    const trimmed = raw.trim();
    if (!trimmed) continue;
    const leaf = trimmed.split('::').pop()!.trim();
    if (leaf) out.add(leaf);
  }
  return out;
}

/**
 * Known-broken wrappers. Empty after the 2026-05-15 cleanup that deleted
 * all 35 dead wrappers from `lib/tauri-api.ts`. If you add a new
 * `invoke('<name>')` call before the Rust handler is ready, list the name
 * here (and remove it once the handler ships) — otherwise this test fails
 * the build and protects everyone else from a "command not found" runtime
 * crash on the desktop.
 *
 * To clear an entry: either implement the Rust handler and register it in
 * `src-tauri/src/main.rs`, OR delete the wrapper from `lib/tauri-api.ts`.
 */
const KNOWN_DEAD_WRAPPERS = new Set<string>([]);

describe('frontend ↔ Tauri bridge', () => {
  const mainRsSource = readFileSync(TAURI_MAIN, 'utf-8');
  const registered = registeredCommands(mainRsSource);

  it('main.rs invoke_handler! block parses to a non-empty set', () => {
    expect(registered.size).toBeGreaterThan(50);
  });

  it('every invoke() call in the frontend targets a registered Tauri command', () => {
    const sources = walkSrcDirs([
      path.join(REPO_ROOT, 'lib'),
      path.join(REPO_ROOT, 'components'),
      path.join(REPO_ROOT, 'app'),
      path.join(REPO_ROOT, 'hooks'),
    ]);

    type Call = { name: string; file: string };
    const calls: Call[] = [];
    for (const file of sources) {
      const text = readFileSync(file, 'utf-8');
      for (const name of extractInvokeTargets(text)) {
        calls.push({ name, file: path.relative(REPO_ROOT, file) });
      }
    }
    expect(calls.length).toBeGreaterThan(20);

    const missing: Call[] = [];
    const seen = new Set<string>();
    for (const c of calls) {
      if (KNOWN_DEAD_WRAPPERS.has(c.name)) continue;
      const key = c.name + '|' + c.file;
      if (seen.has(key)) continue;
      seen.add(key);
      if (!registered.has(c.name)) missing.push(c);
    }
    if (missing.length) {
      const lines = missing.map(m => `  - ${m.name}  (called from ${m.file})`);
      throw new Error(
        `Frontend calls Tauri commands that aren't registered in invoke_handler!:\n${lines.join('\n')}`
      );
    }
  });

  it('every command in `KNOWN_DEAD_WRAPPERS` is still actually missing', () => {
    // Keeps the allowlist honest: if someone implements one of the missing
    // commands, the allowlist entry must be removed so we don't permanently
    // mute that name.
    const stale: string[] = [];
    for (const name of KNOWN_DEAD_WRAPPERS) {
      if (registered.has(name)) stale.push(name);
    }
    if (stale.length) {
      throw new Error(
        `KNOWN_DEAD_WRAPPERS entries are now registered (remove them from the allowlist):\n${stale.map(n => '  - ' + n).join('\n')}`
      );
    }
  });
});
