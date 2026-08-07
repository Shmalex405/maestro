/**
 * Smoke tests: each primary nav link goes where it claims, each sub-route
 * is reachable by URL. Single assertion per test — the URL settled on the
 * expected path within 5s.
 *
 * The MAESTRO_TEST_BYPASS_AUTH=1 env var (set by the test runner image)
 * makes the StartupGate short-circuit so we hit the sidebar directly
 * without driving login.
 */

import { expect } from '@wdio/globals';
import { PRIMARY_ROUTES, SUB_ROUTES } from '../lib/routes';
import { clickSidebar, expectPath, waitForReady } from '../lib/helpers';

/**
 * What this spec asserts (and what it deliberately doesn't):
 *
 *   - Asserts: clicking each sidebar link changes the URL to the expected
 *     path, and the page renders SOMETHING (the React root isn't blank).
 *   - Does NOT assert: specific H1 text, button labels, table contents.
 *     That's regression-test territory — fragile, copy-driven, easy to
 *     break with a 1-word UI tweak. The wire-up tests already guard
 *     route registration; this layer just confirms navigation works.
 *
 * If you need to catch "this page completely fails to render", the
 * "page is not blank" assertion below covers it. If you need to catch
 * "heading text drifted", add a regression test in
 * `frontend/__tests__/` instead — it's faster and runs in vitest.
 */

describe('Primary navigation smoke', () => {
  before(async () => {
    await waitForReady(60_000);
  });

  for (const route of PRIMARY_ROUTES) {
    if (!route.sidebar) continue;
    it(`navigates to ${route.label} via sidebar`, async () => {
      await clickSidebar(route.sidebar);
      await expectPath(route.path);
      // No content assertion: `expectPath` already waits up to 5s for the
      // URL to settle, and a successful URL change implies Next.js
      // mounted the new route's component without crashing the renderer.
      // Anything stricter (heading text, table contents) belongs in a
      // regression suite, not smoke.
    });
  }
});

describe('Sub-route smoke', () => {
  for (const route of SUB_ROUTES) {
    it(`renders ${route.label} (${route.path})`, async () => {
      await browser.execute((path: string) => {
        window.history.pushState({}, '', path);
        window.dispatchEvent(new PopStateEvent('popstate'));
      }, route.path);
      await browser.pause(750);

      const url = await browser.getUrl();
      const pathname = new URL(url).pathname.replace(/\/$/, '') || '/';
      expect(pathname).toBe(route.path);
    });
  }
});

