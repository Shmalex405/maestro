/**
 * Shared WebdriverIO helpers for the desktop e2e suite.
 *
 * Most page-objects build on `waitForReady` (waits until the app's React
 * root has mounted) and `clickSidebar` (drives the sidebar nav). Keep this
 * file small — the POMs in `pages/` are where route-specific selectors
 * live.
 */

/**
 * Resolves once the desktop binary has loaded the React app shell. We can't
 * just wait for `document.body` because Next.js hydrates lazily, so we wait
 * for the sidebar — which only renders after the startup gate releases.
 */
export async function waitForReady(timeoutMs = 30_000) {
  const sidebar = await $('nav');
  await sidebar.waitForExist({ timeout: timeoutMs });
}

/**
 * Click a sidebar link by visible name. The Sidebar component renders each
 * entry as an `<a>` with the name as its inner text. We use XPath because
 * WebdriverIO's `nav a*=Name` shorthand isn't translated server-side —
 * WebKitWebDriver receives the raw string and rejects it as invalid.
 */
export async function clickSidebar(name: string) {
  const link = await $(`//nav//a[contains(normalize-space(.), "${name}")]`);
  await link.waitForClickable({ timeout: 10_000 });
  await link.click();
}

/**
 * Wait until the current URL's pathname matches `expected`, then assert.
 * Replaces the older synchronous `expectPath` — Next.js router navigation
 * is async, and asserting too early surfaces stale URLs from the
 * previous route.
 */
export async function expectPath(expected: string, timeoutMs = 5_000) {
  let last = '';
  await browser
    .waitUntil(
      async () => {
        const url = await browser.getUrl();
        last = new URL(url).pathname.replace(/\/$/, '') || '/';
        return last === expected;
      },
      {
        timeout: timeoutMs,
        interval: 100,
        timeoutMsg: `URL never became ${expected} (last seen: ${last})`,
      },
    )
    .catch((err) => {
      throw err;
    });
}

/**
 * Read the visible text of the first `<h1>` on the page. Used by smoke
 * tests to confirm the page rendered its top-level header.
 */
export async function pageHeading(): Promise<string> {
  const h = await $('h1');
  return (await h.getText()).trim();
}
