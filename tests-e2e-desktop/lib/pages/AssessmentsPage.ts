/**
 * Page object for `/assessments` (list) and `/assessments/new` (wizard).
 *
 * Captures the selectors and actions the smoke + flow tests need. Keep it
 * narrow — only add a selector here once a test actually references it.
 */

import { clickSidebar, waitForReady } from '../helpers';

/**
 * All selectors below use XPath rather than WebdriverIO's `*=` shorthand.
 * The shorthand is only translated for bare element queries — `nav a*=Foo`
 * and `button*=Foo` get sent to the driver verbatim, and WebKitWebDriver
 * (the Linux backing for tauri-driver) rejects them as invalid selectors.
 */
export class AssessmentsPage {
  /** Navigate via the sidebar (covers the primary-nav happy path). */
  async open() {
    await waitForReady();
    await clickSidebar('Assessments');
  }

  /** Click the "New Assessment" button on the list page. */
  async clickNew() {
    const btn = await $('//button[contains(normalize-space(.), "New Assessment")]');
    await btn.waitForClickable({ timeout: 10_000 });
    await btn.click();
  }

  /** Find a row matching the given assessment name in the list. */
  async row(name: string) {
    return $(`//*[contains(normalize-space(.), "${name}")]`);
  }
}

export class NewAssessmentPage {
  /** The wizard's name input — the first user-visible field. */
  async nameField() {
    // WebKitWebDriver doesn't support the CSS case-insensitive flag `i`,
    // so we either fall back to plain attribute match or use XPath. Try
    // both shapes in case the field uses `name`, `aria-label`, or
    // `placeholder` for identification.
    return $(
      '//input[@name="name" or contains(translate(@placeholder, "NAME", "name"), "name")]',
    );
  }

  async typeFor(value: string) {
    const opt = await $(`//*[contains(normalize-space(.), "${value}")]`);
    await opt.waitForClickable({ timeout: 5_000 });
    await opt.click();
  }

  async submit() {
    const btn = await $('//button[contains(normalize-space(.), "Create")]');
    await btn.waitForClickable({ timeout: 5_000 });
    await btn.click();
  }
}
