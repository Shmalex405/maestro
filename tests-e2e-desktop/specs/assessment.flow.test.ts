/**
 * Smoke flow: navigate to the assessments page and confirm the
 * "New Assessment" button opens the modal wizard. We stop short of
 * filling and submitting the form because the wizard's interactive
 * controls (multi-step, type-picker, scope/credential pickers) are
 * shadcn-based composites that need component-specific selectors —
 * worth doing once the basic infra is proven, but not the day-one
 * bar.
 *
 * What this confirms end-to-end:
 *   - Sidebar → /assessments navigation works through real Tauri IPC
 *   - The list page renders and the "New Assessment" button is clickable
 *   - The new-assessment walkthrough modal opens on click (proves the
 *     React tree responds to events, not just renders)
 */

import { expect } from '@wdio/globals';
import { AssessmentsPage } from '../lib/pages/AssessmentsPage';
import { waitForReady } from '../lib/helpers';

describe('Assessment list + modal smoke', () => {
  const list = new AssessmentsPage();

  before(async () => {
    await waitForReady(60_000);
  });

  it('opens the assessments list from the sidebar', async () => {
    await list.open();
    await browser.waitUntil(
      async () => (await browser.getUrl()).includes('/assessments'),
      { timeout: 5_000, timeoutMsg: 'URL never moved to /assessments' },
    );
  });

  it('the New Assessment button opens the walkthrough modal', async () => {
    await list.clickNew();
    // The modal renders a dialog with role="dialog" (shadcn convention).
    // Wait up to 5s for it to appear; any visible dialog is good enough
    // for smoke purposes.
    const dialog = await $('[role="dialog"]');
    await dialog.waitForDisplayed({ timeout: 5_000 });
    expect(await dialog.isDisplayed()).toBe(true);
  });
});
