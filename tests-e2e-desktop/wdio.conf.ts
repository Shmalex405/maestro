/**
 * WebdriverIO configuration for desktop end-to-end tests.
 *
 * Drives the Tauri desktop binary via `tauri-driver` on Linux. `tauri-driver`
 * speaks the W3C WebDriver protocol and shells out to either WebKitWebDriver
 * (Linux) or msedgedriver (Windows) depending on platform; on Linux it
 * defaults to /usr/bin/WebKitWebDriver from webkit2gtk-4.1.
 *
 * This config assumes `tauri-driver` is already running on :4444 — the
 * Dockerfile in this directory does that via xvfb-run. Locally on macOS the
 * suite isn't supported (tauri-driver is Linux/Windows only). See
 * tests-e2e-desktop/README for the manual checklist macOS devs run instead.
 */

import type { Options } from '@wdio/types';
import path from 'node:path';

const TAURI_BINARY =
  process.env.MAESTRO_BINARY_PATH ??
  path.resolve(__dirname, '../frontend/src-tauri/target/debug/Maestro');

export const config: Options.Testrunner = {
  runner: 'local',
  tsConfigPath: './tsconfig.json',

  specs: ['./specs/**/*.test.ts'],

  // Run one Tauri instance at a time. The app holds an exclusive lock on
  // its SQLite DB; parallel instances would race each other.
  maxInstances: 1,

  capabilities: [
    {
      // No `browserName` — tauri-driver rejects sessions that try to
      // negotiate as a known browser (we hit "Failed to match capabilities"
      // until we dropped `browserName: 'wry'`). The driver picks the right
      // proxy target (WebKitWebDriver on Linux, msedgedriver on Windows)
      // based on platform; the `tauri:options.application` cap is what
      // tells it which binary to launch.
      maxInstances: 1,
      'tauri:options': {
        application: TAURI_BINARY,
      },
    } as unknown as WebdriverIO.Capabilities,
  ],

  hostname: process.env.TAURI_DRIVER_HOST ?? '127.0.0.1',
  port: Number(process.env.TAURI_DRIVER_PORT ?? 4444),

  logLevel: (process.env.WDIO_LOG_LEVEL as Options.Testrunner['logLevel']) ?? 'info',
  bail: 0,
  waitforTimeout: 10_000,
  connectionRetryTimeout: 120_000,
  connectionRetryCount: 3,

  framework: 'mocha',
  mochaOpts: {
    ui: 'bdd',
    timeout: 60_000,
  },

  reporters: ['spec'],

  // Take a screenshot on every failed step so CI artifacts surface what went
  // wrong without re-running the test locally.
  afterTest: async function (test, _ctx, { error }) {
    if (error) {
      const safe = test.title.replace(/[^a-z0-9-]/gi, '-');
      const out = path.join(__dirname, 'screenshots', `${safe}-${Date.now()}.png`);
      try { await browser.saveScreenshot(out); } catch { /* ignore */ }
    }
  },
};
