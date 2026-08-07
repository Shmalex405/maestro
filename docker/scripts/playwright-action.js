#!/usr/bin/env node
/**
 * Playwright Action Script
 *
 * Runs inside the Kali Docker container. Accepts a JSON action on argv[1]
 * and drives a Chromium browser via Playwright with persistent context.
 *
 * Usage: node playwright-action.js '{"action":"navigate","params":{"url":"https://example.com"}}'
 *
 * Browser state (cookies, storage) persists at /opt/pentest/output/browser-state/
 */

const { chromium } = require("playwright");
const path = require("path");
const fs = require("fs");

const STATE_DIR = "/opt/pentest/output/browser-state";
const NETWORK_LOG_PATH = "/opt/pentest/output/browser-network.json";
const SESSION_BACKUP_PATH = "/opt/pentest/output/browser-session.json";
const LAST_URL_PATH = "/opt/pentest/output/browser-last-url.txt";
const DEFAULT_TIMEOUT = 30000;

// Actions that don't need the page to be at a specific URL
const NO_NAVIGATE_ACTIONS = new Set(["close", "restore_state"]);

// Ensure state directory exists
if (!fs.existsSync(STATE_DIR)) {
  fs.mkdirSync(STATE_DIR, { recursive: true });
}

function saveLastUrl(url) {
  try {
    if (url && url !== "about:blank") {
      fs.writeFileSync(LAST_URL_PATH, url);
    }
  } catch {}
}

function loadLastUrl() {
  try {
    if (fs.existsSync(LAST_URL_PATH)) {
      return fs.readFileSync(LAST_URL_PATH, "utf-8").trim();
    }
  } catch {}
  return null;
}

async function main() {
  const input = JSON.parse(process.argv[2] || "{}");
  const { action, params = {} } = input;

  if (!action) {
    return output({ success: false, error: "No action specified" });
  }

  let context = null;
  let page = null;

  try {
    // Launch persistent context (reuses cookies/storage across calls)
    context = await chromium.launchPersistentContext(STATE_DIR, {
      headless: true,
      args: [
        "--no-sandbox",
        "--disable-setuid-sandbox",
        "--disable-dev-shm-usage",
        "--disable-gpu",
      ],
      ignoreHTTPSErrors: true,
      viewport: { width: 1280, height: 720 },
    });

    // Get existing page or create new one
    const pages = context.pages();
    page = pages.length > 0 ? pages[0] : await context.newPage();

    // Auto-navigate to last known URL for non-navigate actions
    if (action !== "navigate" && !NO_NAVIGATE_ACTIONS.has(action)) {
      const lastUrl = loadLastUrl();
      if (lastUrl && page.url() === "about:blank") {
        try {
          await page.goto(lastUrl, {
            waitUntil: "domcontentloaded",
            timeout: DEFAULT_TIMEOUT,
          });
        } catch (e) {
          // If auto-navigate fails, continue with about:blank
        }
      }
    }

    // Set up network logging if needed
    if (action === "navigate" || action === "network_log") {
      setupNetworkLogging(page);
    }

    // Execute the action
    const result = await executeAction(action, params, page, context);

    // Save current URL for next call
    saveLastUrl(page.url());

    output(result);
  } catch (error) {
    output({
      success: false,
      error: error.message,
      stack: error.stack,
    });
  } finally {
    if (context) {
      await context.close().catch(() => {});
    }
  }
}

async function executeAction(action, params, page, context) {
  switch (action) {
    case "navigate": {
      const timeout = params.timeout || DEFAULT_TIMEOUT;
      const response = await page.goto(params.url, {
        waitUntil: "domcontentloaded",
        timeout,
      });

      if (params.wait_for) {
        await page.waitForSelector(params.wait_for, { timeout });
      }

      return {
        success: true,
        data: {
          url: page.url(),
          title: await page.title(),
          status: response ? response.status() : null,
        },
      };
    }

    case "click": {
      if (params.text) {
        await page.getByText(params.text, { exact: false }).first().click({
          timeout: params.timeout || DEFAULT_TIMEOUT,
        });
      } else if (params.selector) {
        await page.click(params.selector, {
          timeout: params.timeout || DEFAULT_TIMEOUT,
        });
      } else {
        return { success: false, error: "Must provide selector or text" };
      }

      // Wait briefly for navigation/updates
      await page.waitForTimeout(500);

      return {
        success: true,
        data: {
          url: page.url(),
          title: await page.title(),
        },
      };
    }

    case "fill": {
      await page.fill(params.selector, params.value, {
        timeout: params.timeout || DEFAULT_TIMEOUT,
      });

      return {
        success: true,
        data: { filled: params.selector, value: params.value },
      };
    }

    case "screenshot": {
      const options = {
        fullPage: params.full_page || false,
        type: "png",
      };

      let buffer;
      if (params.selector) {
        const element = await page.$(params.selector);
        if (!element) {
          return { success: false, error: `Element not found: ${params.selector}` };
        }
        buffer = await element.screenshot(options);
      } else {
        buffer = await page.screenshot(options);
      }

      return {
        success: true,
        data: {
          base64: buffer.toString("base64"),
          url: page.url(),
          title: await page.title(),
        },
      };
    }

    case "evaluate": {
      const result = await page.evaluate(params.script);
      return {
        success: true,
        data: {
          result: typeof result === "object" ? JSON.stringify(result) : String(result),
          type: typeof result,
        },
      };
    }

    case "get_cookies": {
      const cookies = await context.cookies();
      return {
        success: true,
        data: { cookies },
      };
    }

    case "set_cookies": {
      await context.addCookies(params.cookies);
      return {
        success: true,
        data: { set: params.cookies.length },
      };
    }

    case "get_content": {
      let content;
      if (params.selector) {
        const element = await page.$(params.selector);
        if (!element) {
          return { success: false, error: `Element not found: ${params.selector}` };
        }
        content =
          params.format === "html"
            ? await element.innerHTML()
            : await element.textContent();
      } else {
        content =
          params.format === "html"
            ? await page.content()
            : await page.innerText("body");
      }

      // Truncate large content
      if (content && content.length > 100000) {
        content = content.slice(0, 100000) + "\n... [truncated]";
      }

      return {
        success: true,
        data: {
          content,
          url: page.url(),
          length: content ? content.length : 0,
        },
      };
    }

    case "wait_for": {
      const state = params.state || "visible";
      const timeout = params.timeout || 10000;

      if (params.selector) {
        await page.waitForSelector(params.selector, { state, timeout });
      } else {
        await page.waitForLoadState("networkidle", { timeout });
      }

      return {
        success: true,
        data: { url: page.url() },
      };
    }

    case "network_log": {
      // Read captured network log
      let log = [];
      try {
        if (fs.existsSync(NETWORK_LOG_PATH)) {
          log = JSON.parse(fs.readFileSync(NETWORK_LOG_PATH, "utf-8"));
        }
      } catch {
        log = [];
      }

      // Filter if pattern provided
      if (params.filter) {
        const regex = new RegExp(params.filter, "i");
        log = log.filter((entry) => regex.test(entry.url));
      }

      return {
        success: true,
        data: { requests: log, count: log.length },
      };
    }

    case "close": {
      // Clear state
      try {
        fs.rmSync(STATE_DIR, { recursive: true, force: true });
        fs.mkdirSync(STATE_DIR, { recursive: true });
      } catch {}

      return {
        success: true,
        data: { message: "Browser session closed and state cleared" },
      };
    }

    case "save_state": {
      // Export cookies + localStorage + sessionStorage + current URL
      const cookies = await context.cookies();
      const currentUrl = page.url();

      // Extract localStorage and sessionStorage via JS evaluation
      let localStorage = {};
      let sessionStorage = {};
      try {
        localStorage = await page.evaluate(() => {
          const items = {};
          for (let i = 0; i < window.localStorage.length; i++) {
            const key = window.localStorage.key(i);
            if (key) items[key] = window.localStorage.getItem(key);
          }
          return items;
        });
        sessionStorage = await page.evaluate(() => {
          const items = {};
          for (let i = 0; i < window.sessionStorage.length; i++) {
            const key = window.sessionStorage.key(i);
            if (key) items[key] = window.sessionStorage.getItem(key);
          }
          return items;
        });
      } catch {
        // Page may not have a valid origin for storage access
      }

      const stateData = {
        cookies,
        localStorage,
        sessionStorage,
        url: currentUrl,
        savedAt: new Date().toISOString(),
      };

      fs.writeFileSync(SESSION_BACKUP_PATH, JSON.stringify(stateData, null, 2));

      return {
        success: true,
        data: {
          message: "Browser state saved",
          path: SESSION_BACKUP_PATH,
          cookieCount: cookies.length,
          localStorageKeys: Object.keys(localStorage).length,
          sessionStorageKeys: Object.keys(sessionStorage).length,
          url: currentUrl,
        },
      };
    }

    case "restore_state": {
      // Import cookies + localStorage + sessionStorage from backup
      if (!fs.existsSync(SESSION_BACKUP_PATH)) {
        return {
          success: false,
          error: "No saved browser state found at " + SESSION_BACKUP_PATH,
        };
      }

      const stateJson = fs.readFileSync(SESSION_BACKUP_PATH, "utf-8");
      const savedState = JSON.parse(stateJson);

      // Restore cookies
      if (savedState.cookies && savedState.cookies.length > 0) {
        await context.addCookies(savedState.cookies);
      }

      // Navigate to saved URL first (needed for storage access)
      if (savedState.url && savedState.url !== "about:blank") {
        await page.goto(savedState.url, {
          waitUntil: "domcontentloaded",
          timeout: DEFAULT_TIMEOUT,
        });
      }

      // Restore localStorage
      if (savedState.localStorage && Object.keys(savedState.localStorage).length > 0) {
        try {
          await page.evaluate((items) => {
            for (const [key, value] of Object.entries(items)) {
              window.localStorage.setItem(key, value);
            }
          }, savedState.localStorage);
        } catch {
          // May fail if page has no valid origin
        }
      }

      // Restore sessionStorage
      if (savedState.sessionStorage && Object.keys(savedState.sessionStorage).length > 0) {
        try {
          await page.evaluate((items) => {
            for (const [key, value] of Object.entries(items)) {
              window.sessionStorage.setItem(key, value);
            }
          }, savedState.sessionStorage);
        } catch {
          // May fail if page has no valid origin
        }
      }

      return {
        success: true,
        data: {
          message: "Browser state restored",
          cookiesRestored: savedState.cookies?.length || 0,
          localStorageRestored: Object.keys(savedState.localStorage || {}).length,
          sessionStorageRestored: Object.keys(savedState.sessionStorage || {}).length,
          url: savedState.url,
          savedAt: savedState.savedAt,
        },
      };
    }

    case "render_pdf_from_file": {
      // Render an HTML file to PDF
      // params: { htmlPath: string, outputPath?: string, options?: { format?, margin?, headerTemplate?, footerTemplate? } }
      const htmlContent = fs.readFileSync(params.htmlPath, "utf-8");
      await page.setContent(htmlContent, { waitUntil: "networkidle" });

      const pdfOptions = {
        path: params.outputPath || "/opt/pentest/output/report.pdf",
        format: "A4",
        margin: { top: "40px", right: "40px", bottom: "60px", left: "40px" },
        printBackground: true,
        displayHeaderFooter: true,
        headerTemplate:
          '<div style="font-size:8px;width:100%;text-align:center;color:#888;padding-top:5px;">Security Assessment Report</div>',
        footerTemplate:
          '<div style="font-size:8px;width:100%;text-align:center;color:#888;padding-bottom:5px;">Page <span class="pageNumber"></span> of <span class="totalPages"></span> | Confidential</div>',
        ...(params.options || {}),
      };

      await page.pdf(pdfOptions);

      // Get file size for confirmation
      const stats = fs.statSync(pdfOptions.path);
      return {
        success: true,
        data: {
          path: pdfOptions.path,
          size_bytes: stats.size,
          size_kb: Math.round(stats.size / 1024),
        },
      };
    }

    case "multi": {
      // Execute multiple actions in sequence within a single browser session
      const steps = params.steps || [];
      const results = [];
      for (const step of steps) {
        const stepResult = await executeAction(step.action, step.params || {}, page, context);
        results.push({ action: step.action, ...stepResult });
        if (!stepResult.success && !step.continueOnError) {
          return { success: false, data: { results, failedAt: step.action } };
        }
        // Optional wait between steps
        if (step.waitMs) {
          await page.waitForTimeout(step.waitMs);
        }
      }
      return { success: true, data: { results, url: page.url(), title: await page.title() } };
    }

    default:
      return { success: false, error: `Unknown action: ${action}` };
  }
}

function setupNetworkLogging(page) {
  const log = [];

  page.on("request", (request) => {
    log.push({
      url: request.url(),
      method: request.method(),
      headers: request.headers(),
      postData: request.postData(),
      resourceType: request.resourceType(),
      timestamp: new Date().toISOString(),
    });
  });

  page.on("response", (response) => {
    const entry = log.find(
      (e) => e.url === response.url() && !e.status
    );
    if (entry) {
      entry.status = response.status();
      entry.statusText = response.statusText();
      entry.responseHeaders = response.headers();
    }
  });

  // Periodically flush to disk
  const flush = () => {
    try {
      fs.writeFileSync(NETWORK_LOG_PATH, JSON.stringify(log.slice(-200), null, 2));
    } catch {}
  };

  page.on("close", flush);
  setTimeout(flush, 5000);
}

function output(data) {
  process.stdout.write(JSON.stringify(data));
}

main().catch((error) => {
  output({ success: false, error: error.message });
  process.exit(1);
});
