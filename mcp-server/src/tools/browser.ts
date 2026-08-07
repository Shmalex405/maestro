/**
 * Browser Tools
 *
 * MCP tool definitions for Playwright-based browser automation.
 * Enables real browser interaction for SPA testing, DOM XSS validation,
 * SSO/TOTP auth flows, and visual exploitation evidence.
 *
 * All browser actions execute inside the Kali Docker container via
 * the playwright-action.js script with persistent browser context.
 */

import { executeInKali } from "../utils/docker-exec";

// Helper to run a browser action inside the container
async function browserAction(
  action: string,
  params: Record<string, any> = {}
): Promise<string> {
  const payload = JSON.stringify({ action, params });
  // Escape single quotes in the JSON payload for bash
  const escaped = payload.replace(/'/g, "'\\''");
  const command = `node /opt/pentest/scripts/playwright-action.js '${escaped}'`;

  const result = await executeInKali(command);

  // Parse and return the JSON result
  try {
    const parsed = JSON.parse(result);
    return JSON.stringify(parsed, null, 2);
  } catch {
    return JSON.stringify({
      success: false,
      error: "Failed to parse browser action result",
      raw: result.slice(0, 2000),
    });
  }
}

// ==================== Tool Definitions ====================

export const browserTools = [
  {
    name: "browser_navigate",
    description:
      "Navigate the browser to a URL. Starts a headless Chromium browser if not already running. Returns page title, URL, and HTTP status. Use this for testing web applications, especially SPAs that require JavaScript execution.",
    inputSchema: {
      type: "object",
      properties: {
        url: {
          type: "string",
          description: "URL to navigate to",
        },
        wait_for: {
          type: "string",
          description: "CSS selector to wait for after navigation (optional)",
        },
        timeout: {
          type: "number",
          description: "Navigation timeout in milliseconds",
          default: 30000,
        },
      },
      required: ["url"],
    },
  },
  {
    name: "browser_click",
    description:
      "Click an element on the current page. Use either a CSS selector or text content to identify the element.",
    inputSchema: {
      type: "object",
      properties: {
        selector: {
          type: "string",
          description: "CSS selector of element to click",
        },
        text: {
          type: "string",
          description: "Text content to match (alternative to selector)",
        },
        timeout: {
          type: "number",
          description: "Timeout in milliseconds",
          default: 10000,
        },
      },
    },
  },
  {
    name: "browser_fill",
    description:
      "Fill a form field with text. Use for login forms, search inputs, etc.",
    inputSchema: {
      type: "object",
      properties: {
        selector: {
          type: "string",
          description: "CSS selector of input field",
        },
        value: {
          type: "string",
          description: "Value to fill in the field",
        },
        timeout: {
          type: "number",
          description: "Timeout in milliseconds",
          default: 10000,
        },
      },
      required: ["selector", "value"],
    },
  },
  {
    name: "browser_screenshot",
    description:
      "Take a screenshot of the current page. Returns base64-encoded PNG. Use for capturing exploitation evidence, error pages, or visual confirmation.",
    inputSchema: {
      type: "object",
      properties: {
        full_page: {
          type: "boolean",
          description: "Capture the full scrollable page",
          default: false,
        },
        selector: {
          type: "string",
          description: "CSS selector to screenshot a specific element (optional)",
        },
      },
    },
  },
  {
    name: "browser_evaluate",
    description:
      "Execute JavaScript in the browser context and return the result. Essential for DOM-based XSS validation — inject a payload and check if it executes. Also useful for extracting data from JavaScript-heavy SPAs.",
    inputSchema: {
      type: "object",
      properties: {
        script: {
          type: "string",
          description:
            "JavaScript code to evaluate in the browser context. Has access to document, window, etc.",
        },
      },
      required: ["script"],
    },
  },
  {
    name: "browser_get_cookies",
    description:
      "Get all cookies for the current browser context. Useful for session analysis, token extraction, and cookie security auditing (HttpOnly, Secure, SameSite flags).",
    inputSchema: {
      type: "object",
      properties: {},
    },
  },
  {
    name: "browser_set_cookies",
    description:
      "Set cookies in the browser context. Use for session hijacking tests, cookie manipulation, or authenticated testing.",
    inputSchema: {
      type: "object",
      properties: {
        cookies: {
          type: "array",
          items: {
            type: "object",
            properties: {
              name: { type: "string" },
              value: { type: "string" },
              domain: { type: "string" },
              path: { type: "string", default: "/" },
            },
            required: ["name", "value"],
          },
          description: "Array of cookies to set",
        },
      },
      required: ["cookies"],
    },
  },
  {
    name: "browser_get_content",
    description:
      "Get the current page content as HTML or text. Use for analyzing rendered DOM, checking for reflected XSS payloads in the DOM, or extracting data from JavaScript-rendered pages.",
    inputSchema: {
      type: "object",
      properties: {
        format: {
          type: "string",
          enum: ["html", "text"],
          description: "Output format",
          default: "text",
        },
        selector: {
          type: "string",
          description: "CSS selector to get content of a specific element (optional)",
        },
      },
    },
  },
  {
    name: "browser_wait_for",
    description:
      "Wait for a CSS selector to appear/disappear, or for the network to go idle. Useful after form submissions or navigation.",
    inputSchema: {
      type: "object",
      properties: {
        selector: {
          type: "string",
          description: "CSS selector to wait for",
        },
        state: {
          type: "string",
          enum: ["visible", "hidden", "attached", "detached"],
          description: "State to wait for",
          default: "visible",
        },
        timeout: {
          type: "number",
          description: "Timeout in milliseconds",
          default: 10000,
        },
      },
    },
  },
  {
    name: "browser_network_log",
    description:
      "Get captured network requests and responses from the current page. Reveals API endpoints, authentication headers, and data transmitted by the browser. Use to discover hidden API calls in SPAs.",
    inputSchema: {
      type: "object",
      properties: {
        filter: {
          type: "string",
          description: "URL pattern to filter results (regex)",
        },
      },
    },
  },
  {
    name: "browser_close",
    description:
      "Close the browser session and clear all state (cookies, storage). Call this when done with browser-based testing.",
    inputSchema: {
      type: "object",
      properties: {},
    },
  },
  {
    name: "browser_save_state",
    description:
      "Save the current browser state (cookies, localStorage, sessionStorage, URL) to disk. " +
      "Use this to preserve authentication state across agent phases or container restarts.",
    inputSchema: {
      type: "object",
      properties: {},
    },
  },
  {
    name: "browser_restore_state",
    description:
      "Restore a previously saved browser state (cookies, localStorage, sessionStorage). " +
      "Use this to resume an authenticated session after an agent switch or container restart.",
    inputSchema: {
      type: "object",
      properties: {},
    },
  },
];

// ==================== Tool Handlers ====================

export const browserHandlers: Record<string, Function> = {
  browser_navigate: async (args: {
    url: string;
    wait_for?: string;
    timeout?: number;
  }) => {
    return browserAction("navigate", args);
  },

  browser_click: async (args: {
    selector?: string;
    text?: string;
    timeout?: number;
  }) => {
    return browserAction("click", args);
  },

  browser_fill: async (args: {
    selector: string;
    value: string;
    timeout?: number;
  }) => {
    return browserAction("fill", args);
  },

  browser_screenshot: async (args: {
    full_page?: boolean;
    selector?: string;
  }) => {
    return browserAction("screenshot", args);
  },

  browser_evaluate: async (args: { script: string }) => {
    return browserAction("evaluate", args);
  },

  browser_get_cookies: async () => {
    return browserAction("get_cookies");
  },

  browser_set_cookies: async (args: {
    cookies: Array<{ name: string; value: string; domain?: string; path?: string }>;
  }) => {
    return browserAction("set_cookies", args);
  },

  browser_get_content: async (args: {
    format?: string;
    selector?: string;
  }) => {
    return browserAction("get_content", args);
  },

  browser_wait_for: async (args: {
    selector?: string;
    state?: string;
    timeout?: number;
  }) => {
    return browserAction("wait_for", args);
  },

  browser_network_log: async (args: { filter?: string }) => {
    return browserAction("network_log", args);
  },

  browser_close: async () => {
    return browserAction("close");
  },

  browser_save_state: async () => {
    return browserAction("save_state");
  },

  browser_restore_state: async () => {
    return browserAction("restore_state");
  },
};
