/**
 * Auth Agent Implementation
 *
 * Lightweight agent dedicated to browser-based authentication.
 * Reads login config from assessmentConfig.auth.browser_login,
 * executes login steps, handles CAPTCHA/MFA via user guidance,
 * and stores auth cookies/headers for downstream agents.
 */

import {
  BaseAgent,
  AgentConfig,
  AgentInput,
  ToolDefinition,
  ProgressCallback,
} from "../base-agent";
import { browserHandlers } from "../../tools/browser";
import { guidanceHandlers } from "../../tools/guidance";
import { BrowserLoginStep } from "../../config/assessment-config";

const AUTH_AGENT_CONFIG: AgentConfig = {
  name: "auth-agent",
  description: "Browser-based authentication setup agent",
  maxIterations: 15,
  timeoutMs: 300000, // 5 minutes
  requiresScopeValidation: false, // Auth URLs are implicitly in scope
  tools: [
    // All browser tools for login flow
    "browser_navigate",
    "browser_click",
    "browser_fill",
    "browser_screenshot",
    "browser_evaluate",
    "browser_get_cookies",
    "browser_set_cookies",
    "browser_get_content",
    "browser_wait_for",
    "browser_network_log",
    "browser_save_state",
    // Guidance for CAPTCHA/MFA/unknown forms
    "request_user_guidance",
  ],
};

const AUTH_TOOL_DEFINITIONS: ToolDefinition[] = [
  {
    name: "browser_navigate",
    description: "Navigate to the login page or target URL.",
    input_schema: {
      type: "object",
      properties: {
        url: { type: "string", description: "URL to navigate to" },
        wait_for: { type: "string", description: "CSS selector to wait for" },
        timeout: { type: "number", description: "Timeout in ms" },
      },
      required: ["url"],
    },
  },
  {
    name: "browser_fill",
    description: "Fill a form field (username, password, etc).",
    input_schema: {
      type: "object",
      properties: {
        selector: { type: "string", description: "CSS selector of input" },
        value: { type: "string", description: "Value to fill" },
      },
      required: ["selector", "value"],
    },
  },
  {
    name: "browser_click",
    description: "Click a button or link (submit, login, etc).",
    input_schema: {
      type: "object",
      properties: {
        selector: { type: "string", description: "CSS selector" },
        text: { type: "string", description: "Text content to match" },
      },
    },
  },
  {
    name: "browser_wait_for",
    description: "Wait for an element after login submission.",
    input_schema: {
      type: "object",
      properties: {
        selector: { type: "string", description: "CSS selector to wait for" },
        state: { type: "string", enum: ["visible", "hidden"], default: "visible" },
        timeout: { type: "number", description: "Timeout in ms", default: 10000 },
      },
    },
  },
  {
    name: "browser_screenshot",
    description: "Capture screenshot for debugging or evidence.",
    input_schema: {
      type: "object",
      properties: {
        full_page: { type: "boolean", default: false },
      },
    },
  },
  {
    name: "browser_evaluate",
    description: "Execute JavaScript to check login state or extract tokens.",
    input_schema: {
      type: "object",
      properties: {
        script: { type: "string", description: "JavaScript to evaluate" },
      },
      required: ["script"],
    },
  },
  {
    name: "browser_get_cookies",
    description: "Get all cookies after successful login. Essential for passing auth to CLI tools.",
    input_schema: { type: "object", properties: {} },
  },
  {
    name: "browser_set_cookies",
    description: "Set cookies if restoring a previous session.",
    input_schema: {
      type: "object",
      properties: {
        cookies: {
          type: "array",
          items: {
            type: "object",
            properties: { name: { type: "string" }, value: { type: "string" }, domain: { type: "string" } },
            required: ["name", "value"],
          },
        },
      },
      required: ["cookies"],
    },
  },
  {
    name: "browser_get_content",
    description: "Get page content to verify login success.",
    input_schema: {
      type: "object",
      properties: {
        format: { type: "string", enum: ["html", "text"], default: "text" },
        selector: { type: "string" },
      },
    },
  },
  {
    name: "browser_network_log",
    description: "Check network requests for auth tokens/headers.",
    input_schema: {
      type: "object",
      properties: {
        filter: { type: "string", description: "URL pattern regex" },
      },
    },
  },
  {
    name: "browser_save_state",
    description: "Save browser state (cookies, storage) to disk for session persistence.",
    input_schema: { type: "object", properties: {} },
  },
  {
    name: "request_user_guidance",
    description:
      "Ask the user for help when blocked by CAPTCHA, MFA, or unknown form. " +
      "Takes a screenshot to show the user. Use this when you can't proceed automatically.",
    input_schema: {
      type: "object",
      properties: {
        situation: { type: "string", description: "What you're blocked on" },
        screenshot: { type: "boolean", description: "Take screenshot", default: true },
        options: { type: "array", items: { type: "string" }, description: "Suggested actions" },
      },
      required: ["situation"],
    },
  },
];

export class AuthAgentImpl extends BaseAgent {
  constructor(onProgress?: ProgressCallback) {
    super(
      AUTH_AGENT_CONFIG,
      { ...browserHandlers, ...guidanceHandlers },
      onProgress
    );
  }

  getToolDefinitions(): ToolDefinition[] {
    return AUTH_TOOL_DEFINITIONS;
  }

  buildInitialPrompt(input: AgentInput): string {
    const config = input.context?.assessmentConfig;
    const loginSteps = config?.auth?.browser_login as BrowserLoginStep[] | undefined;
    const successIndicator = config?.auth?.success_indicator;
    const verifyUrl = config?.auth?.verify_url;

    let prompt = `# Authentication Setup Task

You are the Auth Agent. Your mission is to establish an authenticated browser session for downstream security testing agents.

## CRITICAL RULES:
1. Do NOT call browser_close - the session must persist for other agents
2. After successful login, ALWAYS call browser_get_cookies to capture auth cookies
3. After capturing cookies, ALWAYS call browser_save_state to persist the session
4. If you encounter a CAPTCHA, MFA prompt, or anything you can't handle automatically, call request_user_guidance with screenshot=true

`;

    if (loginSteps?.length) {
      prompt += `## Login Steps (from config):\n\n`;
      for (let i = 0; i < loginSteps.length; i++) {
        const step = loginSteps[i];
        const desc = step.description || `${step.action} ${step.selector || step.url || step.text || ""}`;
        prompt += `${i + 1}. **${step.action}**: ${desc}\n`;
        if (step.url) prompt += `   URL: ${step.url}\n`;
        if (step.selector) prompt += `   Selector: ${step.selector}\n`;
        if (step.value) prompt += `   Value: ${step.value}\n`;
        if (step.text) prompt += `   Text: ${step.text}\n`;
      }
      prompt += `\nFollow these steps in order. If any step fails, try to adapt or call request_user_guidance.\n`;
    } else {
      prompt += `## No login steps configured

You need to discover the login flow. Try:
1. Navigate to the target URL
2. Look for login forms or links
3. If you find a login form, call request_user_guidance to ask for credentials
4. Complete the login process

`;
    }

    if (successIndicator) {
      prompt += `\n## Success Indicator:\nAfter login, verify success by checking for: \`${successIndicator}\`\n`;
    }

    if (verifyUrl) {
      prompt += `\n## Verify Auth:\nAfter login, navigate to ${verifyUrl} to confirm authenticated access.\n`;
    }

    // Targets context
    if (input.targets?.length) {
      prompt += `\n## Target URLs:\n`;
      for (const t of input.targets) {
        prompt += `- ${t}\n`;
      }
    }

    prompt += `
## After Successful Login:

1. Call browser_get_cookies to capture all session cookies
2. Call browser_save_state to persist the session to disk
3. Report the cookies and any auth headers found
4. Note the authenticated URL and session indicators

## On Failure:

If login fails after multiple attempts:
1. Call request_user_guidance with a screenshot explaining the issue
2. If no response or user says to skip, report auth failure and continue
3. Note which authentication steps succeeded and which failed

Begin authentication now.`;

    return prompt;
  }

  getSystemPrompt(): string {
    return `You are the Auth Agent, specialized in browser-based authentication for security assessments.

## Your Capabilities:
- Navigate to login pages
- Fill in credentials (username, password, TOTP)
- Click login buttons and handle redirects
- Detect and report CAPTCHA/MFA challenges
- Capture cookies and auth tokens after login
- Save browser state for session persistence

## Decision Guidelines:

### When to use browser_fill:
- For username/email fields
- For password fields
- For TOTP/OTP code fields (if you have the code)

### When to use browser_click:
- To submit login forms
- To click "Sign In" or "Login" buttons
- To handle OAuth redirects or consent screens

### When to use request_user_guidance:
- CAPTCHA is present (you CANNOT solve CAPTCHAs)
- MFA/2FA challenge appears (SMS, email, authenticator)
- Unknown or complex form you don't understand
- Login fails and you need credentials or help
- ALWAYS include screenshot=true so the user can see what's happening

### When to use browser_get_cookies:
- After successful login ALWAYS capture cookies
- These cookies will be formatted for CLI tools (sqlmap, nuclei, etc.)

### When to use browser_save_state:
- ALWAYS call after successful login to persist the session
- Ensures session survives between agent phases

## IMPORTANT:
- NEVER call browser_close - the session must persist
- Be patient with redirects and page loads
- Check for error messages after login attempts
- Capture both cookies and any Authorization headers from network log`;
  }

  protected extractFindings(result: string, toolName: string, target?: string): void {
    super.extractFindings(result, toolName, target);

    try {
      const parsed = JSON.parse(result);

      // Capture cookies for downstream agents
      if (toolName === "browser_get_cookies" && parsed.success) {
        const cookies = parsed.data?.cookies || [];
        if (cookies.length > 0) {
          // Format cookies as a header string for CLI tools
          const cookieHeader = cookies
            .map((c: { name: string; value: string }) => `${c.name}=${c.value}`)
            .join("; ");

          this.state.context.authCookies = cookieHeader;
          this.state.context.authCookiesRaw = cookies;
          this.state.context.authEstablished = true;
          this.state.context.authTimestamp = new Date().toISOString();

          console.log(
            `[auth-agent] Captured ${cookies.length} cookies for downstream agents`
          );
        }
      }

      // Capture auth headers from network log
      if (toolName === "browser_network_log" && parsed.success) {
        const requests = parsed.data?.requests || [];
        for (const req of requests) {
          const authHeader = req.headers?.authorization || req.headers?.Authorization;
          if (authHeader) {
            this.state.context.authHeaders = {
              Authorization: authHeader,
            };
            console.log(`[auth-agent] Captured Authorization header`);
            break;
          }
        }
      }

      // Track save state success
      if (toolName === "browser_save_state" && parsed.success) {
        this.state.context.browserStateSaved = true;
        console.log(`[auth-agent] Browser state saved to disk`);
      }
    } catch {
      // Not JSON
    }
  }
}
