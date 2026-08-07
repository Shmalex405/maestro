/**
 * Guidance Tool
 *
 * Allows agents to pause and request user guidance when they encounter
 * blockers like CAPTCHAs, MFA challenges, or unknown forms. The tool
 * optionally takes a screenshot, creates a pending prompt, and blocks
 * until the user responds (or times out in autonomous mode).
 */

import {
  PendingPrompt,
  pendingPrompts,
  generatePromptId,
  getPendingPrompts,
} from "./interactive";
import { browserHandlers } from "./browser";

// Screenshot storage path inside the container
const SCREENSHOT_DIR = "/opt/pentest/output/screenshots";

// Configurable mode - defaults to interactive
let guidanceMode: "interactive" | "autonomous" = "interactive";

/**
 * Set the guidance mode (called by orchestrator based on assessment config)
 */
export function setGuidanceMode(mode: "interactive" | "autonomous"): void {
  guidanceMode = mode;
}

/**
 * Get the current guidance mode
 */
export function getGuidanceMode(): "interactive" | "autonomous" {
  return guidanceMode;
}

// Tool definitions for MCP
export const guidanceTools = [
  {
    name: "request_user_guidance",
    description:
      "Pause execution and ask the user for help when you encounter a blocker. " +
      "Use this when you hit a CAPTCHA, MFA challenge, unknown form, login wall, " +
      "or any situation where you need human input to proceed. " +
      "Optionally takes a screenshot to show the user what you're seeing. " +
      "In autonomous mode, returns after a short timeout with instructions to proceed with best judgment.",
    inputSchema: {
      type: "object",
      properties: {
        situation: {
          type: "string",
          description:
            "Clear description of what you're blocked on and what you need from the user",
        },
        screenshot: {
          type: "boolean",
          description:
            "Whether to take a screenshot of the current browser state to show the user (default: false)",
          default: false,
        },
        options: {
          type: "array",
          items: { type: "string" },
          description:
            "Optional list of suggested actions the user can choose from",
        },
      },
      required: ["situation"],
    },
  },
];

// Tool handlers
export const guidanceHandlers: Record<string, Function> = {
  request_user_guidance: async (args: {
    situation: string;
    screenshot?: boolean;
    options?: string[];
  }) => {
    const { situation, screenshot = false, options } = args;

    console.log(`[guidance] Guidance requested: ${situation}`);

    // Take screenshot if requested
    let screenshotPath: string | undefined;
    if (screenshot) {
      try {
        const screenshotResult = await browserHandlers.browser_screenshot({
          full_page: false,
        });
        const parsed = JSON.parse(screenshotResult);
        if (parsed.success && parsed.data?.base64) {
          // Save screenshot to file instead of passing base64 to LLM (saves tokens)
          const filename = `guidance_${Date.now()}.png`;
          screenshotPath = `${SCREENSHOT_DIR}/${filename}`;

          // Write via a simple command since we're in the container context
          const { executeInKali } = await import("../utils/docker-exec");
          await executeInKali(
            `mkdir -p ${SCREENSHOT_DIR} && echo '${parsed.data.base64}' | base64 -d > ${screenshotPath}`
          );
          console.log(`[guidance] Screenshot saved to ${screenshotPath}`);
        }
      } catch (error) {
        console.warn(`[guidance] Failed to take screenshot: ${error}`);
      }
    }

    // In autonomous mode, return immediately with a timeout response
    if (guidanceMode === "autonomous") {
      console.log(
        "[guidance] Autonomous mode - returning with best judgment instruction"
      );
      return JSON.stringify({
        status: "guidance_received",
        user_response:
          "AUTONOMOUS MODE: Proceed with your best judgment. Skip this blocker if possible, " +
          "or try an alternative approach. Document what was skipped in your findings.",
        mode: "autonomous",
        timeout: true,
        situation,
      });
    }

    // Interactive mode - create a pending prompt and block
    const promptId = generatePromptId();

    const promptMessage =
      `🤖 Agent Guidance Needed\n\n` +
      `**Situation:** ${situation}\n` +
      (screenshotPath
        ? `**Screenshot:** ${screenshotPath}\n`
        : "") +
      (options?.length
        ? `\n**Suggested options:**\n${options.map((o, i) => `${i + 1}. ${o}`).join("\n")}\n`
        : "") +
      `\nPlease provide guidance to continue:`;

    return new Promise<string>((resolve, reject) => {
      const prompt: PendingPrompt = {
        id: promptId,
        type: "guidance",
        message: promptMessage,
        screenshotPath,
        options,
        createdAt: new Date(),
        resolve: (value: string) => {
          console.log(`[guidance] User response received: ${value.substring(0, 100)}`);
          resolve(
            JSON.stringify({
              status: "guidance_received",
              user_response: value,
              mode: "interactive",
              timeout: false,
              situation,
            })
          );
        },
        reject: (error: Error) => {
          console.warn(`[guidance] Prompt timed out or was rejected: ${error.message}`);
          resolve(
            JSON.stringify({
              status: "guidance_timeout",
              user_response:
                "No response received within timeout. Proceed with best judgment or skip this step.",
              mode: "interactive",
              timeout: true,
              situation,
            })
          );
        },
      };

      pendingPrompts.set(promptId, prompt);

      // Timeout after 10 minutes in interactive mode
      setTimeout(() => {
        if (pendingPrompts.has(promptId)) {
          pendingPrompts.delete(promptId);
          // Don't reject - resolve with timeout message so agent can continue
          resolve(
            JSON.stringify({
              status: "guidance_timeout",
              user_response:
                "No response received within 10 minutes. Proceed with best judgment or skip this step.",
              mode: "interactive",
              timeout: true,
              situation,
            })
          );
        }
      }, 10 * 60 * 1000);
    });
  },
};
