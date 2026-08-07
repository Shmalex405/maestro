/**
 * Interactive Tools
 *
 * Tools for handling user interaction during automated processes,
 * such as OTP entry, confirmations, and credential input.
 */

import * as readline from "readline";

// Store for pending prompts (used in API/autonomous mode)
export interface PendingPrompt {
  id: string;
  type: "otp" | "password" | "confirmation" | "text" | "guidance";
  message: string;
  appName?: string;
  screenshotPath?: string;
  options?: string[];
  createdAt: Date;
  resolve: (value: string) => void;
  reject: (error: Error) => void;
}

export const pendingPrompts: Map<string, PendingPrompt> = new Map();

// Tool definitions for MCP
export const interactiveTools = [
  {
    name: "prompt_for_otp",
    description:
      "Prompt the user to enter a One-Time Password (OTP) that was sent to their email or phone. " +
      "Use this when authenticating with an application that requires OTP verification. " +
      "Returns the OTP code entered by the user.",
    inputSchema: {
      type: "object",
      properties: {
        app_name: {
          type: "string",
          description: "Name of the application requiring OTP",
        },
        username: {
          type: "string",
          description: "Username/email the OTP was sent to",
        },
        message: {
          type: "string",
          description: "Optional custom message to show the user",
        },
      },
      required: ["app_name", "username"],
    },
  },
  {
    name: "prompt_for_input",
    description:
      "Prompt the user to enter arbitrary text input. " +
      "Use this for interactive authentication flows or when user confirmation is needed.",
    inputSchema: {
      type: "object",
      properties: {
        prompt_type: {
          type: "string",
          enum: ["text", "password", "confirmation"],
          description: "Type of input to request",
        },
        message: {
          type: "string",
          description: "Message/question to show the user",
        },
        app_name: {
          type: "string",
          description: "Optional application context",
        },
      },
      required: ["prompt_type", "message"],
    },
  },
  {
    name: "check_pending_prompt",
    description: "Check if there's a pending prompt waiting for user input (used in API mode)",
    inputSchema: {
      type: "object",
      properties: {
        prompt_id: {
          type: "string",
          description: "ID of the prompt to check",
        },
      },
      required: ["prompt_id"],
    },
  },
  {
    name: "respond_to_prompt",
    description: "Provide a response to a pending prompt (used in API mode)",
    inputSchema: {
      type: "object",
      properties: {
        prompt_id: {
          type: "string",
          description: "ID of the prompt to respond to",
        },
        value: {
          type: "string",
          description: "The user's response",
        },
      },
      required: ["prompt_id", "value"],
    },
  },
];

/**
 * Prompt for OTP in interactive mode (CLI/Claude Code)
 * When running via Claude, this returns a message that Claude will show to the user
 */
async function promptForOtp(args: {
  app_name: string;
  username: string;
  message?: string;
}): Promise<string> {
  const { app_name, username, message } = args;

  // In MCP mode, we return a structured response that tells Claude to ask the user
  // Claude will interpret this and prompt the user directly
  const promptMessage =
    message ||
    `🔐 OTP Required for ${app_name}\n\n` +
    `An OTP code has been sent to: ${username}\n` +
    `Please check your email/phone and enter the code.\n\n` +
    `Enter OTP code:`;

  // Check if we're in interactive terminal mode
  if (process.stdin.isTTY) {
    return await readLineInput(promptMessage);
  }

  // In non-interactive mode (API/autonomous), create a pending prompt
  const promptId = generatePromptId();

  return JSON.stringify({
    status: "awaiting_input",
    prompt_id: promptId,
    type: "otp",
    message: promptMessage,
    app_name,
    username,
    instruction: "Please provide the OTP code to continue authentication",
  });
}

/**
 * Generic prompt for user input
 */
async function promptForInput(args: {
  prompt_type: "text" | "password" | "confirmation";
  message: string;
  app_name?: string;
}): Promise<string> {
  const { prompt_type, message, app_name } = args;

  // In interactive terminal mode
  if (process.stdin.isTTY) {
    if (prompt_type === "confirmation") {
      const response = await readLineInput(`${message} (yes/no): `);
      return response.toLowerCase().startsWith("y") ? "confirmed" : "cancelled";
    }
    return await readLineInput(message + " ");
  }

  // In non-interactive mode, create pending prompt
  const promptId = generatePromptId();

  return JSON.stringify({
    status: "awaiting_input",
    prompt_id: promptId,
    type: prompt_type,
    message,
    app_name,
    instruction: `Please provide ${prompt_type} input to continue`,
  });
}

/**
 * Check status of a pending prompt
 */
function checkPendingPrompt(args: { prompt_id: string }): string {
  const prompt = pendingPrompts.get(args.prompt_id);

  if (!prompt) {
    return JSON.stringify({
      status: "not_found",
      prompt_id: args.prompt_id,
    });
  }

  return JSON.stringify({
    status: "pending",
    prompt_id: args.prompt_id,
    type: prompt.type,
    message: prompt.message,
    app_name: prompt.appName,
    created_at: prompt.createdAt.toISOString(),
  });
}

/**
 * Respond to a pending prompt
 */
function respondToPrompt(args: { prompt_id: string; value: string }): string {
  const prompt = pendingPrompts.get(args.prompt_id);

  if (!prompt) {
    return JSON.stringify({
      status: "error",
      error: "Prompt not found or already responded to",
      prompt_id: args.prompt_id,
    });
  }

  // Resolve the pending promise
  prompt.resolve(args.value);
  pendingPrompts.delete(args.prompt_id);

  return JSON.stringify({
    status: "success",
    prompt_id: args.prompt_id,
    message: "Response received",
  });
}

/**
 * Create a pending prompt and return a promise that resolves when responded
 */
export function createPendingPrompt(
  type: PendingPrompt["type"],
  message: string,
  appName?: string
): Promise<string> {
  const promptId = generatePromptId();

  return new Promise((resolve, reject) => {
    const prompt: PendingPrompt = {
      id: promptId,
      type,
      message,
      appName,
      createdAt: new Date(),
      resolve,
      reject,
    };

    pendingPrompts.set(promptId, prompt);

    // Timeout after 5 minutes
    setTimeout(() => {
      if (pendingPrompts.has(promptId)) {
        pendingPrompts.delete(promptId);
        reject(new Error("Prompt timed out waiting for user input"));
      }
    }, 5 * 60 * 1000);
  });
}

/**
 * Get all pending prompts (for API/frontend)
 */
export function getPendingPrompts(): Array<{
  id: string;
  type: string;
  message: string;
  appName?: string;
  createdAt: string;
}> {
  return Array.from(pendingPrompts.values()).map((p) => ({
    id: p.id,
    type: p.type,
    message: p.message,
    appName: p.appName,
    createdAt: p.createdAt.toISOString(),
  }));
}

/**
 * Respond to a prompt by ID (for API/frontend)
 */
export function submitPromptResponse(promptId: string, value: string): boolean {
  const prompt = pendingPrompts.get(promptId);
  if (!prompt) return false;

  prompt.resolve(value);
  pendingPrompts.delete(promptId);
  return true;
}

// Helper functions

export function generatePromptId(): string {
  return `prompt_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
}

async function readLineInput(prompt: string): Promise<string> {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  return new Promise((resolve) => {
    rl.question(prompt, (answer) => {
      rl.close();
      resolve(answer.trim());
    });
  });
}

// Tool handlers
export const interactiveHandlers: Record<string, Function> = {
  prompt_for_otp: promptForOtp,
  prompt_for_input: promptForInput,
  check_pending_prompt: checkPendingPrompt,
  respond_to_prompt: respondToPrompt,
};
