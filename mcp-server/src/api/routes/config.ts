/**
 * Configuration API Routes
 */

import { Router, Request, Response } from "express";
import * as fs from "fs";
import * as path from "path";
import * as yaml from "yaml";
import { validateScope } from "../../scope/validator";
import {
  initiateOtpFlow,
  authenticateWithOtp,
  getAppCredentials,
} from "../../utils/auth-handler";
import {
  getPendingPrompts,
  submitPromptResponse,
} from "../../tools/interactive";

export const configRouter = Router();

const CONFIG_DIR = path.join(__dirname, "../../../config");

// Helper to read YAML config
function readConfig(filename: string): any {
  const filepath = path.join(CONFIG_DIR, filename);
  if (!fs.existsSync(filepath)) {
    return null;
  }
  const content = fs.readFileSync(filepath, "utf-8");
  return yaml.parse(content);
}

// Helper to write YAML config
function writeConfig(filename: string, data: any): void {
  const filepath = path.join(CONFIG_DIR, filename);
  const content = yaml.stringify(data);
  fs.writeFileSync(filepath, content, "utf-8");
}

// === SCOPE CONFIG ===

// Get scope config
configRouter.get("/scope", (req: Request, res: Response) => {
  try {
    const config = readConfig("scope.yml");
    if (!config) {
      return res.status(404).json({ error: "Scope configuration not found" });
    }
    res.json(config);
  } catch (error) {
    console.error("Error reading scope config:", error);
    res.status(500).json({ error: "Failed to read scope configuration" });
  }
});

// Update scope config
configRouter.put("/scope", (req: Request, res: Response) => {
  try {
    const config = req.body;

    // Validate structure
    if (!config.networks && !config.domains) {
      return res.status(400).json({ error: "Invalid scope configuration: must have networks or domains" });
    }

    writeConfig("scope.yml", config);
    res.json(config);
  } catch (error) {
    console.error("Error writing scope config:", error);
    res.status(500).json({ error: "Failed to write scope configuration" });
  }
});

// Validate a target against scope
configRouter.post("/scope/validate", async (req: Request, res: Response) => {
  try {
    const { target } = req.body;

    if (!target) {
      return res.status(400).json({ error: "Target is required" });
    }

    const result = await validateScope(target);
    res.json(result);
  } catch (error) {
    console.error("Error validating scope:", error);
    res.status(500).json({ error: "Failed to validate scope" });
  }
});

// === CREDENTIALS CONFIG ===

// Get credentials config (masked)
configRouter.get("/credentials", (req: Request, res: Response) => {
  try {
    const config = readConfig("credentials.yml");
    if (!config) {
      return res.status(404).json({ error: "Credentials configuration not found" });
    }

    // Mask sensitive fields
    const masked = JSON.parse(JSON.stringify(config));

    if (masked.applications) {
      for (const app of Object.values(masked.applications) as any[]) {
        if (app.password) app.password = "********";
        if (app.api_key) app.api_key = "********";
        if (app.token) app.token = "********";
        if (app.client_secret) app.client_secret = "********";
        if (app.session_cookie) app.session_cookie = "********";
      }
    }

    if (masked.test_accounts) {
      for (const account of Object.values(masked.test_accounts) as any[]) {
        if (account.password) account.password = "********";
      }
    }

    res.json(masked);
  } catch (error) {
    console.error("Error reading credentials config:", error);
    res.status(500).json({ error: "Failed to read credentials configuration" });
  }
});

// Update credentials config
configRouter.put("/credentials", (req: Request, res: Response) => {
  try {
    const newConfig = req.body;
    const existingConfig = readConfig("credentials.yml") || {};

    // Preserve masked fields from existing config
    if (newConfig.applications && existingConfig.applications) {
      for (const [name, app] of Object.entries(newConfig.applications) as [string, any][]) {
        const existing = existingConfig.applications[name];
        if (existing) {
          if (app.password === "********") app.password = existing.password;
          if (app.api_key === "********") app.api_key = existing.api_key;
          if (app.token === "********") app.token = existing.token;
          if (app.client_secret === "********") app.client_secret = existing.client_secret;
          if (app.session_cookie === "********") app.session_cookie = existing.session_cookie;
        }
      }
    }

    if (newConfig.test_accounts && existingConfig.test_accounts) {
      for (const [role, account] of Object.entries(newConfig.test_accounts) as [string, any][]) {
        const existing = existingConfig.test_accounts[role];
        if (existing && account.password === "********") {
          account.password = existing.password;
        }
      }
    }

    writeConfig("credentials.yml", newConfig);

    // Return masked version
    const masked = JSON.parse(JSON.stringify(newConfig));
    if (masked.applications) {
      for (const app of Object.values(masked.applications) as any[]) {
        if (app.password) app.password = "********";
        if (app.api_key) app.api_key = "********";
        if (app.token) app.token = "********";
        if (app.client_secret) app.client_secret = "********";
        if (app.session_cookie) app.session_cookie = "********";
      }
    }
    if (masked.test_accounts) {
      for (const account of Object.values(masked.test_accounts) as any[]) {
        if (account.password) account.password = "********";
      }
    }

    res.json(masked);
  } catch (error) {
    console.error("Error writing credentials config:", error);
    res.status(500).json({ error: "Failed to write credentials configuration" });
  }
});

// Test credential connection
configRouter.post("/credentials/test", async (req: Request, res: Response) => {
  try {
    const { app_name } = req.body;

    if (!app_name) {
      return res.status(400).json({ error: "app_name is required" });
    }

    const config = readConfig("credentials.yml");
    if (!config?.applications?.[app_name]) {
      return res.status(404).json({ error: `Application '${app_name}' not found` });
    }

    const app = config.applications[app_name];

    // Try to make a simple request to the base_url
    try {
      const response = await fetch(app.base_url, {
        method: "HEAD",
        signal: AbortSignal.timeout(5000),
      });

      res.json({
        success: response.ok,
        message: response.ok
          ? `Successfully connected to ${app.base_url}`
          : `Server responded with ${response.status}`,
      });
    } catch (fetchError: any) {
      res.json({
        success: false,
        message: `Failed to connect: ${fetchError.message}`,
      });
    }
  } catch (error) {
    console.error("Error testing credentials:", error);
    res.status(500).json({ error: "Failed to test credentials" });
  }
});

// === TOOLS CONFIG ===

// Get tools config
configRouter.get("/tools", (req: Request, res: Response) => {
  try {
    const config = readConfig("tools.yml");
    if (!config) {
      return res.status(404).json({ error: "Tools configuration not found" });
    }
    res.json(config);
  } catch (error) {
    console.error("Error reading tools config:", error);
    res.status(500).json({ error: "Failed to read tools configuration" });
  }
});

// Update tools config
configRouter.put("/tools", (req: Request, res: Response) => {
  try {
    const config = req.body;
    writeConfig("tools.yml", config);
    res.json(config);
  } catch (error) {
    console.error("Error writing tools config:", error);
    res.status(500).json({ error: "Failed to write tools configuration" });
  }
});

// === AGENTS CONFIG ===

// Get agents config
configRouter.get("/agents", (req: Request, res: Response) => {
  try {
    const config = readConfig("agents.yml");
    if (!config) {
      return res.status(404).json({ error: "Agents configuration not found" });
    }
    res.json(config);
  } catch (error) {
    console.error("Error reading agents config:", error);
    res.status(500).json({ error: "Failed to read agents configuration" });
  }
});

// Update agents config
configRouter.put("/agents", (req: Request, res: Response) => {
  try {
    const config = req.body;
    writeConfig("agents.yml", config);
    res.json(config);
  } catch (error) {
    console.error("Error writing agents config:", error);
    res.status(500).json({ error: "Failed to write agents configuration" });
  }
});

// === OTP AUTHENTICATION ===

// Initiate OTP flow (sends OTP to user's email/phone)
configRouter.post("/credentials/otp/initiate", async (req: Request, res: Response) => {
  try {
    const { app_name } = req.body;

    if (!app_name) {
      return res.status(400).json({ error: "app_name is required" });
    }

    const app = await getAppCredentials(app_name);
    if (!app) {
      return res.status(404).json({ error: `Application '${app_name}' not found` });
    }

    if (app.auth_type !== "otp_email") {
      return res.status(400).json({
        error: `Application '${app_name}' does not use OTP authentication (auth_type: ${app.auth_type})`
      });
    }

    const result = await initiateOtpFlow(app_name);

    if (result.success) {
      res.json({
        success: true,
        message: `OTP sent to ${result.username}`,
        username: result.username,
      });
    } else {
      res.status(400).json({
        success: false,
        error: result.error,
      });
    }
  } catch (error) {
    console.error("Error initiating OTP:", error);
    res.status(500).json({ error: "Failed to initiate OTP flow" });
  }
});

// Verify OTP and get session token
configRouter.post("/credentials/otp/verify", async (req: Request, res: Response) => {
  try {
    const { app_name, otp_code } = req.body;

    if (!app_name || !otp_code) {
      return res.status(400).json({ error: "app_name and otp_code are required" });
    }

    const result = await authenticateWithOtp(app_name, otp_code);

    if (result.success) {
      res.json({
        success: true,
        message: "Successfully authenticated",
        // Don't return the actual token for security
        authenticated: true,
      });
    } else {
      res.status(400).json({
        success: false,
        error: result.error,
      });
    }
  } catch (error) {
    console.error("Error verifying OTP:", error);
    res.status(500).json({ error: "Failed to verify OTP" });
  }
});

// === INTERACTIVE PROMPTS ===

// Get all pending prompts
configRouter.get("/prompts", (req: Request, res: Response) => {
  try {
    const prompts = getPendingPrompts();
    res.json({ prompts });
  } catch (error) {
    console.error("Error getting pending prompts:", error);
    res.status(500).json({ error: "Failed to get pending prompts" });
  }
});

// Respond to a pending prompt
configRouter.post("/prompts/:id/respond", (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    const { value } = req.body;

    if (!value) {
      return res.status(400).json({ error: "value is required" });
    }

    const success = submitPromptResponse(id, value);

    if (success) {
      res.json({
        success: true,
        message: "Response submitted",
      });
    } else {
      res.status(404).json({
        success: false,
        error: "Prompt not found or already responded to",
      });
    }
  } catch (error) {
    console.error("Error responding to prompt:", error);
    res.status(500).json({ error: "Failed to respond to prompt" });
  }
});
