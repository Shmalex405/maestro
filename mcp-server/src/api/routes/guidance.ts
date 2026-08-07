/**
 * Guidance API Routes
 *
 * REST endpoints for the frontend to interact with guidance prompts
 * created by agents when they encounter blockers (CAPTCHA, MFA, etc).
 */

import { Router, Request, Response } from "express";
import { getPendingPrompts, submitPromptResponse } from "../../tools/interactive";

export const guidanceRouter = Router();

/**
 * GET /api/guidance/pending
 * List all pending guidance requests (with screenshots)
 */
guidanceRouter.get("/pending", (req: Request, res: Response) => {
  const prompts = getPendingPrompts();

  // Filter to only guidance-type prompts, but include all for flexibility
  const guidancePrompts = prompts.map((p) => ({
    id: p.id,
    type: p.type,
    message: p.message,
    appName: p.appName,
    createdAt: p.createdAt,
    isGuidance: p.type === "guidance",
  }));

  res.json({
    count: guidancePrompts.length,
    prompts: guidancePrompts,
  });
});

/**
 * POST /api/guidance/:promptId/respond
 * Submit user's response to a guidance prompt
 */
guidanceRouter.post("/:promptId/respond", (req: Request, res: Response) => {
  const { promptId } = req.params;
  const { response: userResponse } = req.body;

  if (!userResponse) {
    res.status(400).json({
      error: "Missing 'response' in request body",
    });
    return;
  }

  const success = submitPromptResponse(promptId, userResponse);

  if (!success) {
    res.status(404).json({
      error: "Prompt not found or already responded to",
      promptId,
    });
    return;
  }

  res.json({
    success: true,
    promptId,
    message: "Response submitted to agent",
  });
});
