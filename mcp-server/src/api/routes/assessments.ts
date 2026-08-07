/**
 * Assessments API Routes
 */

import { Router, Request, Response } from "express";
import { v4 as uuidv4 } from "uuid";
import { getDatabase } from "../../logging/log-store";
import { AutonomousRunner } from "../../autonomous-runner";
// The SSE bus now lives in ../event-bus so the tool-dispatch chokepoint can emit
// onto it without importing the routes layer. Re-exported here for back-compat.
import { assessmentEvents } from "../event-bus";

export const assessmentsRouter = Router();

export { assessmentEvents };

interface Assessment {
  id: string;
  type: string;
  status: string;
  targets: string | null;
  repo_paths: string | null;
  credential_app: string | null;
  jira_project: string | null;
  email_recipients: string | null;
  severity_threshold: string;
  options: string | null;
  ai_instructions: string | null;
  progress: number;
  current_step: string | null;
  started_at: string;
  completed_at: string | null;
  findings_count: number;
  critical_count: number;
  high_count: number;
  error_message: string | null;
}

// AI Instructions interface
interface AIInstructions {
  missionStatement?: string;
  systemPrompt?: string;
  primaryObjectives?: string[];
  secondaryObjectives?: string[];
  outOfScope?: string[];
  focusAreas?: string[];
  riskTolerance: 'conservative' | 'balanced' | 'aggressive';
  autonomyLevel: 'supervised' | 'autonomous' | 'full-auto';
  escalationRules?: Array<{
    condition: string;
    action: 'alert' | 'pause' | 'continue';
    notify: string[];
  }>;
  updateFrequency: 'realtime' | 'phase-end' | 'completion';
  reportingStyle: 'technical' | 'executive' | 'both';
  mustVerify?: string[];
  knownIssues?: string[];
  previousContext?: string;
  phaseInstructions?: Record<string, string>;
  templateId?: string;
}

// Store running assessment runners
const runningAssessments = new Map<string, AutonomousRunner>();

// List assessments
assessmentsRouter.get("/", (req: Request, res: Response) => {
  try {
    const db = getDatabase();
    const { status, type, page = "1", limit = "20" } = req.query;

    let query = "SELECT * FROM assessments WHERE 1=1";
    const params: any[] = [];

    if (status) {
      query += " AND status = ?";
      params.push(status);
    }

    if (type) {
      query += " AND type = ?";
      params.push(type);
    }

    // Get total count
    const countQuery = query.replace("SELECT *", "SELECT COUNT(*) as count");
    const totalResult = db.prepare(countQuery).get(...params) as { count: number };
    const total = totalResult?.count || 0;

    // Add pagination
    const pageNum = parseInt(page as string);
    const limitNum = parseInt(limit as string);
    const offset = (pageNum - 1) * limitNum;

    query += " ORDER BY started_at DESC LIMIT ? OFFSET ?";
    params.push(limitNum, offset);

    const data = db.prepare(query).all(...params) as Assessment[];

    // Parse JSON fields
    const parsedData = data.map((a) => ({
      ...a,
      targets: a.targets ? JSON.parse(a.targets) : null,
      repo_paths: a.repo_paths ? JSON.parse(a.repo_paths) : null,
      email_recipients: a.email_recipients ? JSON.parse(a.email_recipients) : null,
      options: a.options ? JSON.parse(a.options) : null,
    }));

    res.json({
      data: parsedData,
      total,
      page: pageNum,
      limit: limitNum,
      hasMore: offset + data.length < total,
    });
  } catch (error) {
    console.error("Error listing assessments:", error);
    res.status(500).json({ error: "Failed to list assessments" });
  }
});

// Get single assessment
assessmentsRouter.get("/:id", (req: Request, res: Response) => {
  try {
    const db = getDatabase();
    const { id } = req.params;

    const assessment = db.prepare("SELECT * FROM assessments WHERE id = ?").get(id) as Assessment | undefined;

    if (!assessment) {
      return res.status(404).json({ error: "Assessment not found" });
    }

    res.json({
      ...assessment,
      targets: assessment.targets ? JSON.parse(assessment.targets) : null,
      repo_paths: assessment.repo_paths ? JSON.parse(assessment.repo_paths) : null,
      email_recipients: assessment.email_recipients ? JSON.parse(assessment.email_recipients) : null,
      options: assessment.options ? JSON.parse(assessment.options) : null,
      ai_instructions: assessment.ai_instructions ? JSON.parse(assessment.ai_instructions) : null,
    });
  } catch (error) {
    console.error("Error getting assessment:", error);
    res.status(500).json({ error: "Failed to get assessment" });
  }
});

// Create new assessment
assessmentsRouter.post("/", async (req: Request, res: Response) => {
  try {
    const db = getDatabase();
    const {
      type,
      targets,
      repo_paths,
      credential_app,
      jira_project,
      email_recipients,
      severity_threshold = "medium",
      options,
      ai_instructions,
      phases,
    } = req.body;

    if (!type) {
      return res.status(400).json({ error: "Assessment type is required" });
    }

    const id = uuidv4();
    const now = new Date().toISOString();

    // Ensure ai_instructions column exists (migration might not have run)
    try {
      db.prepare("ALTER TABLE assessments ADD COLUMN ai_instructions TEXT").run();
    } catch (e) {
      // Column already exists, ignore
    }

    try {
      db.prepare("ALTER TABLE assessments ADD COLUMN phases TEXT").run();
    } catch (e) {
      // Column already exists, ignore
    }

    // Insert assessment record
    db.prepare(`
      INSERT INTO assessments (
        id, type, status, targets, repo_paths, credential_app,
        jira_project, email_recipients, severity_threshold, options,
        ai_instructions, phases, progress, started_at, findings_count,
        critical_count, high_count
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      id,
      type,
      "pending",
      targets ? JSON.stringify(targets) : null,
      repo_paths ? JSON.stringify(repo_paths) : null,
      credential_app || null,
      jira_project || null,
      email_recipients ? JSON.stringify(email_recipients) : null,
      severity_threshold,
      options ? JSON.stringify(options) : null,
      ai_instructions ? JSON.stringify(ai_instructions) : null,
      phases ? JSON.stringify(phases) : null,
      0,
      now,
      0,
      0,
      0
    );

    // Start the assessment in background
    runAssessmentInBackground(id, {
      type,
      targets,
      repo_paths,
      jira_project,
      email_recipients,
      severity_threshold,
      ai_instructions,
      phases,
    });

    const assessment = db.prepare("SELECT * FROM assessments WHERE id = ?").get(id);

    res.status(201).json(assessment);
  } catch (error) {
    console.error("Error creating assessment:", error);
    res.status(500).json({ error: "Failed to create assessment" });
  }
});

// Cancel assessment
assessmentsRouter.delete("/:id", (req: Request, res: Response) => {
  try {
    const db = getDatabase();
    const { id } = req.params;

    const assessment = db.prepare("SELECT * FROM assessments WHERE id = ?").get(id) as Assessment | undefined;

    if (!assessment) {
      return res.status(404).json({ error: "Assessment not found" });
    }

    if (assessment.status !== "running" && assessment.status !== "pending") {
      return res.status(400).json({ error: "Assessment is not running" });
    }

    // Update status to cancelled
    db.prepare("UPDATE assessments SET status = ?, completed_at = ? WHERE id = ?")
      .run("cancelled", new Date().toISOString(), id);

    // Remove from running assessments
    runningAssessments.delete(id);

    // Emit cancellation event
    assessmentEvents.emit(`assessment:${id}`, {
      type: "status_change",
      data: { status: "cancelled", message: "Assessment cancelled by user" },
    });

    res.json({ success: true });
  } catch (error) {
    console.error("Error cancelling assessment:", error);
    res.status(500).json({ error: "Failed to cancel assessment" });
  }
});

// SSE endpoint for assessment events
assessmentsRouter.get("/:id/events", (req: Request, res: Response) => {
  const { id } = req.params;

  // Set SSE headers
  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");
  res.setHeader("Access-Control-Allow-Origin", "*");

  // Send initial connection event
  res.write(`event: connected\ndata: ${JSON.stringify({ assessmentId: id })}\n\n`);

  // Subscribe to events for this assessment
  const listener = (event: { type: string; data: any }) => {
    res.write(`event: ${event.type}\ndata: ${JSON.stringify(event.data)}\n\n`);
  };

  assessmentEvents.on(`assessment:${id}`, listener);

  // Clean up on client disconnect
  req.on("close", () => {
    assessmentEvents.off(`assessment:${id}`, listener);
  });
});

// Progress ingest (cross-process bridge). The STDIO MCP process (where the live
// assessment's `claude` tool calls run) POSTs each ProgressEvent here so it lands
// on THIS process's SSE bus and reaches subscribers. Localhost-only relay — no DB
// write, fire-and-forget from the caller's perspective. See progress/emitter.ts.
assessmentsRouter.post("/:id/progress", (req: Request, res: Response) => {
  const { id } = req.params;
  const event = req.body;
  if (event && typeof event === "object") {
    assessmentEvents.emit(`assessment:${id}`, {
      type: "progress_event",
      data: event,
    });
  }
  res.json({ ok: true });
});

// Get assessment logs
assessmentsRouter.get("/:id/logs", (req: Request, res: Response) => {
  try {
    const db = getDatabase();
    const { id } = req.params;

    // Get audit logs for this assessment's session
    const logs = db
      .prepare(
        `SELECT * FROM audit_logs
         WHERE session_id = ?
         ORDER BY timestamp ASC`
      )
      .all(id);

    res.json(logs);
  } catch (error) {
    console.error("Error getting assessment logs:", error);
    res.status(500).json({ error: "Failed to get assessment logs" });
  }
});

// Helper function to run assessment in background
async function runAssessmentInBackground(
  assessmentId: string,
  config: {
    type: string;
    targets?: string[];
    repo_paths?: string[];
    jira_project?: string;
    email_recipients?: string[];
    severity_threshold?: string;
    ai_instructions?: AIInstructions;
    phases?: string[];
  }
) {
  const db = getDatabase();

  try {
    // Update status to running
    db.prepare("UPDATE assessments SET status = ? WHERE id = ?").run("running", assessmentId);

    assessmentEvents.emit(`assessment:${assessmentId}`, {
      type: "status_change",
      data: { status: "running", message: "Assessment started" },
    });

    // Create runner instance
    const runner = new AutonomousRunner();
    runningAssessments.set(assessmentId, runner);

    // Run the assessment
    const result = await runner.runAssessment(config as any);

    // Update assessment with results
    db.prepare(`
      UPDATE assessments
      SET status = ?, completed_at = ?, findings_count = ?,
          critical_count = ?, high_count = ?, error_message = ?
      WHERE id = ?
    `).run(
      result.success ? "completed" : "failed",
      new Date().toISOString(),
      result.findings_count,
      result.critical_count,
      result.high_count,
      result.error || null,
      assessmentId
    );

    // Emit completion event
    assessmentEvents.emit(`assessment:${assessmentId}`, {
      type: result.success ? "completed" : "error",
      data: result,
    });

  } catch (error) {
    console.error(`Assessment ${assessmentId} failed:`, error);

    db.prepare("UPDATE assessments SET status = ?, completed_at = ?, error_message = ? WHERE id = ?")
      .run("failed", new Date().toISOString(), String(error), assessmentId);

    assessmentEvents.emit(`assessment:${assessmentId}`, {
      type: "error",
      data: { message: String(error) },
    });
  } finally {
    runningAssessments.delete(assessmentId);
  }
}

// Export function to emit progress events (to be called from autonomous runner)
export function emitAssessmentProgress(
  assessmentId: string,
  progress: number,
  currentStep: string
) {
  const db = getDatabase();

  db.prepare("UPDATE assessments SET progress = ?, current_step = ? WHERE id = ?")
    .run(progress, currentStep, assessmentId);

  assessmentEvents.emit(`assessment:${assessmentId}`, {
    type: "progress",
    data: { percent: progress, currentTool: currentStep },
  });
}
