/**
 * Jira Integration API Routes
 *
 * Provides endpoints for testing connection, listing projects/boards/issue types/epics,
 * and creating tickets (single, bulk, combined).
 */

import { Router, Request, Response } from "express";
import {
  testJiraConnection,
  testJiraConnectionWithCredentials,
  listJiraProjects,
  listJiraProjectsWithCredentials,
  listJiraBoards,
  listJiraIssueTypes,
  listJiraEpics,
  searchJiraIssues,
  createJiraTicketEnhanced,
  createCombinedJiraTicket,
  createJiraTicketFromReport,
} from "../../integrations/jira";

export const jiraRouter = Router();

/**
 * POST /api/jira/test
 * Test Jira connection. Accepts optional explicit credentials in body.
 */
jiraRouter.post("/test", async (req: Request, res: Response) => {
  try {
    const { url, email, api_token } = req.body || {};
    if (url && email && api_token) {
      const result = await testJiraConnectionWithCredentials(url, email, api_token);
      return res.json(result);
    }
    const result = await testJiraConnection();
    res.json(result);
  } catch (error) {
    res.status(500).json({ status: "error", error: "Failed to test Jira connection" });
  }
});

/**
 * GET /api/jira/projects
 */
jiraRouter.get("/projects", async (_req: Request, res: Response) => {
  try {
    const result = await listJiraProjects();
    res.json(result);
  } catch (error) {
    res.status(500).json({ status: "error", error: "Failed to list Jira projects" });
  }
});

/**
 * POST /api/jira/projects — with explicit credentials (pre-save)
 */
jiraRouter.post("/projects", async (req: Request, res: Response) => {
  try {
    const { url, email, api_token } = req.body || {};
    if (!url || !email || !api_token) {
      return res.status(400).json({ status: "error", error: "url, email, and api_token are required" });
    }
    const result = await listJiraProjectsWithCredentials(url, email, api_token);
    res.json(result);
  } catch (error) {
    res.status(500).json({ status: "error", error: "Failed to list Jira projects" });
  }
});

/**
 * GET /api/jira/boards?project=KEY
 */
jiraRouter.get("/boards", async (req: Request, res: Response) => {
  try {
    const { project } = req.query;
    const result = await listJiraBoards(project as string | undefined);
    res.json(result);
  } catch (error) {
    res.status(500).json({ status: "error", error: "Failed to list Jira boards" });
  }
});

/**
 * GET /api/jira/issue-types/:projectKey
 */
jiraRouter.get("/issue-types/:projectKey", async (req: Request, res: Response) => {
  try {
    const result = await listJiraIssueTypes(req.params.projectKey);
    res.json(result);
  } catch (error) {
    res.status(500).json({ status: "error", error: "Failed to list issue types" });
  }
});

/**
 * GET /api/jira/epics/:projectKey
 */
jiraRouter.get("/epics/:projectKey", async (req: Request, res: Response) => {
  try {
    const result = await listJiraEpics(req.params.projectKey);
    res.json(result);
  } catch (error) {
    res.status(500).json({ status: "error", error: "Failed to list epics" });
  }
});

/**
 * GET /api/jira/search/:projectKey?q=text&issueType=Epic&maxResults=20
 * Search Jira issues by text within a project.
 */
jiraRouter.get("/search/:projectKey", async (req: Request, res: Response) => {
  try {
    const { projectKey } = req.params;
    const { q, issueType, maxResults } = req.query;
    const result = await searchJiraIssues(projectKey, (q as string) || "", {
      issueType: issueType as string | undefined,
      maxResults: maxResults ? parseInt(maxResults as string, 10) : undefined,
    });
    res.json(result);
  } catch (error) {
    res.status(500).json({ status: "error", error: "Failed to search Jira issues" });
  }
});

/**
 * POST /api/jira/tickets
 * Create ticket(s) from findings.
 * Body: { finding_ids: string[], mode: "individual" | "combined", options: CreateTicketOptions, title?: string }
 */
jiraRouter.post("/tickets", async (req: Request, res: Response) => {
  try {
    const { finding_ids, mode, options, title } = req.body;

    if (!finding_ids || !Array.isArray(finding_ids) || finding_ids.length === 0) {
      return res.status(400).json({ status: "error", error: "finding_ids array is required" });
    }
    if (!options?.projectKey) {
      return res.status(400).json({ status: "error", error: "options.projectKey is required" });
    }

    if (mode === "combined") {
      // Single combined ticket
      const result = await createCombinedJiraTicket(finding_ids, { ...options, title });
      return res.json(result);
    }

    // Individual tickets — create one per finding
    const results: Array<{ finding_id: string; status: string; ticket_key?: string; error?: string }> = [];
    for (const findingId of finding_ids) {
      const result = await createJiraTicketEnhanced(findingId, options);
      results.push({ finding_id: findingId, ...result });
    }

    const created = results.filter((r) => r.status === "created");
    const failed = results.filter((r) => r.status === "error");

    res.json({
      status: failed.length === 0 ? "created" : created.length > 0 ? "partial" : "error",
      total: results.length,
      created: created.length,
      failed: failed.length,
      results,
    });
  } catch (error) {
    res.status(500).json({ status: "error", error: "Failed to create Jira tickets" });
  }
});

/**
 * POST /api/jira/tickets/from-report
 * Create a ticket from pre-formatted report markdown content.
 * Body: { projectKey, epicKey, summary, markdownBody, priority, labels, issueType? }
 */
jiraRouter.post("/tickets/from-report", async (req: Request, res: Response) => {
  try {
    const { projectKey, epicKey, summary, markdownBody, priority, labels, issueType, customFields } = req.body;

    if (!projectKey || !summary || !markdownBody) {
      return res.status(400).json({ status: "error", error: "projectKey, summary, and markdownBody are required" });
    }

    const result = await createJiraTicketFromReport({
      projectKey,
      epicKey: epicKey || "",
      summary,
      markdownBody,
      priority: priority || "Medium",
      labels: labels || ["security"],
      issueType,
      customFields,
    });

    res.json(result);
  } catch (error) {
    res.status(500).json({ status: "error", error: "Failed to create ticket from report" });
  }
});
