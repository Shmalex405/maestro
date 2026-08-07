/**
 * Findings API Routes
 */

import { Router, Request, Response } from "express";
import { getDatabase } from "../../logging/log-store";
import {
  generateReportContent,
  Finding,
  getFindingWithEvidence,
  getFindingsForAssessment,
} from "../../integrations/findings-db";
import { createJiraTicket } from "../../integrations/jira";

export const findingsRouter = Router();

// List findings with filters
findingsRouter.get("/", (req: Request, res: Response) => {
  try {
    const db = getDatabase();
    const {
      severity,
      status,
      target,
      search,
      assessment_id,
      page = "1",
      limit = "20",
      sort = "created_at:desc",
    } = req.query;

    let query: string;
    const params: any[] = [];

    // If filtering by assessment, join with assessment_findings table
    if (assessment_id) {
      query = `SELECT DISTINCT f.* FROM findings f
               JOIN assessment_findings af ON f.id = af.finding_id
               WHERE af.assessment_id = ?`;
      params.push(assessment_id);
    } else {
      query = "SELECT * FROM findings WHERE 1=1";
    }

    // Filter by severity (comma-separated)
    if (severity) {
      const severities = (severity as string).split(",");
      const placeholders = severities.map(() => "?").join(",");
      query += ` AND ${assessment_id ? "f." : ""}severity IN (${placeholders})`;
      params.push(...severities);
    }

    // Filter by status (comma-separated)
    if (status) {
      const statuses = (status as string).split(",");
      const placeholders = statuses.map(() => "?").join(",");
      query += ` AND ${assessment_id ? "f." : ""}status IN (${placeholders})`;
      params.push(...statuses);
    }

    // Filter by target (partial match)
    if (target) {
      query += ` AND ${assessment_id ? "f." : ""}target LIKE ?`;
      params.push(`%${target}%`);
    }

    // Search in title and description
    if (search) {
      const prefix = assessment_id ? "f." : "";
      query += ` AND (${prefix}title LIKE ? OR ${prefix}description LIKE ?)`;
      params.push(`%${search}%`, `%${search}%`);
    }

    // Get total count
    const countQuery = query.replace("SELECT *", "SELECT COUNT(*) as count");
    const totalResult = db.prepare(countQuery).get(...params) as { count: number };
    const total = totalResult?.count || 0;

    // Add sorting
    const [sortField, sortOrder] = (sort as string).split(":");
    const validFields = ["created_at", "severity", "status", "title", "target"];
    const validOrders = ["asc", "desc"];
    const prefix = assessment_id ? "f." : "";

    if (validFields.includes(sortField) && validOrders.includes(sortOrder)) {
      // Custom severity ordering
      if (sortField === "severity") {
        query += ` ORDER BY CASE ${prefix}severity
          WHEN 'critical' THEN 1
          WHEN 'high' THEN 2
          WHEN 'medium' THEN 3
          WHEN 'low' THEN 4
          WHEN 'info' THEN 5
          ELSE 6 END ${sortOrder.toUpperCase()}`;
      } else {
        query += ` ORDER BY ${prefix}${sortField} ${sortOrder.toUpperCase()}`;
      }
    } else {
      query += ` ORDER BY ${prefix}created_at DESC`;
    }

    // Add pagination
    const pageNum = parseInt(page as string);
    const limitNum = parseInt(limit as string);
    const offset = (pageNum - 1) * limitNum;

    query += " LIMIT ? OFFSET ?";
    params.push(limitNum, offset);

    const data = db.prepare(query).all(...params);

    res.json({
      data,
      total,
      page: pageNum,
      limit: limitNum,
      hasMore: offset + data.length < total,
    });
  } catch (error) {
    console.error("Error listing findings:", error);
    res.status(500).json({ error: "Failed to list findings" });
  }
});

// Get findings stats
findingsRouter.get("/stats", (req: Request, res: Response) => {
  try {
    const db = getDatabase();

    const total = (db.prepare("SELECT COUNT(*) as count FROM findings").get() as { count: number }).count;

    const bySeverity = db
      .prepare("SELECT severity, COUNT(*) as count FROM findings GROUP BY severity")
      .all() as { severity: string; count: number }[];

    const byStatus = db
      .prepare("SELECT status, COUNT(*) as count FROM findings GROUP BY status")
      .all() as { status: string; count: number }[];

    res.json({
      total,
      by_severity: Object.fromEntries(bySeverity.map((r) => [r.severity, r.count])),
      by_status: Object.fromEntries(byStatus.map((r) => [r.status, r.count])),
    });
  } catch (error) {
    console.error("Error getting findings stats:", error);
    res.status(500).json({ error: "Failed to get findings stats" });
  }
});

// Export findings
findingsRouter.get("/export", async (req: Request, res: Response) => {
  try {
    const db = getDatabase();
    const { format = "json", severity, status } = req.query;

    let query = "SELECT * FROM findings WHERE 1=1";
    const params: any[] = [];

    if (severity) {
      const severities = (severity as string).split(",");
      const placeholders = severities.map(() => "?").join(",");
      query += ` AND severity IN (${placeholders})`;
      params.push(...severities);
    }

    if (status) {
      const statuses = (status as string).split(",");
      const placeholders = statuses.map(() => "?").join(",");
      query += ` AND status IN (${placeholders})`;
      params.push(...statuses);
    }

    query += " ORDER BY created_at DESC";

    const findings = db.prepare(query).all(...params) as Finding[];

    if (format === "csv") {
      // Generate CSV
      const headers = [
        "id",
        "title",
        "severity",
        "status",
        "target",
        "cve",
        "created_at",
        "jira_ticket",
      ];
      const csv = [
        headers.join(","),
        ...findings.map((f) =>
          headers.map((h) => `"${(f[h as keyof Finding] || "").toString().replace(/"/g, '""')}"`).join(",")
        ),
      ].join("\n");

      res.setHeader("Content-Type", "text/csv");
      res.setHeader("Content-Disposition", "attachment; filename=findings.csv");
      return res.send(csv);
    }

    if (format === "markdown" || format === "html") {
      const content = await generateReportContent(findings, format as string, true);

      if (format === "markdown") {
        res.setHeader("Content-Type", "text/markdown");
        res.setHeader("Content-Disposition", "attachment; filename=findings.md");
      } else {
        res.setHeader("Content-Type", "text/html");
      }

      return res.send(content);
    }

    // Default: JSON
    res.json(findings);
  } catch (error) {
    console.error("Error exporting findings:", error);
    res.status(500).json({ error: "Failed to export findings" });
  }
});

// Get single finding with evidence sources
findingsRouter.get("/:id", async (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    const { include_evidence } = req.query;

    // If evidence requested, get full finding with evidence sources
    if (include_evidence === "true") {
      const findingWithEvidence = await getFindingWithEvidence(id);

      if (!findingWithEvidence) {
        return res.status(404).json({ error: "Finding not found" });
      }

      return res.json(findingWithEvidence);
    }

    // Standard finding lookup
    const db = getDatabase();
    const finding = db.prepare("SELECT * FROM findings WHERE id = ?").get(id);

    if (!finding) {
      return res.status(404).json({ error: "Finding not found" });
    }

    res.json(finding);
  } catch (error) {
    console.error("Error getting finding:", error);
    res.status(500).json({ error: "Failed to get finding" });
  }
});

// Update finding
findingsRouter.patch("/:id", (req: Request, res: Response) => {
  try {
    const db = getDatabase();
    const { id } = req.params;
    const updates = req.body;

    // Check if finding exists
    const existing = db.prepare("SELECT * FROM findings WHERE id = ?").get(id);
    if (!existing) {
      return res.status(404).json({ error: "Finding not found" });
    }

    // Build update query
    const allowedFields = ["status", "remediation", "jira_ticket"];
    const setClauses: string[] = [];
    const params: any[] = [];

    for (const field of allowedFields) {
      if (updates[field] !== undefined) {
        setClauses.push(`${field} = ?`);
        params.push(updates[field]);
      }
    }

    if (setClauses.length === 0) {
      return res.status(400).json({ error: "No valid fields to update" });
    }

    // Add updated_at
    setClauses.push("updated_at = ?");
    params.push(new Date().toISOString());

    // Add id for WHERE clause
    params.push(id);

    db.prepare(`UPDATE findings SET ${setClauses.join(", ")} WHERE id = ?`).run(...params);

    const updated = db.prepare("SELECT * FROM findings WHERE id = ?").get(id);
    res.json(updated);
  } catch (error) {
    console.error("Error updating finding:", error);
    res.status(500).json({ error: "Failed to update finding" });
  }
});

// Delete finding
findingsRouter.delete("/:id", (req: Request, res: Response) => {
  try {
    const db = getDatabase();
    const { id } = req.params;

    const existing = db.prepare("SELECT * FROM findings WHERE id = ?").get(id);
    if (!existing) {
      return res.status(404).json({ error: "Finding not found" });
    }

    db.prepare("DELETE FROM findings WHERE id = ?").run(id);
    res.json({ success: true });
  } catch (error) {
    console.error("Error deleting finding:", error);
    res.status(500).json({ error: "Failed to delete finding" });
  }
});

// Get findings for a specific assessment
findingsRouter.get("/assessment/:assessmentId", async (req: Request, res: Response) => {
  try {
    const { assessmentId } = req.params;

    const findings = await getFindingsForAssessment(assessmentId);

    res.json({
      data: findings,
      total: findings.length,
      assessment_id: assessmentId,
    });
  } catch (error) {
    console.error("Error getting findings for assessment:", error);
    res.status(500).json({ error: "Failed to get findings for assessment" });
  }
});

// Create Jira ticket for finding
findingsRouter.post("/:id/jira", async (req: Request, res: Response) => {
  try {
    const db = getDatabase();
    const { id } = req.params;
    const { project_key } = req.body;

    if (!project_key) {
      return res.status(400).json({ error: "project_key is required" });
    }

    const finding = db.prepare("SELECT * FROM findings WHERE id = ?").get(id) as Finding | undefined;
    if (!finding) {
      return res.status(404).json({ error: "Finding not found" });
    }

    if (finding.jira_ticket) {
      return res.status(400).json({
        error: "Finding already has a Jira ticket",
        ticket_key: finding.jira_ticket,
      });
    }

    // Create Jira ticket
    const priority = finding.severity === "critical" ? "Highest" : finding.severity === "high" ? "High" : "Medium";
    const result = await createJiraTicket(id, project_key, priority);

    if (result.ticket_key) {
      // Update finding with ticket key
      db.prepare("UPDATE findings SET jira_ticket = ?, updated_at = ? WHERE id = ?")
        .run(result.ticket_key, new Date().toISOString(), id);
    }

    res.json(result);
  } catch (error) {
    console.error("Error creating Jira ticket:", error);
    res.status(500).json({ error: "Failed to create Jira ticket" });
  }
});
