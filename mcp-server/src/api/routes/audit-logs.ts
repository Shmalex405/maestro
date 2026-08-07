/**
 * Audit Logs API Routes
 */

import { Router, Request, Response } from "express";
import { getDatabase } from "../../logging/log-store";

export const auditLogsRouter = Router();

// List audit logs with filters
auditLogsRouter.get("/", (req: Request, res: Response) => {
  try {
    const db = getDatabase();
    const {
      tool,
      target,
      from,
      to,
      page = "1",
      limit = "50",
    } = req.query;

    let query = "SELECT * FROM audit_logs WHERE 1=1";
    const params: any[] = [];

    if (tool) {
      query += " AND tool = ?";
      params.push(tool);
    }

    if (target) {
      query += " AND target LIKE ?";
      params.push(`%${target}%`);
    }

    if (from) {
      query += " AND timestamp >= ?";
      params.push(from);
    }

    if (to) {
      query += " AND timestamp <= ?";
      params.push(to);
    }

    // Get total count
    const countQuery = query.replace("SELECT *", "SELECT COUNT(*) as count");
    const totalResult = db.prepare(countQuery).get(...params) as { count: number };
    const total = totalResult?.count || 0;

    // Add sorting and pagination
    query += " ORDER BY timestamp DESC";

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
    console.error("Error listing audit logs:", error);
    res.status(500).json({ error: "Failed to list audit logs" });
  }
});

// Get audit log statistics
auditLogsRouter.get("/stats", (req: Request, res: Response) => {
  try {
    const db = getDatabase();

    const total = (db.prepare("SELECT COUNT(*) as count FROM audit_logs").get() as { count: number }).count;

    const byTool = db
      .prepare("SELECT tool, COUNT(*) as count FROM audit_logs GROUP BY tool ORDER BY count DESC LIMIT 10")
      .all() as { tool: string; count: number }[];

    const byDay = db
      .prepare(`
        SELECT DATE(timestamp) as day, COUNT(*) as count
        FROM audit_logs
        WHERE timestamp >= datetime('now', '-30 days')
        GROUP BY DATE(timestamp)
        ORDER BY day DESC
      `)
      .all() as { day: string; count: number }[];

    const recentActivity = db
      .prepare("SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT 10")
      .all();

    res.json({
      total,
      by_tool: Object.fromEntries(byTool.map((r) => [r.tool, r.count])),
      by_day: byDay,
      recent_activity: recentActivity,
    });
  } catch (error) {
    console.error("Error getting audit log stats:", error);
    res.status(500).json({ error: "Failed to get audit log stats" });
  }
});
