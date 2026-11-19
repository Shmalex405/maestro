/**
 * Reports API Routes
 *
 * The engine owns its own SQLite database (a Docker volume inside the
 * container), separate from the desktop's. In local mode the desktop pulls
 * the engine's report rows through this route and copies them into its own
 * database, which is what its Reports page reads. Read-only: the desktop
 * never writes the engine's database.
 */

import { Router, Request, Response } from "express";
import { getDatabase } from "../../logging/log-store";

export const reportsRouter = Router();

// List reports recorded for one assessment
reportsRouter.get("/assessment/:assessmentId", (req: Request, res: Response) => {
  try {
    const db = getDatabase();
    const { assessmentId } = req.params;
    const reports = db
      .prepare(
        `SELECT * FROM reports WHERE assessment_id = ? ORDER BY created_at DESC`
      )
      .all(assessmentId);

    res.json({
      data: reports,
      total: reports.length,
      assessment_id: assessmentId,
    });
  } catch (error) {
    console.error("Error listing reports for assessment:", error);
    res.status(500).json({ error: "Failed to list reports for assessment" });
  }
});
