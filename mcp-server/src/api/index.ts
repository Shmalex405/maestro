/**
 * API Router for Frontend Dashboard
 *
 * This module provides REST API endpoints for the Next.js frontend
 * to interact with the pentest system.
 */

import { Router } from "express";
import { assessmentsRouter } from "./routes/assessments";
import { assessmentPlanRouter } from "./routes/assessment-plan";
import { assessmentTestResultsRouter } from "./routes/assessment-test-results";
import { findingsRouter } from "./routes/findings";
import { configRouter } from "./routes/config";
import { auditLogsRouter } from "./routes/audit-logs";
import { systemRouter } from "./routes/system";
import { contextRouter } from "./routes/context";
import { templatesRouter } from "./routes/templates";
import { guidanceRouter } from "./routes/guidance";
import { jiraRouter } from "./routes/jira";

export function createApiRouter(): Router {
  const router = Router();

  // Top-level health check
  router.get("/health", (req, res) => {
    res.json({ status: "ok", timestamp: new Date().toISOString() });
  });

  // Mount route handlers
  router.use("/assessments", assessmentsRouter);
  // Authoritative per-test outcomes from checkpoints — mounted on the same base;
  // its /:id/test-results path doesn't collide with assessmentsRouter's routes.
  router.use("/assessments", assessmentTestResultsRouter);
  router.use("/assessment-plan", assessmentPlanRouter);
  router.use("/findings", findingsRouter);
  router.use("/config", configRouter);
  router.use("/audit-logs", auditLogsRouter);
  router.use("/system", systemRouter);
  router.use("/context", contextRouter);
  router.use("/templates", templatesRouter);
  router.use("/guidance", guidanceRouter);
  router.use("/jira", jiraRouter);

  return router;
}
