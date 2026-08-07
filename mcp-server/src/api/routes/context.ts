/**
 * Context API Routes
 * Provides contextual intelligence for assessment configuration
 */

import { Router, Request, Response } from "express";
import { getDatabase } from "../../logging/log-store";

export const contextRouter = Router();

interface TargetContext {
  target: string;
  previousAssessments: Array<{
    id: string;
    type: string;
    status: string;
    completedAt: string;
    findingsCount: number;
    criticalCount: number;
    highCount: number;
  }>;
  openFindings: Array<{
    id: string;
    title: string;
    severity: string;
    status: string;
    createdAt: string;
    daysSinceCreated: number;
  }>;
  remediatedFindings: Array<{
    id: string;
    title: string;
    severity: string;
    remediatedAt: string;
    daysSinceRemediated: number;
    lastTestedAt?: string;
    needsRegressionTest: boolean;
  }>;
  stats: {
    totalAssessments: number;
    lastAssessmentDate?: string;
    daysSinceLastAssessment?: number;
    totalFindings: number;
    openCritical: number;
    openHigh: number;
    pendingRegressionTests: number;
  };
}

interface IntelligenceSuggestion {
  id: string;
  type: 'regression' | 'open-finding' | 'coverage-gap' | 'threat-intel' | 'compliance';
  priority: 'high' | 'medium' | 'low';
  title: string;
  description: string;
  reasoning: string;
  relatedFindingId?: string;
}

/**
 * Get contextual intelligence for targets
 * POST /api/context/targets
 * Body: { targets: string[] }
 */
contextRouter.post("/targets", (req: Request, res: Response) => {
  try {
    const db = getDatabase();
    const { targets } = req.body;

    if (!targets || !Array.isArray(targets) || targets.length === 0) {
      return res.status(400).json({ error: "targets array is required" });
    }

    const now = new Date();
    const targetContexts: TargetContext[] = [];
    const allSuggestions: IntelligenceSuggestion[] = [];
    const allRegressionTests: Array<{
      findingId: string;
      title: string;
      severity: string;
      target: string;
      remediatedAt: string;
    }> = [];

    // Calculate days since a date
    const daysSince = (dateStr: string): number => {
      const date = new Date(dateStr);
      return Math.floor((now.getTime() - date.getTime()) / (1000 * 60 * 60 * 24));
    };

    for (const target of targets) {
      // Find previous assessments for this target
      const assessments = db.prepare(`
        SELECT id, type, status, completed_at, findings_count, critical_count, high_count, targets
        FROM assessments
        WHERE targets LIKE ?
        ORDER BY started_at DESC
        LIMIT 10
      `).all(`%${target}%`) as any[];

      const previousAssessments = assessments
        .filter(a => {
          // Verify the target is actually in the targets array
          try {
            const targetsArr = JSON.parse(a.targets || "[]");
            return targetsArr.some((t: string) =>
              t === target ||
              target.includes(t) ||
              t.includes(target)
            );
          } catch {
            return false;
          }
        })
        .map(a => ({
          id: a.id,
          type: a.type,
          status: a.status,
          completedAt: a.completed_at,
          findingsCount: a.findings_count,
          criticalCount: a.critical_count,
          highCount: a.high_count,
        }));

      // Find open findings for this target
      const openFindingsRaw = db.prepare(`
        SELECT id, title, severity, status, created_at
        FROM findings
        WHERE target LIKE ? AND status IN ('open', 'in_progress')
        ORDER BY
          CASE severity
            WHEN 'critical' THEN 1
            WHEN 'high' THEN 2
            WHEN 'medium' THEN 3
            WHEN 'low' THEN 4
            ELSE 5
          END,
          created_at DESC
        LIMIT 20
      `).all(`%${target}%`) as any[];

      const openFindings = openFindingsRaw.map(f => ({
        id: f.id,
        title: f.title,
        severity: f.severity,
        status: f.status,
        createdAt: f.created_at,
        daysSinceCreated: daysSince(f.created_at),
      }));

      // Find remediated findings that may need regression testing
      const remediatedFindingsRaw = db.prepare(`
        SELECT id, title, severity, updated_at, validated_at
        FROM findings
        WHERE target LIKE ? AND status = 'remediated'
        ORDER BY updated_at DESC
        LIMIT 10
      `).all(`%${target}%`) as any[];

      const REGRESSION_THRESHOLD_DAYS = 30; // Suggest regression if remediated in last 30 days

      const remediatedFindings = remediatedFindingsRaw.map(f => {
        const daysRemediated = daysSince(f.updated_at);
        const lastTestedDays = f.validated_at ? daysSince(f.validated_at) : null;
        const needsTest = daysRemediated <= REGRESSION_THRESHOLD_DAYS &&
                          (lastTestedDays === null || lastTestedDays > daysRemediated);

        return {
          id: f.id,
          title: f.title,
          severity: f.severity,
          remediatedAt: f.updated_at,
          daysSinceRemediated: daysRemediated,
          lastTestedAt: f.validated_at,
          needsRegressionTest: needsTest,
        };
      });

      // Add regression tests to global list
      remediatedFindings
        .filter(f => f.needsRegressionTest)
        .forEach(f => {
          allRegressionTests.push({
            findingId: f.id,
            title: f.title,
            severity: f.severity,
            target: target,
            remediatedAt: f.remediatedAt,
          });
        });

      // Calculate stats
      const openCritical = openFindings.filter(f => f.severity === 'critical').length;
      const openHigh = openFindings.filter(f => f.severity === 'high').length;
      const pendingRegressionTests = remediatedFindings.filter(f => f.needsRegressionTest).length;
      const lastAssessment = previousAssessments[0];

      const stats = {
        totalAssessments: previousAssessments.length,
        lastAssessmentDate: lastAssessment?.completedAt,
        daysSinceLastAssessment: lastAssessment ? daysSince(lastAssessment.completedAt) : undefined,
        totalFindings: openFindings.length + remediatedFindings.length,
        openCritical,
        openHigh,
        pendingRegressionTests,
      };

      // Generate suggestions for this target
      if (openCritical > 0) {
        const criticalFinding = openFindings.find(f => f.severity === 'critical');
        allSuggestions.push({
          id: `critical-${target}`,
          type: 'open-finding',
          priority: 'high',
          title: `${openCritical} Critical Finding${openCritical > 1 ? 's' : ''} Open`,
          description: `Target has unresolved critical vulnerabilities that should be prioritized`,
          reasoning: criticalFinding
            ? `"${criticalFinding.title}" has been open for ${criticalFinding.daysSinceCreated} days`
            : 'Critical findings require immediate attention',
          relatedFindingId: criticalFinding?.id,
        });
      }

      if (pendingRegressionTests > 0) {
        const highSevRegression = remediatedFindings.find(f =>
          f.needsRegressionTest && (f.severity === 'critical' || f.severity === 'high')
        );
        allSuggestions.push({
          id: `regression-${target}`,
          type: 'regression',
          priority: highSevRegression ? 'high' : 'medium',
          title: `${pendingRegressionTests} Regression Test${pendingRegressionTests > 1 ? 's' : ''} Recommended`,
          description: `Recently remediated findings should be verified`,
          reasoning: highSevRegression
            ? `"${highSevRegression.title}" was marked remediated ${highSevRegression.daysSinceRemediated} days ago`
            : 'Verify that fixes are effective',
          relatedFindingId: highSevRegression?.id,
        });
      }

      if (stats.daysSinceLastAssessment && stats.daysSinceLastAssessment > 90) {
        allSuggestions.push({
          id: `coverage-${target}`,
          type: 'coverage-gap',
          priority: 'medium',
          title: 'Extended Time Since Last Assessment',
          description: `Target hasn't been tested in ${stats.daysSinceLastAssessment} days`,
          reasoning: 'Regular security assessments help identify new vulnerabilities',
        });
      }

      targetContexts.push({
        target,
        previousAssessments,
        openFindings,
        remediatedFindings,
        stats,
      });
    }

    // Build coverage analysis
    const testedRecently = targetContexts
      .filter(t => t.stats.daysSinceLastAssessment !== undefined && t.stats.daysSinceLastAssessment <= 30)
      .map(t => t.target);

    const needsTesting = targetContexts
      .filter(t => t.stats.daysSinceLastAssessment !== undefined && t.stats.daysSinceLastAssessment > 30)
      .map(t => t.target);

    const neverTested = targetContexts
      .filter(t => t.stats.totalAssessments === 0)
      .map(t => t.target);

    // Build summary
    const totalOpenFindings = targetContexts.reduce((sum, t) => sum + t.openFindings.length, 0);
    const totalPreviousAssessments = targetContexts.reduce((sum, t) => sum + t.stats.totalAssessments, 0);
    const totalPendingRegression = allRegressionTests.length;

    // Find most critical open finding
    let mostCriticalOpenFinding: { id: string; title: string; target: string } | undefined;
    for (const ctx of targetContexts) {
      const critical = ctx.openFindings.find(f => f.severity === 'critical');
      if (critical) {
        mostCriticalOpenFinding = {
          id: critical.id,
          title: critical.title,
          target: ctx.target,
        };
        break;
      }
    }

    // Sort suggestions by priority
    const priorityOrder = { high: 0, medium: 1, low: 2 };
    allSuggestions.sort((a, b) => priorityOrder[a.priority] - priorityOrder[b.priority]);

    res.json({
      targets: targetContexts,
      suggestions: allSuggestions,
      regressionTests: allRegressionTests,
      coverageAnalysis: {
        testedRecently,
        needsTesting,
        neverTested,
      },
      summary: {
        totalPreviousAssessments,
        totalOpenFindings,
        pendingRegressionTests: totalPendingRegression,
        oldestUntestedTarget: neverTested[0],
        mostCriticalOpenFinding,
      },
    });
  } catch (error) {
    console.error("Error getting target context:", error);
    res.status(500).json({ error: "Failed to get target context" });
  }
});

/**
 * Get context for a single finding (for regression test details)
 * GET /api/context/finding/:id
 */
contextRouter.get("/finding/:id", (req: Request, res: Response) => {
  try {
    const db = getDatabase();
    const { id } = req.params;

    const finding = db.prepare(`
      SELECT f.*,
             GROUP_CONCAT(DISTINCT a.id) as assessment_ids
      FROM findings f
      LEFT JOIN assessment_findings af ON f.id = af.finding_id
      LEFT JOIN assessments a ON af.assessment_id = a.id
      WHERE f.id = ?
      GROUP BY f.id
    `).get(id) as any;

    if (!finding) {
      return res.status(404).json({ error: "Finding not found" });
    }

    // Get related findings (same target, similar type)
    const relatedFindings = db.prepare(`
      SELECT id, title, severity, status, created_at
      FROM findings
      WHERE target = ? AND id != ?
      ORDER BY created_at DESC
      LIMIT 5
    `).all(finding.target, id);

    res.json({
      finding,
      relatedFindings,
      assessmentIds: finding.assessment_ids?.split(',') || [],
    });
  } catch (error) {
    console.error("Error getting finding context:", error);
    res.status(500).json({ error: "Failed to get finding context" });
  }
});
