/**
 * Checkpoint Manager
 *
 * Saves and restores orchestrator state between agent phases.
 * Enables assessment resume after failures, crashes, or intentional pauses.
 */

import { getDatabase } from "../logging/log-store";
import { AgentFinding } from "./base-agent";
import { OrchestratorConfig, AgentName } from "./orchestrator";

export interface Checkpoint {
  id: string;
  assessmentId: string;
  agentName: string;
  phaseIndex: number;
  sharedContext: Record<string, any>;
  allFindings: AgentFinding[];
  completedAgents: AgentName[];
  orchestratorConfig: OrchestratorConfig;
  status: "completed" | "failed_during";
  errorMessage?: string;
  createdAt: string;
}

type CheckpointInput = Omit<Checkpoint, "id" | "createdAt">;

// Max checkpoint payload size (10MB) - truncate evidence if exceeded
const MAX_CHECKPOINT_SIZE = 10 * 1024 * 1024;

export class CheckpointManager {
  /**
   * Save a checkpoint after an agent completes (or fails)
   */
  saveCheckpoint(input: CheckpointInput): string {
    const db = getDatabase();
    const id = `checkpoint-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    const createdAt = new Date().toISOString();

    // Strip large toolResults from context to keep checkpoint size manageable
    const cleanedContext = this.stripLargeData(input.sharedContext);
    const cleanedFindings = this.stripFindingsEvidence(input.allFindings);

    const sharedContextJson = JSON.stringify(cleanedContext);
    const allFindingsJson = JSON.stringify(cleanedFindings);
    const completedAgentsJson = JSON.stringify(input.completedAgents);
    const orchestratorConfigJson = JSON.stringify(input.orchestratorConfig);

    // Check total size
    const totalSize =
      sharedContextJson.length +
      allFindingsJson.length +
      completedAgentsJson.length +
      orchestratorConfigJson.length;

    if (totalSize > MAX_CHECKPOINT_SIZE) {
      console.warn(
        `[checkpoint-manager] Checkpoint size (${(totalSize / 1024 / 1024).toFixed(1)}MB) exceeds limit. Truncating context.`
      );
    }

    const stmt = db.prepare(`
      INSERT INTO assessment_checkpoints (
        id, assessment_id, agent_name, phase_index,
        shared_context, all_findings, completed_agents,
        orchestrator_config, status, error_message, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    stmt.run(
      id,
      input.assessmentId,
      input.agentName,
      input.phaseIndex,
      sharedContextJson,
      allFindingsJson,
      completedAgentsJson,
      orchestratorConfigJson,
      input.status,
      input.errorMessage || null,
      createdAt
    );

    console.log(
      `[checkpoint-manager] Saved checkpoint ${id} for assessment ${input.assessmentId} after ${input.agentName} (${input.status})`
    );

    return id;
  }

  /**
   * Load the latest checkpoint for an assessment
   */
  getLatestCheckpoint(assessmentId: string): Checkpoint | null {
    const db = getDatabase();

    const row = db
      .prepare(
        `SELECT * FROM assessment_checkpoints
         WHERE assessment_id = ?
         ORDER BY created_at DESC
         LIMIT 1`
      )
      .get(assessmentId) as any;

    if (!row) return null;

    return this.rowToCheckpoint(row);
  }

  /**
   * Load all checkpoints for an assessment (ordered by creation time)
   */
  getCheckpoints(assessmentId: string): Checkpoint[] {
    const db = getDatabase();

    const rows = db
      .prepare(
        `SELECT * FROM assessment_checkpoints
         WHERE assessment_id = ?
         ORDER BY created_at ASC`
      )
      .all(assessmentId) as any[];

    return rows.map((row) => this.rowToCheckpoint(row));
  }

  /**
   * Delete all checkpoints for an assessment (cleanup after completion)
   */
  deleteCheckpoints(assessmentId: string): void {
    const db = getDatabase();

    const result = db
      .prepare(`DELETE FROM assessment_checkpoints WHERE assessment_id = ?`)
      .run(assessmentId);

    console.log(
      `[checkpoint-manager] Deleted ${result.changes} checkpoints for assessment ${assessmentId}`
    );
  }

  /**
   * Convert a database row to a Checkpoint object
   */
  private rowToCheckpoint(row: any): Checkpoint {
    return {
      id: row.id,
      assessmentId: row.assessment_id,
      agentName: row.agent_name,
      phaseIndex: row.phase_index,
      sharedContext: JSON.parse(row.shared_context || "{}"),
      allFindings: JSON.parse(row.all_findings || "[]"),
      completedAgents: JSON.parse(row.completed_agents || "[]"),
      orchestratorConfig: JSON.parse(row.orchestrator_config || "{}"),
      status: row.status,
      errorMessage: row.error_message || undefined,
      createdAt: row.created_at,
    };
  }

  /**
   * Strip large data from shared context to keep checkpoints manageable.
   * Removes raw tool results (can be re-generated on resume) but keeps
   * summary data, findings, and agent-produced context.
   */
  private stripLargeData(context: Record<string, any>): Record<string, any> {
    const cleaned = { ...context };

    // Remove raw tool results (these are large and can be re-generated)
    delete cleaned.toolResults;

    // Truncate very large string values
    for (const [key, value] of Object.entries(cleaned)) {
      if (typeof value === "string" && value.length > 50000) {
        cleaned[key] = value.slice(0, 50000) + "\n... [truncated for checkpoint]";
      }
    }

    return cleaned;
  }

  /**
   * Strip long evidence strings from findings to reduce checkpoint size.
   * Keep first 5000 chars of evidence per finding.
   */
  private stripFindingsEvidence(findings: AgentFinding[]): AgentFinding[] {
    return findings.map((f) => ({
      ...f,
      evidence:
        f.evidence && f.evidence.length > 5000
          ? f.evidence.slice(0, 5000) + "\n... [truncated for checkpoint]"
          : f.evidence,
    }));
  }
}
