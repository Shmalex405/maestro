import { getDatabase } from "../logging/log-store";
import { v4 as uuidv4 } from "uuid";
import {
  generateFingerprint,
  extractVulnerabilityType,
  FingerprintInput,
} from "./finding-fingerprint";
import { OracleReceipt, verdictIsEarned } from "../verification/oracles";

export interface Finding {
  id: string;
  title: string;
  severity: string;
  description: string;
  target: string;
  evidence?: string;
  remediation?: string;
  cve?: string;
  cwe?: string;
  cycode_ref?: string;
  status: string;
  exploitable?: string; // "true" | "false" | "potentially" — pentest exploitability status
  created_at: string;
  updated_at?: string;
  jira_ticket?: string;
  // Code context fields
  file_path?: string;
  line_start?: number;
  line_end?: number;
  code_snippet?: string;
  category?: string;
  // Code remediation fields
  remediation_code?: string;
  remediation_explanation?: string;
  // Multiple file locations for findings affecting many files (secrets, SAST)
  file_locations?: string; // JSON-encoded array of {file, line, context, commit_hash?, author?}
  // Structured correlation keys (migration 0030) — for the DAST correlation join
  port?: number;
  service?: string;
  component?: string;
  image_digest?: string;
  // Deduplication fields
  fingerprint?: string;
  vulnerability_type?: string;
  source?: string;
  first_seen_at?: string;
  last_seen_at?: string;
  occurrence_count?: number;
  // Oracle verdict fields (migration 0049). Written ONLY by applyVerdict() after
  // an oracle earned the verdict in code — never accepted from create_finding.
  verdict?: string; // "candidate" | "verified" | "refuted"
  oracle_kind?: string;
  receipt_json?: string;
  capsule_json?: string;
  replay_n?: number;
  replay_successes?: number;
  verified_at?: string;
  claimed_mechanism?: string;
}

export interface FindingInput {
  title: string;
  severity: string;
  description: string;
  target: string;
  evidence?: string;
  remediation?: string;
  cve?: string;
  cwe?: string;
  cycode_ref?: string;
  source?: string;
  exploitable?: string; // "true" | "false" | "potentially"
  file_path?: string;
  line_start?: number;
  line_end?: number;
  code_snippet?: string;
  category?: string;
  remediation_code?: string;
  remediation_explanation?: string;
  file_locations?: string; // JSON-encoded array of {file, line, context, commit_hash?, author?}
  // Structured correlation keys (migration 0030) — set by scanners that know them.
  port?: number;
  service?: string;
  component?: string;
  image_digest?: string;
}

export interface UpsertResult {
  finding: Finding;
  isNew: boolean;
  wasUpdated: boolean;
  evidenceAdded: boolean;
}

export interface FindingEvidence {
  id: string;
  finding_id: string;
  source: string;
  assessment_id?: string;
  evidence_content: string;
  created_at: string;
}

export interface AssessmentFinding {
  id: string;
  assessment_id: string;
  finding_id: string;
  source?: string;
  evidence_snapshot?: string;
  discovered_at: string;
}

export interface FindingWithEvidence extends Finding {
  evidence_sources: FindingEvidence[];
  assessments: AssessmentFinding[];
}

const SEVERITY_ORDER: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

/**
 * Upsert a finding - create if new, update if duplicate fingerprint exists.
 * Handles evidence aggregation and assessment linking.
 */
export async function upsertFinding(
  input: FindingInput,
  assessmentId?: string
): Promise<UpsertResult> {
  const db = getDatabase();
  const now = new Date().toISOString();

  // Generate fingerprint for deduplication
  const fingerprintInput: FingerprintInput = {
    target: input.target,
    title: input.title,
    cve: input.cve,
    cwe: input.cwe,
    description: input.description,
    file_path: input.file_path,
    line_start: input.line_start,
  };
  const fingerprint = generateFingerprint(fingerprintInput);
  const vulnType = extractVulnerabilityType(input.title, input.cve, input.cwe);

  // Check for existing finding with same fingerprint
  const existing = db
    .prepare("SELECT * FROM findings WHERE fingerprint = ?")
    .get(fingerprint) as Finding | undefined;

  let resultFinding: Finding;
  let isNew = false;
  let wasUpdated = false;
  let evidenceAdded = false;

  if (existing) {
    // UPDATE existing finding
    const existingSeverity = SEVERITY_ORDER[existing.severity] ?? 5;
    const newSeverity = SEVERITY_ORDER[input.severity] ?? 5;

    // Upgrade severity if new one is higher (lower number = more severe)
    const finalSeverity =
      newSeverity < existingSeverity ? input.severity : existing.severity;

    db.prepare(
      `
      UPDATE findings SET
        last_seen_at = ?,
        occurrence_count = occurrence_count + 1,
        updated_at = ?,
        severity = ?,
        file_path = COALESCE(file_path, ?),
        line_start = COALESCE(line_start, ?),
        line_end = COALESCE(line_end, ?),
        code_snippet = COALESCE(code_snippet, ?),
        remediation_code = COALESCE(?, remediation_code),
        remediation_explanation = COALESCE(?, remediation_explanation),
        exploitable = COALESCE(?, exploitable),
        file_locations = COALESCE(?, file_locations)
      WHERE id = ?
    `
    ).run(
      now,
      now,
      finalSeverity,
      input.file_path || null,
      input.line_start ?? null,
      input.line_end ?? null,
      input.code_snippet || null,
      input.remediation_code || null,
      input.remediation_explanation || null,
      input.exploitable || null,
      input.file_locations || null,
      existing.id
    );

    resultFinding = {
      ...existing,
      last_seen_at: now,
      updated_at: now,
      occurrence_count: (existing.occurrence_count || 1) + 1,
      severity: finalSeverity,
      file_path: existing.file_path || input.file_path,
      line_start: existing.line_start ?? input.line_start,
      line_end: existing.line_end ?? input.line_end,
      code_snippet: existing.code_snippet || input.code_snippet,
      remediation_code: input.remediation_code || existing.remediation_code,
      remediation_explanation: input.remediation_explanation || existing.remediation_explanation,
      exploitable: input.exploitable || existing.exploitable,
      file_locations: input.file_locations || existing.file_locations,
    };

    wasUpdated = true;

    // Add new evidence if provided and different from existing
    if (input.evidence && input.evidence !== existing.evidence) {
      evidenceAdded = await addEvidence(
        existing.id,
        input.source || "unknown",
        assessmentId,
        input.evidence
      );
    }
  } else {
    // INSERT new finding
    const id = uuidv4();

    db.prepare(
      `
      INSERT INTO findings (
        id, fingerprint, title, severity, description, target,
        evidence, remediation, cve, cycode_ref, vulnerability_type,
        source, status, exploitable, created_at, first_seen_at, last_seen_at,
        occurrence_count, assessment_id, updated_at,
        file_path, line_start, line_end, code_snippet, cwe, category,
        remediation_code, remediation_explanation, file_locations,
        port, service, component, image_digest
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, ?, ?, ?, 1, ?, ?,
                ?, ?, ?, ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?)
    `
    ).run(
      id,
      fingerprint,
      input.title,
      input.severity,
      input.description,
      input.target,
      input.evidence || null,
      input.remediation || null,
      input.cve || null,
      input.cycode_ref || null,
      vulnType,
      input.source || null,
      input.exploitable || "potentially",
      now,
      now,
      now,
      assessmentId || null, // Direct link for Tauri compatibility
      now,
      input.file_path || null,
      input.line_start ?? null,
      input.line_end ?? null,
      input.code_snippet || null,
      input.cwe || null,
      input.category || null,
      input.remediation_code || null,
      input.remediation_explanation || null,
      input.file_locations || null,
      input.port ?? null,
      input.service || null,
      input.component || null,
      input.image_digest || null
    );

    resultFinding = {
      id,
      fingerprint,
      title: input.title,
      severity: input.severity,
      description: input.description,
      target: input.target,
      evidence: input.evidence,
      remediation: input.remediation,
      cve: input.cve,
      cwe: input.cwe,
      cycode_ref: input.cycode_ref,
      vulnerability_type: vulnType,
      source: input.source,
      file_path: input.file_path,
      line_start: input.line_start,
      line_end: input.line_end,
      code_snippet: input.code_snippet,
      category: input.category,
      remediation_code: input.remediation_code,
      remediation_explanation: input.remediation_explanation,
      file_locations: input.file_locations,
      port: input.port,
      service: input.service,
      component: input.component,
      image_digest: input.image_digest,
      status: "open",
      exploitable: input.exploitable || "potentially",
      created_at: now,
      first_seen_at: now,
      last_seen_at: now,
      occurrence_count: 1,
    };

    isNew = true;

    // Add initial evidence to evidence table
    if (input.evidence) {
      await addEvidence(id, input.source || "unknown", assessmentId, input.evidence);
    }
  }

  // Link to assessment if provided
  if (assessmentId) {
    await linkFindingToAssessment(
      resultFinding.id,
      assessmentId,
      input.source,
      input.evidence
    );
  }

  return { finding: resultFinding, isNew, wasUpdated, evidenceAdded };
}

/**
 * Add evidence from a specific source to a finding.
 * Skips if identical evidence already exists.
 */
export async function addEvidence(
  findingId: string,
  source: string,
  assessmentId?: string,
  evidence?: string
): Promise<boolean> {
  if (!evidence) return false;

  const db = getDatabase();

  // Check if we already have this exact evidence
  const existingEvidence = db
    .prepare(
      `
    SELECT id FROM finding_evidence
    WHERE finding_id = ? AND evidence_content = ?
  `
    )
    .get(findingId, evidence);

  if (existingEvidence) {
    return false; // Evidence already exists
  }

  db.prepare(
    `
    INSERT INTO finding_evidence (id, finding_id, source, assessment_id, evidence_content, created_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `
  ).run(uuidv4(), findingId, source, assessmentId || null, evidence, new Date().toISOString());

  return true;
}

/**
 * Link a finding to an assessment.
 * Uses INSERT OR IGNORE to handle duplicate links.
 */
export async function linkFindingToAssessment(
  findingId: string,
  assessmentId: string,
  source?: string,
  evidence?: string
): Promise<void> {
  const db = getDatabase();

  db.prepare(
    `
    INSERT OR IGNORE INTO assessment_findings
    (id, assessment_id, finding_id, source, evidence_snapshot, discovered_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `
  ).run(
    uuidv4(),
    assessmentId,
    findingId,
    source || null,
    evidence || null,
    new Date().toISOString()
  );
}

/**
 * Get a finding with all its evidence sources and assessment links.
 */
export async function getFindingWithEvidence(
  findingId: string
): Promise<FindingWithEvidence | null> {
  const db = getDatabase();

  const finding = db
    .prepare("SELECT * FROM findings WHERE id = ?")
    .get(findingId) as Finding | undefined;

  if (!finding) return null;

  const evidenceSources = db
    .prepare(
      `
    SELECT * FROM finding_evidence
    WHERE finding_id = ?
    ORDER BY created_at DESC
  `
    )
    .all(findingId) as FindingEvidence[];

  const assessments = db
    .prepare(
      `
    SELECT af.* FROM assessment_findings af
    WHERE af.finding_id = ?
    ORDER BY af.discovered_at DESC
  `
    )
    .all(findingId) as AssessmentFinding[];

  return {
    ...finding,
    evidence_sources: evidenceSources,
    assessments,
  };
}

/**
 * Get findings for a specific assessment.
 */
export async function getFindingsForAssessment(
  assessmentId: string
): Promise<Finding[]> {
  const db = getDatabase();

  return db
    .prepare(
      `
    SELECT f.* FROM findings f
    JOIN assessment_findings af ON f.id = af.finding_id
    WHERE af.assessment_id = ?
    ORDER BY
      CASE f.severity
        WHEN 'critical' THEN 0
        WHEN 'high' THEN 1
        WHEN 'medium' THEN 2
        WHEN 'low' THEN 3
        ELSE 4
      END,
      f.created_at DESC
  `
    )
    .all(assessmentId) as Finding[];
}

/**
 * Legacy createFinding - now wraps upsertFinding for backwards compatibility.
 */
export async function createFinding(finding: Finding): Promise<void> {
  await upsertFinding({
    title: finding.title,
    severity: finding.severity,
    description: finding.description,
    target: finding.target,
    evidence: finding.evidence,
    remediation: finding.remediation,
    cve: finding.cve,
    cycode_ref: finding.cycode_ref,
    source: finding.source,
  });
}

export async function getFindings(ids?: string[]): Promise<Finding[]> {
  const db = getDatabase();

  if (ids && ids.length > 0) {
    const placeholders = ids.map(() => "?").join(",");
    return db.prepare(`SELECT * FROM findings WHERE id IN (${placeholders})`).all(...ids) as Finding[];
  }

  return db.prepare("SELECT * FROM findings ORDER BY created_at DESC").all() as Finding[];
}

/** Fetch one finding by id, or undefined. Used by the oracle layer. */
export function getFindingById(id: string): Finding | undefined {
  const db = getDatabase();
  return db.prepare("SELECT * FROM findings WHERE id = ?").get(id) as Finding | undefined;
}

/**
 * The ONLY path to a non-candidate verdict.
 *
 * Writing `verified` requires a receipt that actually earned it — a named
 * oracle, every replay successful, and no refusal reason. That check is
 * re-applied here rather than trusted from the caller, so a bug (or a future
 * caller that means well) cannot mint a verified finding by passing a
 * hand-built receipt object. The same invariant is enforced a third time by the
 * CHECK constraint in backend migration 0049.
 *
 * `create_finding` deliberately has no route to this function.
 */
export function applyVerdict(params: {
  finding_id: string;
  receipt: OracleReceipt;
  capsule: unknown;
  claimed_mechanism?: string;
}): { finding_id: string; verdict: string; oracle_kind: string; downgraded: boolean } {
  const db = getDatabase();
  const { finding_id, receipt, capsule, claimed_mechanism } = params;

  // Re-derive the verdict from the receipt instead of taking receipt.verdict at
  // face value. If the receipt does not stand up, the finding stays a candidate.
  const earned = verdictIsEarned(receipt);
  const verdict = earned ? "verified" : receipt.verdict === "refuted" ? "refuted" : "candidate";
  const downgraded = receipt.verdict === "verified" && !earned;

  db.prepare(
    `UPDATE findings SET
       verdict = ?,
       oracle_kind = ?,
       receipt_json = ?,
       capsule_json = ?,
       replay_n = ?,
       replay_successes = ?,
       verified_at = ?,
       claimed_mechanism = COALESCE(?, claimed_mechanism),
       updated_at = ?
     WHERE id = ?`
  ).run(
    verdict,
    receipt.oracle_kind,
    JSON.stringify(receipt),
    JSON.stringify(capsule),
    receipt.n,
    receipt.successes,
    verdict === "verified" ? new Date().toISOString() : null,
    claimed_mechanism || null,
    new Date().toISOString(),
    finding_id
  );

  return { finding_id, verdict, oracle_kind: receipt.oracle_kind, downgraded };
}

export async function generateReportContent(
  findings: Finding[],
  format: string,
  includeEvidence: boolean
): Promise<string> {
  if (format === "json") {
    return JSON.stringify(findings, null, 2);
  }
  
  const severity_order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const sorted = findings.sort((a, b) => 
    (severity_order[a.severity as keyof typeof severity_order] || 5) - 
    (severity_order[b.severity as keyof typeof severity_order] || 5)
  );
  
  const summary = {
    total: findings.length,
    critical: findings.filter(f => f.severity === "critical").length,
    high: findings.filter(f => f.severity === "high").length,
    medium: findings.filter(f => f.severity === "medium").length,
    low: findings.filter(f => f.severity === "low").length,
    info: findings.filter(f => f.severity === "info").length,
  };
  
  if (format === "markdown") {
    let md = `# Security Assessment Report\n\n`;
    md += `**Generated:** ${new Date().toISOString()}\n\n`;
    md += `## Executive Summary\n\n`;
    md += `| Severity | Count |\n|----------|-------|\n`;
    md += `| Critical | ${summary.critical} |\n`;
    md += `| High | ${summary.high} |\n`;
    md += `| Medium | ${summary.medium} |\n`;
    md += `| Low | ${summary.low} |\n`;
    md += `| Info | ${summary.info} |\n\n`;
    md += `## Findings\n\n`;
    
    for (const finding of sorted) {
      md += `### ${finding.title}\n\n`;
      md += `**Severity:** ${finding.severity.toUpperCase()}\n`;
      md += `**Target:** ${finding.target}\n`;
      if (finding.cve) md += `**CVE:** ${finding.cve}\n`;
      md += `\n${finding.description}\n\n`;
      
      if (includeEvidence && finding.evidence) {
        md += `**Evidence:**\n\`\`\`\n${finding.evidence}\n\`\`\`\n\n`;
      }
      
      if (finding.remediation) {
        md += `**Remediation:** ${finding.remediation}\n\n`;
      }
      
      md += `---\n\n`;
    }
    
    return md;
  }
  
  // HTML format
  let html = `<!DOCTYPE html><html><head><title>Security Report</title>
    <style>
      body { font-family: Arial, sans-serif; margin: 40px; }
      .critical { color: #d32f2f; }
      .high { color: #f57c00; }
      .medium { color: #fbc02d; }
      .low { color: #388e3c; }
      .info { color: #1976d2; }
      .finding { border: 1px solid #ddd; padding: 20px; margin: 20px 0; border-radius: 8px; }
      .evidence { background: #f5f5f5; padding: 10px; font-family: monospace; overflow-x: auto; }
    </style>
  </head><body>`;
  
  html += `<h1>Security Assessment Report</h1>`;
  html += `<p><strong>Generated:</strong> ${new Date().toISOString()}</p>`;
  html += `<h2>Executive Summary</h2>`;
  html += `<table><tr><th>Severity</th><th>Count</th></tr>`;
  html += `<tr><td class="critical">Critical</td><td>${summary.critical}</td></tr>`;
  html += `<tr><td class="high">High</td><td>${summary.high}</td></tr>`;
  html += `<tr><td class="medium">Medium</td><td>${summary.medium}</td></tr>`;
  html += `<tr><td class="low">Low</td><td>${summary.low}</td></tr>`;
  html += `<tr><td class="info">Info</td><td>${summary.info}</td></tr></table>`;
  
  html += `<h2>Findings</h2>`;
  
  for (const finding of sorted) {
    html += `<div class="finding">`;
    html += `<h3>${finding.title}</h3>`;
    html += `<p><strong>Severity:</strong> <span class="${finding.severity}">${finding.severity.toUpperCase()}</span></p>`;
    html += `<p><strong>Target:</strong> ${finding.target}</p>`;
    if (finding.cve) html += `<p><strong>CVE:</strong> ${finding.cve}</p>`;
    html += `<p>${finding.description}</p>`;
    
    if (includeEvidence && finding.evidence) {
      html += `<p><strong>Evidence:</strong></p><div class="evidence"><pre>${finding.evidence}</pre></div>`;
    }
    
    if (finding.remediation) {
      html += `<p><strong>Remediation:</strong> ${finding.remediation}</p>`;
    }
    
    html += `</div>`;
  }
  
  html += `</body></html>`;
  return html;
}

/**
 * Save a report record to the shared database so it appears in the Tauri app's reports page.
 */
export async function saveReportRecord(params: {
  assessmentId: string;
  name: string;
  format: string;
  filePath: string;
  findingsCount: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
}): Promise<string> {
  const db = getDatabase();
  const id = uuidv4();
  const now = new Date().toISOString();

  db.prepare(
    `INSERT INTO reports (id, assessment_id, name, format, file_path, created_at, updated_at,
                          findings_count, critical_count, high_count, medium_count, low_count, exploitable_count)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)`
  ).run(
    id,
    params.assessmentId,
    params.name,
    params.format,
    params.filePath,
    now,
    now,
    params.findingsCount,
    params.criticalCount,
    params.highCount,
    params.mediumCount,
    params.lowCount
  );

  return id;
}

/**
 * Compare findings between two assessments.
 * Classifies each finding as new, fixed, unchanged, or severity-changed.
 */
export async function compareAssessments(
  oldAssessmentId: string,
  newAssessmentId: string
): Promise<{
  new_findings: Finding[];
  fixed_findings: Finding[];
  unchanged_findings: Finding[];
  severity_changed: Array<{ finding: Finding; old_severity: string; new_severity: string }>;
  summary: { new: number; fixed: number; unchanged: number; severity_changed: number };
}> {
  const db = getDatabase();

  // Get findings for each assessment via their fingerprints
  const oldFindings = db.prepare(`
    SELECT f.* FROM findings f
    JOIN assessment_findings af ON f.id = af.finding_id
    WHERE af.assessment_id = ?
  `).all(oldAssessmentId) as Finding[];

  const newFindings = db.prepare(`
    SELECT f.* FROM findings f
    JOIN assessment_findings af ON f.id = af.finding_id
    WHERE af.assessment_id = ?
  `).all(newAssessmentId) as Finding[];

  const oldByFingerprint = new Map(oldFindings.map(f => [f.fingerprint, f]));
  const newByFingerprint = new Map(newFindings.map(f => [f.fingerprint, f]));

  const new_findings: Finding[] = [];
  const fixed_findings: Finding[] = [];
  const unchanged_findings: Finding[] = [];
  const severity_changed: Array<{ finding: Finding; old_severity: string; new_severity: string }> = [];

  // Findings in new but not in old = new
  for (const [fp, finding] of newByFingerprint) {
    const oldFinding = oldByFingerprint.get(fp);
    if (!oldFinding) {
      new_findings.push(finding);
    } else if (oldFinding.severity !== finding.severity) {
      severity_changed.push({
        finding,
        old_severity: oldFinding.severity,
        new_severity: finding.severity,
      });
    } else {
      unchanged_findings.push(finding);
    }
  }

  // Findings in old but not in new = fixed
  for (const [fp, finding] of oldByFingerprint) {
    if (!newByFingerprint.has(fp)) {
      fixed_findings.push(finding);
    }
  }

  return {
    new_findings,
    fixed_findings,
    unchanged_findings,
    severity_changed,
    summary: {
      new: new_findings.length,
      fixed: fixed_findings.length,
      unchanged: unchanged_findings.length,
      severity_changed: severity_changed.length,
    },
  };
}
