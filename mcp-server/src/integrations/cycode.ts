import { parse } from "csv-parse/sync";
import { v4 as uuidv4 } from "uuid";

export interface CycodeFinding {
  id: string;
  original_id: string;
  vulnerability_type: string;
  severity: string;
  file_path: string;
  line_number: number;
  code_snippet: string;
  description: string;
  remediation: string;
  cwe?: string;
}

export async function parseCycodeCSV(csvContent: string): Promise<CycodeFinding[]> {
  const records = parse(csvContent, {
    columns: true,
    skip_empty_lines: true,
    trim: true,
  });
  
  return records.map((record: any) => ({
    id: uuidv4(),
    original_id: record.id || record.finding_id || "",
    vulnerability_type: record.vulnerability_type || record.type || record.rule_name || "",
    severity: normalizeSeverity(record.severity || record.risk_level || "medium"),
    file_path: record.file_path || record.file || record.location || "",
    line_number: parseInt(record.line_number || record.line || "0", 10),
    code_snippet: record.code_snippet || record.snippet || record.code || "",
    description: record.description || record.message || "",
    remediation: record.remediation || record.fix || record.recommendation || "",
    cwe: record.cwe || record.cwe_id || undefined,
  }));
}

function normalizeSeverity(severity: string): string {
  const normalized = severity.toLowerCase();
  if (["critical", "high", "medium", "low", "info"].includes(normalized)) {
    return normalized;
  }
  // Map numeric or other formats
  if (normalized === "1" || normalized === "very high") return "critical";
  if (normalized === "2") return "high";
  if (normalized === "3") return "medium";
  if (normalized === "4") return "low";
  return "medium";
}

export function getExploitContext(finding: CycodeFinding): string {
  return `
Vulnerability Type: ${finding.vulnerability_type}
Severity: ${finding.severity}
File: ${finding.file_path}:${finding.line_number}
CWE: ${finding.cwe || "Unknown"}

Code Context:
${finding.code_snippet}

Description:
${finding.description}

This finding was identified by static analysis (Cycode). 
The goal is to validate if this vulnerability is exploitable in the running application.
`;
}
