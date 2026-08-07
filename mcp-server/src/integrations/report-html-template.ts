/**
 * Professional HTML Report Template
 *
 * Generates a complete styled HTML document from findings data,
 * designed for PDF export via Playwright page.pdf().
 */

import { Finding } from "./findings-db";

export interface ReportOptions {
  title?: string;
  target?: string;
  assessor?: string;
  classification?: string;
  includeEvidence?: boolean;
  date?: string;
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#dc3545",
  high: "#fd7e14",
  medium: "#ffc107",
  low: "#28a745",
  info: "#17a2b8",
};

const SEVERITY_ORDER: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function severityBadge(severity: string): string {
  const color = SEVERITY_COLORS[severity] || "#6c757d";
  const textColor = severity === "medium" ? "#856404" : "#fff";
  return `<span class="severity-badge" style="background:${color};color:${textColor};">${severity.toUpperCase()}</span>`;
}

function sortBySeverity(findings: Finding[]): Finding[] {
  return [...findings].sort(
    (a, b) =>
      (SEVERITY_ORDER[a.severity] ?? 5) - (SEVERITY_ORDER[b.severity] ?? 5)
  );
}

function countBySeverity(findings: Finding[]): Record<string, number> {
  const counts: Record<string, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };
  for (const f of findings) {
    counts[f.severity] = (counts[f.severity] || 0) + 1;
  }
  return counts;
}

function slugify(text: string): string {
  return text
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "");
}

export function generateProfessionalHtml(
  findings: Finding[],
  options: ReportOptions = {}
): string {
  const {
    title = "Security Assessment Report",
    target = "Target Application",
    assessor = "Automated Security Assessment (Claude + Kali MCP)",
    classification = "Confidential",
    includeEvidence = true,
    date = new Date().toLocaleDateString("en-US", {
      year: "numeric",
      month: "long",
      day: "numeric",
    }),
  } = options;

  const sorted = sortBySeverity(findings);
  const counts = countBySeverity(findings);
  const totalFindings = findings.length;

  // Determine overall risk level
  let riskLevel = "Low";
  let riskColor = SEVERITY_COLORS.low;
  if (counts.critical > 0) {
    riskLevel = "Critical";
    riskColor = SEVERITY_COLORS.critical;
  } else if (counts.high > 0) {
    riskLevel = "High";
    riskColor = SEVERITY_COLORS.high;
  } else if (counts.medium > 0) {
    riskLevel = "Medium";
    riskColor = SEVERITY_COLORS.medium;
  }

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${escapeHtml(title)}</title>
  <style>
    /* ========== Base Styles ========== */
    * { margin: 0; padding: 0; box-sizing: border-box; }

    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
      font-size: 11pt;
      line-height: 1.6;
      color: #1a1a2e;
      background: #fff;
    }

    /* ========== Title Page ========== */
    .title-page {
      display: flex;
      flex-direction: column;
      justify-content: center;
      align-items: center;
      min-height: 85vh;
      text-align: center;
      page-break-after: always;
    }

    .title-page h1 {
      font-size: 28pt;
      font-weight: 700;
      color: #1a1a2e;
      margin-bottom: 8px;
      letter-spacing: -0.5px;
    }

    .title-page .subtitle {
      font-size: 16pt;
      color: #4a4a6a;
      margin-bottom: 40px;
    }

    .title-page .meta-table {
      margin: 0 auto;
      border-collapse: collapse;
      font-size: 11pt;
    }

    .title-page .meta-table td {
      padding: 6px 16px;
      text-align: left;
    }

    .title-page .meta-table td:first-child {
      font-weight: 600;
      color: #4a4a6a;
    }

    .classification-banner {
      display: inline-block;
      background: #dc3545;
      color: #fff;
      font-size: 10pt;
      font-weight: 600;
      padding: 4px 20px;
      border-radius: 3px;
      margin-top: 40px;
      letter-spacing: 1px;
    }

    /* ========== Section Styles ========== */
    .content {
      padding: 0 10px;
    }

    h2 {
      font-size: 18pt;
      color: #1a1a2e;
      border-bottom: 2px solid #1a1a2e;
      padding-bottom: 6px;
      margin: 30px 0 16px 0;
      page-break-after: avoid;
    }

    h3 {
      font-size: 13pt;
      color: #2d2d4e;
      margin: 20px 0 10px 0;
      page-break-after: avoid;
    }

    h4 {
      font-size: 11pt;
      color: #4a4a6a;
      margin: 14px 0 8px 0;
    }

    p {
      margin-bottom: 10px;
    }

    /* ========== Table of Contents ========== */
    .toc {
      page-break-after: always;
    }

    .toc ul {
      list-style: none;
      padding: 0;
    }

    .toc li {
      padding: 4px 0;
      border-bottom: 1px dotted #ccc;
    }

    .toc a {
      text-decoration: none;
      color: #1a1a2e;
    }

    .toc li.toc-sub {
      padding-left: 24px;
      font-size: 10pt;
    }

    /* ========== Tables ========== */
    table {
      width: 100%;
      border-collapse: collapse;
      margin: 12px 0 20px 0;
      font-size: 10pt;
    }

    th {
      background: #1a1a2e;
      color: #fff;
      font-weight: 600;
      padding: 8px 12px;
      text-align: left;
    }

    td {
      padding: 8px 12px;
      border-bottom: 1px solid #e0e0e0;
    }

    tr:nth-child(even) td {
      background: #f8f9fa;
    }

    /* ========== Severity Badges ========== */
    .severity-badge {
      display: inline-block;
      font-size: 9pt;
      font-weight: 700;
      padding: 2px 10px;
      border-radius: 3px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }

    /* ========== Summary Cards ========== */
    .summary-grid {
      display: flex;
      gap: 12px;
      margin: 16px 0 24px 0;
      flex-wrap: wrap;
    }

    .summary-card {
      flex: 1;
      min-width: 100px;
      text-align: center;
      padding: 16px 8px;
      border-radius: 6px;
      border: 1px solid #e0e0e0;
    }

    .summary-card .count {
      font-size: 24pt;
      font-weight: 700;
      display: block;
    }

    .summary-card .label {
      font-size: 9pt;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      color: #666;
    }

    /* ========== Finding Cards ========== */
    .finding {
      border: 1px solid #e0e0e0;
      border-radius: 8px;
      padding: 20px;
      margin: 16px 0;
      page-break-inside: avoid;
      border-left: 4px solid #ccc;
    }

    .finding-critical { border-left-color: ${SEVERITY_COLORS.critical}; }
    .finding-high { border-left-color: ${SEVERITY_COLORS.high}; }
    .finding-medium { border-left-color: ${SEVERITY_COLORS.medium}; }
    .finding-low { border-left-color: ${SEVERITY_COLORS.low}; }
    .finding-info { border-left-color: ${SEVERITY_COLORS.info}; }

    .finding-header {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      margin-bottom: 12px;
    }

    .finding-title {
      font-size: 12pt;
      font-weight: 600;
      color: #1a1a2e;
      flex: 1;
    }

    .finding-meta {
      display: flex;
      gap: 16px;
      margin-bottom: 12px;
      font-size: 10pt;
      color: #4a4a6a;
    }

    .finding-meta strong {
      color: #1a1a2e;
    }

    .finding-description {
      margin-bottom: 12px;
      line-height: 1.6;
    }

    /* ========== Evidence Blocks ========== */
    .evidence-block {
      background: #f5f5f0;
      border: 1px solid #ddd;
      border-radius: 4px;
      padding: 12px 16px;
      margin: 10px 0;
      font-family: 'SFMono-Regular', 'Consolas', 'Liberation Mono', 'Menlo', monospace;
      font-size: 9pt;
      line-height: 1.5;
      white-space: pre-wrap;
      word-break: break-word;
      overflow-x: auto;
      max-height: 300px;
      overflow-y: auto;
    }

    /* ========== Remediation ========== */
    .remediation {
      background: #e8f5e9;
      border-left: 3px solid ${SEVERITY_COLORS.low};
      padding: 10px 16px;
      margin: 10px 0;
      border-radius: 0 4px 4px 0;
    }

    .remediation strong {
      display: block;
      margin-bottom: 4px;
      color: #2e7d32;
    }

    /* ========== Code Remediation ========== */
    .remediation-code-block {
      background: #e8f5e9;
      border: 1px solid #4caf50;
      border-radius: 4px;
      padding: 12px 16px;
      margin: 10px 0;
      font-family: 'SFMono-Regular', 'Consolas', 'Liberation Mono', 'Menlo', monospace;
      font-size: 9pt;
      line-height: 1.5;
      white-space: pre-wrap;
      word-break: break-word;
    }

    .remediation-note {
      font-size: 10pt;
      color: #2e7d32;
      font-style: italic;
      margin: 8px 0;
    }

    /* ========== Risk Level Banner ========== */
    .risk-banner {
      text-align: center;
      padding: 12px;
      border-radius: 6px;
      font-weight: 700;
      font-size: 14pt;
      margin: 16px 0;
      color: #fff;
    }

    /* ========== Print Styles ========== */
    @media print {
      body { font-size: 10pt; }
      .title-page { min-height: 90vh; }
      .finding { page-break-inside: avoid; }
      h2 { page-break-after: avoid; }
      h3 { page-break-after: avoid; }
      table { page-break-inside: auto; }
      tr { page-break-inside: avoid; }
    }

    /* ========== Page Break Helpers ========== */
    .page-break { page-break-before: always; }
  </style>
</head>
<body>

  <!-- ==================== TITLE PAGE ==================== -->
  <div class="title-page">
    <h1>${escapeHtml(title)}</h1>
    <div class="subtitle">${escapeHtml(target)}</div>
    <table class="meta-table">
      <tr><td>Date:</td><td>${escapeHtml(date)}</td></tr>
      <tr><td>Assessor:</td><td>${escapeHtml(assessor)}</td></tr>
      <tr><td>Total Findings:</td><td>${totalFindings}</td></tr>
      <tr><td>Risk Level:</td><td style="color:${riskColor};font-weight:700;">${riskLevel}</td></tr>
    </table>
    <div class="classification-banner">${escapeHtml(classification)}</div>
  </div>

  <div class="content">

  <!-- ==================== TABLE OF CONTENTS ==================== -->
  <div class="toc">
    <h2>Table of Contents</h2>
    <ul>
      <li><a href="#executive-summary">1. Executive Summary</a></li>
      <li><a href="#scope-methodology">2. Scope &amp; Methodology</a></li>
      <li><a href="#findings-summary">3. Findings Summary</a></li>
      <li><a href="#detailed-findings">4. Detailed Findings</a></li>
${sorted
  .map(
    (f, i) =>
      `      <li class="toc-sub"><a href="#finding-${i + 1}">4.${i + 1}. ${escapeHtml(f.title)}</a></li>`
  )
  .join("\n")}
      <li><a href="#exploitation-summary">5. Exploitation Summary Matrix</a></li>
      <li><a href="#recommendations">6. Recommendations</a></li>
    </ul>
  </div>

  <!-- ==================== EXECUTIVE SUMMARY ==================== -->
  <h2 id="executive-summary">1. Executive Summary</h2>

  <p>This security assessment was conducted against <strong>${escapeHtml(target)}</strong> on ${escapeHtml(date)}.
  A total of <strong>${totalFindings} findings</strong> were identified across the target environment.</p>

  <div class="risk-banner" style="background:${riskColor};">
    Overall Risk Level: ${riskLevel}
  </div>

  <div class="summary-grid">
    <div class="summary-card" style="border-color:${SEVERITY_COLORS.critical};">
      <span class="count" style="color:${SEVERITY_COLORS.critical};">${counts.critical}</span>
      <span class="label">Critical</span>
    </div>
    <div class="summary-card" style="border-color:${SEVERITY_COLORS.high};">
      <span class="count" style="color:${SEVERITY_COLORS.high};">${counts.high}</span>
      <span class="label">High</span>
    </div>
    <div class="summary-card" style="border-color:${SEVERITY_COLORS.medium};">
      <span class="count" style="color:${SEVERITY_COLORS.medium};">${counts.medium}</span>
      <span class="label">Medium</span>
    </div>
    <div class="summary-card" style="border-color:${SEVERITY_COLORS.low};">
      <span class="count" style="color:${SEVERITY_COLORS.low};">${counts.low}</span>
      <span class="label">Low</span>
    </div>
    <div class="summary-card" style="border-color:${SEVERITY_COLORS.info};">
      <span class="count" style="color:${SEVERITY_COLORS.info};">${counts.info}</span>
      <span class="label">Info</span>
    </div>
  </div>

  <table>
    <tr><th>Severity</th><th>Count</th><th>Percentage</th></tr>
    ${["critical", "high", "medium", "low", "info"]
      .map(
        (s) =>
          `<tr><td>${severityBadge(s)}</td><td>${counts[s]}</td><td>${totalFindings > 0 ? Math.round((counts[s] / totalFindings) * 100) : 0}%</td></tr>`
      )
      .join("\n    ")}
    <tr style="font-weight:700;"><td>Total</td><td>${totalFindings}</td><td>100%</td></tr>
  </table>

  <!-- ==================== SCOPE & METHODOLOGY ==================== -->
  <h2 id="scope-methodology" class="page-break">2. Scope &amp; Methodology</h2>

  <h3>Target</h3>
  <p>${escapeHtml(target)}</p>

  <h3>Assessment Type</h3>
  <p>Automated security assessment combining static analysis, dynamic testing, vulnerability scanning, and manual exploitation validation.</p>

  <h3>Tools Used</h3>
  <table>
    <tr><th>Category</th><th>Tools</th></tr>
    <tr><td>Reconnaissance</td><td>Nmap, DNS enumeration, HTTP header analysis</td></tr>
    <tr><td>Static Analysis (SAST)</td><td>Semgrep, Bandit, njsscan, Gitleaks</td></tr>
    <tr><td>Vulnerability Scanning</td><td>Nuclei, Nikto</td></tr>
    <tr><td>Web Application Testing</td><td>SQLMap, XSS testing, Ffuf, Playwright</td></tr>
    <tr><td>Exploit Validation</td><td>Metasploit, Custom scripts, cURL</td></tr>
  </table>

  <!-- ==================== FINDINGS SUMMARY ==================== -->
  <h2 id="findings-summary" class="page-break">3. Findings Summary</h2>

  <table>
    <tr><th>#</th><th>Finding</th><th>Severity</th><th>Target</th><th>CVE</th></tr>
    ${sorted
      .map(
        (f, i) =>
          `<tr>
        <td>${i + 1}</td>
        <td>${escapeHtml(f.title)}</td>
        <td>${severityBadge(f.severity)}</td>
        <td>${escapeHtml(f.target)}</td>
        <td>${f.cve ? escapeHtml(f.cve) : "—"}</td>
      </tr>`
      )
      .join("\n    ")}
  </table>

  <!-- ==================== DETAILED FINDINGS ==================== -->
  <h2 id="detailed-findings" class="page-break">4. Detailed Findings</h2>

  ${sorted
    .map(
      (f, i) => `
  <div class="finding finding-${f.severity}" id="finding-${i + 1}">
    <div class="finding-header">
      <span class="finding-title">${i + 1}. ${escapeHtml(f.title)}</span>
      ${severityBadge(f.severity)}
    </div>
    <div class="finding-meta">
      <span><strong>Target:</strong> ${escapeHtml(f.target)}</span>
      ${f.cve ? `<span><strong>CVE:</strong> ${escapeHtml(f.cve)}</span>` : ""}
      ${f.cwe ? `<span><strong>CWE:</strong> ${escapeHtml(f.cwe)}</span>` : ""}
      ${f.source ? `<span><strong>Source:</strong> ${escapeHtml(f.source)}</span>` : ""}
    </div>
    ${f.file_path ? `<div class="finding-meta"><span><strong>File:</strong> ${escapeHtml(f.file_path)}${f.line_start ? `:${f.line_start}` : ""}${f.line_end ? `-${f.line_end}` : ""}</span></div>` : ""}

    <div class="finding-description">${escapeHtml(f.description)}</div>

    ${
      f.code_snippet
        ? `<h4>Code Context</h4>
    <div class="evidence-block">${escapeHtml(f.code_snippet)}</div>`
        : ""
    }

    ${
      includeEvidence && f.evidence
        ? `<h4>Evidence</h4>
    <div class="evidence-block">${escapeHtml(f.evidence)}</div>`
        : ""
    }

    ${
      f.remediation_code
        ? `<h4>Vulnerable Code</h4>
    <div class="evidence-block">${escapeHtml(f.code_snippet || "")}</div>
    <h4>Remediation Code</h4>
    <div class="remediation-code-block">${escapeHtml(f.remediation_code)}</div>
    ${f.remediation_explanation ? `<p class="remediation-note">${escapeHtml(f.remediation_explanation)}</p>` : ""}`
        : ""
    }

    ${
      f.remediation
        ? `<div class="remediation">
      <strong>Remediation</strong>
      ${escapeHtml(f.remediation)}
    </div>`
        : ""
    }
  </div>`
    )
    .join("\n")}

  <!-- ==================== EXPLOITATION SUMMARY ==================== -->
  <h2 id="exploitation-summary" class="page-break">5. Exploitation Summary Matrix</h2>

  <table>
    <tr><th>#</th><th>Vulnerability</th><th>Severity</th><th>Exploitable</th><th>Notes</th></tr>
    ${sorted
      .map(
        (f, i) =>
          `<tr>
        <td>${i + 1}</td>
        <td>${escapeHtml(f.title)}</td>
        <td>${severityBadge(f.severity)}</td>
        <td>${f.evidence ? "Evidence Captured" : "Not Validated"}</td>
        <td>${f.remediation ? escapeHtml(f.remediation.slice(0, 80)) + (f.remediation.length > 80 ? "..." : "") : "—"}</td>
      </tr>`
      )
      .join("\n    ")}
  </table>

  <!-- ==================== RECOMMENDATIONS ==================== -->
  <h2 id="recommendations" class="page-break">6. Recommendations</h2>

  ${
    counts.critical > 0
      ? `<h3>Immediate (Critical)</h3>
  <ul>
    ${sorted
      .filter((f) => f.severity === "critical")
      .map(
        (f) =>
          `<li><strong>${escapeHtml(f.title)}:</strong> ${f.remediation ? escapeHtml(f.remediation) : "Requires immediate remediation."}</li>`
      )
      .join("\n    ")}
  </ul>`
      : ""
  }

  ${
    counts.high > 0
      ? `<h3>Short-Term (High)</h3>
  <ul>
    ${sorted
      .filter((f) => f.severity === "high")
      .map(
        (f) =>
          `<li><strong>${escapeHtml(f.title)}:</strong> ${f.remediation ? escapeHtml(f.remediation) : "Should be addressed promptly."}</li>`
      )
      .join("\n    ")}
  </ul>`
      : ""
  }

  ${
    counts.medium > 0
      ? `<h3>Medium-Term (Medium)</h3>
  <ul>
    ${sorted
      .filter((f) => f.severity === "medium")
      .map(
        (f) =>
          `<li><strong>${escapeHtml(f.title)}:</strong> ${f.remediation ? escapeHtml(f.remediation) : "Plan remediation within standard sprint cycle."}</li>`
      )
      .join("\n    ")}
  </ul>`
      : ""
  }

  ${
    counts.low + counts.info > 0
      ? `<h3>Best Practices (Low / Info)</h3>
  <ul>
    ${sorted
      .filter((f) => f.severity === "low" || f.severity === "info")
      .map(
        (f) =>
          `<li><strong>${escapeHtml(f.title)}:</strong> ${f.remediation ? escapeHtml(f.remediation) : "Consider addressing as part of ongoing security improvements."}</li>`
      )
      .join("\n    ")}
  </ul>`
      : ""
  }

  <h3>General Defense-in-Depth Recommendations</h3>
  <ul>
    <li>Implement comprehensive input validation at all system boundaries</li>
    <li>Enforce least-privilege access controls across all API endpoints</li>
    <li>Deploy Content-Security-Policy and other security headers</li>
    <li>Enable comprehensive logging and monitoring for security events</li>
    <li>Conduct regular security assessments and penetration testing</li>
  </ul>

  <!-- ==================== FOOTER ==================== -->
  <div style="margin-top:40px;padding-top:20px;border-top:1px solid #e0e0e0;text-align:center;color:#888;font-size:9pt;">
    <p>Generated by Kali MCP Pentest &mdash; ${escapeHtml(date)}</p>
    <p>${escapeHtml(classification)}</p>
  </div>

  </div><!-- .content -->
</body>
</html>`;
}
