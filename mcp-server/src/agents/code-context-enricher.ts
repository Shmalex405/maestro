/**
 * Code Context Enricher
 *
 * Two-tier enrichment that runs between QA and Report in the orchestrator pipeline.
 * When source code is available, enriches findings with:
 *   Tier 1: Source code snippets and file:line references (all findings with file_path)
 *   Tier 2: LLM-generated code fixes (HIGH/CRITICAL findings only)
 *
 * Gracefully skips when source code is not available — this is a reference layer,
 * not a hard requirement.
 */

import { AgentFinding } from "./base-agent";
import { codeScanHandlers } from "../tools/code-scan";
import { getLLMProvider } from "../llm";
import type { LLMProvider } from "../llm";

export interface EnrichmentResult {
  codeContextCount: number;   // Tier 1: findings with code location attached
  remediationCount: number;   // Tier 2: findings with LLM-generated fixes
}

interface GeneratedFix {
  fixedCode: string;
  explanation: string;
}

/**
 * Extract a file path from a finding's metadata or target.
 */
function getFilePath(finding: AgentFinding): string | null {
  // Check metadata.file first (common in SAST findings)
  if (finding.metadata?.file && typeof finding.metadata.file === "string") {
    return finding.metadata.file;
  }
  // Check metadata.file_path
  if (finding.metadata?.file_path && typeof finding.metadata.file_path === "string") {
    return finding.metadata.file_path;
  }
  // Check if target looks like a file path (starts with / and has an extension)
  if (finding.target?.startsWith("/") && /\.\w+$/.test(finding.target)) {
    return finding.target;
  }
  return null;
}

/**
 * Extract a line number from a finding's metadata.
 */
function getLineStart(finding: AgentFinding): number | null {
  if (finding.metadata?.line && typeof finding.metadata.line === "number") {
    return finding.metadata.line;
  }
  if (finding.metadata?.line_start && typeof finding.metadata.line_start === "number") {
    return finding.metadata.line_start;
  }
  return null;
}

/**
 * Generate a concrete code fix using the LLM.
 * Returns null on failure (best-effort).
 */
async function generateFix(
  llm: LLMProvider,
  finding: AgentFinding
): Promise<GeneratedFix | null> {
  const codeContext = finding.metadata?.codeContext;
  const language = finding.metadata?.codeContextLanguage || "unknown";
  const filePath = finding.metadata?.codeContextFile || "unknown";

  if (!codeContext) return null;

  const prompt = `You are a security engineer. Given the following vulnerable code, provide a concrete fix.

**Vulnerability:** ${finding.title}
**Severity:** ${finding.severity}
**File:** ${filePath}
**Language:** ${language}
**Description:** ${finding.description}

**Vulnerable Code:**
\`\`\`${language}
${codeContext}
\`\`\`

Respond with ONLY a JSON object (no markdown, no explanation outside the JSON):
{
  "fixed_code": "the corrected code snippet",
  "explanation": "1-2 sentence explanation of what was changed and why"
}`;

  try {
    const response = await llm.chat({
      system: "You are a security code remediation assistant. Respond only with valid JSON.",
      messages: [{ role: "user", content: prompt }],
      tools: [],
      maxTokens: 2048,
      temperature: 0.2,
    });

    const text = response.textContent.trim();
    // Try to extract JSON from the response
    const jsonMatch = text.match(/\{[\s\S]*\}/);
    if (!jsonMatch) return null;

    const parsed = JSON.parse(jsonMatch[0]);
    if (!parsed.fixed_code || !parsed.explanation) return null;

    return {
      fixedCode: parsed.fixed_code,
      explanation: parsed.explanation,
    };
  } catch {
    return null;
  }
}

/**
 * Enrich findings with source code context and remediation code.
 *
 * Tier 1: All findings with a file_path get source code snippets attached.
 * Tier 2: HIGH/CRITICAL findings get LLM-generated code fixes.
 *
 * Skips false positives (qaFalsePositive) and findings without file paths.
 * Failures are silently skipped — code context is supplemental.
 */
export async function enrichFindingsWithCodeContext(
  findings: AgentFinding[],
  onProgress?: (msg: string) => void
): Promise<EnrichmentResult> {
  let codeContextCount = 0;
  let remediationCount = 0;

  // All findings with file_path that aren't false positives
  const withFilePath = findings.filter(
    (f) => !f.metadata?.qaFalsePositive && getFilePath(f)
  );

  if (withFilePath.length === 0) {
    return { codeContextCount: 0, remediationCount: 0 };
  }

  onProgress?.(`Enriching ${withFilePath.length} findings with code context`);

  // ── Tier 1: Attach source code context to ALL findings with file_path ──
  for (const finding of withFilePath) {
    try {
      const filePath = getFilePath(finding)!;
      const lineStart = getLineStart(finding);

      const codeResult = JSON.parse(
        await codeScanHandlers.analyze_code_context({
          file_path: filePath,
          line_start: lineStart ? Math.max(1, lineStart - 5) : undefined,
          line_end: lineStart ? lineStart + 20 : undefined,
          vulnerability_type: finding.metadata?.vulnerability_type,
        })
      );

      if (codeResult.error || !codeResult.code_snippet) continue;

      finding.metadata = finding.metadata || {};
      finding.metadata.codeContext = codeResult.code_snippet;
      finding.metadata.codeContextFile = `${filePath}${lineStart ? `:${lineStart}` : ""}`;
      finding.metadata.codeContextLanguage = codeResult.language;
      finding.metadata.codeContextVerified = true;
      codeContextCount++;
    } catch {
      // Skip silently — code context is a reference, not a requirement
    }
  }

  onProgress?.(`Code context attached to ${codeContextCount} findings`);

  // ── Tier 2: Generate remediation code for HIGH/CRITICAL findings ──
  const criticalFindings = withFilePath.filter(
    (f) =>
      (f.severity === "high" || f.severity === "critical") &&
      f.metadata?.codeContextVerified
  );

  if (criticalFindings.length > 0) {
    let llm: LLMProvider;
    try {
      llm = getLLMProvider();
    } catch {
      onProgress?.("LLM provider not available — skipping Tier 2 remediation generation");
      return { codeContextCount, remediationCount: 0 };
    }

    onProgress?.(`Generating code fixes for ${criticalFindings.length} high/critical findings`);

    for (const finding of criticalFindings) {
      try {
        const fix = await generateFix(llm, finding);
        if (!fix) continue;

        finding.metadata!.remediationCode = fix.fixedCode;
        finding.metadata!.remediationExplanation = fix.explanation;
        finding.metadata!.remediationVerified = true;
        remediationCount++;
      } catch {
        // Skip silently — remediation is best-effort
      }
    }

    onProgress?.(`Generated fixes for ${remediationCount} findings`);
  }

  return { codeContextCount, remediationCount };
}
