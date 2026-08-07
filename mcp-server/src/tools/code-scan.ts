import { executeInKali } from "../utils/docker-exec";
import * as fs from "fs";
import * as path from "path";
import {
  sastCacheLookup,
  sastCacheUpsert,
  sha256Hex,
} from "../integrations/cache-client";

/**
 * Run a SAST scanner inside the Kali container with cache awareness.
 * Caching is opt-in: callers that pass `target_id` get the lookup →
 * run-if-miss → upsert flow; without it the scanner runs directly.
 *
 * Inputs:
 *   - target_id: stable identity from the targets table. When absent,
 *     caching is disabled.
 *   - commit_sha: explicit override; otherwise `git rev-parse HEAD` is
 *     run in repo_path. Failure (not a git repo) disables caching.
 *   - scanner: 'semgrep' | 'bandit' | 'njsscan' | 'gitleaks' | 'grype' | …
 *   - scanner_version_cmd: shell command that prints the scanner version
 *     (e.g., "semgrep --version"). Stable across runs of the same binary.
 *   - rule_pack_identifier: opaque string the caller hashes into the
 *     cache key. For hosted rulesets (p/security-audit) the identifier
 *     IS the version; for local rule files, hash file contents instead.
 *   - dependency_lock_file: optional relative path to a lockfile (e.g.
 *     "package-lock.json"). When present, the file's content hash becomes
 *     part of the cache key so dependency updates bust the cache.
 *   - runner: function that runs the actual scanner and returns the
 *     parsed JSON string. Only invoked on cache miss.
 *
 * Output: stringified JSON, either the cache-hit marker or the runner's
 * result. The cache-hit marker has shape { cached: true, scanned_at,
 * expires_at, finding_fingerprints[], note }.
 */
async function runWithSastCache(opts: {
  repo_path: string;
  scanner: string;
  scanner_version_cmd: string;
  rule_pack_identifier: string;
  dependency_lock_file?: string;
  target_id?: string;
  commit_sha?: string;
  runner: () => Promise<string>;
}): Promise<string> {
  const {
    repo_path,
    scanner,
    scanner_version_cmd,
    rule_pack_identifier,
    dependency_lock_file,
    target_id,
    runner,
  } = opts;

  if (!target_id) {
    return runner();
  }

  // Resolve commit_sha when not explicitly provided.
  let commit_sha = opts.commit_sha;
  if (!commit_sha) {
    try {
      commit_sha = (await executeInKali(`git -C ${repo_path} rev-parse HEAD`)).trim();
    } catch {
      // Not a git repo or no HEAD — caching disabled.
      return runner();
    }
  }

  // Resolve scanner_version.
  let scanner_version = "unknown";
  try {
    scanner_version = (await executeInKali(scanner_version_cmd)).trim();
  } catch {
    // Keep "unknown" — scanner-side checksums still differ on a real
    // upgrade because the path-based binary itself will produce a
    // different output. Worst case we get an over-cache that lasts at
    // most until expires_at.
  }

  // Optional dependency lockfile hash for scanners that key on it.
  let dependency_lock_hash: string | undefined;
  if (dependency_lock_file) {
    try {
      const lockPath = path.join(repo_path, dependency_lock_file);
      const content = await executeInKali(`cat ${lockPath}`);
      dependency_lock_hash = sha256Hex(content);
    } catch {
      // Lockfile missing — leave hash undefined; lookup tolerates that.
    }
  }

  const rule_pack_hash = sha256Hex(rule_pack_identifier);
  const cacheKey = {
    target_id,
    commit_sha,
    scanner,
    scanner_version,
    rule_pack_hash,
    dependency_lock_hash,
  };

  const lookup = await sastCacheLookup(cacheKey);
  if (lookup.cached && lookup.entry) {
    return JSON.stringify({
      cached: true,
      scanner,
      cache_key: cacheKey,
      scanned_at: lookup.entry.scan_completed_at,
      expires_at: lookup.entry.expires_at,
      finding_fingerprints: lookup.entry.finding_fingerprints,
      note: `Result loaded from SAST cache (${scanner}) — scanner did not re-run. Findings persist in the findings DB.`,
    });
  }

  // Miss — run scanner, persist results in background.
  const scan_started_at = new Date().toISOString();
  const parsed = await runner();
  const scan_completed_at = new Date().toISOString();

  let finding_fingerprints: string[] = [];
  try {
    const parsedObj = JSON.parse(parsed) as { findings?: Array<{ fingerprint?: string }> };
    finding_fingerprints = (parsedObj.findings ?? [])
      .map((f) => f.fingerprint)
      .filter((fp): fp is string => typeof fp === "string");
  } catch {
    // Parsed wasn't JSON with the expected shape — leave the array empty.
  }

  void sastCacheUpsert({
    ...cacheKey,
    finding_fingerprints,
    scan_started_at,
    scan_completed_at,
  });

  return parsed;
}

export const codeScanTools = [
  {
    name: "scan_repository",
    description: "Perform a comprehensive security scan on a local repository. Runs multiple scanners based on detected languages.",
    inputSchema: {
      type: "object",
      properties: {
        repo_path: { type: "string", description: "Absolute path to the local repository" },
        scan_types: { 
          type: "array", 
          items: { type: "string", enum: ["sast", "secrets", "dependencies", "iac", "all"] },
          description: "Types of scans to run",
          default: ["all"]
        },
        severity_threshold: {
          type: "string",
          enum: ["info", "low", "medium", "high", "critical"],
          description: "Minimum severity to report",
          default: "low"
        },
      },
      required: ["repo_path"],
    },
  },
  {
    name: "scan_semgrep",
    description: "Run Semgrep SAST scanner on a repository. Supports Python, JavaScript, TypeScript, Java, Go, Ruby, and more. When target_id is provided, results are cached and reused on subsequent runs against the same commit (Phase 4 of caching plan).",
    inputSchema: {
      type: "object",
      properties: {
        repo_path: { type: "string", description: "Path to repository" },
        rules: {
          type: "string",
          description: "Semgrep ruleset (e.g., 'p/security-audit', 'p/owasp-top-ten', 'p/python')",
          default: "p/security-audit"
        },
        languages: {
          type: "array",
          items: { type: "string" },
          description: "Specific languages to scan",
        },
        target_id: {
          type: "string",
          description: "Optional canonical target_id (UUID from targets API). When set with a resolvable commit_sha, the scanner consults the SAST cache before running and stores results on completion. Omitting it disables caching for this call.",
        },
        commit_sha: {
          type: "string",
          description: "Optional explicit commit SHA. When omitted, the scanner attempts `git rev-parse HEAD` in repo_path. Caching is skipped if neither is resolvable.",
        },
      },
      required: ["repo_path"],
    },
  },
  {
    name: "scan_bandit",
    description: "Run Bandit security scanner on Python code. When target_id is provided, results are cached and reused on subsequent runs against the same commit (Phase 4 of caching plan).",
    inputSchema: {
      type: "object",
      properties: {
        repo_path: { type: "string", description: "Path to Python repository" },
        severity: {
          type: "string",
          enum: ["low", "medium", "high"],
          default: "low"
        },
        confidence: {
          type: "string",
          enum: ["low", "medium", "high"],
          default: "medium"
        },
        target_id: { type: "string", description: "Optional canonical target_id for cache lookup" },
        commit_sha: { type: "string", description: "Optional explicit commit SHA; auto-resolved from repo_path when omitted" },
      },
      required: ["repo_path"],
    },
  },
  {
    name: "scan_njsscan",
    description: "Run njsscan for Node.js/JavaScript security scanning. When target_id is provided, results are cached and reused on subsequent runs against the same commit (Phase 4 of caching plan).",
    inputSchema: {
      type: "object",
      properties: {
        repo_path: { type: "string", description: "Path to JavaScript/Node.js repository" },
        target_id: { type: "string", description: "Optional canonical target_id for cache lookup" },
        commit_sha: { type: "string", description: "Optional explicit commit SHA" },
      },
      required: ["repo_path"],
    },
  },
  {
    name: "scan_secrets",
    description: "Scan for hardcoded secrets, API keys, and credentials using gitleaks and trufflehog. When target_id is provided, results are cached per commit + include_git_history flag (Phase 4 of caching plan).",
    inputSchema: {
      type: "object",
      properties: {
        repo_path: { type: "string", description: "Path to repository" },
        include_git_history: {
          type: "boolean",
          description: "Scan git history for secrets",
          default: false
        },
        target_id: { type: "string", description: "Optional canonical target_id for cache lookup" },
        commit_sha: { type: "string", description: "Optional explicit commit SHA" },
      },
      required: ["repo_path"],
    },
  },
  {
    name: "scan_dependencies",
    description: "Scan dependencies for known vulnerabilities using safety (Python), npm audit (Node.js), and grype. When target_id is provided, the lockfile content is hashed into the cache key so dependency updates bust the cache cleanly (Phase 4 of caching plan).",
    inputSchema: {
      type: "object",
      properties: {
        repo_path: { type: "string", description: "Path to repository" },
        package_manager: {
          type: "string",
          enum: ["auto", "pip", "npm", "yarn", "maven", "gradle", "go"],
          default: "auto"
        },
        target_id: { type: "string", description: "Optional canonical target_id for cache lookup" },
        commit_sha: { type: "string", description: "Optional explicit commit SHA" },
      },
      required: ["repo_path"],
    },
  },
  {
    name: "scan_iac",
    description: "Scan Infrastructure as Code (Terraform, CloudFormation, Kubernetes, Docker) for misconfigurations. When target_id is provided, results are cached and reused on subsequent runs against the same commit (Phase 4 of caching plan).",
    inputSchema: {
      type: "object",
      properties: {
        repo_path: { type: "string", description: "Path to repository" },
        frameworks: {
          type: "array",
          items: { type: "string", enum: ["terraform", "cloudformation", "kubernetes", "dockerfile", "all"] },
          default: ["all"]
        },
        target_id: { type: "string", description: "Optional canonical target_id for cache lookup" },
        commit_sha: { type: "string", description: "Optional explicit commit SHA" },
      },
      required: ["repo_path"],
    },
  },
  {
    name: "analyze_code_context",
    description: "Analyze specific code file/function for security issues. Useful for understanding vulnerabilities before exploitation.",
    inputSchema: {
      type: "object",
      properties: {
        file_path: { type: "string", description: "Path to the specific file" },
        line_start: { type: "number", description: "Starting line number" },
        line_end: { type: "number", description: "Ending line number" },
        vulnerability_type: { 
          type: "string", 
          description: "Type of vulnerability to look for (sqli, xss, ssrf, etc.)"
        },
      },
      required: ["file_path"],
    },
  },
  {
    name: "detect_languages",
    description: "Detect programming languages used in a repository.",
    inputSchema: {
      type: "object",
      properties: {
        repo_path: { type: "string", description: "Path to repository" },
      },
      required: ["repo_path"],
    },
  },
  {
    name: "generate_scan_report",
    description: "Generate a consolidated report from all scan results.",
    inputSchema: {
      type: "object",
      properties: {
        scan_id: { type: "string", description: "Scan session ID" },
        format: { 
          type: "string", 
          enum: ["json", "markdown", "csv"],
          default: "json"
        },
      },
      required: ["scan_id"],
    },
  },
];

// Store scan results in memory for consolidation
const scanResults: Map<string, any[]> = new Map();

export const codeScanHandlers: Record<string, Function> = {
  scan_repository: async (args: { repo_path: string; scan_types?: string[]; severity_threshold?: string }) => {
    const { repo_path, scan_types = ["all"], severity_threshold = "low" } = args;
    
    // Validate repo path exists
    if (!fs.existsSync(repo_path)) {
      return JSON.stringify({ error: `Repository path not found: ${repo_path}` });
    }
    
    const scanId = `scan-${Date.now()}`;
    const results: any = {
      scan_id: scanId,
      repo_path,
      started_at: new Date().toISOString(),
      findings: [],
      summary: {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0,
      },
    };
    
    // Detect languages
    const languages = await detectLanguages(repo_path);
    results.languages = languages;
    
    const runAll = scan_types.includes("all");
    
    // Run SAST scans
    if (runAll || scan_types.includes("sast")) {
      const sastResults = await runSastScans(repo_path, languages);
      results.findings.push(...sastResults);
    }
    
    // Run secrets scan
    if (runAll || scan_types.includes("secrets")) {
      const secretsResults = await runSecretsScans(repo_path, false);
      results.findings.push(...secretsResults);
    }
    
    // Run dependency scan
    if (runAll || scan_types.includes("dependencies")) {
      const depResults = await runDependencyScans(repo_path, "auto");
      results.findings.push(...depResults);
    }
    
    // Run IaC scan
    if (runAll || scan_types.includes("iac")) {
      const iacResults = await runIacScans(repo_path);
      results.findings.push(...iacResults);
    }
    
    // Filter by severity
    const severityOrder = ["info", "low", "medium", "high", "critical"];
    const minSeverityIndex = severityOrder.indexOf(severity_threshold);
    results.findings = results.findings.filter((f: any) => 
      severityOrder.indexOf(f.severity?.toLowerCase() || "info") >= minSeverityIndex
    );
    
    // Calculate summary
    results.findings.forEach((f: any) => {
      const sev = f.severity?.toLowerCase() || "info";
      if (results.summary[sev] !== undefined) {
        results.summary[sev]++;
      }
    });
    
    results.completed_at = new Date().toISOString();
    results.total_findings = results.findings.length;
    
    // Store for later retrieval
    scanResults.set(scanId, results.findings);
    
    return JSON.stringify(results, null, 2);
  },

  scan_semgrep: async (args: {
    repo_path: string;
    rules?: string;
    languages?: string[];
    target_id?: string;
    commit_sha?: string;
  }) => {
    const { repo_path, rules = "p/security-audit", languages, target_id, commit_sha } = args;
    return runWithSastCache({
      repo_path,
      scanner: "semgrep",
      scanner_version_cmd: "semgrep --version 2>&1",
      rule_pack_identifier: rules,
      target_id,
      commit_sha,
      runner: async () => {
        let command = `semgrep --config ${rules} --json ${repo_path}`;
        if (languages && languages.length > 0) {
          command += ` --lang ${languages.join(",")}`;
        }
        const output = await executeInKali(command);
        return parseSemgrepOutput(output);
      },
    });
  },

  scan_bandit: async (args: {
    repo_path: string;
    severity?: string;
    confidence?: string;
    target_id?: string;
    commit_sha?: string;
  }) => {
    const { repo_path, severity = "low", confidence = "medium", target_id, commit_sha } = args;

    const severityMap: Record<string, string> = { low: "l", medium: "m", high: "h" };
    const confMap: Record<string, string> = { low: "l", medium: "m", high: "h" };

    return runWithSastCache({
      repo_path,
      scanner: "bandit",
      scanner_version_cmd: "bandit --version 2>&1",
      // Rule pack identifier folds severity+confidence in since changing
      // either changes the bandit output. Otherwise a low-confidence run
      // followed by a high-confidence run would hit a stale cache.
      rule_pack_identifier: `bandit:default:sev=${severity}:conf=${confidence}`,
      target_id,
      commit_sha,
      runner: async () => {
        const command = `bandit -r ${repo_path} -f json -ll -i${severityMap[severity]} -c${confMap[confidence]} 2>/dev/null`;
        const output = await executeInKali(command);
        return parseBanditOutput(output);
      },
    });
  },

  scan_njsscan: async (args: {
    repo_path: string;
    target_id?: string;
    commit_sha?: string;
  }) => {
    const { repo_path, target_id, commit_sha } = args;
    return runWithSastCache({
      repo_path,
      scanner: "njsscan",
      scanner_version_cmd: "njsscan --version 2>&1",
      rule_pack_identifier: "njsscan:default",
      target_id,
      commit_sha,
      runner: async () => {
        const command = `njsscan --json ${repo_path} 2>/dev/null`;
        const output = await executeInKali(command);
        return parseNjsscanOutput(output);
      },
    });
  },

  scan_secrets: async (args: {
    repo_path: string;
    include_git_history?: boolean;
    target_id?: string;
    commit_sha?: string;
  }) => {
    const { repo_path, include_git_history = false, target_id, commit_sha } = args;

    return runWithSastCache({
      repo_path,
      // 'gitleaks+trufflehog' makes the scanner identity clear in cache
      // keys — same content scanned by either alone produces different
      // results, so a fused name avoids cross-contamination.
      scanner: "gitleaks+trufflehog",
      scanner_version_cmd: "gitleaks version 2>&1 && trufflehog --version 2>&1",
      // Folding include_git_history into the identifier — with-history
      // and without-history scans produce very different result sets
      // and must not share a cache row.
      rule_pack_identifier: `secrets:gitleaks+trufflehog:history=${include_git_history}`,
      target_id,
      commit_sha,
      runner: async () => {
        const results: any[] = [];

        // Run gitleaks
        let gitleaksCmd = `gitleaks detect --source ${repo_path} --report-format json --report-path /tmp/gitleaks.json`;
        if (!include_git_history) {
          gitleaksCmd += " --no-git";
        }
        try {
          await executeInKali(gitleaksCmd);
          const gitleaksOutput = await executeInKali("cat /tmp/gitleaks.json");
          const gitleaksResults = parseGitleaksOutput(gitleaksOutput, repo_path);
          results.push(...gitleaksResults);
        } catch (e) {
          // gitleaks returns non-zero if findings exist
        }

        // Run trufflehog
        const truffleCmd = include_git_history
          ? `trufflehog git file://${repo_path} --json`
          : `trufflehog filesystem ${repo_path} --json`;
        try {
          const truffleOutput = await executeInKali(truffleCmd);
          const truffleResults = parseTrufflehogOutput(truffleOutput, repo_path);
          results.push(...truffleResults);
        } catch (e) {
          // Ignore errors
        }

        return JSON.stringify(
          {
            scanner: "secrets",
            findings: deduplicateFindings(results),
          },
          null,
          2,
        );
      },
    });
  },

  scan_dependencies: async (args: {
    repo_path: string;
    package_manager?: string;
    target_id?: string;
    commit_sha?: string;
  }) => {
    const { repo_path, package_manager = "auto", target_id, commit_sha } = args;
    const detectedManagers =
      package_manager === "auto" ? detectPackageManagers(repo_path) : [package_manager];

    // Pick the most likely lockfile for the dependency_lock_hash. When
    // multiple managers are detected we pick the first one's lockfile —
    // it's a best-effort signal, not a hard contract; the rule_pack
    // identifier covers the cross-manager combination.
    const lockfileForManager: Record<string, string> = {
      pip: "requirements.txt",
      npm: "package-lock.json",
      yarn: "yarn.lock",
      maven: "pom.xml",
      gradle: "build.gradle",
      go: "go.sum",
    };
    const dependency_lock_file = detectedManagers
      .map((m) => lockfileForManager[m])
      .find((f) => f != null);

    return runWithSastCache({
      repo_path,
      scanner: "dependencies",
      // Dependency scanners ship together (safety/npm-audit/grype). Pin
      // all three versions in the cache key so any one upgrade busts.
      scanner_version_cmd:
        "grype version 2>&1 ; safety --version 2>&1 ; npm --version 2>&1",
      rule_pack_identifier: `dependencies:managers=${detectedManagers.join(",")}`,
      dependency_lock_file,
      target_id,
      commit_sha,
      runner: async () => {
        const results: any[] = [];
        for (const pm of detectedManagers) {
          switch (pm) {
            case "pip": {
              const safetyCmd = `safety check --json -r ${repo_path}/requirements.txt`;
              try {
                const safetyOutput = await executeInKali(safetyCmd);
                results.push(...parseSafetyOutput(safetyOutput));
              } catch (e) {}
              break;
            }
            case "npm":
            case "yarn": {
              const npmCmd = `cd ${repo_path} && npm audit --json`;
              try {
                const npmOutput = await executeInKali(npmCmd);
                results.push(...parseNpmAuditOutput(npmOutput));
              } catch (e) {}
              break;
            }
          }
        }

        // Also run grype for container/general dependency scanning
        const grypeCmd = `grype dir:${repo_path} -o json`;
        try {
          const grypeOutput = await executeInKali(grypeCmd);
          results.push(...parseGrypeOutput(grypeOutput));
        } catch (e) {}

        return JSON.stringify(
          {
            scanner: "dependencies",
            package_managers: detectedManagers,
            findings: results,
          },
          null,
          2,
        );
      },
    });
  },

  scan_iac: async (args: {
    repo_path: string;
    frameworks?: string[];
    target_id?: string;
    commit_sha?: string;
  }) => {
    const { repo_path, frameworks = ["all"], target_id, commit_sha } = args;

    return runWithSastCache({
      repo_path,
      scanner: "iac",
      scanner_version_cmd: "checkov --version 2>&1 ; kics version 2>&1",
      rule_pack_identifier: `iac:checkov+kics:frameworks=${frameworks.join(",")}`,
      target_id,
      commit_sha,
      runner: async () => {
        const results: any[] = [];

        let checkovCmd = `checkov -d ${repo_path} -o json`;
        if (!frameworks.includes("all")) {
          checkovCmd += ` --framework ${frameworks.join(",")}`;
        }
        try {
          const checkovOutput = await executeInKali(checkovCmd);
          results.push(...parseCheckovOutput(checkovOutput));
        } catch (e) {}

        const kicsCmd = `kics scan -p ${repo_path} -o /tmp/kics --report-formats json`;
        try {
          await executeInKali(kicsCmd);
          const kicsOutput = await executeInKali("cat /tmp/kics/results.json");
          results.push(...parseKicsOutput(kicsOutput));
        } catch (e) {}

        return JSON.stringify(
          {
            scanner: "iac",
            findings: results,
          },
          null,
          2,
        );
      },
    });
  },

  analyze_code_context: async (args: { file_path: string; line_start?: number; line_end?: number; vulnerability_type?: string }) => {
    const { file_path, line_start, line_end, vulnerability_type } = args;
    
    if (!fs.existsSync(file_path)) {
      return JSON.stringify({ error: `File not found: ${file_path}` });
    }
    
    const content = fs.readFileSync(file_path, "utf-8");
    const lines = content.split("\n");
    
    let codeSnippet: string;
    let contextStart: number;
    let contextEnd: number;
    
    if (line_start && line_end) {
      // Get specific lines with context
      contextStart = Math.max(1, line_start - 5);
      contextEnd = Math.min(lines.length, line_end + 5);
      codeSnippet = lines.slice(contextStart - 1, contextEnd).join("\n");
    } else {
      // Return first 100 lines
      contextStart = 1;
      contextEnd = Math.min(100, lines.length);
      codeSnippet = lines.slice(0, 100).join("\n");
    }
    
    // Detect file type
    const ext = path.extname(file_path).toLowerCase();
    const languageMap: Record<string, string> = {
      ".py": "python",
      ".js": "javascript",
      ".ts": "typescript",
      ".jsx": "javascript",
      ".tsx": "typescript",
      ".java": "java",
      ".go": "go",
      ".rb": "ruby",
      ".php": "php",
      ".cs": "csharp",
      ".cpp": "cpp",
      ".c": "c",
    };
    
    const language = languageMap[ext] || "unknown";
    
    // Run targeted semgrep if vulnerability type specified
    let targetedFindings: any[] = [];
    if (vulnerability_type) {
      const ruleMap: Record<string, string> = {
        sqli: "p/sql-injection",
        xss: "p/xss",
        ssrf: "p/ssrf",
        xxe: "p/xxe",
        rce: "p/command-injection",
        path_traversal: "p/path-traversal",
        auth: "p/insecure-auth",
        crypto: "p/insecure-crypto",
      };
      
      const rule = ruleMap[vulnerability_type.toLowerCase()];
      if (rule) {
        const cmd = `semgrep --config ${rule} --json ${file_path}`;
        try {
          const output = await executeInKali(cmd);
          targetedFindings = JSON.parse(parseSemgrepOutput(output)).findings || [];
        } catch (e) {}
      }
    }
    
    return JSON.stringify({
      file_path,
      language,
      line_range: { start: contextStart, end: contextEnd },
      code_snippet: codeSnippet,
      targeted_findings: targetedFindings,
      analysis_hints: generateAnalysisHints(codeSnippet, language, vulnerability_type),
    }, null, 2);
  },

  detect_languages: async (args: { repo_path: string }) => {
    const { repo_path } = args;
    const languages = await detectLanguages(repo_path);
    
    return JSON.stringify({
      repo_path,
      languages,
      recommended_scanners: getRecommendedScanners(languages),
    }, null, 2);
  },

  generate_scan_report: async (args: { scan_id: string; format?: string }) => {
    const { scan_id, format = "json" } = args;
    
    const findings = scanResults.get(scan_id);
    if (!findings) {
      return JSON.stringify({ error: `Scan ID not found: ${scan_id}` });
    }
    
    if (format === "json") {
      return JSON.stringify(findings, null, 2);
    }
    
    if (format === "csv") {
      const headers = "id,title,severity,file,line,description,scanner\n";
      const rows = findings.map((f: any, i: number) => 
        `${i + 1},"${f.title || ""}",${f.severity || ""},${f.file || ""},${f.line || ""},"${(f.description || "").replace(/"/g, '""')}",${f.scanner || ""}`
      ).join("\n");
      return headers + rows;
    }
    
    if (format === "markdown") {
      let md = `# Security Scan Report\n\n`;
      md += `**Scan ID:** ${scan_id}\n\n`;
      md += `## Summary\n\n`;
      md += `Total Findings: ${findings.length}\n\n`;
      md += `## Findings\n\n`;
      
      findings.forEach((f: any, i: number) => {
        md += `### ${i + 1}. ${f.title || "Finding"}\n\n`;
        md += `- **Severity:** ${f.severity || "Unknown"}\n`;
        md += `- **File:** ${f.file || "N/A"}:${f.line || "N/A"}\n`;
        md += `- **Scanner:** ${f.scanner || "Unknown"}\n\n`;
        md += `${f.description || ""}\n\n`;
        if (f.code_snippet) {
          md += `\`\`\`\n${f.code_snippet}\n\`\`\`\n\n`;
        }
        md += `---\n\n`;
      });
      
      return md;
    }
    
    return JSON.stringify({ error: `Unknown format: ${format}` });
  },
};

// Helper functions

/**
 * Extract code context (±N lines) around a finding from the source file.
 * Returns null if the file doesn't exist (e.g. git-history-only findings).
 * Intentionally does NOT include the matched secret — only surrounding context.
 */
function extractCodeContext(
  filePath: string,
  line: number,
  window: number = 5
): { snippet: string; lineStart: number; lineEnd: number } | null {
  try {
    if (!fs.existsSync(filePath)) return null;
    const content = fs.readFileSync(filePath, "utf-8");
    const lines = content.split("\n");
    const lineStart = Math.max(1, line - window);
    const lineEnd = Math.min(lines.length, line + window);
    const snippet = lines.slice(lineStart - 1, lineEnd).join("\n");
    return { snippet, lineStart, lineEnd };
  } catch {
    return null;
  }
}

async function detectLanguages(repoPath: string): Promise<string[]> {
  const languages: Set<string> = new Set();
  const extensions: Record<string, string> = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "typescript",
    ".jsx": "javascript",
    ".tsx": "typescript",
    ".java": "java",
    ".go": "go",
    ".rb": "ruby",
    ".php": "php",
    ".cs": "csharp",
    ".cpp": "cpp",
    ".c": "c",
    ".rs": "rust",
    ".swift": "swift",
    ".kt": "kotlin",
    ".scala": "scala",
  };
  
  function scanDir(dir: string) {
    try {
      const items = fs.readdirSync(dir);
      for (const item of items) {
        if (item.startsWith(".") || item === "node_modules" || item === "vendor" || item === "venv") {
          continue;
        }
        const fullPath = path.join(dir, item);
        const stat = fs.statSync(fullPath);
        if (stat.isDirectory()) {
          scanDir(fullPath);
        } else {
          const ext = path.extname(item).toLowerCase();
          if (extensions[ext]) {
            languages.add(extensions[ext]);
          }
        }
      }
    } catch (e) {}
  }
  
  scanDir(repoPath);
  return Array.from(languages);
}

function detectPackageManagers(repoPath: string): string[] {
  const managers: string[] = [];
  
  if (fs.existsSync(path.join(repoPath, "requirements.txt")) || 
      fs.existsSync(path.join(repoPath, "setup.py")) ||
      fs.existsSync(path.join(repoPath, "Pipfile"))) {
    managers.push("pip");
  }
  
  if (fs.existsSync(path.join(repoPath, "package.json"))) {
    if (fs.existsSync(path.join(repoPath, "yarn.lock"))) {
      managers.push("yarn");
    } else {
      managers.push("npm");
    }
  }
  
  if (fs.existsSync(path.join(repoPath, "pom.xml"))) {
    managers.push("maven");
  }
  
  if (fs.existsSync(path.join(repoPath, "build.gradle"))) {
    managers.push("gradle");
  }
  
  if (fs.existsSync(path.join(repoPath, "go.mod"))) {
    managers.push("go");
  }
  
  return managers;
}

function getRecommendedScanners(languages: string[]): Record<string, string[]> {
  const recommendations: Record<string, string[]> = {
    sast: ["semgrep"],
    secrets: ["gitleaks", "trufflehog"],
    dependencies: [],
  };
  
  if (languages.includes("python")) {
    recommendations.sast.push("bandit");
    recommendations.dependencies.push("safety");
  }
  
  if (languages.includes("javascript") || languages.includes("typescript")) {
    recommendations.sast.push("njsscan");
    recommendations.dependencies.push("npm-audit");
  }
  
  if (languages.includes("java")) {
    recommendations.sast.push("semgrep-java");
  }
  
  if (languages.includes("go")) {
    recommendations.sast.push("gosec");
  }
  
  return recommendations;
}

async function runSastScans(repoPath: string, languages: string[]): Promise<any[]> {
  const findings: any[] = [];
  
  // Always run semgrep
  try {
    const semgrepCmd = `semgrep --config p/security-audit --config p/owasp-top-ten --json ${repoPath}`;
    const output = await executeInKali(semgrepCmd);
    const parsed = JSON.parse(parseSemgrepOutput(output));
    if (parsed.findings) {
      findings.push(...parsed.findings);
    }
  } catch (e) {}
  
  // Run language-specific scanners
  if (languages.includes("python")) {
    try {
      const banditCmd = `bandit -r ${repoPath} -f json 2>/dev/null`;
      const output = await executeInKali(banditCmd);
      const parsed = parseBanditObject(output);
      if (parsed.findings) {
        findings.push(...parsed.findings);
      }
    } catch (e) {}
  }
  
  if (languages.includes("javascript") || languages.includes("typescript")) {
    try {
      const njsCmd = `njsscan --json ${repoPath} 2>/dev/null`;
      const output = await executeInKali(njsCmd);
      const parsed = parseNjsscanObject(output);
      if (parsed.findings) {
        findings.push(...parsed.findings);
      }
    } catch (e) {}
  }
  
  return findings;
}

async function runSecretsScans(repoPath: string, includeHistory: boolean): Promise<any[]> {
  const findings: any[] = [];
  
  try {
    const gitleaksCmd = `gitleaks detect --source ${repoPath} --report-format json --report-path -${includeHistory ? "" : " --no-git"}`;
    const output = await executeInKali(gitleaksCmd);
    findings.push(...parseGitleaksOutput(output, repoPath));
  } catch (e) {}
  
  return findings;
}

async function runDependencyScans(repoPath: string, pm: string): Promise<any[]> {
  const findings: any[] = [];
  
  try {
    const grypeCmd = `grype dir:${repoPath} -o json`;
    const output = await executeInKali(grypeCmd);
    findings.push(...parseGrypeOutput(output));
  } catch (e) {}
  
  return findings;
}

async function runIacScans(repoPath: string): Promise<any[]> {
  const findings: any[] = [];
  
  try {
    const checkovCmd = `checkov -d ${repoPath} -o json`;
    const output = await executeInKali(checkovCmd);
    findings.push(...parseCheckovOutput(output));
  } catch (e) {}
  
  return findings;
}

// Output parsers

function parseSemgrepOutput(output: string): string {
  try {
    const data = JSON.parse(output);
    const findings = (data.results || []).map((r: any) => ({
      id: r.check_id,
      title: r.check_id?.split(".")?.pop() || r.check_id,
      severity: mapSeverity(r.extra?.severity || "WARNING"),
      file: r.path,
      line: r.start?.line,
      line_end: r.end?.line,
      code_snippet: r.extra?.lines,
      description: r.extra?.message,
      scanner: "semgrep",
      cwe: r.extra?.metadata?.cwe,
      owasp: r.extra?.metadata?.owasp,
    }));
    
    return JSON.stringify({ scanner: "semgrep", findings }, null, 2);
  } catch (e) {
    return JSON.stringify({ scanner: "semgrep", findings: [], error: String(e) });
  }
}

function parseBanditOutput(output: string): string {
  const result = parseBanditObject(output);
  return JSON.stringify(result, null, 2);
}

function parseBanditObject(output: string): { scanner: string; findings: any[]; error?: string } {
  try {
    // Strip any non-JSON preamble — find first `{"` to skip warnings containing stray `{`
    const jsonStart = output.search(/\{\s*"/);
    const cleanOutput = jsonStart >= 0 ? output.slice(jsonStart) : output;
    const data = JSON.parse(cleanOutput);
    const findings = (data.results || []).map((r: any) => ({
      id: r.test_id,
      title: r.test_name,
      severity: r.issue_severity?.toLowerCase() || "medium",
      file: r.filename,
      line: r.line_number,
      line_end: r.line_range?.[1],
      code_snippet: r.code,
      description: r.issue_text,
      scanner: "bandit",
      cwe: r.issue_cwe?.id ? `CWE-${r.issue_cwe.id}` : undefined,
    }));

    return { scanner: "bandit", findings };
  } catch (e) {
    return { scanner: "bandit", findings: [], error: String(e) };
  }
}

function parseNjsscanOutput(output: string): string {
  const result = parseNjsscanObject(output);
  return JSON.stringify(result, null, 2);
}

function parseNjsscanObject(output: string): { scanner: string; findings: any[]; error?: string } {
  try {
    // Strip any non-JSON preamble — find first `{"` to skip warnings containing stray `{`
    const jsonStart = output.search(/\{\s*"/);
    const cleanOutput = jsonStart >= 0 ? output.slice(jsonStart) : output;
    const data = JSON.parse(cleanOutput);
    const findings: any[] = [];

    for (const [ruleId, ruleData] of Object.entries(data.nodejs || {})) {
      const rule = ruleData as any;
      if (rule.files) {
        for (const file of rule.files) {
          findings.push({
            id: ruleId,
            title: rule.metadata?.description || ruleId,
            severity: mapSeverity(rule.metadata?.severity || "WARNING"),
            file: file.file_path,
            line: file.match_lines?.[0],
            line_end: file.match_lines?.[1],
            code_snippet: file.match_string,
            description: rule.metadata?.description,
            scanner: "njsscan",
            cwe: rule.metadata?.cwe,
          });
        }
      }
    }

    return { scanner: "njsscan", findings };
  } catch (e) {
    return { scanner: "njsscan", findings: [], error: String(e) };
  }
}

function parseGitleaksOutput(output: string, repoPath?: string): any[] {
  try {
    const data = JSON.parse(output);
    return (data || []).map((r: any) => {
      // Gitleaks outputs absolute paths when --source is absolute,
      // so avoid double-joining by checking if File is already absolute
      let filePath: string | undefined;
      let relativeFile = r.File;
      if (r.File && path.isAbsolute(r.File)) {
        filePath = r.File;
        // Extract relative path for storage
        if (repoPath && r.File.startsWith(repoPath)) {
          relativeFile = r.File.slice(repoPath.length).replace(/^\//, "");
        }
      } else if (repoPath && r.File) {
        filePath = path.join(repoPath, r.File);
      }
      const ctx = filePath && r.StartLine ? extractCodeContext(filePath, r.StartLine) : null;
      return {
        id: r.RuleID,
        title: `Secret Detected: ${r.RuleID}`,
        severity: "high",
        file: relativeFile,
        line: r.StartLine,
        line_end: ctx?.lineEnd ?? r.EndLine,
        code_snippet: ctx?.snippet,
        description: r.Description || `Potential secret found matching rule: ${r.RuleID}`,
        scanner: "gitleaks",
        secret_type: r.RuleID,
      };
    });
  } catch (e) {
    return [];
  }
}

function parseTrufflehogOutput(output: string, repoPath?: string): any[] {
  const findings: any[] = [];

  try {
    const lines = output.trim().split("\n");
    for (const line of lines) {
      if (!line) continue;
      const data = JSON.parse(line);
      let relFile = data.SourceMetadata?.Data?.Filesystem?.file;
      const fileLine = data.SourceMetadata?.Data?.Filesystem?.line;
      let filePath: string | undefined;
      if (relFile && path.isAbsolute(relFile)) {
        filePath = relFile;
        if (repoPath && relFile.startsWith(repoPath)) {
          relFile = relFile.slice(repoPath.length).replace(/^\//, "");
        }
      } else if (repoPath && relFile) {
        filePath = path.join(repoPath, relFile);
      }
      const ctx = filePath && fileLine ? extractCodeContext(filePath, fileLine) : null;
      findings.push({
        id: data.DetectorName,
        title: `Secret Detected: ${data.DetectorName}`,
        severity: "high",
        file: relFile,
        line: fileLine,
        line_end: ctx?.lineEnd,
        code_snippet: ctx?.snippet,
        description: `Secret detected by ${data.DetectorName}`,
        scanner: "trufflehog",
        secret_type: data.DetectorName,
      });
    }
  } catch (e) {}

  return findings;
}

function parseSafetyOutput(output: string): any[] {
  try {
    const data = JSON.parse(output);
    return (data.vulnerabilities || []).map((v: any) => ({
      id: v.vulnerability_id,
      title: `Vulnerable Dependency: ${v.package_name}`,
      severity: mapCvssToSeverity(v.cvss_score),
      description: v.advisory,
      scanner: "safety",
      package: v.package_name,
      installed_version: v.installed_version,
      vulnerable_versions: v.vulnerable_versions,
      cve: v.cve,
    }));
  } catch (e) {
    return [];
  }
}

function parseNpmAuditOutput(output: string): any[] {
  try {
    const data = JSON.parse(output);
    const findings: any[] = [];
    
    for (const [id, vuln] of Object.entries(data.vulnerabilities || {})) {
      const v = vuln as any;
      findings.push({
        id: id,
        title: `Vulnerable Dependency: ${v.name}`,
        severity: v.severity || "medium",
        description: v.via?.[0]?.title || v.via?.[0] || "Vulnerability in dependency",
        scanner: "npm-audit",
        package: v.name,
        range: v.range,
        fix_available: v.fixAvailable,
      });
    }
    
    return findings;
  } catch (e) {
    return [];
  }
}

function parseGrypeOutput(output: string): any[] {
  try {
    const data = JSON.parse(output);
    return (data.matches || []).map((m: any) => ({
      id: m.vulnerability?.id,
      title: `${m.artifact?.name}: ${m.vulnerability?.id}`,
      severity: m.vulnerability?.severity?.toLowerCase() || "medium",
      description: m.vulnerability?.description,
      scanner: "grype",
      package: m.artifact?.name,
      installed_version: m.artifact?.version,
      fixed_version: m.vulnerability?.fix?.versions?.[0],
      cve: m.vulnerability?.id,
    }));
  } catch (e) {
    return [];
  }
}

function parseCheckovOutput(output: string): any[] {
  try {
    const data = JSON.parse(output);
    const findings: any[] = [];
    
    for (const check of data.results?.failed_checks || []) {
      findings.push({
        id: check.check_id,
        title: check.check_id,
        severity: mapCheckovSeverity(check.check_id),
        file: check.file_path,
        line: check.file_line_range?.[0],
        line_end: check.file_line_range?.[1],
        description: check.check_name,
        scanner: "checkov",
        resource: check.resource,
        guideline: check.guideline,
      });
    }
    
    return findings;
  } catch (e) {
    return [];
  }
}

function parseKicsOutput(output: string): any[] {
  try {
    const data = JSON.parse(output);
    const findings: any[] = [];
    
    for (const query of data.queries || []) {
      for (const file of query.files || []) {
        findings.push({
          id: query.query_id,
          title: query.query_name,
          severity: query.severity?.toLowerCase() || "medium",
          file: file.file_name,
          line: file.line,
          description: query.description,
          scanner: "kics",
          platform: query.platform,
          category: query.category,
        });
      }
    }
    
    return findings;
  } catch (e) {
    return [];
  }
}

function mapSeverity(severity: string): string {
  const map: Record<string, string> = {
    "ERROR": "high",
    "WARNING": "medium",
    "INFO": "low",
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
  };
  return map[severity.toUpperCase()] || "medium";
}

function mapCvssToSeverity(cvss: number): string {
  if (cvss >= 9.0) return "critical";
  if (cvss >= 7.0) return "high";
  if (cvss >= 4.0) return "medium";
  if (cvss >= 0.1) return "low";
  return "info";
}

function mapCheckovSeverity(checkId: string): string {
  // Checkov doesn't provide severity, estimate from check ID patterns
  if (checkId.includes("CRITICAL") || checkId.includes("CKV_SECRET")) return "high";
  return "medium";
}

function deduplicateFindings(findings: any[]): any[] {
  const seen = new Set<string>();
  return findings.filter(f => {
    const key = `${f.file}:${f.line}:${f.id}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function generateAnalysisHints(code: string, language: string, vulnType?: string): string[] {
  const hints: string[] = [];
  
  // Common vulnerability patterns
  const patterns: Record<string, RegExp[]> = {
    sqli: [
      /execute\s*\([^)]*\+/i,
      /query\s*\([^)]*\+/i,
      /f["'].*\{.*\}.*["']/,
      /\.format\s*\(/,
      /%s/,
    ],
    xss: [
      /innerHTML\s*=/,
      /document\.write/,
      /\{\{.*\}\}/,
      /dangerouslySetInnerHTML/,
    ],
    ssrf: [
      /requests?\.(get|post|put|delete)\s*\(/,
      /fetch\s*\(/,
      /urllib/,
      /http\.request/,
    ],
    rce: [
      /exec\s*\(/,
      /eval\s*\(/,
      /system\s*\(/,
      /subprocess/,
      /child_process/,
    ],
  };
  
  if (vulnType && patterns[vulnType.toLowerCase()]) {
    for (const pattern of patterns[vulnType.toLowerCase()]) {
      if (pattern.test(code)) {
        hints.push(`Potential ${vulnType.toUpperCase()} pattern detected: ${pattern.source}`);
      }
    }
  } else {
    // Check all patterns
    for (const [type, typePatterns] of Object.entries(patterns)) {
      for (const pattern of typePatterns) {
        if (pattern.test(code)) {
          hints.push(`Potential ${type.toUpperCase()} pattern detected: ${pattern.source}`);
        }
      }
    }
  }
  
  return hints;
}
