/**
 * Code Intelligence Tools
 *
 * Tools for deep source code analysis and attack surface mapping.
 * Used by the code-intel agent to understand application architecture,
 * entry points, data flows, and security defenses before testing.
 */

import { executeInKali } from "../utils/docker-exec";

// ==================== Tool Definitions ====================

export const codeIntelTools = [
  {
    name: "map_entry_points",
    description: `Discover all HTTP routes, API endpoints, and entry points in a codebase.
Uses framework-specific patterns to find routes in Express, Flask, Django, Spring, FastAPI, etc.
Returns structured list of endpoints with method, path, handler file:line, and parameters.`,
    inputSchema: {
      type: "object",
      properties: {
        repo_path: {
          type: "string",
          description: "Path to repository (use /mnt/host-home/ prefix for local paths)",
        },
        framework: {
          type: "string",
          description: "Web framework hint: express, flask, django, fastapi, spring, rails, nextjs, etc. If not provided, will auto-detect.",
        },
      },
      required: ["repo_path"],
    },
  },
  {
    name: "trace_data_flows",
    description: `Trace data flow from a specific entry point through the application.
Reads the handler code and follows function calls to identify where user input goes:
database queries, file system operations, external HTTP calls, command execution, email sending.
Returns the code context with identified sinks and whether they are parameterized/validated.`,
    inputSchema: {
      type: "object",
      properties: {
        repo_path: {
          type: "string",
          description: "Path to repository",
        },
        entry_point: {
          type: "string",
          description: "Route or function to trace from (e.g., '/api/users/:id' or 'handleLogin')",
        },
        file_path: {
          type: "string",
          description: "File containing the entry point handler",
        },
        line_start: {
          type: "number",
          description: "Starting line number (optional)",
        },
        line_end: {
          type: "number",
          description: "Ending line number (optional)",
        },
      },
      required: ["repo_path", "entry_point"],
    },
  },
  {
    name: "analyze_defenses",
    description: `Analyze security defenses present in the codebase.
Checks for: authentication middleware, CSRF protection, rate limiting, input validation libraries,
parameterized queries (ORM usage), output encoding, security headers (helmet, etc.), CORS configuration.
Returns a structured summary of defenses found and any gaps.`,
    inputSchema: {
      type: "object",
      properties: {
        repo_path: {
          type: "string",
          description: "Path to repository",
        },
        defense_type: {
          type: "string",
          enum: ["all", "auth", "input_validation", "csrf", "rate_limiting", "output_encoding", "sql_parameterization", "headers"],
          description: "Specific defense category to analyze",
          default: "all",
        },
      },
      required: ["repo_path"],
    },
  },
  {
    name: "generate_attack_surface",
    description: `Generate a structured attack surface map from the codebase analysis.
Compiles entry points, data flows, defenses, and produces prioritized attack vectors.
This is typically called after map_entry_points, trace_data_flows, and analyze_defenses.
The output feeds into downstream agents (vuln-scan, web-app) for targeted testing.`,
    inputSchema: {
      type: "object",
      properties: {
        repo_path: {
          type: "string",
          description: "Path to repository",
        },
        entry_points: {
          type: "string",
          description: "JSON string of previously discovered entry points",
        },
        defenses: {
          type: "string",
          description: "JSON string of previously analyzed defenses",
        },
        include_low_risk: {
          type: "boolean",
          description: "Include low-risk attack vectors in output",
          default: false,
        },
      },
      required: ["repo_path"],
    },
  },
];

// ==================== Tool Handlers ====================

// Framework detection patterns for entry point mapping
const FRAMEWORK_PATTERNS: Record<string, { pattern: string; description: string }[]> = {
  express: [
    { pattern: "app\\.(get|post|put|delete|patch|all|use)\\s*\\(", description: "Express route" },
    { pattern: "router\\.(get|post|put|delete|patch|all|use)\\s*\\(", description: "Express router" },
  ],
  flask: [
    { pattern: "@app\\.route\\(", description: "Flask route" },
    { pattern: "@blueprint\\.route\\(", description: "Flask blueprint route" },
    { pattern: "@\\w+\\.route\\(", description: "Flask blueprint route" },
  ],
  django: [
    { pattern: "path\\s*\\(", description: "Django URL path" },
    { pattern: "re_path\\s*\\(", description: "Django regex URL" },
    { pattern: "url\\s*\\(", description: "Django legacy URL" },
  ],
  fastapi: [
    { pattern: "@app\\.(get|post|put|delete|patch)\\s*\\(", description: "FastAPI route" },
    { pattern: "@router\\.(get|post|put|delete|patch)\\s*\\(", description: "FastAPI router" },
  ],
  spring: [
    { pattern: "@(Get|Post|Put|Delete|Patch|Request)Mapping", description: "Spring mapping" },
    { pattern: "@RestController", description: "Spring REST controller" },
  ],
  rails: [
    { pattern: "(get|post|put|patch|delete|resources|resource)\\s", description: "Rails route" },
  ],
  nextjs: [
    { pattern: "export\\s+(async\\s+)?function\\s+(GET|POST|PUT|DELETE|PATCH)", description: "Next.js API route" },
  ],
};

// Defense detection patterns
const DEFENSE_PATTERNS: Record<string, { pattern: string; description: string }[]> = {
  auth: [
    { pattern: "passport\\.|jwt\\.|jsonwebtoken|bcrypt|argon2", description: "Auth library" },
    { pattern: "isAuthenticated|requireAuth|authMiddleware|protect|authorize", description: "Auth middleware" },
    { pattern: "@login_required|@permission_required|LoginRequiredMixin", description: "Auth decorator" },
  ],
  csrf: [
    { pattern: "csurf|csrf|csrfProtection|@csrf_exempt|csrf_token", description: "CSRF protection" },
  ],
  rate_limiting: [
    { pattern: "express-rate-limit|rate.limit|throttle|RateLimiter", description: "Rate limiting" },
  ],
  input_validation: [
    { pattern: "joi\\.|zod\\.|yup\\.|express-validator|class-validator", description: "Validation library (JS)" },
    { pattern: "wtforms|marshmallow|pydantic|cerberus", description: "Validation library (Python)" },
  ],
  sql_parameterization: [
    { pattern: "sequelize|prisma|typeorm|knex|mongoose|sqlalchemy|django\\.db", description: "ORM usage" },
    { pattern: "\\$\\d|\\?|%s|:param|@param", description: "Parameterized query" },
  ],
  output_encoding: [
    { pattern: "escape|sanitize|DOMPurify|xss|encode|bleach", description: "Output encoding/sanitization" },
  ],
  headers: [
    { pattern: "helmet|cors|Content-Security-Policy|X-Frame-Options|HSTS", description: "Security headers" },
  ],
};

export const codeIntelHandlers: Record<string, Function> = {
  map_entry_points: async (args: { repo_path: string; framework?: string }) => {
    const { repo_path, framework } = args;

    // Auto-detect framework if not provided
    let detectedFramework = framework;
    if (!detectedFramework) {
      const detectCmd = `cd ${repo_path} && (cat package.json 2>/dev/null | head -50; cat requirements.txt 2>/dev/null | head -30; cat Gemfile 2>/dev/null | head -30; cat pom.xml 2>/dev/null | head -30; cat go.mod 2>/dev/null | head -20) 2>/dev/null || true`;
      const depOutput = await executeInKali(detectCmd);

      if (depOutput.includes("express")) detectedFramework = "express";
      else if (depOutput.includes("flask")) detectedFramework = "flask";
      else if (depOutput.includes("django")) detectedFramework = "django";
      else if (depOutput.includes("fastapi")) detectedFramework = "fastapi";
      else if (depOutput.includes("spring")) detectedFramework = "spring";
      else if (depOutput.includes("rails")) detectedFramework = "rails";
      else if (depOutput.includes("next")) detectedFramework = "nextjs";
    }

    // Get patterns for the detected framework (or use all)
    const frameworks = detectedFramework
      ? [detectedFramework]
      : Object.keys(FRAMEWORK_PATTERNS);

    const results: any[] = [];

    for (const fw of frameworks) {
      const patterns = FRAMEWORK_PATTERNS[fw] || [];
      for (const { pattern, description } of patterns) {
        const grepCmd = `cd ${repo_path} && grep -rn --include='*.ts' --include='*.js' --include='*.py' --include='*.java' --include='*.rb' --include='*.go' --include='*.php' -E '${pattern}' . 2>/dev/null | grep -v node_modules | grep -v __pycache__ | grep -v .git | head -100`;
        const output = await executeInKali(grepCmd);

        if (output.trim()) {
          for (const line of output.trim().split("\n")) {
            const match = line.match(/^\.\/(.+?):(\d+):(.+)$/);
            if (match) {
              results.push({
                file: match[1],
                line: parseInt(match[2]),
                code: match[3].trim(),
                framework: fw,
                type: description,
              });
            }
          }
        }
      }
    }

    return JSON.stringify({
      framework: detectedFramework || "unknown",
      entryPointCount: results.length,
      entryPoints: results,
    }, null, 2);
  },

  trace_data_flows: async (args: {
    repo_path: string;
    entry_point: string;
    file_path?: string;
    line_start?: number;
    line_end?: number;
  }) => {
    const { repo_path, entry_point, file_path } = args;

    // If file_path is provided, read the specific handler code
    let handlerCode = "";
    if (file_path) {
      const start = args.line_start || 1;
      const end = args.line_end || start + 100;
      const readCmd = `cd ${repo_path} && sed -n '${start},${end}p' '${file_path}' 2>/dev/null`;
      handlerCode = await executeInKali(readCmd);
    }

    // Search for dangerous sink patterns near the entry point
    const sinkPatterns = [
      { type: "database", pattern: "query\\(|execute\\(|raw\\(|\\$\\{.*\\}.*FROM|INSERT|UPDATE|DELETE|SELECT", description: "SQL query" },
      { type: "command_exec", pattern: "exec\\(|spawn\\(|system\\(|popen\\(|subprocess|child_process|os\\.system", description: "Command execution" },
      { type: "filesystem", pattern: "readFile|writeFile|readdir|open\\(|unlink|fs\\.|os\\.path|pathlib", description: "File system operation" },
      { type: "external_http", pattern: "fetch\\(|axios|requests\\.(get|post)|http\\.request|urllib", description: "External HTTP call" },
      { type: "template_render", pattern: "render\\(|template|innerHTML|dangerouslySetInnerHTML|Markup\\(|\\|safe", description: "Template rendering" },
    ];

    const sinks: any[] = [];

    for (const { type, pattern, description } of sinkPatterns) {
      // Search in the same file first, then nearby files
      const searchPath = file_path ? `'${file_path}'` : ".";
      const grepCmd = `cd ${repo_path} && grep -rn --include='*.ts' --include='*.js' --include='*.py' --include='*.java' --include='*.rb' -E '${pattern}' ${searchPath} 2>/dev/null | grep -v node_modules | grep -v test | head -20`;
      const output = await executeInKali(grepCmd);

      if (output.trim()) {
        for (const line of output.trim().split("\n")) {
          const match = line.match(/^(.+?):(\d+):(.+)$/);
          if (match) {
            sinks.push({
              type,
              description,
              file: match[1].replace(/^\.\//, ""),
              line: parseInt(match[2]),
              code: match[3].trim().slice(0, 200),
            });
          }
        }
      }
    }

    return JSON.stringify({
      entryPoint: entry_point,
      handlerFile: file_path || "not specified",
      handlerCode: handlerCode.slice(0, 5000),
      sinks,
      sinkCount: sinks.length,
    }, null, 2);
  },

  analyze_defenses: async (args: { repo_path: string; defense_type?: string }) => {
    const { repo_path, defense_type = "all" } = args;

    const categories = defense_type === "all"
      ? Object.keys(DEFENSE_PATTERNS)
      : [defense_type];

    const defenses: Record<string, any[]> = {};
    const summary: Record<string, boolean> = {};

    for (const category of categories) {
      const patterns = DEFENSE_PATTERNS[category] || [];
      defenses[category] = [];

      for (const { pattern, description } of patterns) {
        const grepCmd = `cd ${repo_path} && grep -rn --include='*.ts' --include='*.js' --include='*.py' --include='*.java' --include='*.rb' --include='*.go' -E '${pattern}' . 2>/dev/null | grep -v node_modules | grep -v __pycache__ | grep -v .git | grep -v test | head -20`;
        const output = await executeInKali(grepCmd);

        if (output.trim()) {
          for (const line of output.trim().split("\n")) {
            const match = line.match(/^\.\/(.+?):(\d+):(.+)$/);
            if (match) {
              defenses[category].push({
                description,
                file: match[1],
                line: parseInt(match[2]),
                code: match[3].trim().slice(0, 200),
              });
            }
          }
        }
      }

      summary[category] = defenses[category].length > 0;
    }

    return JSON.stringify({
      summary,
      defenses,
      gaps: Object.entries(summary)
        .filter(([, found]) => !found)
        .map(([category]) => category),
    }, null, 2);
  },

  generate_attack_surface: async (args: {
    repo_path: string;
    entry_points?: string;
    defenses?: string;
    include_low_risk?: boolean;
  }) => {
    // This tool aggregates data - it's primarily for the LLM to structure results.
    // Parse any provided data
    let entryPoints: any[] = [];
    let defensesData: any = {};

    try {
      if (args.entry_points) entryPoints = JSON.parse(args.entry_points);
    } catch {}

    try {
      if (args.defenses) defensesData = JSON.parse(args.defenses);
    } catch {}

    // Get basic repo info
    const infoCmd = `cd ${args.repo_path} && (wc -l $(find . -name '*.ts' -o -name '*.js' -o -name '*.py' -o -name '*.java' | grep -v node_modules | head -100) 2>/dev/null | tail -1; echo "---"; ls -la 2>/dev/null | head -20) || true`;
    const repoInfo = await executeInKali(infoCmd);

    return JSON.stringify({
      repo_path: args.repo_path,
      repoInfo: repoInfo.slice(0, 2000),
      entryPointCount: entryPoints.length,
      entryPoints: entryPoints.slice(0, 50),
      defenses: defensesData,
      message: "Use this data to build a structured AttackSurfaceMap. Prioritize entry points with missing defenses (e.g., routes without auth middleware, queries without parameterization, inputs without validation).",
    }, null, 2);
  },
};
