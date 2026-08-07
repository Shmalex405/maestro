# Code Intelligence Agent Skill

## Purpose
The Code Intelligence Agent performs deep source code analysis to map the attack surface of web applications before testing. It identifies entry points, traces data flows, catalogs security defenses, and produces a prioritized attack surface map that guides downstream testing agents.

## When to Use
- Before running web-app or vuln-scan agents on a target with source code access
- When you have access to the application's repository
- To dramatically reduce false positives and focus testing on the most vulnerable paths
- As the first phase in a full assessment when `repo_paths` are provided

## Available Tools

### detect_languages
Detect programming languages and frameworks in a repository.
```
Arguments:
  - repo_path: Path to repository (use /mnt/host-home/ prefix for local repos)
```

### map_entry_points
Discover all HTTP routes, API endpoints, and entry points.
```
Arguments:
  - repo_path: Path to repository
  - framework: Framework hint (express, flask, django, fastapi, spring, rails, nextjs)
```

### trace_data_flows
Trace data flow from an entry point to identify sinks.
```
Arguments:
  - repo_path: Path to repository
  - entry_point: Route or function to trace (e.g., '/api/users/:id')
  - file_path: File containing the handler (optional)
  - line_start: Starting line number (optional)
  - line_end: Ending line number (optional)
```

### analyze_defenses
Analyze security defenses in the codebase.
```
Arguments:
  - repo_path: Path to repository
  - defense_type: "all", "auth", "input_validation", "csrf", "rate_limiting", "output_encoding", "sql_parameterization", "headers"
```

### generate_attack_surface
Generate a structured attack surface map from analysis results.
```
Arguments:
  - repo_path: Path to repository
  - entry_points: JSON string of discovered entry points (optional)
  - defenses: JSON string of analyzed defenses (optional)
  - include_low_risk: Include low-risk vectors (default: false)
```

### scan_semgrep (reused from security-scan)
Run Semgrep SAST for pattern-based vulnerability detection.
```
Arguments:
  - repo_path: Path to repository
  - rules: Semgrep ruleset (default: "p/security-audit")
```

### analyze_code_context (reused from security-scan)
Read and analyze specific code files for security issues.
```
Arguments:
  - file_path: Path to the specific file
  - line_start: Starting line number (optional)
  - line_end: Ending line number (optional)
  - vulnerability_type: sqli, xss, ssrf, rce, etc. (optional)
```

## Workflow

The agent follows this sequence:

1. **Detect Languages & Framework** - Understand the codebase type
2. **Map Entry Points** - Discover all routes/endpoints with handler locations
3. **Trace Data Flows** - For high-priority endpoints, follow user input to sinks
4. **Run Semgrep** - Catch vulnerability patterns via SAST
5. **Analyze Defenses** - Catalog security controls and identify gaps
6. **Deep Dive** - Read suspicious files for detailed analysis
7. **Generate Attack Surface Map** - Produce prioritized output

## Attack Surface Map Schema

The output stored in `context.attackSurface` includes:
- **framework** & **language** detected
- **entryPoints** - Routes with method, path, handler file:line, auth status, parameters
- **dataFlows** - Source-to-sink mappings with parameterization status
- **defenses** - CSRF, rate limiting, input validation, auth middleware present/absent
- **prioritizedAttackVectors** - Ranked list of what to test first (sqli, xss, ssrf, rce, etc.)

## Priority Rules
- Route with no auth middleware + database access = HIGH priority
- Route with input validation + parameterized queries = LOW priority
- File upload handlers = ALWAYS high priority
- Admin routes = ALWAYS high priority
- Endpoints that execute commands or access filesystem = HIGH priority

## Downstream Agent Integration
- **vuln-scan agent**: Uses `prioritizedAttackVectors` to select targeted Nuclei templates
- **web-app agent**: Uses entry points and data flows to focus injection testing
- **exploit agent**: Uses defense gaps to craft more effective validation

## Best Practices
- Skip node_modules/, vendor/, __pycache__/, .git/, test/ directories
- Focus on source code, not configuration or documentation
- Don't trace every route — prioritize auth, uploads, admin, user data, API keys
- Provide framework hint if you know it (improves detection accuracy)
