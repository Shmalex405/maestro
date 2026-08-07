/**
 * Prompt Templates API Routes
 * Manages reusable assessment configuration templates
 */

import { Router, Request, Response } from "express";
import { getDatabase } from "../../logging/log-store";

export const templatesRouter = Router();

interface PromptTemplate {
  id: string;
  name: string;
  description: string;
  category: 'compliance' | 'industry' | 'attack-type' | 'custom';
  system_prompt: string;
  focus_areas: string[];
  risk_profile: 'aggressive' | 'balanced' | 'conservative';
  phase_instructions?: Record<string, string>;
  phases?: string[];
  severity_threshold?: string;
  author?: string;
  usage_count: number;
  tags?: string[];
  is_builtin: boolean;
  created_at: string;
  updated_at: string;
}

// Built-in templates
const BUILTIN_TEMPLATES: Omit<PromptTemplate, 'created_at' | 'updated_at'>[] = [
  {
    id: 'owasp-top-10',
    name: 'OWASP Top 10',
    description: 'Comprehensive testing for OWASP Top 10 vulnerabilities including injection, broken authentication, XSS, and more.',
    category: 'attack-type',
    system_prompt: 'Focus on identifying OWASP Top 10 vulnerabilities. Prioritize injection flaws, authentication issues, sensitive data exposure, and access control problems. Document each finding with OWASP category reference.',
    focus_areas: ['injection', 'authentication', 'xss', 'access-control', 'security-misconfiguration'],
    risk_profile: 'balanced',
    phases: ['recon', 'vuln_scan', 'web_app', 'report'],
    phase_instructions: {
      web_app: 'Test for all OWASP Top 10 categories systematically',
      report: 'Include OWASP category mapping for each finding'
    },
    author: 'Maestro',
    usage_count: 0,
    tags: ['owasp', 'web', 'standard'],
    is_builtin: true,
  },
  {
    id: 'pci-dss-compliance',
    name: 'PCI-DSS Compliance',
    description: 'Security assessment aligned with PCI-DSS requirements for payment card industry compliance.',
    category: 'compliance',
    system_prompt: 'Conduct assessment with PCI-DSS compliance in mind. Focus on cardholder data protection, access control, network security, and vulnerability management requirements. Map findings to specific PCI-DSS requirements.',
    focus_areas: ['encryption', 'access-control', 'network-security', 'authentication', 'logging'],
    risk_profile: 'conservative',
    phases: ['recon', 'vuln_scan', 'web_app', 'report'],
    severity_threshold: 'medium',
    phase_instructions: {
      vuln_scan: 'Include PCI-DSS specific vulnerability checks',
      report: 'Map all findings to PCI-DSS requirements (e.g., Req 6.5.x)'
    },
    author: 'Maestro',
    usage_count: 0,
    tags: ['pci', 'compliance', 'payment'],
    is_builtin: true,
  },
  {
    id: 'api-security',
    name: 'API Security Assessment',
    description: 'Focused testing for REST/GraphQL APIs including authentication, authorization, injection, and rate limiting.',
    category: 'attack-type',
    system_prompt: 'Focus on API-specific vulnerabilities. Test authentication mechanisms (JWT, OAuth, API keys), authorization boundaries, input validation, rate limiting, and data exposure. Check for BOLA, BFLA, and mass assignment.',
    focus_areas: ['api-security', 'authentication', 'authorization', 'injection', 'rate-limiting'],
    risk_profile: 'balanced',
    phases: ['recon', 'vuln_scan', 'web_app', 'exploit', 'report'],
    phase_instructions: {
      recon: 'Enumerate API endpoints and document authentication methods',
      web_app: 'Test BOLA, BFLA, injection, and rate limiting on each endpoint'
    },
    author: 'Maestro',
    usage_count: 0,
    tags: ['api', 'rest', 'graphql', 'authentication'],
    is_builtin: true,
  },
  {
    id: 'pre-release-gate',
    name: 'Pre-Release Security Gate',
    description: 'Quick but thorough assessment for release validation. Focus on critical and high severity issues that would block deployment.',
    category: 'industry',
    system_prompt: 'This is a release gate assessment. Focus on identifying any CRITICAL or HIGH severity issues that should block deployment. Be thorough but efficient. Clearly distinguish between release-blocking and advisory findings.',
    focus_areas: ['critical-vulns', 'authentication', 'injection', 'data-exposure'],
    risk_profile: 'balanced',
    phases: ['vuln_scan', 'web_app', 'report'],
    severity_threshold: 'high',
    phase_instructions: {
      report: 'Clearly mark which findings are release-blocking vs advisory'
    },
    author: 'Maestro',
    usage_count: 0,
    tags: ['release', 'ci-cd', 'gate', 'quick'],
    is_builtin: true,
  },
  {
    id: 'quick-recon',
    name: 'Quick Reconnaissance',
    description: 'Fast discovery scan to map attack surface. Identifies hosts, open ports, services, and technologies.',
    category: 'attack-type',
    system_prompt: 'Perform quick reconnaissance to map the attack surface. Identify live hosts, open ports, running services, and web technologies. Do not perform deep vulnerability scanning.',
    focus_areas: ['discovery', 'port-scanning', 'service-detection'],
    risk_profile: 'conservative',
    phases: ['recon'],
    phase_instructions: {
      recon: 'Quick scan only - prioritize breadth over depth'
    },
    author: 'Maestro',
    usage_count: 0,
    tags: ['recon', 'discovery', 'quick'],
    is_builtin: true,
  },
  {
    id: 'full-pentest',
    name: 'Full Penetration Test',
    description: 'Comprehensive penetration test with all phases including exploitation validation.',
    category: 'attack-type',
    system_prompt: 'Conduct a thorough penetration test covering all phases. Start with reconnaissance, perform vulnerability scanning, test web applications, validate exploits, and document everything comprehensively.',
    focus_areas: ['comprehensive', 'exploitation', 'lateral-movement'],
    risk_profile: 'aggressive',
    phases: ['recon', 'vuln_scan', 'web_app', 'exploit', 'report'],
    phase_instructions: {
      exploit: 'Validate all HIGH and CRITICAL findings with proof of exploitability',
      report: 'Include detailed exploitation evidence and attack narratives'
    },
    author: 'Maestro',
    usage_count: 0,
    tags: ['pentest', 'comprehensive', 'exploitation'],
    is_builtin: true,
  },
  {
    id: 'code-security-review',
    name: 'Code Security Review',
    description: 'Static analysis and code review for security vulnerabilities, secrets, and dependency issues.',
    category: 'attack-type',
    system_prompt: 'Perform comprehensive code security review. Scan for SAST findings, hardcoded secrets, vulnerable dependencies, and insecure coding patterns. Prioritize findings that are exploitable in production.',
    focus_areas: ['sast', 'secrets', 'dependencies', 'code-quality'],
    risk_profile: 'balanced',
    phases: ['sast', 'report'],
    phase_instructions: {
      sast: 'Run all available scanners - Semgrep, Bandit, Gitleaks, dependency checks'
    },
    author: 'Maestro',
    usage_count: 0,
    tags: ['code', 'sast', 'secrets', 'dependencies'],
    is_builtin: true,
  },
  {
    id: 'soc2-audit-prep',
    name: 'SOC 2 Audit Preparation',
    description: 'Security assessment aligned with SOC 2 Trust Services Criteria for audit preparation.',
    category: 'compliance',
    system_prompt: 'Assess security controls relevant to SOC 2 Trust Services Criteria. Focus on security, availability, and confidentiality. Document control gaps and evidence for audit preparation.',
    focus_areas: ['access-control', 'encryption', 'logging', 'monitoring', 'incident-response'],
    risk_profile: 'conservative',
    phases: ['recon', 'vuln_scan', 'web_app', 'report'],
    phase_instructions: {
      report: 'Map findings to SOC 2 Trust Services Criteria'
    },
    author: 'Maestro',
    usage_count: 0,
    tags: ['soc2', 'compliance', 'audit'],
    is_builtin: true,
  },
];

/**
 * Initialize templates table and seed built-in templates
 */
function initializeTemplatesTable() {
  const db = getDatabase();

  // Create templates table if not exists
  db.exec(`
    CREATE TABLE IF NOT EXISTS prompt_templates (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      description TEXT,
      category TEXT NOT NULL,
      system_prompt TEXT NOT NULL,
      focus_areas TEXT,
      risk_profile TEXT NOT NULL DEFAULT 'balanced',
      phase_instructions TEXT,
      phases TEXT,
      severity_threshold TEXT,
      author TEXT,
      usage_count INTEGER DEFAULT 0,
      tags TEXT,
      is_builtin INTEGER DEFAULT 0,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    )
  `);

  // Seed built-in templates if not exist
  const insertStmt = db.prepare(`
    INSERT OR IGNORE INTO prompt_templates
    (id, name, description, category, system_prompt, focus_areas, risk_profile,
     phase_instructions, phases, severity_threshold, author, usage_count, tags, is_builtin, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  const now = new Date().toISOString();
  for (const template of BUILTIN_TEMPLATES) {
    insertStmt.run(
      template.id,
      template.name,
      template.description,
      template.category,
      template.system_prompt,
      JSON.stringify(template.focus_areas),
      template.risk_profile,
      template.phase_instructions ? JSON.stringify(template.phase_instructions) : null,
      template.phases ? JSON.stringify(template.phases) : null,
      template.severity_threshold || null,
      template.author || null,
      template.usage_count,
      template.tags ? JSON.stringify(template.tags) : null,
      template.is_builtin ? 1 : 0,
      now,
      now
    );
  }
}

// Initialize on module load
try {
  initializeTemplatesTable();
} catch (error) {
  console.error("Failed to initialize templates table:", error);
}

/**
 * Helper to parse template from DB row
 */
function parseTemplate(row: any): PromptTemplate {
  return {
    id: row.id,
    name: row.name,
    description: row.description,
    category: row.category,
    system_prompt: row.system_prompt,
    focus_areas: row.focus_areas ? JSON.parse(row.focus_areas) : [],
    risk_profile: row.risk_profile,
    phase_instructions: row.phase_instructions ? JSON.parse(row.phase_instructions) : undefined,
    phases: row.phases ? JSON.parse(row.phases) : undefined,
    severity_threshold: row.severity_threshold,
    author: row.author,
    usage_count: row.usage_count,
    tags: row.tags ? JSON.parse(row.tags) : undefined,
    is_builtin: !!row.is_builtin,
    created_at: row.created_at,
    updated_at: row.updated_at,
  };
}

/**
 * List all templates
 * GET /api/templates
 */
templatesRouter.get("/", (req: Request, res: Response) => {
  try {
    const db = getDatabase();
    const { category, search, builtin } = req.query;

    let query = "SELECT * FROM prompt_templates WHERE 1=1";
    const params: any[] = [];

    if (category) {
      query += " AND category = ?";
      params.push(category);
    }

    if (builtin !== undefined) {
      query += " AND is_builtin = ?";
      params.push(builtin === 'true' ? 1 : 0);
    }

    if (search) {
      query += " AND (name LIKE ? OR description LIKE ? OR tags LIKE ?)";
      const searchTerm = `%${search}%`;
      params.push(searchTerm, searchTerm, searchTerm);
    }

    query += " ORDER BY is_builtin DESC, usage_count DESC, name ASC";

    const rows = db.prepare(query).all(...params) as any[];
    const templates = rows.map(parseTemplate);

    res.json({ templates });
  } catch (error) {
    console.error("Error listing templates:", error);
    res.status(500).json({ error: "Failed to list templates" });
  }
});

/**
 * Get single template
 * GET /api/templates/:id
 */
templatesRouter.get("/:id", (req: Request, res: Response) => {
  try {
    const db = getDatabase();
    const { id } = req.params;

    const row = db.prepare("SELECT * FROM prompt_templates WHERE id = ?").get(id) as any;

    if (!row) {
      return res.status(404).json({ error: "Template not found" });
    }

    res.json(parseTemplate(row));
  } catch (error) {
    console.error("Error getting template:", error);
    res.status(500).json({ error: "Failed to get template" });
  }
});

/**
 * Create new template
 * POST /api/templates
 */
templatesRouter.post("/", (req: Request, res: Response) => {
  try {
    const db = getDatabase();
    const {
      name,
      description,
      category,
      system_prompt,
      focus_areas,
      risk_profile,
      phase_instructions,
      phases,
      severity_threshold,
      author,
      tags,
    } = req.body;

    if (!name || !system_prompt) {
      return res.status(400).json({ error: "name and system_prompt are required" });
    }

    const id = `custom-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    const now = new Date().toISOString();

    db.prepare(`
      INSERT INTO prompt_templates
      (id, name, description, category, system_prompt, focus_areas, risk_profile,
       phase_instructions, phases, severity_threshold, author, tags, is_builtin, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)
    `).run(
      id,
      name,
      description || '',
      category || 'custom',
      system_prompt,
      focus_areas ? JSON.stringify(focus_areas) : '[]',
      risk_profile || 'balanced',
      phase_instructions ? JSON.stringify(phase_instructions) : null,
      phases ? JSON.stringify(phases) : null,
      severity_threshold || null,
      author || null,
      tags ? JSON.stringify(tags) : null,
      now,
      now
    );

    const row = db.prepare("SELECT * FROM prompt_templates WHERE id = ?").get(id) as any;
    res.status(201).json(parseTemplate(row));
  } catch (error) {
    console.error("Error creating template:", error);
    res.status(500).json({ error: "Failed to create template" });
  }
});

/**
 * Update template (custom only)
 * PUT /api/templates/:id
 */
templatesRouter.put("/:id", (req: Request, res: Response) => {
  try {
    const db = getDatabase();
    const { id } = req.params;

    // Check if template exists and is not builtin
    const existing = db.prepare("SELECT * FROM prompt_templates WHERE id = ?").get(id) as any;
    if (!existing) {
      return res.status(404).json({ error: "Template not found" });
    }
    if (existing.is_builtin) {
      return res.status(403).json({ error: "Cannot modify built-in templates" });
    }

    const {
      name,
      description,
      category,
      system_prompt,
      focus_areas,
      risk_profile,
      phase_instructions,
      phases,
      severity_threshold,
      tags,
    } = req.body;

    const now = new Date().toISOString();

    db.prepare(`
      UPDATE prompt_templates SET
        name = COALESCE(?, name),
        description = COALESCE(?, description),
        category = COALESCE(?, category),
        system_prompt = COALESCE(?, system_prompt),
        focus_areas = COALESCE(?, focus_areas),
        risk_profile = COALESCE(?, risk_profile),
        phase_instructions = ?,
        phases = ?,
        severity_threshold = ?,
        tags = ?,
        updated_at = ?
      WHERE id = ?
    `).run(
      name,
      description,
      category,
      system_prompt,
      focus_areas ? JSON.stringify(focus_areas) : null,
      risk_profile,
      phase_instructions ? JSON.stringify(phase_instructions) : existing.phase_instructions,
      phases ? JSON.stringify(phases) : existing.phases,
      severity_threshold !== undefined ? severity_threshold : existing.severity_threshold,
      tags ? JSON.stringify(tags) : existing.tags,
      now,
      id
    );

    const row = db.prepare("SELECT * FROM prompt_templates WHERE id = ?").get(id) as any;
    res.json(parseTemplate(row));
  } catch (error) {
    console.error("Error updating template:", error);
    res.status(500).json({ error: "Failed to update template" });
  }
});

/**
 * Delete template (custom only)
 * DELETE /api/templates/:id
 */
templatesRouter.delete("/:id", (req: Request, res: Response) => {
  try {
    const db = getDatabase();
    const { id } = req.params;

    const existing = db.prepare("SELECT * FROM prompt_templates WHERE id = ?").get(id) as any;
    if (!existing) {
      return res.status(404).json({ error: "Template not found" });
    }
    if (existing.is_builtin) {
      return res.status(403).json({ error: "Cannot delete built-in templates" });
    }

    db.prepare("DELETE FROM prompt_templates WHERE id = ?").run(id);
    res.status(204).send();
  } catch (error) {
    console.error("Error deleting template:", error);
    res.status(500).json({ error: "Failed to delete template" });
  }
});

/**
 * Increment usage count
 * POST /api/templates/:id/use
 */
templatesRouter.post("/:id/use", (req: Request, res: Response) => {
  try {
    const db = getDatabase();
    const { id } = req.params;

    const result = db.prepare(`
      UPDATE prompt_templates
      SET usage_count = usage_count + 1, updated_at = ?
      WHERE id = ?
    `).run(new Date().toISOString(), id);

    if (result.changes === 0) {
      return res.status(404).json({ error: "Template not found" });
    }

    res.json({ success: true });
  } catch (error) {
    console.error("Error updating template usage:", error);
    res.status(500).json({ error: "Failed to update template usage" });
  }
});

/**
 * Get template categories with counts
 * GET /api/templates/categories
 */
templatesRouter.get("/meta/categories", (req: Request, res: Response) => {
  try {
    const db = getDatabase();

    const rows = db.prepare(`
      SELECT category, COUNT(*) as count
      FROM prompt_templates
      GROUP BY category
    `).all() as any[];

    const categories = rows.reduce((acc, row) => {
      acc[row.category] = row.count;
      return acc;
    }, {} as Record<string, number>);

    res.json({ categories });
  } catch (error) {
    console.error("Error getting categories:", error);
    res.status(500).json({ error: "Failed to get categories" });
  }
});
