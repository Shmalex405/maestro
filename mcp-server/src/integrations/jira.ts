import { getDatabase } from "../logging/log-store";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import * as yaml from "yaml";

interface JiraConfig {
  base_url: string;
  email: string;
  api_token: string;
}

export interface JiraProject {
  id: string;
  key: string;
  name: string;
  projectTypeKey: string;
  avatarUrl?: string;
}

export interface JiraBoard {
  id: number;
  name: string;
  type: string;
  projectKey: string;
}

/**
 * Read Jira config with fallback chain:
 * 1. Environment variables (for CI/server deploys)
 * 2. integrations.yml from host-mounted config or local dev path
 */
function getJiraConfig(): JiraConfig {
  // Priority 1: Environment variables
  const envConfig: JiraConfig = {
    base_url: process.env.JIRA_BASE_URL || "",
    email: process.env.JIRA_EMAIL || "",
    api_token: process.env.JIRA_API_TOKEN || "",
  };

  if (envConfig.base_url && envConfig.api_token) {
    return envConfig;
  }

  // Priority 2: integrations.yml
  const configPaths = [
    "/mnt/host-home/.kali-mcp-pentest/integrations.yml", // Docker context
    path.join(os.homedir(), ".kali-mcp-pentest", "integrations.yml"), // Local dev
  ];

  for (const configPath of configPaths) {
    try {
      if (fs.existsSync(configPath)) {
        const content = fs.readFileSync(configPath, "utf-8");
        const config = yaml.parse(content);
        if (config?.jira?.enabled && config.jira.url && config.jira.api_token) {
          return {
            base_url: config.jira.url.replace(/\/+$/, ""), // strip trailing slashes
            email: config.jira.email || "",
            api_token: config.jira.api_token,
          };
        }
      }
    } catch (e) {
      console.warn(`[jira] Could not read config from ${configPath}:`, e);
    }
  }

  return envConfig;
}

/** Get the default project key from saved config */
export function getDefaultProjectKey(): string | null {
  const configPaths = [
    "/mnt/host-home/.kali-mcp-pentest/integrations.yml",
    path.join(os.homedir(), ".kali-mcp-pentest", "integrations.yml"),
  ];
  for (const configPath of configPaths) {
    try {
      if (fs.existsSync(configPath)) {
        const content = fs.readFileSync(configPath, "utf-8");
        const config = yaml.parse(content);
        if (config?.jira?.project_key) return config.jira.project_key;
      }
    } catch {
      /* skip */
    }
  }
  return null;
}

function makeAuthHeader(config: JiraConfig): string {
  return `Basic ${Buffer.from(`${config.email}:${config.api_token}`).toString("base64")}`;
}

export async function createJiraTicket(
  findingId: string,
  projectKey: string,
  priority: string
): Promise<{ status: string; ticket_key?: string; error?: string }> {
  const config = getJiraConfig();

  if (!config.base_url || !config.api_token) {
    return { status: "error", error: "Jira not configured. Set credentials in Settings > Integrations or via environment variables." };
  }

  // Get finding from database
  const db = getDatabase();
  const finding = db.prepare("SELECT * FROM findings WHERE id = ?").get(findingId) as any;

  if (!finding) {
    return { status: "error", error: "Finding not found" };
  }

  const ticketData = {
    fields: {
      project: { key: projectKey },
      summary: `[Security] ${finding.title}`,
      description: {
        type: "doc",
        version: 1,
        content: [
          {
            type: "paragraph",
            content: [{ type: "text", text: finding.description }],
          },
          {
            type: "heading",
            attrs: { level: 3 },
            content: [{ type: "text", text: "Evidence" }],
          },
          {
            type: "codeBlock",
            content: [{ type: "text", text: finding.evidence || "N/A" }],
          },
          {
            type: "heading",
            attrs: { level: 3 },
            content: [{ type: "text", text: "Remediation" }],
          },
          {
            type: "paragraph",
            content: [{ type: "text", text: finding.remediation || "N/A" }],
          },
        ],
      },
      issuetype: { name: "Bug" },
      priority: { name: priority },
      labels: ["security", "automated-scan", finding.severity],
    },
  };

  try {
    const response = await fetch(`${config.base_url}/rest/api/3/issue`, {
      method: "POST",
      headers: {
        Authorization: makeAuthHeader(config),
        "Content-Type": "application/json",
      },
      body: JSON.stringify(ticketData),
    });

    if (!response.ok) {
      const error = await response.text();
      return { status: "error", error };
    }

    const result = (await response.json()) as { key: string };

    // Update finding with ticket reference
    db.prepare("UPDATE findings SET jira_ticket = ?, updated_at = ? WHERE id = ?").run(
      result.key,
      new Date().toISOString(),
      findingId
    );

    return { status: "created", ticket_key: result.key };
  } catch (error) {
    return { status: "error", error: String(error) };
  }
}

/**
 * Test Jira connection by fetching the authenticated user's profile.
 */
export async function testJiraConnection(): Promise<{
  status: string;
  user?: string;
  email?: string;
  error?: string;
}> {
  const config = getJiraConfig();
  if (!config.base_url || !config.api_token) {
    return { status: "error", error: "Jira not configured" };
  }

  try {
    const response = await fetch(`${config.base_url}/rest/api/3/myself`, {
      headers: {
        Authorization: makeAuthHeader(config),
        "Content-Type": "application/json",
      },
    });

    if (!response.ok) {
      const text = await response.text();
      return { status: "error", error: `HTTP ${response.status}: ${text}` };
    }

    const data = (await response.json()) as { displayName: string; emailAddress: string };
    return { status: "ok", user: data.displayName, email: data.emailAddress };
  } catch (error) {
    return { status: "error", error: String(error) };
  }
}

/**
 * List all accessible Jira projects.
 */
export async function listJiraProjects(): Promise<{
  status: string;
  projects?: JiraProject[];
  error?: string;
}> {
  const config = getJiraConfig();
  if (!config.base_url || !config.api_token) {
    return { status: "error", error: "Jira not configured" };
  }

  try {
    const response = await fetch(
      `${config.base_url}/rest/api/3/project/search?maxResults=100&orderBy=name`,
      {
        headers: {
          Authorization: makeAuthHeader(config),
          "Content-Type": "application/json",
        },
      }
    );

    if (!response.ok) {
      const text = await response.text();
      return { status: "error", error: `HTTP ${response.status}: ${text}` };
    }

    const data = (await response.json()) as { values: any[] };
    const projects: JiraProject[] = data.values.map((p: any) => ({
      id: p.id,
      key: p.key,
      name: p.name,
      projectTypeKey: p.projectTypeKey,
      avatarUrl: p.avatarUrls?.["48x48"],
    }));

    return { status: "ok", projects };
  } catch (error) {
    return { status: "error", error: String(error) };
  }
}

/**
 * List all accessible Jira boards (Scrum/Kanban).
 */
export async function listJiraBoards(projectKeyOrId?: string): Promise<{
  status: string;
  boards?: JiraBoard[];
  error?: string;
}> {
  const config = getJiraConfig();
  if (!config.base_url || !config.api_token) {
    return { status: "error", error: "Jira not configured" };
  }

  try {
    let url = `${config.base_url}/rest/agile/1.0/board?maxResults=100`;
    if (projectKeyOrId) {
      url += `&projectKeyOrId=${encodeURIComponent(projectKeyOrId)}`;
    }

    const response = await fetch(url, {
      headers: {
        Authorization: makeAuthHeader(config),
        "Content-Type": "application/json",
      },
    });

    if (!response.ok) {
      const text = await response.text();
      return { status: "error", error: `HTTP ${response.status}: ${text}` };
    }

    const data = (await response.json()) as { values: any[] };
    const boards: JiraBoard[] = data.values.map((b: any) => ({
      id: b.id,
      name: b.name,
      type: b.type,
      projectKey: b.location?.projectKey || "",
    }));

    return { status: "ok", boards };
  } catch (error) {
    return { status: "error", error: String(error) };
  }
}

/**
 * Test connection using explicitly provided credentials (before they're saved).
 */
export async function testJiraConnectionWithCredentials(
  baseUrl: string,
  email: string,
  apiToken: string
): Promise<{ status: string; user?: string; error?: string }> {
  const url = baseUrl.replace(/\/+$/, "");
  try {
    const response = await fetch(`${url}/rest/api/3/myself`, {
      headers: {
        Authorization: `Basic ${Buffer.from(`${email}:${apiToken}`).toString("base64")}`,
        "Content-Type": "application/json",
      },
    });

    if (!response.ok) {
      const text = await response.text();
      return { status: "error", error: `HTTP ${response.status}: ${text}` };
    }

    const data = (await response.json()) as { displayName: string };
    return { status: "ok", user: data.displayName };
  } catch (error) {
    return { status: "error", error: String(error) };
  }
}

/**
 * List projects using explicitly provided credentials (before they're saved).
 */
export async function listJiraProjectsWithCredentials(
  baseUrl: string,
  email: string,
  apiToken: string
): Promise<{ status: string; projects?: JiraProject[]; error?: string }> {
  const url = baseUrl.replace(/\/+$/, "");
  try {
    const response = await fetch(`${url}/rest/api/3/project/search?maxResults=100&orderBy=name`, {
      headers: {
        Authorization: `Basic ${Buffer.from(`${email}:${apiToken}`).toString("base64")}`,
        "Content-Type": "application/json",
      },
    });

    if (!response.ok) {
      const text = await response.text();
      return { status: "error", error: `HTTP ${response.status}: ${text}` };
    }

    const data = (await response.json()) as { values: any[] };
    const projects: JiraProject[] = data.values.map((p: any) => ({
      id: p.id,
      key: p.key,
      name: p.name,
      projectTypeKey: p.projectTypeKey,
      avatarUrl: p.avatarUrls?.["48x48"],
    }));

    return { status: "ok", projects };
  } catch (error) {
    return { status: "error", error: String(error) };
  }
}

// ─── Issue Types ────────────────────────────────────────────────────────────

export interface JiraIssueType {
  id: string;
  name: string;
  description: string;
  subtask: boolean;
  iconUrl?: string;
}

/**
 * List issue types available for a project (Bug, Story, Task, Epic, etc.)
 */
export async function listJiraIssueTypes(projectKey: string): Promise<{
  status: string;
  issueTypes?: JiraIssueType[];
  error?: string;
}> {
  const config = getJiraConfig();
  if (!config.base_url || !config.api_token) {
    return { status: "error", error: "Jira not configured" };
  }

  try {
    const response = await fetch(
      `${config.base_url}/rest/api/3/project/${encodeURIComponent(projectKey)}`,
      {
        headers: {
          Authorization: makeAuthHeader(config),
          "Content-Type": "application/json",
        },
      }
    );

    if (!response.ok) {
      const text = await response.text();
      return { status: "error", error: `HTTP ${response.status}: ${text}` };
    }

    const data = (await response.json()) as { issueTypes: any[] };
    const issueTypes: JiraIssueType[] = (data.issueTypes || [])
      .filter((t: any) => !t.subtask)
      .map((t: any) => ({
        id: t.id,
        name: t.name,
        description: t.description || "",
        subtask: t.subtask,
        iconUrl: t.iconUrl,
      }));

    return { status: "ok", issueTypes };
  } catch (error) {
    return { status: "error", error: String(error) };
  }
}

// ─── Epics ──────────────────────────────────────────────────────────────────

export interface JiraEpic {
  id: string;
  key: string;
  summary: string;
  status: string;
}

/**
 * List open epics in a project.
 */
export async function listJiraEpics(projectKey: string): Promise<{
  status: string;
  epics?: JiraEpic[];
  error?: string;
}> {
  const config = getJiraConfig();
  if (!config.base_url || !config.api_token) {
    return { status: "error", error: "Jira not configured" };
  }

  try {
    const jql = `project = "${projectKey}" AND issuetype = Epic ORDER BY statusCategory ASC, updated DESC`;
    const response = await fetch(
      `${config.base_url}/rest/api/3/search/jql`,
      {
        method: "POST",
        headers: {
          Authorization: makeAuthHeader(config),
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ jql, maxResults: 100, fields: ["summary", "status"] }),
      }
    );

    if (!response.ok) {
      const text = await response.text();
      return { status: "error", error: `HTTP ${response.status}: ${text}` };
    }

    const data = (await response.json()) as { issues: any[] };
    const epics: JiraEpic[] = (data.issues || []).map((issue: any) => ({
      id: issue.id,
      key: issue.key,
      summary: issue.fields.summary,
      status: issue.fields.status?.name || "Unknown",
    }));

    return { status: "ok", epics };
  } catch (error) {
    return { status: "error", error: String(error) };
  }
}

// ─── Search ────────────────────────────────────────────────────────────────

export interface JiraSearchResult {
  id: string;
  key: string;
  summary: string;
  issueType: string;
  status: string;
  priority?: string;
  assignee?: string;
}

/**
 * Search Jira issues using JQL text search.
 * Supports searching across epics, stories, bugs, etc.
 */
export async function searchJiraIssues(
  projectKey: string,
  query: string,
  options?: { issueType?: string; maxResults?: number }
): Promise<{ status: string; results?: JiraSearchResult[]; error?: string }> {
  const config = getJiraConfig();
  if (!config.base_url || !config.api_token) {
    return { status: "error", error: "Jira not configured" };
  }

  try {
    const maxResults = options?.maxResults || 20;
    // Escape JQL special characters: + - & | ! ( ) { } [ ] ^ " ~ * ? \ /
    const escapedQuery = query.replace(/([+\-&|!(){}[\]^"~*?\\\/])/g, "\\$1");

    let jql = `project = "${projectKey}"`;
    if (options?.issueType) {
      jql += ` AND issuetype = "${options.issueType}"`;
    }
    if (query.trim()) {
      // Use summary ~ "term" for word-contains matching (Jira tokenizes and matches).
      // Also try exact key match for "ND-12345" style queries.
      // Avoid text~ and wildcards which are unreliable across Jira versions.
      jql += ` AND (summary ~ "${escapedQuery}" OR key = "${query.trim().toUpperCase()}")`;
    }
    jql += ` ORDER BY updated DESC`;

    console.log(`[jira-search] JQL: ${jql}`);

    const response = await fetch(`${config.base_url}/rest/api/3/search/jql`, {
      method: "POST",
      headers: {
        Authorization: makeAuthHeader(config),
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        jql,
        maxResults,
        fields: ["summary", "status", "issuetype", "priority", "assignee"],
      }),
    });

    if (!response.ok) {
      const text = await response.text();
      console.error(`[jira-search] Error: HTTP ${response.status}: ${text}`);
      return { status: "error", error: `HTTP ${response.status}: ${text}` };
    }

    const data = (await response.json()) as { issues: any[] };
    const results: JiraSearchResult[] = (data.issues || []).map((issue: any) => ({
      id: issue.id,
      key: issue.key,
      summary: issue.fields.summary,
      issueType: issue.fields.issuetype?.name || "Unknown",
      status: issue.fields.status?.name || "Unknown",
      priority: issue.fields.priority?.name,
      assignee: issue.fields.assignee?.displayName,
    }));

    return { status: "ok", results };
  } catch (error) {
    return { status: "error", error: String(error) };
  }
}

// ─── Enhanced Ticket Creation ───────────────────────────────────────────────

export interface FindingContentOverride {
  title?: string;
  description?: string;
  evidence?: string;
  remediation?: string;
}

export interface CreateTicketOptions {
  projectKey: string;
  issueType?: string;
  epicKey?: string;
  priority?: string;
  labels?: string[];
  /** Per-finding content overrides keyed by finding ID */
  content_overrides?: Record<string, FindingContentOverride>;
}

/**
 * Create a Jira ticket for a single finding with enhanced options.
 */
export async function createJiraTicketEnhanced(
  findingId: string,
  options: CreateTicketOptions
): Promise<{ status: string; ticket_key?: string; error?: string }> {
  const config = getJiraConfig();

  if (!config.base_url || !config.api_token) {
    return { status: "error", error: "Jira not configured" };
  }

  const db = getDatabase();
  const finding = db.prepare("SELECT * FROM findings WHERE id = ?").get(findingId) as any;

  if (!finding) {
    return { status: "error", error: `Finding not found: ${findingId}` };
  }

  // Apply content overrides if provided
  const overrides = options.content_overrides?.[findingId];
  const effectiveFinding = overrides
    ? {
        ...finding,
        title: overrides.title ?? finding.title,
        description: overrides.description ?? finding.description,
        evidence: overrides.evidence ?? finding.evidence,
        remediation: overrides.remediation ?? finding.remediation,
      }
    : finding;

  const fields: any = {
    project: { key: options.projectKey },
    summary: `[Security] ${effectiveFinding.title}`,
    description: buildFindingDescription(effectiveFinding),
    issuetype: { name: options.issueType || "Bug" },
    priority: { name: options.priority || severityToPriority(finding.severity) },
    labels: options.labels || ["security", "automated-scan", finding.severity],
  };

  if (options.epicKey) {
    fields.parent = { key: options.epicKey };
  }

  try {
    const response = await fetch(`${config.base_url}/rest/api/3/issue`, {
      method: "POST",
      headers: {
        Authorization: makeAuthHeader(config),
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ fields }),
    });

    if (!response.ok) {
      const error = await response.text();
      return { status: "error", error };
    }

    const result = (await response.json()) as { key: string };

    db.prepare("UPDATE findings SET jira_ticket = ?, updated_at = ? WHERE id = ?").run(
      result.key,
      new Date().toISOString(),
      findingId
    );

    return { status: "created", ticket_key: result.key };
  } catch (error) {
    return { status: "error", error: String(error) };
  }
}

/**
 * Create a single combined Jira ticket from multiple findings.
 */
export async function createCombinedJiraTicket(
  findingIds: string[],
  options: CreateTicketOptions & { title?: string }
): Promise<{ status: string; ticket_key?: string; error?: string }> {
  const config = getJiraConfig();

  if (!config.base_url || !config.api_token) {
    return { status: "error", error: "Jira not configured" };
  }

  const db = getDatabase();
  const rawFindings = findingIds
    .map((id) => db.prepare("SELECT * FROM findings WHERE id = ?").get(id) as any)
    .filter(Boolean);

  if (rawFindings.length === 0) {
    return { status: "error", error: "No findings found for the given IDs" };
  }

  // Apply content overrides if provided
  const findings = rawFindings.map((f: any) => {
    const overrides = options.content_overrides?.[f.id];
    if (!overrides) return f;
    return {
      ...f,
      title: overrides.title ?? f.title,
      description: overrides.description ?? f.description,
      evidence: overrides.evidence ?? f.evidence,
      remediation: overrides.remediation ?? f.remediation,
    };
  });

  const severityOrder = ["critical", "high", "medium", "low", "info"];
  const highestSeverity = findings
    .map((f: any) => f.severity)
    .sort((a: string, b: string) => severityOrder.indexOf(a) - severityOrder.indexOf(b))[0];

  const summary = options.title || `[Security] ${findings.length} vulnerabilities found`;

  const fields: any = {
    project: { key: options.projectKey },
    summary,
    description: buildCombinedDescription(findings),
    issuetype: { name: options.issueType || "Bug" },
    priority: { name: options.priority || severityToPriority(highestSeverity) },
    labels: options.labels || ["security", "automated-scan", "bulk"],
  };

  if (options.epicKey) {
    fields.parent = { key: options.epicKey };
  }

  try {
    const response = await fetch(`${config.base_url}/rest/api/3/issue`, {
      method: "POST",
      headers: {
        Authorization: makeAuthHeader(config),
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ fields }),
    });

    if (!response.ok) {
      const error = await response.text();
      return { status: "error", error };
    }

    const result = (await response.json()) as { key: string };

    const stmt = db.prepare("UPDATE findings SET jira_ticket = ?, updated_at = ? WHERE id = ?");
    const now = new Date().toISOString();
    for (const finding of findings) {
      stmt.run(result.key, now, finding.id);
    }

    return { status: "created", ticket_key: result.key };
  } catch (error) {
    return { status: "error", error: String(error) };
  }
}

// ─── Report-Based Ticket Creation ─────────────────────────────────────────

export interface ReportTicketParams {
  projectKey: string;
  epicKey: string;
  summary: string;
  markdownBody: string;   // Full finding markdown (metadata table + description + evidence + impact + remediation)
  priority: string;       // Project-specific priority name (e.g. "P1", "P2", etc.)
  labels: string[];
  issueType?: string;
  customFields?: Record<string, any>;  // Additional custom fields (e.g. { "customfield_10316": { "value": "QA" } })
}

/**
 * Convert markdown text to Jira ADF (Atlassian Document Format).
 * Handles: headings, paragraphs, code blocks, tables, bullet lists, bold/italic, horizontal rules.
 */
function markdownToAdf(markdown: string): any {
  const lines = markdown.split("\n");
  const content: any[] = [];
  let i = 0;

  while (i < lines.length) {
    const line = lines[i];

    // Skip empty lines
    if (line.trim() === "") {
      i++;
      continue;
    }

    // Horizontal rule
    if (/^-{3,}$/.test(line.trim()) || /^\*{3,}$/.test(line.trim())) {
      content.push({ type: "rule" });
      i++;
      continue;
    }

    // Headings
    const headingMatch = line.match(/^(#{1,6})\s+(.+)$/);
    if (headingMatch) {
      const level = Math.min(headingMatch[1].length, 6);
      content.push({
        type: "heading",
        attrs: { level },
        content: parseInlineMarks(headingMatch[2]),
      });
      i++;
      continue;
    }

    // Code block (fenced)
    if (line.trim().startsWith("```")) {
      const lang = line.trim().replace(/^```/, "").trim() || undefined;
      const codeLines: string[] = [];
      i++;
      while (i < lines.length && !lines[i].trim().startsWith("```")) {
        codeLines.push(lines[i]);
        i++;
      }
      i++; // skip closing ```
      const attrs: any = {};
      if (lang) attrs.language = lang;
      content.push({
        type: "codeBlock",
        ...(lang ? { attrs } : {}),
        content: codeLines.length > 0
          ? [{ type: "text", text: codeLines.join("\n") }]
          : [],
      });
      continue;
    }

    // Table (pipe-delimited)
    if (line.trim().startsWith("|") && line.trim().endsWith("|")) {
      const tableRows: any[] = [];
      let isFirst = true;

      while (i < lines.length && lines[i].trim().startsWith("|") && lines[i].trim().endsWith("|")) {
        const row = lines[i].trim();
        // Skip separator rows (|---|---|)
        if (/^\|[\s\-:|]+\|$/.test(row)) {
          i++;
          continue;
        }

        const cells = row
          .slice(1, -1)
          .split("|")
          .map((c) => c.trim());

        const cellType = isFirst ? "tableHeader" : "tableCell";
        const rowContent = cells.map((cell) => ({
          type: cellType,
          content: [{ type: "paragraph", content: parseInlineMarks(cell) }],
        }));

        tableRows.push({ type: "tableRow", content: rowContent });
        isFirst = false;
        i++;
      }

      if (tableRows.length > 0) {
        content.push({ type: "table", content: tableRows });
      }
      continue;
    }

    // Bullet list
    if (line.match(/^[-*]\s+/)) {
      const listItems: any[] = [];
      while (i < lines.length && lines[i].match(/^[-*]\s+/)) {
        const text = lines[i].replace(/^[-*]\s+/, "");
        listItems.push({
          type: "listItem",
          content: [{ type: "paragraph", content: parseInlineMarks(text) }],
        });
        i++;
      }
      content.push({ type: "bulletList", content: listItems });
      continue;
    }

    // Numbered list
    if (line.match(/^\d+\.\s+/)) {
      const listItems: any[] = [];
      while (i < lines.length && lines[i].match(/^\d+\.\s+/)) {
        const text = lines[i].replace(/^\d+\.\s+/, "");
        listItems.push({
          type: "listItem",
          content: [{ type: "paragraph", content: parseInlineMarks(text) }],
        });
        i++;
      }
      content.push({ type: "orderedList", content: listItems });
      continue;
    }

    // Regular paragraph — collect consecutive non-special lines
    const paraLines: string[] = [];
    while (
      i < lines.length &&
      lines[i].trim() !== "" &&
      !lines[i].match(/^#{1,6}\s/) &&
      !lines[i].trim().startsWith("```") &&
      !(lines[i].trim().startsWith("|") && lines[i].trim().endsWith("|")) &&
      !lines[i].match(/^[-*]\s+/) &&
      !lines[i].match(/^\d+\.\s+/) &&
      !/^-{3,}$/.test(lines[i].trim()) &&
      !/^\*{3,}$/.test(lines[i].trim())
    ) {
      paraLines.push(lines[i]);
      i++;
    }

    if (paraLines.length > 0) {
      content.push({
        type: "paragraph",
        content: parseInlineMarks(paraLines.join(" ")),
      });
    }
  }

  return { type: "doc", version: 1, content };
}

/**
 * Parse inline markdown marks (bold, italic, code, links) into ADF inline nodes.
 */
function parseInlineMarks(text: string): any[] {
  const nodes: any[] = [];
  // Regex to match: **bold**, *italic*, `code`, [text](url)
  const regex = /(\*\*(.+?)\*\*)|(\*(.+?)\*)|(`(.+?)`)|(\[(.+?)\]\((.+?)\))/g;

  let lastIndex = 0;
  let match: RegExpExecArray | null;

  while ((match = regex.exec(text)) !== null) {
    // Add plain text before this match
    if (match.index > lastIndex) {
      nodes.push({ type: "text", text: text.slice(lastIndex, match.index) });
    }

    if (match[1]) {
      // **bold**
      nodes.push({ type: "text", text: match[2], marks: [{ type: "strong" }] });
    } else if (match[3]) {
      // *italic*
      nodes.push({ type: "text", text: match[4], marks: [{ type: "em" }] });
    } else if (match[5]) {
      // `code`
      nodes.push({ type: "text", text: match[6], marks: [{ type: "code" }] });
    } else if (match[7]) {
      // [text](url)
      nodes.push({
        type: "text",
        text: match[8],
        marks: [{ type: "link", attrs: { href: match[9] } }],
      });
    }

    lastIndex = match.index + match[0].length;
  }

  // Remaining text
  if (lastIndex < text.length) {
    nodes.push({ type: "text", text: text.slice(lastIndex) });
  }

  // If no matches at all, return the raw text
  if (nodes.length === 0) {
    nodes.push({ type: "text", text: text || " " });
  }

  return nodes;
}

/**
 * Create a Jira ticket from pre-formatted report content (markdown → ADF).
 * Does not require findings to exist in the database.
 */
export async function createJiraTicketFromReport(
  params: ReportTicketParams
): Promise<{ status: string; ticket_key?: string; url?: string; error?: string }> {
  const config = getJiraConfig();

  if (!config.base_url || !config.api_token) {
    return { status: "error", error: "Jira not configured" };
  }

  const adfDescription = markdownToAdf(params.markdownBody);

  const fields: any = {
    project: { key: params.projectKey },
    summary: params.summary,
    description: adfDescription,
    issuetype: { name: params.issueType || "Bug" },
    priority: { name: params.priority },
    labels: params.labels,
    ...(params.customFields || {}),
  };

  if (params.epicKey) {
    fields.parent = { key: params.epicKey };
  }

  try {
    const response = await fetch(`${config.base_url}/rest/api/3/issue`, {
      method: "POST",
      headers: {
        Authorization: makeAuthHeader(config),
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ fields }),
    });

    if (!response.ok) {
      const errorText = await response.text();
      console.error(`[jira] Failed to create ticket: HTTP ${response.status}: ${errorText}`);
      return { status: "error", error: `HTTP ${response.status}: ${errorText}` };
    }

    const result = (await response.json()) as { key: string };
    const url = `${config.base_url}/browse/${result.key}`;
    console.log(`[jira] Created ticket ${result.key} → ${url}`);
    return { status: "created", ticket_key: result.key, url };
  } catch (error) {
    return { status: "error", error: String(error) };
  }
}

// ─── Helpers ────────────────────────────────────────────────────────────────

function severityToPriority(severity: string): string {
  switch (severity) {
    case "critical": return "Highest";
    case "high": return "High";
    case "medium": return "Medium";
    case "low": return "Low";
    case "info": return "Lowest";
    default: return "Medium";
  }
}

function buildFindingDescription(finding: any): any {
  return {
    type: "doc",
    version: 1,
    content: [
      { type: "paragraph", content: [{ type: "text", text: finding.description }] },
      ...(finding.evidence
        ? [
            { type: "heading", attrs: { level: 3 }, content: [{ type: "text", text: "Evidence" }] },
            { type: "codeBlock", content: [{ type: "text", text: finding.evidence }] },
          ]
        : []),
      ...(finding.remediation
        ? [
            { type: "heading", attrs: { level: 3 }, content: [{ type: "text", text: "Remediation" }] },
            { type: "paragraph", content: [{ type: "text", text: finding.remediation }] },
          ]
        : []),
      {
        type: "paragraph",
        content: [
          { type: "text", text: `Severity: ${(finding.severity || "").toUpperCase()} | Target: ${finding.target || "N/A"}`, marks: [{ type: "em" }] },
        ],
      },
    ],
  };
}

function buildCombinedDescription(findings: any[]): any {
  const content: any[] = [
    {
      type: "paragraph",
      content: [{ type: "text", text: `This ticket tracks ${findings.length} security vulnerabilities discovered during an automated assessment.` }],
    },
    { type: "heading", attrs: { level: 2 }, content: [{ type: "text", text: "Findings Summary" }] },
  ];

  const tableRows: any[] = [
    {
      type: "tableRow",
      content: [
        { type: "tableHeader", content: [{ type: "paragraph", content: [{ type: "text", text: "#" }] }] },
        { type: "tableHeader", content: [{ type: "paragraph", content: [{ type: "text", text: "Severity" }] }] },
        { type: "tableHeader", content: [{ type: "paragraph", content: [{ type: "text", text: "Title" }] }] },
        { type: "tableHeader", content: [{ type: "paragraph", content: [{ type: "text", text: "Target" }] }] },
      ],
    },
  ];

  findings.forEach((f: any, i: number) => {
    tableRows.push({
      type: "tableRow",
      content: [
        { type: "tableCell", content: [{ type: "paragraph", content: [{ type: "text", text: String(i + 1) }] }] },
        { type: "tableCell", content: [{ type: "paragraph", content: [{ type: "text", text: (f.severity || "").toUpperCase(), marks: [{ type: "strong" }] }] }] },
        { type: "tableCell", content: [{ type: "paragraph", content: [{ type: "text", text: f.title }] }] },
        { type: "tableCell", content: [{ type: "paragraph", content: [{ type: "text", text: f.target || "N/A" }] }] },
      ],
    });
  });

  content.push({ type: "table", content: tableRows });
  content.push({ type: "heading", attrs: { level: 2 }, content: [{ type: "text", text: "Details" }] });

  for (const f of findings) {
    content.push(
      { type: "heading", attrs: { level: 3 }, content: [{ type: "text", text: `${(f.severity || "").toUpperCase()}: ${f.title}` }] },
      { type: "paragraph", content: [{ type: "text", text: f.description || "No description." }] }
    );
    if (f.evidence) {
      content.push({ type: "codeBlock", content: [{ type: "text", text: f.evidence }] });
    }
    if (f.remediation) {
      content.push({ type: "paragraph", content: [{ type: "text", text: `Remediation: ${f.remediation}`, marks: [{ type: "em" }] }] });
    }
    content.push({ type: "rule" });
  }

  return { type: "doc", version: 1, content };
}
