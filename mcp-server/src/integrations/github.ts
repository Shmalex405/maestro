import { getDatabase } from "../logging/log-store";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import * as yaml from "yaml";

/**
 * GitHub integration — the PR half of the "ticket + PR" remediation flow.
 *
 * Mirrors the shape of `jira.ts`: read credentials from env or the same
 * `integrations.yml` the desktop Settings → Integrations page writes, then
 * expose a small set of REST-backed helpers. The Personal Access Token stored
 * there already carries the `repo` scope (the desktop UI requests it), which is
 * exactly what opening a pull request needs — no extra credential.
 *
 * The one action that matters here is `openRemediationPR`: given an approved
 * code-associated finding, splice its `remediation_code` into the affected file
 * on a fresh branch and open a DRAFT PR for a human to review. Draft is
 * deliberate — this never merges anything, it stages a fix the team signs off
 * on, and links it back to the Jira ticket.
 */

interface GithubConfig {
  token: string;
  username?: string;
  /** REST API base — https://api.github.com for github.com, or a GHES host. */
  apiBase: string;
}

/**
 * Read GitHub config with the same fallback chain as `getJiraConfig`:
 * 1. Environment variables (CI / server deploys)
 * 2. integrations.yml from the host-mounted config or local dev path — the
 *    exact `github:` stanza the desktop Integrations page persists
 *    (`{ enabled, personal_access_token, username }`).
 */
function getGithubConfig(): GithubConfig {
  const apiBase = (process.env.GITHUB_API_BASE || "https://api.github.com").replace(/\/+$/, "");

  const envToken = process.env.GITHUB_TOKEN || process.env.GITHUB_PAT || "";
  if (envToken) {
    return { token: envToken, apiBase };
  }

  const configPaths = [
    "/mnt/host-home/.kali-mcp-pentest/integrations.yml", // Docker context
    path.join(os.homedir(), ".kali-mcp-pentest", "integrations.yml"), // Local dev
  ];

  for (const configPath of configPaths) {
    try {
      if (fs.existsSync(configPath)) {
        const content = fs.readFileSync(configPath, "utf-8");
        const config = yaml.parse(content);
        if (config?.github?.enabled && config.github.personal_access_token) {
          return {
            token: config.github.personal_access_token,
            username: config.github.username,
            apiBase,
          };
        }
      }
    } catch (e) {
      console.warn(`[github] Could not read config from ${configPath}:`, e);
    }
  }

  return { token: "", apiBase };
}

function ghHeaders(config: GithubConfig): Record<string, string> {
  return {
    Authorization: `Bearer ${config.token}`,
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
    "Content-Type": "application/json",
  };
}

async function ghFetch(
  config: GithubConfig,
  pathname: string,
  init?: RequestInit,
): Promise<{ ok: boolean; status: number; body: any }> {
  const res = await fetch(`${config.apiBase}${pathname}`, {
    ...init,
    headers: { ...ghHeaders(config), ...(init?.headers || {}) },
  });
  const text = await res.text();
  let body: any = undefined;
  try {
    body = text ? JSON.parse(text) : undefined;
  } catch {
    body = text;
  }
  return { ok: res.ok, status: res.status, body };
}

/** Verify the token by resolving the authenticated user. */
export async function testGithubConnection(): Promise<{
  status: string;
  username?: string;
  error?: string;
}> {
  const config = getGithubConfig();
  if (!config.token) {
    return { status: "error", error: "GitHub not configured. Add a token in Settings > Integrations or set GITHUB_TOKEN." };
  }
  const { ok, status, body } = await ghFetch(config, "/user");
  if (!ok) {
    return { status: "error", error: `HTTP ${status}: ${typeof body === "string" ? body : body?.message ?? ""}` };
  }
  return { status: "ok", username: body?.login };
}

/** A single file change to stage on the PR branch. */
export interface FileEdit {
  /** Repo-relative path, e.g. "vnext/domains/payments/client.go". */
  path: string;
  /**
   * "splice" — replace the inclusive 1-based line range [lineStart, lineEnd]
   *   with `content` (the finding's remediation_code). Used for SAST fixes and
   *   dependency-manifest bumps where we know the exact location.
   * "replace" — overwrite the whole file with `content`.
   */
  mode: "splice" | "replace";
  content: string;
  lineStart?: number;
  lineEnd?: number;
}

export interface OpenPROptions {
  owner: string;
  repo: string;
  /** Base branch to target; defaults to the repo's default branch. */
  baseBranch?: string;
  branch: string;
  title: string;
  body: string;
  edits: FileEdit[];
  /** Draft by default — a remediation PR is always human-reviewed before merge. */
  draft?: boolean;
}

export interface OpenPRResult {
  status: "created" | "error";
  url?: string;
  number?: number;
  branch?: string;
  error?: string;
}

/** Base64 helpers for the Contents API (which round-trips file bytes as base64). */
function decodeBase64(b64: string): string {
  return Buffer.from(b64, "base64").toString("utf-8");
}
function encodeBase64(s: string): string {
  return Buffer.from(s, "utf-8").toString("base64");
}

/**
 * Apply an edit to a file's current text. Splice replaces an inclusive 1-based
 * line range; replace overwrites wholesale. Preserves the file's newline count
 * so the resulting diff is minimal and reviewable.
 */
function applyEdit(current: string, edit: FileEdit): string {
  if (edit.mode === "replace") return edit.content;

  if (edit.lineStart == null || edit.lineEnd == null) {
    throw new Error(`splice edit for ${edit.path} requires lineStart and lineEnd`);
  }
  if (edit.lineStart < 1 || edit.lineEnd < edit.lineStart) {
    throw new Error(`invalid line range ${edit.lineStart}-${edit.lineEnd} for ${edit.path}`);
  }

  const lines = current.split("\n");
  if (edit.lineEnd > lines.length) {
    throw new Error(
      `line range ${edit.lineStart}-${edit.lineEnd} exceeds ${edit.path} length (${lines.length} lines) — the finding's line numbers may be stale`,
    );
  }
  const before = lines.slice(0, edit.lineStart - 1);
  const after = lines.slice(edit.lineEnd);
  const replacement = edit.content.replace(/\n$/, "").split("\n");
  return [...before, ...replacement, ...after].join("\n");
}

/**
 * Open a draft remediation PR: branch off base, stage each edit via the
 * Contents API, then open the PR. Each step surfaces a precise error rather
 * than leaving a half-created branch silently — the caller reports it to the UI.
 */
export async function openRemediationPR(opts: OpenPROptions): Promise<OpenPRResult> {
  const config = getGithubConfig();
  if (!config.token) {
    return { status: "error", error: "GitHub not configured. Add a token in Settings > Integrations or set GITHUB_TOKEN." };
  }
  const { owner, repo } = opts;

  // Resolve the base branch (default branch when not specified) and its head SHA.
  let baseBranch = opts.baseBranch;
  if (!baseBranch) {
    const repoInfo = await ghFetch(config, `/repos/${owner}/${repo}`);
    if (!repoInfo.ok) {
      return { status: "error", error: `Cannot read repo ${owner}/${repo}: HTTP ${repoInfo.status} ${repoInfo.body?.message ?? ""}` };
    }
    baseBranch = repoInfo.body?.default_branch;
    if (!baseBranch) return { status: "error", error: `Could not determine default branch for ${owner}/${repo}` };
  }

  const baseRef = await ghFetch(config, `/repos/${owner}/${repo}/git/ref/heads/${encodeURIComponent(baseBranch)}`);
  if (!baseRef.ok) {
    return { status: "error", error: `Cannot read base branch ${baseBranch}: HTTP ${baseRef.status} ${baseRef.body?.message ?? ""}` };
  }
  const baseSha: string = baseRef.body?.object?.sha;
  if (!baseSha) return { status: "error", error: `No commit SHA for ${baseBranch}` };

  // Create the PR branch. A 422 means it already exists — reuse it so a retry
  // after a partial failure is idempotent rather than a hard stop.
  const createRef = await ghFetch(config, `/repos/${owner}/${repo}/git/refs`, {
    method: "POST",
    body: JSON.stringify({ ref: `refs/heads/${opts.branch}`, sha: baseSha }),
  });
  if (!createRef.ok && createRef.status !== 422) {
    return { status: "error", error: `Cannot create branch ${opts.branch}: HTTP ${createRef.status} ${createRef.body?.message ?? ""}` };
  }

  // Stage each edit as a commit on the branch via the Contents API.
  for (const edit of opts.edits) {
    const encodedPath = edit.path.split("/").map(encodeURIComponent).join("/");
    let currentSha: string | undefined;
    let newContent: string;

    if (edit.mode === "splice") {
      const fileRes = await ghFetch(config, `/repos/${owner}/${repo}/contents/${encodedPath}?ref=${encodeURIComponent(opts.branch)}`);
      if (!fileRes.ok) {
        return { status: "error", error: `Cannot read ${edit.path}: HTTP ${fileRes.status} ${fileRes.body?.message ?? ""}` };
      }
      if (fileRes.body?.encoding !== "base64" || typeof fileRes.body?.content !== "string") {
        return { status: "error", error: `${edit.path} is not a readable text file (encoding ${fileRes.body?.encoding})` };
      }
      currentSha = fileRes.body.sha;
      try {
        newContent = applyEdit(decodeBase64(fileRes.body.content), edit);
      } catch (e) {
        return { status: "error", error: e instanceof Error ? e.message : String(e) };
      }
    } else {
      // replace — fetch the existing sha if the file is already present.
      const fileRes = await ghFetch(config, `/repos/${owner}/${repo}/contents/${encodedPath}?ref=${encodeURIComponent(opts.branch)}`);
      currentSha = fileRes.ok ? fileRes.body?.sha : undefined;
      newContent = edit.content;
    }

    const put = await ghFetch(config, `/repos/${owner}/${repo}/contents/${encodedPath}`, {
      method: "PUT",
      body: JSON.stringify({
        message: `${opts.title} — ${edit.path}`,
        content: encodeBase64(newContent),
        branch: opts.branch,
        ...(currentSha ? { sha: currentSha } : {}),
      }),
    });
    if (!put.ok) {
      return { status: "error", error: `Cannot commit ${edit.path}: HTTP ${put.status} ${put.body?.message ?? ""}` };
    }
  }

  // Open the pull request (draft by default).
  const pr = await ghFetch(config, `/repos/${owner}/${repo}/pulls`, {
    method: "POST",
    body: JSON.stringify({
      title: opts.title,
      head: opts.branch,
      base: baseBranch,
      body: opts.body,
      draft: opts.draft ?? true,
    }),
  });
  if (!pr.ok) {
    return { status: "error", error: `Cannot open PR: HTTP ${pr.status} ${pr.body?.message ?? ""}` };
  }

  return {
    status: "created",
    url: pr.body?.html_url,
    number: pr.body?.number,
    branch: opts.branch,
  };
}

/**
 * Persist the PR linkage on the finding row so the Findings UI can render a PR
 * chip next to the Jira chip — mirrors how `createJiraTicket` writes back
 * `jira_ticket`.
 */
export function recordFindingPR(
  findingId: string,
  pr: { url?: string; number?: number; branch?: string; status?: string },
): void {
  const db = getDatabase();
  db.prepare(
    "UPDATE findings SET pr_url = ?, pr_number = ?, pr_branch = ?, pr_status = ?, updated_at = ? WHERE id = ?",
  ).run(pr.url ?? null, pr.number ?? null, pr.branch ?? null, pr.status ?? "draft", new Date().toISOString(), findingId);
}
