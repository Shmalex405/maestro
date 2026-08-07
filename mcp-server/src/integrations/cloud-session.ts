/**
 * Cloud session bridge for the local MCP server.
 *
 * The desktop app writes the active org's backend URL + Cognito ID token to
 * a small file on the host (`~/.kali-mcp-pentest/cloud-session.json`). When
 * present and unexpired, MCP write tools (create_finding, etc.) POST to the
 * org's cloud backend instead of writing to local SQLite. When absent or
 * expired, the existing local-SQLite path runs unchanged.
 *
 * The file path can be overridden with MAESTRO_CLOUD_SESSION_PATH for the
 * in-container HTTP server case (where the host home is mounted elsewhere).
 *
 * No refresh logic lives here — that's the desktop's job. If our token is
 * expired, we surface the failure rather than silently falling back; the
 * desktop's getValidIdToken() refreshes on the next user-driven read and
 * rewrites the file.
 */
import * as fs from "fs";
import * as path from "path";
import * as os from "os";

interface CloudSession {
  backendUrl: string;
  idToken: string;
  tokenExpiry: number; // unix ms
  writtenAt?: string;
}

const SESSION_PATH =
  process.env.MAESTRO_CLOUD_SESSION_PATH ||
  path.join(os.homedir(), ".kali-mcp-pentest", "cloud-session.json");

/** Read the active cloud session, or null if no session is configured (user
 *  not authenticated, or running an offline / local-only setup). Returns null
 *  on parse errors rather than throwing — the caller falls back to local. */
export function loadCloudSession(): CloudSession | null {
  try {
    if (!fs.existsSync(SESSION_PATH)) return null;
    const raw = fs.readFileSync(SESSION_PATH, "utf-8");
    const parsed = JSON.parse(raw) as CloudSession;
    if (!parsed.backendUrl || !parsed.idToken) return null;
    return parsed;
  } catch (err) {
    console.warn(`[cloud-session] failed to load ${SESSION_PATH}: ${err}`);
    return null;
  }
}

/** True iff a cloud session file exists with a non-expired token. We use a
 *  60s safety buffer — within the last minute of validity we treat the
 *  token as expired so a request that takes 200ms doesn't land at the server
 *  with a just-aged-out token. */
export function hasCloudSession(): boolean {
  const session = loadCloudSession();
  if (!session) return false;
  if (!session.tokenExpiry) return false;
  return Date.now() < session.tokenExpiry - 60_000;
}

export class CloudSessionError extends Error {
  constructor(public status: number, message: string) {
    super(message);
    this.name = "CloudSessionError";
  }
}

/** POST/PATCH/PUT/DELETE against `${backendUrl}/api/v1${endpoint}` with the
 *  current cloud session's bearer token. Throws CloudSessionError on
 *  expired session or non-2xx response — callers should let the error
 *  surface rather than fall back silently. */
export async function cloudRequest<T>(
  endpoint: string,
  options: { method?: string; body?: unknown } = {}
): Promise<T> {
  const session = loadCloudSession();
  if (!session) {
    throw new CloudSessionError(401, "No cloud session — desktop not authenticated");
  }
  if (Date.now() >= session.tokenExpiry - 60_000) {
    throw new CloudSessionError(
      401,
      "Cloud session expired — desktop needs to refresh (open Maestro and try again)"
    );
  }

  const baseTrim = session.backendUrl.replace(/\/+$/, "");
  const url = `${baseTrim}/api/v1${endpoint}`;
  const init: RequestInit = {
    method: options.method || "GET",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${session.idToken}`,
    },
  };
  if (options.body !== undefined) {
    init.body = typeof options.body === "string" ? options.body : JSON.stringify(options.body);
  }

  const res = await fetch(url, init);
  if (!res.ok) {
    let detail = `Cloud request failed: ${res.status} ${res.statusText}`;
    try {
      const body = (await res.json()) as { detail?: string; message?: string };
      detail = body.detail || body.message || detail;
    } catch {
      // body wasn't JSON — keep the status-line detail
    }
    throw new CloudSessionError(res.status, detail);
  }
  const text = await res.text();
  return text ? (JSON.parse(text) as T) : (null as T);
}

/** Multipart-upload a file (typically a freshly-rendered PDF) to a
 *  cloud endpoint. Reads the file from the container filesystem and
 *  streams the bytes as a single `file` part. Backend `/reports/{id}/upload`
 *  expects this shape — see backend-rs/src/routes/reports.rs. */
export async function cloudUploadFile<T>(
  endpoint: string,
  filePath: string,
  contentType: string = "application/pdf",
): Promise<T> {
  const session = loadCloudSession();
  if (!session) {
    throw new CloudSessionError(401, "No cloud session — desktop not authenticated");
  }
  if (Date.now() >= session.tokenExpiry - 60_000) {
    throw new CloudSessionError(
      401,
      "Cloud session expired — desktop needs to refresh (open Maestro and try again)"
    );
  }

  const fs = await import("node:fs/promises");
  const path = await import("node:path");
  const bytes = await fs.readFile(filePath);
  const filename = path.basename(filePath);

  const form = new FormData();
  // Node 18+ has Blob built in; the cast keeps TS happy with FormData typing.
  form.append("file", new Blob([new Uint8Array(bytes)], { type: contentType }), filename);

  const baseTrim = session.backendUrl.replace(/\/+$/, "");
  const url = `${baseTrim}/api/v1${endpoint}`;
  const res = await fetch(url, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${session.idToken}`,
      // No Content-Type header — fetch sets multipart boundary
      // automatically when body is FormData.
    },
    body: form,
  });

  if (!res.ok) {
    let detail = `Cloud upload failed: ${res.status} ${res.statusText}`;
    try {
      const body = (await res.json()) as { detail?: string; message?: string };
      detail = body.detail || body.message || detail;
    } catch {
      // body wasn't JSON — keep the status-line detail
    }
    throw new CloudSessionError(res.status, detail);
  }
  const text = await res.text();
  return text ? (JSON.parse(text) as T) : (null as T);
}
