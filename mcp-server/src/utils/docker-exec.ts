import Docker from "dockerode";
import { PassThrough } from "stream";
import { exec as cpExec } from "child_process";
import { recordToolExecution } from "../logging/tool-provenance";
import { screenCommand } from "./destructive-guard";

const CONTAINER_NAME = "kali-pentest";

/** Rich result of a container command: stdout, stderr, and the real exit code. */
export interface ExecResult {
  stdout: string;
  stderr: string;
  exitCode: number | null;
}

// Detect if we're running inside the Kali container
export function isInsideContainer(): boolean {
  try {
    // Check if /.dockerenv exists (standard Docker marker)
    require("fs").accessSync("/.dockerenv");
    return true;
  } catch {
    // Fall back to checking hostname
    const os = require("os");
    return os.hostname() === CONTAINER_NAME;
  }
}

const runningInsideContainer = isInsideContainer();

// When inside the container, execute commands directly
function executeLocally(command: string): Promise<ExecResult> {
  return new Promise((resolve, reject) => {
    cpExec(command, { maxBuffer: 50 * 1024 * 1024, timeout: 600000 }, (error, stdout, stderr) => {
      if (error && !stdout && !stderr && typeof (error as any).code !== "number") {
        // Genuine launch failure (no output, no numeric exit code) — surface it.
        reject(error);
        return;
      }
      // child_process puts the exit code on the error object; 0 when no error.
      const exitCode = error && typeof (error as any).code === "number" ? (error as any).code : 0;
      resolve({ stdout, stderr, exitCode });
    });
  });
}

// When outside the container, use Docker API to exec into it
function executeViaDocker(command: string): Promise<ExecResult> {
  const docker = new Docker({ socketPath: "/var/run/docker.sock" });
  const container = docker.getContainer(CONTAINER_NAME);

  return new Promise(async (resolve, reject) => {
    try {
      const exec = await container.exec({
        Cmd: ["bash", "-c", command],
        AttachStdout: true,
        AttachStderr: true,
      });

      exec.start({ hijack: true, stdin: false }, (err: Error | null, stream: NodeJS.ReadableStream | undefined) => {
        if (err) {
          reject(err);
          return;
        }

        if (!stream) {
          reject(new Error("No stream returned from exec"));
          return;
        }

        const stdout = new PassThrough();
        const stderr = new PassThrough();
        docker.modem.demuxStream(stream, stdout, stderr);

        let output = "";
        let stderrOutput = "";

        stdout.on("data", (chunk: Buffer) => {
          output += chunk.toString();
        });

        stderr.on("data", (chunk: Buffer) => {
          stderrOutput += chunk.toString();
        });

        stream.on("end", async () => {
          stdout.end();
          stderr.end();
          // Query the real exit code the soft-fail pattern would otherwise hide.
          let exitCode: number | null = null;
          try {
            const info = await exec.inspect();
            exitCode = typeof info.ExitCode === "number" ? info.ExitCode : null;
          } catch {
            exitCode = null;
          }
          resolve({ stdout: output, stderr: stderrOutput, exitCode });
        });

        stream.on("error", (error: Error) => {
          reject(error);
        });
      });
    } catch (err) {
      reject(err);
    }
  });
}

/**
 * Execute a command in Kali and return the full result (stdout, stderr, exit code).
 * Records tool-execution provenance as a side-effect, attributed to the current
 * AsyncLocalStorage tool context. Provenance recording never affects the result.
 */
export async function executeInKaliDetailed(command: string): Promise<ExecResult> {
  const startedAt = Date.now();

  // Harness-wide non-destructive backstop: refuse catastrophic OS/disk/infra
  // operations before they ever reach the container, for EVERY tool. The command
  // never executes; provenance records it as not-run so the coverage gate never
  // mistakes a refusal for a clean tool run.
  const screen = screenCommand(command);
  if (screen.blocked) {
    const message =
      `DESTRUCTIVE_BLOCKED: refused to execute a ${screen.category} command ` +
      `(${screen.reason}). The Maestro harness is non-destructive by construction — ` +
      `this operation is never run, regardless of which tool requested it. Command withheld.`;
    recordToolExecution({
      command,
      exitCode: 126,
      ran: false,
      durationMs: Date.now() - startedAt,
      stderr: message,
    });
    return { stdout: "", stderr: message, exitCode: 126 };
  }

  let result: ExecResult;
  try {
    result = runningInsideContainer ? await executeLocally(command) : await executeViaDocker(command);
  } catch (err) {
    // Launch failure (process never ran): record it, then re-throw as before.
    recordToolExecution({
      command,
      exitCode: null,
      ran: false,
      durationMs: Date.now() - startedAt,
      stderr: String(err),
    });
    throw err;
  }
  recordToolExecution({
    command,
    exitCode: result.exitCode,
    ran: true,
    durationMs: Date.now() - startedAt,
    stderr: result.stderr,
  });
  return result;
}

/**
 * Back-compat string entry point used by all existing tool handlers. Returns
 * stdout (falling back to stderr) exactly as before — the exit code is now
 * captured for provenance but the string contract is unchanged.
 */
export async function executeInKali(command: string): Promise<string> {
  const { stdout, stderr } = await executeInKaliDetailed(command);
  return stdout || stderr;
}

export async function isKaliRunning(): Promise<boolean> {
  if (runningInsideContainer) {
    return true; // We're inside it, so it's running
  }

  try {
    const docker = new Docker({ socketPath: "/var/run/docker.sock" });
    const container = docker.getContainer(CONTAINER_NAME);
    const info = await container.inspect();
    return info.State.Running;
  } catch {
    return false;
  }
}
