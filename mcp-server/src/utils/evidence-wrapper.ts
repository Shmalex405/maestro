/**
 * Evidence capture wrapper for MCP tool handlers.
 * Provides structured request/response evidence that tools can include in their output.
 */

export interface HttpEvidence {
  /** The curl command that was executed */
  curl_command: string;
  /** HTTP method used */
  method: string;
  /** Target URL */
  url: string;
  /** Request headers sent */
  request_headers?: Record<string, string>;
  /** Request body sent */
  request_body?: string;
  /** HTTP response status code */
  response_status?: number;
  /** Response headers received */
  response_headers?: Record<string, string>;
  /** Response body received (truncated if large) */
  response_body?: string;
  /** Timestamp of the request */
  timestamp: string;
}

export interface ToolEvidence {
  /** Tool name that generated this evidence */
  tool_name: string;
  /** All HTTP request/response pairs captured during execution */
  evidence_captures: HttpEvidence[];
}

/**
 * Build a curl command string that captures both response body and headers.
 * Returns the command and paths for output files.
 */
export function buildEvidenceCurl(opts: {
  url: string;
  method?: string;
  headers?: Record<string, string>;
  body?: string;
  outputPrefix?: string;
}): { command: string; bodyFile: string; headerFile: string; curlCommand: string } {
  const { url, method = "GET", headers = {}, body, outputPrefix = "/tmp/evidence" } = opts;
  const bodyFile = `${outputPrefix}-body.txt`;
  const headerFile = `${outputPrefix}-headers.txt`;

  const parts = [`curl -s -o ${bodyFile} -D ${headerFile} -w "%{http_code}"`];
  parts.push(`-X ${method}`);

  for (const [key, value] of Object.entries(headers)) {
    parts.push(`-H "${key}: ${value}"`);
  }

  if (body) {
    parts.push(`-d '${body.replace(/'/g, "'\\''")}'`);
  }

  parts.push(`"${url}"`);

  const curlCommand = parts.join(" ");
  return { command: curlCommand, bodyFile, headerFile, curlCommand };
}

/**
 * Generate a shell script block that captures HTTP evidence into JSON.
 * Use this inside executeInKali calls to get structured evidence back.
 */
export function evidenceCaptureScript(opts: {
  url: string;
  method?: string;
  headers?: Record<string, string>;
  body?: string;
  label?: string;
  index?: number;
}): string {
  const { url, method = "GET", headers = {}, body, label = "request", index = 0 } = opts;
  const prefix = `/tmp/ev-${index}`;

  const headerFlags = Object.entries(headers)
    .map(([k, v]) => `-H "${k}: ${v}"`)
    .join(" ");

  const bodyFlag = body ? `-d '${body.replace(/'/g, "'\\''")}'` : "";

  return [
    `STATUS_${index}=$(curl -s -o ${prefix}-body.txt -D ${prefix}-headers.txt -w "%{http_code}" -X ${method} ${headerFlags} ${bodyFlag} "${url}")`,
    `BODY_${index}=$(cat ${prefix}-body.txt 2>/dev/null | head -c 10000)`,
    `HDRS_${index}=$(cat ${prefix}-headers.txt 2>/dev/null)`,
  ].join(" && ");
}

/**
 * Parse evidence from shell variable output into HttpEvidence structure.
 */
export function parseEvidenceFromOutput(
  raw: string,
  curlCommand: string,
  url: string,
  method: string
): HttpEvidence {
  // Try to extract status code, headers, body from the raw output
  const statusMatch = raw.match(/HTTP\/[\d.]+ (\d{3})/);
  const status = statusMatch ? parseInt(statusMatch[1]) : undefined;

  return {
    curl_command: curlCommand,
    method,
    url,
    response_status: status,
    response_body: raw.slice(0, 10000), // Cap at 10KB
    timestamp: new Date().toISOString(),
  };
}
