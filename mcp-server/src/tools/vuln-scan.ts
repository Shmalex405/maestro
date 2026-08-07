import { executeInKali } from "../utils/docker-exec";

export const vulnScanTools = [
  {
    name: "run_nuclei",
    description: "Run nuclei vulnerability scanner with specified templates.",
    inputSchema: {
      type: "object",
      properties: {
        target: { type: "string", description: "Target URL" },
        templates: { type: "string", description: "Template tags (e.g., 'cve,owasp')", default: "cve,owasp-top-10" },
        severity: { type: "string", description: "Severity filter", default: "medium,high,critical" },
      },
      required: ["target"],
    },
  },
  {
    name: "run_nikto",
    description: "Run nikto web server scanner.",
    inputSchema: {
      type: "object",
      properties: {
        target: { type: "string", description: "Target URL" },
        tuning: { type: "string", description: "Scan tuning options", default: "x" },
      },
      required: ["target"],
    },
  },
  {
    name: "run_wpscan",
    description: "Scan WordPress installations for vulnerabilities.",
    inputSchema: {
      type: "object",
      properties: {
        target: { type: "string", description: "WordPress URL" },
        enumerate: { type: "string", description: "Enumeration options (u,p,t,vp)", default: "vp,vt,u" },
      },
      required: ["target"],
    },
  },
  {
    name: "search_exploits",
    description: "Search for exploits using searchsploit.",
    inputSchema: {
      type: "object",
      properties: {
        query: { type: "string", description: "Search query (service name, CVE, etc.)" },
      },
      required: ["query"],
    },
  },
];

export const vulnScanHandlers: Record<string, Function> = {
  run_nuclei: async (args: { target: string; templates?: string; severity?: string }) => {
    const { target, templates = "cve,owasp-top-10", severity = "medium,high,critical" } = args;
    // -stats-json writes periodic {"requests":N,...} lines to stderr; capture
    // them to a file, then echo the peak (cumulative) request count to stdout as
    // a sentinel the pipeline parses for the "attacks executed" metric. Findings
    // (-jsonl) stay on stdout untouched; the sentinel carries no template-id so
    // the finding parser ignores it. Best-effort: if stats are unavailable the
    // sentinel is empty and the pipeline falls back to a calibrated estimate.
    const statsFile = "/tmp/nuclei_stats_$$.jsonl";
    const command =
      `nuclei -u ${target} -tags ${templates} -severity ${severity} -timeout 10 -retries 2 -jsonl ` +
      `-stats -stats-json -stats-interval 5 2>${statsFile}; ` +
      `echo "__NUCLEI_REQUESTS__:$(grep -ho '"requests":[0-9]*' ${statsFile} 2>/dev/null | grep -o '[0-9]*' | sort -n | tail -1)"; ` +
      `rm -f ${statsFile}`;
    return await executeInKali(command);
  },

  run_nikto: async (args: { target: string; tuning?: string }) => {
    const { target, tuning = "x" } = args;
    const command = `nikto -h ${target} -Tuning ${tuning} -Format csv -timeout 10`;
    return await executeInKali(command);
  },

  run_wpscan: async (args: { target: string; enumerate?: string }) => {
    const { target, enumerate = "vp,vt,u" } = args;
    const command = `wpscan --url ${target} --enumerate ${enumerate} --format json --no-banner`;
    return await executeInKali(command);
  },

  search_exploits: async (args: { query: string }) => {
    const { query } = args;
    const command = `searchsploit ${query} --json`;
    return await executeInKali(command);
  },
};
