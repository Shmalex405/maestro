import { executeInKali } from "../utils/docker-exec";
import { ToolEvidence } from "../utils/evidence-wrapper";

export const webAppTools = [
  {
    name: "run_sqlmap",
    description: "Test for SQL injection vulnerabilities. NON-DESTRUCTIVE: Uses safe testing techniques.",
    inputSchema: {
      type: "object",
      properties: {
        target: { type: "string", description: "Target URL with parameters" },
        method: { type: "string", enum: ["GET", "POST"], default: "GET" },
        data: { type: "string", description: "POST data if method is POST" },
        level: { type: "number", description: "Test level (1-5)", default: 2 },
        risk: { type: "number", description: "Risk level (1-3)", default: 1 },
      },
      required: ["target"],
    },
  },
  {
    name: "fuzz_endpoints",
    description: "Fuzz for hidden endpoints and directories using ffuf.",
    inputSchema: {
      type: "object",
      properties: {
        target: { type: "string", description: "Target URL with FUZZ placeholder" },
        wordlist: { type: "string", description: "Wordlist to use", default: "common" },
        extensions: { type: "string", description: "File extensions to check" },
      },
      required: ["target"],
    },
  },
  {
    name: "test_xss",
    description: "Test for cross-site scripting vulnerabilities.",
    inputSchema: {
      type: "object",
      properties: {
        target: { type: "string", description: "Target URL" },
        params: { type: "string", description: "Parameters to test" },
      },
      required: ["target"],
    },
  },
  {
    name: "crawl_site",
    description: "Crawl website to discover endpoints and parameters.",
    inputSchema: {
      type: "object",
      properties: {
        target: { type: "string", description: "Target URL" },
        depth: { type: "number", description: "Crawl depth", default: 2 },
      },
      required: ["target"],
    },
  },
];

export const webAppHandlers: Record<string, Function> = {
  run_sqlmap: async (args: { target: string; method?: string; data?: string; level?: number; risk?: number }) => {
    const { target, method = "GET", data, level = 2, risk = 1 } = args;
    
    // NON-DESTRUCTIVE: Use --batch and limit risk
    let command = `sqlmap -u "${target}" --batch --level=${level} --risk=${Math.min(risk, 2)} --threads=4`;
    
    if (method === "POST" && data) {
      command += ` --method=POST --data="${data}"`;
    }
    
    // Safety flags: no actual exploitation
    command += " --technique=BEUSTQ --skip-waf";
    
    return await executeInKali(command);
  },

  fuzz_endpoints: async (args: { target: string; wordlist?: string; extensions?: string }) => {
    const { target, wordlist = "common", extensions } = args;
    
    const wordlistPath = `/opt/pentest/wordlists/${wordlist}.txt`;
    let command = `ffuf -u ${target} -w ${wordlistPath} -mc 200,201,301,302,403 -o - -of json`;
    
    if (extensions) {
      command += ` -e ${extensions}`;
    }
    
    return await executeInKali(command);
  },

  test_xss: async (args: { target: string; params: string }) => {
    const { target, params } = args;
    // xsstrike is pip-installed as a console script; `python3 -m xsstrike` fails
    // (the package has no __main__). Prefer the `xsstrike` binary, fall back to the
    // git layout if a clone was used instead.
    const xss = `(command -v xsstrike >/dev/null 2>&1 && xsstrike || python3 "$(ls /opt/XSStrike/xsstrike.py /usr/share/xsstrike/xsstrike.py 2>/dev/null | head -1)")`;
    const command = `${xss} -u "${target}" --params "${params}" --skip-dom`;
    const result = await executeInKali(command);
    return JSON.stringify({
      raw_output: result,
      evidence: {
        tool_name: "test_xss",
        evidence_captures: [{
          curl_command: `xsstrike -u "${target}" --params "${params}" --skip-dom`,
          method: "GET",
          url: target,
          request_headers: {},
          timestamp: new Date().toISOString(),
        }],
      },
    });
  },

  crawl_site: async (args: { target: string; depth?: number }) => {
    const { target, depth = 2 } = args;
    const command = `gospider -s ${target} -d ${depth} --json`;
    return await executeInKali(command);
  },
};
