import { executeInKali } from "../utils/docker-exec";

export const assessmentContextTools = [
  {
    name: "save_assessment_context",
    description: "Save assessment context data so other agents can access results from prior phases. Data is keyed by agent name and stored as JSON.",
    inputSchema: {
      type: "object",
      properties: {
        assessment_id: { type: "string", description: "Assessment ID" },
        agent_name: { type: "string", description: "Name of the agent saving context (e.g., 'recon-infra', 'web-security')" },
        context_data: { type: "string", description: "JSON-encoded context data to save (findings, test results, discovered endpoints, etc.)" },
      },
      required: ["assessment_id", "agent_name", "context_data"],
    },
  },
  {
    name: "load_assessment_context",
    description: "Load assessment context data saved by other agents in prior phases. Returns all agent contexts or a specific agent's context.",
    inputSchema: {
      type: "object",
      properties: {
        assessment_id: { type: "string", description: "Assessment ID" },
        agent_name: { type: "string", description: "Optional: load only this agent's context. Omit to load all." },
      },
      required: ["assessment_id"],
    },
  },
];

export const assessmentContextHandlers: Record<string, Function> = {
  save_assessment_context: async (args: { assessment_id: string; agent_name: string; context_data: string }) => {
    const { assessment_id, agent_name, context_data } = args;
    const dir = `/opt/pentest/output/assessment-context`;
    const filePath = `${dir}/${assessment_id}.json`;

    // Read existing context or create new
    const readCmd = `mkdir -p ${dir} && cat ${filePath} 2>/dev/null || echo '{}'`;
    const existing = await executeInKali(readCmd);

    let context: Record<string, unknown>;
    try {
      context = JSON.parse(existing);
    } catch {
      context = {};
    }

    // Merge agent's data
    let agentData: unknown;
    try {
      agentData = JSON.parse(context_data);
    } catch {
      agentData = context_data;
    }
    context[agent_name] = {
      data: agentData,
      updated_at: new Date().toISOString(),
    };

    // Write back
    const writeCmd = `cat > ${filePath} << 'CTXEOF'\n${JSON.stringify(context, null, 2)}\nCTXEOF`;
    await executeInKali(writeCmd);

    return JSON.stringify({
      status: "saved",
      assessment_id,
      agent_name,
      agents_with_context: Object.keys(context),
    });
  },

  load_assessment_context: async (args: { assessment_id: string; agent_name?: string }) => {
    const { assessment_id, agent_name } = args;
    const filePath = `/opt/pentest/output/assessment-context/${assessment_id}.json`;

    const readCmd = `cat ${filePath} 2>/dev/null || echo '{}'`;
    const raw = await executeInKali(readCmd);

    let context: Record<string, unknown>;
    try {
      context = JSON.parse(raw);
    } catch {
      context = {};
    }

    if (agent_name) {
      return JSON.stringify({
        assessment_id,
        agent_name,
        context: context[agent_name] || null,
        available_agents: Object.keys(context),
      });
    }

    return JSON.stringify({
      assessment_id,
      agents: Object.keys(context),
      context,
    });
  },
};
