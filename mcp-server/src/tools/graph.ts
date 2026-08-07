// Attack-graph substrate tools (backend migration 0046 + /graph/*).
//
// The generic successor to `record_attack_paths`: instead of one opaque JSONB
// snapshot per producer, these tools read/write the persistent, accumulating
// node/edge union and run the graph queries the snapshot can't answer
// (pathfinding, reachability, cross-finding/cross-assessment lateral movement).
//
// All are brain-agnostic and org-scoped via the cloud JWT session — they gate on
// hasCloudSession() and route through cloudRequest exactly like record_attack_paths
// (which is kept as a thin back-compat alias). No cloud account is required: the
// substrate is org-wide, keyed by the JWT's org_id.

import { cloudRequest, hasCloudSession, CloudSessionError } from "../integrations/cloud-session";

function noSession(what: string): string {
  return JSON.stringify({
    ok: false,
    error: `No active cloud session — ${what} requires a signed-in backend session (local-only run).`,
  });
}

function failure(e: unknown): string {
  const msg =
    e instanceof CloudSessionError
      ? `cloud request failed (${e.status}): ${e.message}`
      : e instanceof Error
        ? e.message
        : String(e);
  return JSON.stringify({ ok: false, error: msg });
}

function qs(params: Record<string, string | number | boolean | undefined | null>): string {
  const parts: string[] = [];
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null && v !== "") {
      parts.push(`${encodeURIComponent(k)}=${encodeURIComponent(String(v))}`);
    }
  }
  return parts.length ? `?${parts.join("&")}` : "";
}

export const graphTools = [
  {
    name: "query_attack_paths",
    description:
      "Read the accumulated attack-graph substrate: the union of every node/edge ever ingested by any producer (chain-analysis, cloud-analysis, identity-analysis, reachability correlations), keyed org-wide. Returns { nodes, edges } so you can inspect what's already in the graph before assembling new chains — including lateral-movement nodes that emerged across targets. Filter nodes by kind / target_id. No-op with ok:false if there is no active cloud session.",
    inputSchema: {
      type: "object",
      properties: {
        target_id: { type: "string", description: "Filter nodes to this target (optional)" },
        kind: {
          type: "string",
          description:
            "Filter nodes to one kind (source/exposure/workload/vulnerability/identity/asset or a custom kind)",
        },
        limit: { type: "number", description: "Max rows per collection (default 200 nodes / 500 edges)" },
      },
      required: [],
    },
  },
  {
    name: "find_attack_paths",
    description:
      "Pathfind over the accumulated substrate with a recursive graph traversal (cycle-guarded, depth-capped). Ask the graph for attack paths instead of hand-assembling them: e.g. every path from an internet 'source' node to a crown-jewel 'asset' (is_goal) node. Set exploited_only to keep only EXPLOITED edges (drops detected-only/dashed). Set verified_only to keep only edges an oracle re-proved — a provably-traversable path rather than a reported one. Set reachable_only for the near-linear 'can X reach a crown jewel?' answer (distinct reachable goals, no path enumeration). Set seed_caps/goal_caps to PLAN a post-exploitation campaign: the walk accumulates the attacker's capabilities (seed_caps ∪ each node's grants ∪ each edge's grants) and only crosses an edge whose `requires` are all held — the capability-gated planner that answers 'from this foothold, what's reachable next?'. Returns { paths:[{start_key,nodes,edges,depth}], truncated } or { reachable:[...], truncated }. No-op with ok:false if there is no active cloud session.",
    inputSchema: {
      type: "object",
      properties: {
        source_kind: {
          type: "string",
          description: "Start from all nodes of this kind (defaults to 'source' if neither source_* given)",
        },
        source_keys: {
          type: "array",
          items: { type: "string" },
          description: "Start from these specific node ids (overrides source_kind)",
        },
        goal_kind: {
          type: "string",
          description:
            "Treat nodes of this kind as goals. If omitted, goals are nodes flagged is_goal (built-in: 'asset').",
        },
        max_depth: { type: "number", description: "Max path length (default 6, clamped to 12)" },
        exploited_only: {
          type: "boolean",
          description: "Traverse only edges that were actually exploited (default false)",
        },
        verified_only: {
          type: "boolean",
          description:
            "Traverse only edges whose backing finding an ORACLE re-proved (default false). exploited_only asks 'did a run walk this?'; verified_only asks 'was every step re-proven in code?' — use it to produce a path each step of which carries a replay capsule the customer can run. Migration 0050.",
        },
        seed_caps: {
          type: "array",
          items: { type: "string" },
          description:
            "Post-exploitation planning: capabilities the attacker starts holding at every entry node (e.g. ['unauthenticated_access'] for an anonymous start, or a foothold's grants). An edge is crossed only when its `requires` ⊆ the capabilities accumulated so far. Omit for plain reachability.",
        },
        goal_caps: {
          type: "array",
          items: { type: "string" },
          description:
            "Post-exploitation planning: goal is reached when ALL these capabilities are held (e.g. ['cloud_org_admin']), alongside is_goal / goal_kind nodes.",
        },
        reachable_only: {
          type: "boolean",
          description: "Return distinct reachable goals only, no path enumeration (default false)",
        },
        limit: { type: "number", description: "Max paths/goals returned (default 500)" },
      },
      required: [],
    },
  },
  {
    name: "register_graph_kinds",
    description:
      "Register custom node/edge kinds (the OpenGraph-style extension bundle) so the substrate and the explorer UI render them with your styling — no code change. Each kind: { kind (unique name), is_edge? (false=node), is_goal? (treat as crown jewel), label?, display? ({fill,stroke,text,icon}), schema? (JSON-schema for attrs) }. Cannot redefine a built-in kind. Use this before ingesting nodes of a novel kind (e.g. an okta-identity surface), or pass auto_register to ingest_graph. No-op with ok:false if there is no active cloud session.",
    inputSchema: {
      type: "object",
      properties: {
        kinds: {
          type: "array",
          description: "Kind definitions to register",
          items: { type: "object" },
        },
      },
      required: ["kinds"],
    },
  },
  {
    name: "ingest_graph",
    description:
      "Generic dual-write ingest into the attack-graph substrate — the successor to record_attack_paths. Writes typed nodes + edges into the accumulating union (re-runs MERGE: sources/assessments grow, last_seen advances — never wipes). Nodes: { id, kind, label?, layer?, severity?, sub?, is_goal? (tag crown jewels), grants? (capabilities LANDING on this node yields, e.g. a credential/loot node granting ['db_cred']), attrs? }. Edges: { from, to, kind? (default 'leads_to'), exploited?, requires? (preconditions ⊆ held to traverse — the capability-gated planner reads these), grants? (capabilities this step yields), verified_by_finding_id? (the finding whose ORACLE RECEIPT backs this step — the edge's verdict is DERIVED from that finding, so pointing at one cannot make an unproven edge look proven; set it so find_attack_paths(verified_only) can return provably-traversable paths), attrs? }. Stamp requires/grants from the chain-patterns.yml capability map so find_attack_paths can plan post-exploitation campaigns. Every kind must be registered (built-in or via kinds[]/auto_register) or the ingest is rejected. No-op with ok:false if there is no active cloud session.",
    inputSchema: {
      type: "object",
      properties: {
        source: {
          type: "string",
          description: "Producer label (e.g. chain-analysis, cloud-analysis, identity-analysis)",
        },
        target_id: { type: "string", description: "Target this graph belongs to (optional; union is org-wide)" },
        assessment_id: {
          type: "string",
          description: "Assessment run id (defaults to MAESTRO_ASSESSMENT_ID)",
        },
        nodes: { type: "array", description: "Graph nodes", items: { type: "object" } },
        edges: { type: "array", description: "Graph edges", items: { type: "object" } },
        kinds: {
          type: "array",
          description: "Custom kinds referenced by the nodes/edges, registered before ingest",
          items: { type: "object" },
        },
        auto_register: {
          type: "boolean",
          description: "Auto-register any unknown kind as a minimal custom kind instead of rejecting",
        },
      },
      required: ["source", "nodes", "edges"],
    },
  },
];

export const graphHandlers: Record<string, Function> = {
  query_attack_paths: async (args: { target_id?: string; kind?: string; limit?: number }) => {
    if (!hasCloudSession()) return noSession("query_attack_paths");
    try {
      const nodes = await cloudRequest<unknown[]>(
        `/graph/nodes${qs({ target_id: args.target_id, kind: args.kind, limit: args.limit })}`,
      );
      const edges = await cloudRequest<unknown[]>(`/graph/edges${qs({ limit: args.limit })}`);
      return JSON.stringify(
        { ok: true, nodes, edges, node_count: nodes.length, edge_count: edges.length },
        null,
        2,
      );
    } catch (e) {
      return failure(e);
    }
  },

  find_attack_paths: async (args: {
    source_kind?: string;
    source_keys?: string[];
    goal_kind?: string;
    max_depth?: number;
    exploited_only?: boolean;
    verified_only?: boolean;
    seed_caps?: string[];
    goal_caps?: string[];
    reachable_only?: boolean;
    limit?: number;
  }) => {
    if (!hasCloudSession()) return noSession("find_attack_paths");
    try {
      const resp = await cloudRequest<Record<string, unknown>>("/graph/paths", {
        method: "POST",
        body: {
          source_kind: args.source_kind ?? null,
          source_keys: Array.isArray(args.source_keys) ? args.source_keys : null,
          goal_kind: args.goal_kind ?? null,
          max_depth: typeof args.max_depth === "number" ? args.max_depth : 6,
          exploited_only: args.exploited_only ?? false,
          verified_only: args.verified_only ?? false,
          seed_caps: Array.isArray(args.seed_caps) ? args.seed_caps : null,
          goal_caps: Array.isArray(args.goal_caps) ? args.goal_caps : null,
          reachable_only: args.reachable_only ?? false,
          limit: typeof args.limit === "number" ? args.limit : 500,
        },
      });
      return JSON.stringify({ ok: true, ...resp }, null, 2);
    } catch (e) {
      return failure(e);
    }
  },

  register_graph_kinds: async (args: { kinds: unknown[] }) => {
    if (!hasCloudSession()) return noSession("register_graph_kinds");
    try {
      const registered = await cloudRequest<unknown[]>("/graph/kinds", {
        method: "POST",
        body: { kinds: Array.isArray(args.kinds) ? args.kinds : [] },
      });
      return JSON.stringify(
        { ok: true, registered, count: Array.isArray(registered) ? registered.length : 0 },
        null,
        2,
      );
    } catch (e) {
      return failure(e);
    }
  },

  ingest_graph: async (args: {
    source: string;
    target_id?: string;
    assessment_id?: string;
    nodes: unknown[];
    edges: unknown[];
    kinds?: unknown[];
    auto_register?: boolean;
  }) => {
    if (!hasCloudSession()) return noSession("ingest_graph");
    try {
      const resp = await cloudRequest<Record<string, unknown>>("/graph/ingest", {
        method: "POST",
        body: {
          source: args.source,
          target_id: args.target_id ?? null,
          assessment_id: args.assessment_id ?? process.env.MAESTRO_ASSESSMENT_ID ?? null,
          nodes: Array.isArray(args.nodes) ? args.nodes : [],
          edges: Array.isArray(args.edges) ? args.edges : [],
          kinds: Array.isArray(args.kinds) ? args.kinds : [],
          auto_register: args.auto_register ?? false,
        },
      });
      return JSON.stringify({ ok: true, ...resp }, null, 2);
    } catch (e) {
      return failure(e);
    }
  },
};
