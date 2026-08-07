import { validateScope } from "./validator";
import { checkExclusions } from "./exclusion-guard";

// Single source of truth for per-tool scope validation, shared by BOTH entry
// points: the STDIO MCP server (server.ts `setupTools`, used by the in-container
// assessment agents) and the HTTP `/tools/call` endpoint (autonomous-runner.ts,
// used by the Tauri frontend). These two paths drifted once — the identity +
// cloud fail-closed guards were added to setupTools but not to the HTTP path, so
// an out-of-scope Entra tenant could be enumerated through the frontend. Keeping
// the logic here means a new scope dimension is enforced everywhere at once.
//
// Dimension precedence (a tool uses exactly one): identity → ai → cloud → k8s →
// network. Identity is checked FIRST and short-circuits the network check,
// because identity AD tools pass a `domain` argument that the network-target
// extractor would otherwise grab and mis-validate against the network scope
// (blocking the tool with the wrong reason, or — if the AD domain happens to
// match a network pattern — skipping identity gating entirely). AI is checked
// next on its own `ai_target_id` arg (the AI validator additionally requires the
// target's endpoint to resolve into the network/domain scope, so an AI tool can
// never become a path around the URL scope validator).

export interface ToolScopeResult {
  valid: boolean;
  /** Present when `valid` is false — the user-facing violation message. */
  error?: string;
  /** When the call validated against the identity OR ai dimension, the full
   *  matched target object from scope.yml. The dispatcher threads this into the
   *  handler context (keyed by `dimension`) so tools can resolve named credential
   *  refs and per-target fields without the LLM passing them. */
  matched_target?: any;
  /** Which dimension `matched_target` belongs to, so the dispatcher threads it
   *  into the right handler-context slot. */
  dimension?: "identity" | "ai";
}

export async function validateToolScope(
  name: string,
  args: Record<string, unknown> | undefined,
  isLocalOnly: (toolName: string) => boolean,
): Promise<ToolScopeResult> {
  // Local-only tools (file scans, agent orchestrators, browser, prompts) handle
  // their own scoping or touch no network — never gate them here.
  if (isLocalOnly(name)) return { valid: true };

  // Cross-cutting, deny-wins exclusion check — runs BEFORE the per-dimension
  // dispatch so a never-touch / excluded target is blocked no matter which arg
  // name it arrives under. Closes the gap where identity/AI/cloud-ARN exclusions
  // were documented in scope.yml but enforced nowhere, and where the dispatcher's
  // terminal fail-open let a target under an unrecognized arg name through.
  const exclusion = await checkExclusions(args);
  if (exclusion.blocked) {
    return { valid: false, error: `SCOPE EXCLUSION: ${exclusion.reason}` };
  }

  const argObj = args ?? {};
  const target = (argObj.target || argObj.domain || argObj.cidr) as string | undefined;
  const cloudAccountId = argObj.cloud_account_id as string | undefined;
  const clusterId = argObj.cluster_id as string | undefined;
  const identityTarget = (argObj.tenant_id || argObj.identity_target_id) as string | undefined;
  const aiTarget = argObj.ai_target_id as string | undefined;

  // 1. Identity tools (Entra tenant / AD domain / M365). Gated on
  //    identity_targets; fail-closed when none are defined. Short-circuits so an
  //    AD tool's `domain` is never run through the network scope check.
  if (identityTarget) {
    const { validateIdentityScope } = await import("./identity-scope-validator");
    const idCheck = await validateIdentityScope(identityTarget);
    if (!idCheck.valid) {
      return {
        valid: false,
        error: `IDENTITY SCOPE VIOLATION: Target "${identityTarget}" is not in scope. Reason: ${idCheck.reason}`,
      };
    }
    return { valid: true, matched_target: idCheck.matched_target, dimension: "identity" };
  }

  // 1b. AI/LLM tools (chat_app / agent / rag_app / model_api / mcp_server). Gated
  //     on ai_targets; fail-closed when none are defined. Keyed on a dedicated
  //     `ai_target_id` arg so it never collides with the identity/network args.
  //     The AI validator ALSO requires the target's endpoint to resolve into the
  //     domains/networks scope (so AI tools can't bypass the URL scope validator).
  if (aiTarget) {
    const { validateAiScope } = await import("./ai-scope-validator");
    const aiCheck = await validateAiScope(aiTarget);
    if (!aiCheck.valid) {
      return {
        valid: false,
        error: `AI SCOPE VIOLATION: Target "${aiTarget}" is not in scope. Reason: ${aiCheck.reason}`,
      };
    }
    return { valid: true, matched_target: aiCheck.matched_target, dimension: "ai" };
  }

  // 2. Cloud account tools. Gated on cloud_accounts; fail-closed when none.
  if (cloudAccountId) {
    const { validateCloudScope } = await import("./cloud-scope-validator");
    const cloudCheck = await validateCloudScope(cloudAccountId);
    if (!cloudCheck.valid) {
      return {
        valid: false,
        error: `CLOUD SCOPE VIOLATION: Account "${cloudAccountId}" is not in scope. Reason: ${cloudCheck.reason}`,
      };
    }
    return { valid: true };
  }

  // 3. Kubernetes cluster tools.
  if (clusterId) {
    const { validateK8sScope } = await import("./cloud-scope-validator");
    const namespace = argObj.namespace as string | undefined;
    const k8sCheck = await validateK8sScope(clusterId, namespace);
    if (!k8sCheck.valid) {
      return {
        valid: false,
        error: `K8S SCOPE VIOLATION: Cluster "${clusterId}"${namespace ? ` namespace "${namespace}"` : ""} is not in scope. Reason: ${k8sCheck.reason}`,
      };
    }
    return { valid: true };
  }

  // 4. Network tools (IP / CIDR / host / non-identity domain).
  if (target) {
    const scopeCheck = await validateScope(target);
    if (!scopeCheck.valid) {
      return {
        valid: false,
        error: `SCOPE VIOLATION: Target "${target}" is not in scope. Reason: ${scopeCheck.reason}`,
      };
    }
  }

  return { valid: true };
}
