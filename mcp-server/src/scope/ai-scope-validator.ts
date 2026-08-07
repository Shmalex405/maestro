import { getScopeConfig } from "./scope-config";
import { validateScope } from "./validator";

export interface AiValidationResult {
  valid: boolean;
  reason?: string;
  matched?: string;
  kind?: string;
  /** The full matched ai_target object from scope.yml. Threaded into the handler
   *  context so an AI tool can resolve the endpoint, model, declared_tools, and
   *  named credential ref (credential_ref) without the LLM passing them. */
  matched_target?: any;
}

/**
 * Validates whether an AI target (an `ai_targets[]` entry id, or its endpoint URL)
 * is authorized in scope.yml. Fail-closed: with no ai_targets configured, AI tools
 * are rejected (we never touch an AI system that isn't explicitly in scope).
 * Mirrors validateIdentityScope.
 *
 * SCOPE INVARIANT (charter §4, mirrors the AD domain-controller-IP rule): the
 * matched target's `endpoint` MUST ALSO resolve into the in-scope domains/networks
 * — otherwise the AI tools become a path around the URL scope validator. We run
 * the endpoint through validateScope (which normalizes a URL to its hostname), and
 * reject when it doesn't match. Targets without an endpoint (rare; e.g. a local
 * mcp_server reference) skip the cross-check.
 */
export async function validateAiScope(
  targetId: string
): Promise<AiValidationResult> {
  // ai_targets isn't strongly typed in ScopeConfig; read it loosely.
  const config = (await getScopeConfig()) as any;
  const targets: any[] = config.ai_targets;

  if (!targets || targets.length === 0) {
    return { valid: false, reason: "No ai_targets defined in scope.yml" };
  }

  const match = targets.find(
    (t) => t.id === targetId || t.endpoint === targetId || t.base_url === targetId
  );

  if (!match) {
    const authorized = targets
      .map((t) => t.id || t.endpoint || t.base_url)
      .filter(Boolean)
      .join(", ");
    return {
      valid: false,
      reason: `AI target "${targetId}" is not in scope. Authorized targets: ${authorized}`,
    };
  }

  // Endpoint must ALSO be in the network/domain scope (charter §4).
  const endpoint: string | undefined = match.endpoint || match.base_url;
  if (endpoint) {
    const netCheck = await validateScope(endpoint);
    if (!netCheck.valid) {
      return {
        valid: false,
        reason: `AI target "${targetId}" endpoint "${endpoint}" does not resolve into an in-scope domains/networks entry (${netCheck.reason}). Add the host to scope.yml domains/networks.`,
      };
    }
  }

  return {
    valid: true,
    matched: match.id || match.endpoint || match.base_url,
    kind: match.kind,
    matched_target: match,
  };
}
