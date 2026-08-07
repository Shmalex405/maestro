import { getScopeConfig } from "./scope-config";

export interface IdentityValidationResult {
  valid: boolean;
  reason?: string;
  matched?: string;
  kind?: string;
  /** The IDP provider of the matched target: entra | m365 | ad | okta |
   *  google_workspace | ping | onelogin | jumpcloud | auth0. Lets a tool confirm
   *  it's pointed at the right provider's target. */
  provider?: string;
  /** The full matched identity_target object from scope.yml. Threaded into the
   *  handler context so a tool can resolve named credential refs
   *  (e.g. sa_key_ref) and per-target fields (delegated_subject) without the
   *  LLM having to pass them explicitly. */
  matched_target?: any;
}

/**
 * Validates whether an identity target (Entra tenant id, AD domain, or a target
 * id) is authorized in scope.yml `identity_targets[]`. Fail-closed: with no
 * identity_targets configured, identity tools are rejected (we never touch
 * identity infra that isn't explicitly in scope). Mirrors validateCloudScope.
 */
export async function validateIdentityScope(
  targetId: string
): Promise<IdentityValidationResult> {
  // identity_targets isn't in the typed ScopeConfig yet; read it loosely.
  const config = (await getScopeConfig()) as any;
  const targets: any[] = config.identity_targets;

  if (!targets || targets.length === 0) {
    return { valid: false, reason: "No identity_targets defined in scope.yml" };
  }

  const match = targets.find(
    (t) => t.id === targetId || t.tenant_id === targetId || t.domain === targetId
  );

  if (!match) {
    const authorized = targets
      .map((t) => t.id || t.tenant_id || t.domain)
      .filter(Boolean)
      .join(", ");
    return {
      valid: false,
      reason: `Identity target "${targetId}" is not in scope. Authorized targets: ${authorized}`,
    };
  }

  return {
    valid: true,
    matched: match.id || match.tenant_id || match.domain,
    kind: match.kind,
    provider: match.provider,
    matched_target: match,
  };
}
