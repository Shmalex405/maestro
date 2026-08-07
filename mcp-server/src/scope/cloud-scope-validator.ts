import { getScopeConfig, CloudAccount, KubernetesCluster } from "./scope-config";

export interface CloudValidationResult {
  valid: boolean;
  reason?: string;
  matched_account?: string;
  provider?: string;
}

/**
 * Validates whether a cloud account ID is authorized in scope.yml cloud_accounts[].id.
 */
export async function validateCloudScope(cloudAccountId: string): Promise<CloudValidationResult> {
  const config = await getScopeConfig();

  if (!config.cloud_accounts || config.cloud_accounts.length === 0) {
    return {
      valid: false,
      reason: "No cloud_accounts defined in scope.yml",
    };
  }

  const account = config.cloud_accounts.find(
    (a: CloudAccount) => a.id === cloudAccountId
  );

  if (!account) {
    return {
      valid: false,
      reason: `Cloud account "${cloudAccountId}" is not in scope. Authorized accounts: ${config.cloud_accounts.map((a: CloudAccount) => a.id).join(", ")}`,
    };
  }

  return {
    valid: true,
    matched_account: account.id,
    provider: account.provider,
  };
}

/**
 * Validates whether a Kubernetes cluster (and optionally a namespace) is authorized
 * in scope.yml kubernetes[].id. If a namespace is provided, checks it is listed in
 * namespaces_in_scope and NOT listed in namespaces_excluded.
 */
export async function validateK8sScope(
  clusterId: string,
  namespace?: string
): Promise<CloudValidationResult> {
  const config = await getScopeConfig();

  if (!config.kubernetes || config.kubernetes.length === 0) {
    return {
      valid: false,
      reason: "No kubernetes clusters defined in scope.yml",
    };
  }

  const cluster = config.kubernetes.find(
    (k: KubernetesCluster) => k.id === clusterId
  );

  if (!cluster) {
    return {
      valid: false,
      reason: `Kubernetes cluster "${clusterId}" is not in scope. Authorized clusters: ${config.kubernetes.map((k: KubernetesCluster) => k.id).join(", ")}`,
    };
  }

  // If no namespace specified, cluster-level validation is sufficient
  if (!namespace) {
    return {
      valid: true,
      matched_account: cluster.id,
      provider: cluster.provider,
    };
  }

  // Check if namespace is explicitly excluded
  if (
    cluster.namespaces_excluded &&
    cluster.namespaces_excluded.includes(namespace)
  ) {
    return {
      valid: false,
      reason: `Namespace "${namespace}" is explicitly excluded from cluster "${clusterId}"`,
      matched_account: cluster.id,
      provider: cluster.provider,
    };
  }

  // If namespaces_in_scope is defined, the namespace must be listed
  if (cluster.namespaces_in_scope && cluster.namespaces_in_scope.length > 0) {
    if (!cluster.namespaces_in_scope.includes(namespace)) {
      return {
        valid: false,
        reason: `Namespace "${namespace}" is not in scope for cluster "${clusterId}". Authorized namespaces: ${cluster.namespaces_in_scope.join(", ")}`,
        matched_account: cluster.id,
        provider: cluster.provider,
      };
    }
  }

  return {
    valid: true,
    matched_account: cluster.id,
    provider: cluster.provider,
  };
}

/**
 * Validates whether an ARN is allowed under a given cloud account's exclusions list.
 * ARN exclusions use glob-style patterns (e.g., "arn:aws:s3:::production-*").
 */
export async function validateCloudArn(
  arn: string,
  cloudAccountId: string
): Promise<CloudValidationResult> {
  const config = await getScopeConfig();

  if (!config.cloud_accounts || config.cloud_accounts.length === 0) {
    return {
      valid: false,
      reason: "No cloud_accounts defined in scope.yml",
    };
  }

  const account = config.cloud_accounts.find(
    (a: CloudAccount) => a.id === cloudAccountId
  );

  if (!account) {
    return {
      valid: false,
      reason: `Cloud account "${cloudAccountId}" is not in scope`,
    };
  }

  // If no exclusions defined, the ARN is allowed
  if (!account.exclusions || account.exclusions.length === 0) {
    return {
      valid: true,
      matched_account: account.id,
      provider: account.provider,
    };
  }

  // Check if the ARN matches any exclusion pattern
  for (const exclusion of account.exclusions) {
    if (matchesArnPattern(arn, exclusion)) {
      return {
        valid: false,
        reason: `ARN "${arn}" matches exclusion pattern: ${exclusion}`,
        matched_account: account.id,
        provider: account.provider,
      };
    }
  }

  return {
    valid: true,
    matched_account: account.id,
    provider: account.provider,
  };
}

/**
 * Matches an ARN against a glob-style exclusion pattern.
 * Supports '*' as a wildcard for any characters within a segment
 * and '**' is not used (ARN segments are colon-delimited).
 */
function matchesArnPattern(arn: string, pattern: string): boolean {
  // Escape regex special chars except '*', then convert '*' to '.*'
  const regexStr =
    "^" +
    pattern
      .replace(/[.+?^${}()|[\]\\]/g, "\\$&")
      .replace(/\*/g, ".*") +
    "$";
  const regex = new RegExp(regexStr);
  return regex.test(arn);
}
