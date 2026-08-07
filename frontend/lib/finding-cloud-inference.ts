/**
 * Cloud-shape inference for findings.
 *
 * The persisted Finding type doesn't have native cloud columns (arn,
 * cloud_provider, account_id, region) — those would require a Rust schema
 * change and a migration. Instead, cloud-recon and cloud-exploit agents
 * write cloud-shaped data into the existing fields:
 *
 *   - target = ARN (AWS), /subscriptions/.../ path (Azure), projects/...
 *     URL (GCP), or cluster/namespace/kind/name (K8s, by convention)
 *   - source = "cloud-recon", "cloud-exploit", "prowler", "scoutsuite",
 *     "kube-hunter", etc.
 *
 * This helper sniffs those existing fields and reconstructs cloud
 * metadata so the UI can filter, group, and badge cloud findings without
 * a backend change. Returns an empty object when no cloud shape can be
 * inferred — callers should treat that as "this is not a cloud finding."
 */

import type { Finding } from './types';

export type CloudProvider = 'aws' | 'azure' | 'gcp' | 'k8s';

export type CloudCategory =
  | 'iam'
  | 'storage'
  | 'compute'
  | 'k8s'
  | 'networking'
  | 'logging';

export interface InferredCloud {
  provider?: CloudProvider;
  category?: CloudCategory;
  arn?: string;
  account_id?: string;
  region?: string;
  resource_type?: string;
  k8s_cluster?: string;
  k8s_namespace?: string;
}

// Map AWS service names to a coarse category. The Infrastructure sub-pills
// use these buckets so users can narrow by attack surface (IAM vs Storage
// vs Compute) instead of having to know AWS's 200+ service names.
const AWS_SERVICE_CATEGORY: Record<string, CloudCategory> = {
  iam: 'iam',
  sts: 'iam',
  organizations: 'iam',
  s3: 'storage',
  ebs: 'storage',
  rds: 'storage',
  dynamodb: 'storage',
  secretsmanager: 'storage',
  ssm: 'storage',
  ec2: 'compute',
  lambda: 'compute',
  ecs: 'compute',
  eks: 'compute',
  fargate: 'compute',
  ecr: 'compute',
  vpc: 'networking',
  apigateway: 'networking',
  cloudfront: 'networking',
  route53: 'networking',
  elasticloadbalancing: 'networking',
  cloudtrail: 'logging',
  cloudwatch: 'logging',
  guardduty: 'logging',
  config: 'logging',
};

// Tool-name → provider hint. Backend writes finding.source as the tool
// that produced the finding. Some tools are provider-specific.
const SOURCE_PROVIDER_HINTS: Array<{ pattern: RegExp; provider: CloudProvider }> = [
  { pattern: /prowler|cloudfox|scoutsuite|pmapper|pacu/i, provider: 'aws' },
  { pattern: /kube-?hunter|kubescape|kubectl|kube-?bench/i, provider: 'k8s' },
  { pattern: /aws-?cli|sts|iam-?enum/i, provider: 'aws' },
  { pattern: /az-?cli|azure-?cli/i, provider: 'azure' },
  { pattern: /gcloud|gcp-?audit/i, provider: 'gcp' },
];

/**
 * Parse an AWS ARN into its components.
 * Format: arn:partition:service:region:account-id:resource-type/resource-id
 *      OR arn:partition:service:region:account-id:resource-type:resource-id
 */
function parseArn(arn: string): {
  service: string;
  region: string;
  account_id: string;
  resource_type: string;
} | null {
  // arn:aws:s3:::bucket-name -> region and account empty
  // arn:aws:iam::123456789012:role/MyRole
  // arn:aws:ec2:us-east-1:123456789012:instance/i-abc123
  const match = arn.match(
    /^arn:(aws|aws-cn|aws-us-gov):([^:]+):([^:]*):(\d+|):(.+)$/,
  );
  if (!match) return null;
  const [, , service, region, accountId, resource] = match;
  // resource can be "type/id" or "type:id" or just "name"
  const resourceType = resource.includes('/')
    ? resource.split('/')[0]
    : resource.includes(':')
      ? resource.split(':')[0]
      : resource;
  return {
    service,
    region,
    account_id: accountId,
    resource_type: resourceType,
  };
}

/**
 * Sniff cloud metadata from a finding. Returns empty object for non-cloud
 * findings — callers can use a truthiness check on `provider` to decide
 * whether to render cloud-specific UI.
 */
export function inferCloudFromFinding(finding: Finding): InferredCloud {
  const target = finding.target || '';
  const source = (finding.source || finding.source_tool || '').toLowerCase();

  // 1. AWS ARN — the strongest signal. Carries provider, account, region,
  //    resource type, and category all in one string.
  if (target.startsWith('arn:')) {
    const parsed = parseArn(target);
    if (parsed) {
      return {
        provider: 'aws',
        category: AWS_SERVICE_CATEGORY[parsed.service] ?? 'compute',
        arn: target,
        account_id: parsed.account_id || undefined,
        region: parsed.region || undefined,
        resource_type: parsed.resource_type,
      };
    }
  }

  // 2. Azure resource ID format:
  //    /subscriptions/{sub-id}/resourceGroups/{rg}/providers/{ns}/{type}/{name}
  if (target.startsWith('/subscriptions/')) {
    const parts = target.split('/').filter(Boolean);
    const subIdx = parts.indexOf('subscriptions');
    const rgIdx = parts.indexOf('resourceGroups');
    const account_id = subIdx >= 0 ? parts[subIdx + 1] : undefined;
    // Provider+type tells us category — Microsoft.Storage = storage,
    // Microsoft.Compute = compute, etc.
    const provIdx = parts.indexOf('providers');
    const ns = provIdx >= 0 ? parts[provIdx + 1] : '';
    const resourceType = provIdx >= 0 ? parts[provIdx + 2] : undefined;
    let category: CloudCategory = 'compute';
    if (/storage|sql|cosmos|keyvault/i.test(ns)) category = 'storage';
    else if (/network|frontdoor|cdn/i.test(ns)) category = 'networking';
    else if (/identity|aad|authorization/i.test(ns)) category = 'iam';
    else if (/insights|monitor|operationalinsights/i.test(ns)) category = 'logging';
    return {
      provider: 'azure',
      category,
      account_id,
      resource_type: resourceType,
      // resourceGroups isn't a region but it's the closest scope marker
      region: rgIdx >= 0 ? parts[rgIdx + 1] : undefined,
    };
  }

  // 3. GCP resource path: projects/{project}/{collection}/...
  const gcpMatch = target.match(/^projects\/([^/]+)\/([^/]+)/);
  if (gcpMatch) {
    const [, project, collection] = gcpMatch;
    let category: CloudCategory = 'compute';
    if (/buckets|sql|datasets|secrets/i.test(collection)) category = 'storage';
    else if (/serviceAccounts|roles|policies/i.test(collection)) category = 'iam';
    else if (/networks|subnetworks|firewalls|forwardingRules/i.test(collection))
      category = 'networking';
    else if (/logs|sinks|metrics/i.test(collection)) category = 'logging';
    return {
      provider: 'gcp',
      category,
      account_id: project,
      resource_type: collection,
    };
  }

  // 4. K8s convention: cluster/namespace/kind/name. Not a standard AWS-style
  //    identifier — agents adopt this convention so the target field is
  //    self-describing for K8s findings.
  const k8sMatch = target.match(/^([^/]+)\/([^/]+)\/(pod|deployment|service|secret|role|rolebinding|clusterrole|clusterrolebinding|configmap)\/([^/]+)$/i);
  if (k8sMatch) {
    return {
      provider: 'k8s',
      category: 'k8s',
      k8s_cluster: k8sMatch[1],
      k8s_namespace: k8sMatch[2],
      resource_type: k8sMatch[3].toLowerCase(),
    };
  }

  // 5. Source-tool sniffing — last-resort hint. Lets us at least surface
  //    "this is an AWS finding" even when target doesn't match any of the
  //    structured formats above. Category falls back to 'compute' as a
  //    catch-all — better-than-nothing for filter purposes.
  for (const { pattern, provider } of SOURCE_PROVIDER_HINTS) {
    if (pattern.test(source)) {
      return {
        provider,
        category: provider === 'k8s' ? 'k8s' : 'compute',
      };
    }
  }

  return {};
}

/**
 * Display label for a cloud category. Used in sub-pill labels and chips.
 */
export const CATEGORY_LABELS: Record<CloudCategory, string> = {
  iam: 'IAM',
  storage: 'Storage',
  compute: 'Compute',
  k8s: 'Kubernetes',
  networking: 'Networking',
  logging: 'Logging',
};

/**
 * Display label + color for a provider. Mirrors the colors used in
 * config/cloud-accounts and the assessment header bar so visual identity
 * stays consistent across the app.
 */
export const PROVIDER_DISPLAY: Record<CloudProvider, { label: string; color: string }> = {
  aws: { label: 'AWS', color: 'bg-orange-500' },
  azure: { label: 'Azure', color: 'bg-blue-500' },
  gcp: { label: 'GCP', color: 'bg-red-500' },
  k8s: { label: 'K8s', color: 'bg-cyan-600' },
};
