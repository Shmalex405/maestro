/**
 * Cloud Recon Agent Implementation
 *
 * Specialized agent for cloud infrastructure reconnaissance and asset enumeration.
 * Discovers EC2 instances, S3 buckets, Lambda functions, IAM roles, K8s clusters,
 * and maps networking, endpoints, and logging configurations.
 */

import {
  BaseAgent,
  AgentConfig,
  AgentInput,
  ToolDefinition,
  ProgressCallback,
} from "../base-agent";
import { cloudReconHandlers } from "../../tools/cloud-recon";
import { cloudSecurityHandlers } from "../../tools/cloud-security";
import { cloudIamHandlers } from "../../tools/cloud-iam";
import { kubernetesSecurityHandlers } from "../../tools/kubernetes-security";
import { cloudComputeHandlers } from "../../tools/cloud-compute";

const CLOUD_RECON_AGENT_CONFIG: AgentConfig = {
  name: "cloud-recon-agent",
  description: "Cloud infrastructure reconnaissance and asset enumeration agent",
  maxIterations: 30,
  timeoutMs: 1200000, // 20 minutes — ScoutSuite/Prowler scans take time
  requiresScopeValidation: true,
  tools: [
    // Cloud Recon tools
    "enum_cloud_account",
    "audit_cloud_posture",
    "enum_cloud_networking",
    "discover_cloud_assets_external",
    "enum_cloud_endpoints",
    "enum_cloud_logging",
    "check_cloud_storage_public",
    // Existing cloud tools
    "test_cloud_metadata",
    "check_s3_bucket",
    // IAM enumeration (not exploitation)
    "enum_iam_policies",
    "test_credential_exposure",
    // K8s enumeration
    "enum_k8s_cluster",
    "test_k8s_api_server",
    "test_k8s_rbac",
    // Container scanning
    "scan_container_image",
  ],
};

const CLOUD_RECON_TOOL_DEFINITIONS: ToolDefinition[] = [
  {
    name: "enum_cloud_account",
    description:
      "Enumerate all resources in an authorized cloud account using ScoutSuite. " +
      "Discovers EC2 instances, S3 buckets, Lambda functions, RDS databases, IAM roles, EKS clusters.",
    input_schema: {
      type: "object",
      properties: {
        provider: { type: "string", description: "Cloud provider: aws, azure, gcp" },
        cloud_account_id: { type: "string", description: "Account ID from scope.yml" },
        services: { type: "array", items: { type: "string" }, description: "Services to enumerate" },
      },
      required: ["provider", "cloud_account_id"],
    },
  },
  {
    name: "audit_cloud_posture",
    description:
      "Run Prowler security audit with CIS Benchmark mappings. Returns categorized findings.",
    input_schema: {
      type: "object",
      properties: {
        provider: { type: "string", description: "Cloud provider: aws, azure, gcp" },
        cloud_account_id: { type: "string", description: "Account ID from scope.yml" },
        severity: { type: "string", description: "Severity filter (default: critical,high)" },
        checks: { type: "array", items: { type: "string" }, description: "Specific check IDs" },
      },
      required: ["provider", "cloud_account_id"],
    },
  },
  {
    name: "enum_cloud_networking",
    description:
      "Map cloud networking: VPCs, subnets, security groups, NACLs, peering, public IPs, load balancers.",
    input_schema: {
      type: "object",
      properties: {
        provider: { type: "string", description: "Cloud provider: aws, azure, gcp" },
        cloud_account_id: { type: "string", description: "Account ID from scope.yml" },
        vpc_ids: { type: "array", items: { type: "string" }, description: "Specific VPCs" },
      },
      required: ["provider", "cloud_account_id"],
    },
  },
  {
    name: "discover_cloud_assets_external",
    description:
      "External discovery of cloud-hosted assets (buckets, blobs) by company name keywords.",
    input_schema: {
      type: "object",
      properties: {
        keywords: { type: "array", items: { type: "string" }, description: "Company/project names" },
        providers: { type: "array", items: { type: "string" }, description: "Providers to search" },
        brute_force: { type: "boolean", description: "Enable bucket name brute forcing" },
      },
      required: ["keywords"],
    },
  },
  {
    name: "enum_cloud_endpoints",
    description:
      "Discover public-facing cloud endpoints: API Gateways, CloudFront, ALB/ELB, CDN endpoints.",
    input_schema: {
      type: "object",
      properties: {
        provider: { type: "string", description: "Cloud provider: aws, azure, gcp" },
        cloud_account_id: { type: "string", description: "Account ID from scope.yml" },
      },
      required: ["provider", "cloud_account_id"],
    },
  },
  {
    name: "enum_cloud_logging",
    description:
      "Check security logging: CloudTrail, Azure Monitor, GCP Cloud Audit. Identifies gaps.",
    input_schema: {
      type: "object",
      properties: {
        provider: { type: "string", description: "Cloud provider: aws, azure, gcp" },
        cloud_account_id: { type: "string", description: "Account ID from scope.yml" },
      },
      required: ["provider", "cloud_account_id"],
    },
  },
  {
    name: "check_cloud_storage_public",
    description:
      "Enumerate all storage buckets and test each for public access, overpermissive ACLs.",
    input_schema: {
      type: "object",
      properties: {
        provider: { type: "string", description: "Cloud provider: aws, azure, gcp" },
        cloud_account_id: { type: "string", description: "Account ID from scope.yml" },
        sample_content: { type: "boolean", description: "Download samples from public buckets" },
      },
      required: ["provider", "cloud_account_id"],
    },
  },
  {
    name: "test_cloud_metadata",
    description:
      "Test for cloud metadata service exposure via SSRF. Probes AWS IMDS v1/v2, Azure, GCP.",
    input_schema: {
      type: "object",
      properties: {
        target: { type: "string", description: "SSRF target URL" },
        providers: { type: "array", items: { type: "string" }, description: "Providers to test" },
      },
    },
  },
  {
    name: "check_s3_bucket",
    description: "Test S3 bucket permissions: listing, read, write, ACL, policy.",
    input_schema: {
      type: "object",
      properties: {
        bucket_name: { type: "string", description: "S3 bucket name" },
        region: { type: "string", description: "AWS region" },
      },
      required: ["bucket_name"],
    },
  },
  {
    name: "enum_iam_policies",
    description:
      "Analyze IAM policies for wildcards, admin-equivalent access, dangerous action combos.",
    input_schema: {
      type: "object",
      properties: {
        provider: { type: "string", description: "Cloud provider: aws, azure, gcp" },
        cloud_account_id: { type: "string", description: "Account ID from scope.yml" },
        principal: { type: "string", description: "Specific IAM user/role ARN" },
      },
      required: ["provider", "cloud_account_id"],
    },
  },
  {
    name: "test_credential_exposure",
    description:
      "Check for stale access keys, keys in env vars, keys in user-data, unrotated credentials.",
    input_schema: {
      type: "object",
      properties: {
        provider: { type: "string", description: "Cloud provider: aws, azure, gcp" },
        cloud_account_id: { type: "string", description: "Account ID from scope.yml" },
        max_key_age_days: { type: "number", description: "Flag keys older than this (default: 90)" },
      },
      required: ["provider", "cloud_account_id"],
    },
  },
  {
    name: "enum_k8s_cluster",
    description:
      "Enumerate K8s cluster: namespaces, pods, services, RBAC, ingresses, network policies.",
    input_schema: {
      type: "object",
      properties: {
        cluster_id: { type: "string", description: "Cluster ID from scope.yml" },
        namespace: { type: "string", description: "Specific namespace (default: all)" },
      },
      required: ["cluster_id"],
    },
  },
  {
    name: "test_k8s_api_server",
    description:
      "Test K8s API server: anonymous auth, exposed dashboard, metrics endpoints.",
    input_schema: {
      type: "object",
      properties: {
        cluster_id: { type: "string", description: "Cluster ID from scope.yml" },
        api_server_url: { type: "string", description: "API server URL override" },
      },
      required: ["cluster_id"],
    },
  },
  {
    name: "test_k8s_rbac",
    description:
      "Analyze K8s RBAC for overprivileged service accounts, cluster-admin bindings.",
    input_schema: {
      type: "object",
      properties: {
        cluster_id: { type: "string", description: "Cluster ID from scope.yml" },
        service_account: { type: "string", description: "Specific SA to test" },
        attempt_escalation: { type: "boolean", description: "Attempt privesc (default: true)" },
      },
      required: ["cluster_id"],
    },
  },
  {
    name: "scan_container_image",
    description: "Scan container image for CVEs using Trivy.",
    input_schema: {
      type: "object",
      properties: {
        image: { type: "string", description: "Image reference (e.g., nginx:latest)" },
        severity: { type: "string", description: "Severity filter (default: CRITICAL,HIGH)" },
        scan_type: { type: "string", description: "Scan type: vuln, config, secret, license" },
      },
      required: ["image"],
    },
  },
];

export class CloudReconAgentImpl extends BaseAgent {
  constructor(onProgress?: (update: any) => void) {
    const handlers = {
      ...cloudReconHandlers,
      ...cloudSecurityHandlers,
      ...cloudIamHandlers,
      ...kubernetesSecurityHandlers,
      scan_container_image: cloudComputeHandlers.scan_container_image,
    };
    super(CLOUD_RECON_AGENT_CONFIG, handlers, onProgress);
  }

  getToolDefinitions(): ToolDefinition[] {
    return CLOUD_RECON_TOOL_DEFINITIONS;
  }

  buildInitialPrompt(input: AgentInput): string {
    const targets = input.targets?.join(", ") || "targets from scope";
    return (
      `You are the cloud-recon agent performing cloud infrastructure reconnaissance.\n\n` +
      `Targets: ${targets}\n\n` +
      `Your mission: Enumerate all cloud resources, map networking, analyze IAM, ` +
      `discover public assets, and check logging configuration.\n\n` +
      `Execute these tests in order:\n` +
      `1. CLOUD-01: enum_cloud_account (ScoutSuite scan)\n` +
      `2. CLOUD-04: enum_cloud_endpoints\n` +
      `3. CLOUD-03: enum_cloud_networking\n` +
      `4. CLOUD-02: discover_cloud_assets_external\n` +
      `5. CLOUD-05: enum_iam_policies\n` +
      `6. CLOUD-10: test_credential_exposure\n` +
      `7. CLOUD-11: check_cloud_storage_public\n` +
      `8. CLOUD-12: test_public_snapshots (via audit_cloud_posture)\n` +
      `9. CLOUD-16: test_cloud_metadata\n` +
      `10. CLOUD-20: Analyze networking for 0.0.0.0/0 exposure\n` +
      `11. CLOUD-27: enum_cloud_logging\n` +
      `12. CLOUD-28: audit_cloud_posture (alerting)\n` +
      `13. CLOUD-21: test_k8s_rbac\n` +
      `14. CLOUD-25: test_k8s_api_server\n` +
      `15. CLOUD-26: scan_container_image\n\n` +
      `For each test, call the MCP tool and create findings for any vulnerabilities discovered.`
    );
  }

  getSystemPrompt(): string {
    return (
      `You are a cloud security reconnaissance agent specialized in AWS, Azure, and GCP ` +
      `infrastructure enumeration. Your role is to discover and catalog all cloud resources, ` +
      `identify misconfigurations, analyze IAM policies, and map networking topology.\n\n` +
      `You discover — the cloud-exploit agent proves exploitability.\n\n` +
      `Rules:\n` +
      `- Use ONLY MCP tools for all operations\n` +
      `- Create findings for every misconfiguration discovered\n` +
      `- Include real evidence: actual CLI output, actual API responses\n` +
      `- If no cloud_accounts in scope, mark all tests N_A\n` +
      `- Save comprehensive inventory for downstream agents`
    );
  }

  extractFindings(result: string): Array<{
    title: string;
    severity: string;
    target: string;
    description: string;
    evidence: string;
    remediation: string;
  }> {
    const findings: Array<{
      title: string;
      severity: string;
      target: string;
      description: string;
      evidence: string;
      remediation: string;
    }> = [];

    // Pattern: public access detected
    if (/public.*(access|listing|read|write)/i.test(result)) {
      findings.push({
        title: "Public Cloud Storage Access",
        severity: "high",
        target: "cloud-storage",
        description: "Cloud storage bucket allows public access",
        evidence: result.substring(0, 2000),
        remediation: "Enable Block Public Access and review bucket policies",
      });
    }

    // Pattern: wildcard IAM policy
    if (/"Action"\s*:\s*"\*"/i.test(result) || /Action.*:\s*\*/i.test(result)) {
      findings.push({
        title: "Overpermissive IAM Policy",
        severity: "critical",
        target: "iam-policy",
        description: "IAM policy with wildcard (*) action detected",
        evidence: result.substring(0, 2000),
        remediation: "Apply principle of least privilege — restrict actions to specific services",
      });
    }

    // Pattern: stale credentials
    if (/key.*age.*(90|120|180|365)/i.test(result) || /unrotated/i.test(result)) {
      findings.push({
        title: "Stale Cloud Credentials",
        severity: "medium",
        target: "iam-credentials",
        description: "Access keys have not been rotated within the required period",
        evidence: result.substring(0, 2000),
        remediation: "Rotate access keys regularly and enforce rotation policies",
      });
    }

    // Pattern: anonymous K8s access
    if (/anonymous.*auth/i.test(result) || /system:anonymous.*allowed/i.test(result)) {
      findings.push({
        title: "Kubernetes Anonymous Authentication Enabled",
        severity: "high",
        target: "k8s-api-server",
        description: "Kubernetes API server allows anonymous authentication",
        evidence: result.substring(0, 2000),
        remediation: "Disable anonymous auth: --anonymous-auth=false",
      });
    }

    // Pattern: missing CloudTrail
    if (/no.*trail/i.test(result) || /cloudtrail.*disabled/i.test(result) || /logging.*not.*enabled/i.test(result)) {
      findings.push({
        title: "Security Logging Not Configured",
        severity: "medium",
        target: "cloud-logging",
        description: "Security audit logging (CloudTrail/Azure Monitor/GCP Audit) is not properly configured",
        evidence: result.substring(0, 2000),
        remediation: "Enable multi-region CloudTrail with log file validation and S3 access logging",
      });
    }

    return findings;
  }
}
