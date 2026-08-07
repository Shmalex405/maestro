// Cloud asset inventory + reachability collection (W2-A — the keystone primitive
// for the reachability-correlation layer; see docs/cloud-build-plan.md).
//
// Unlike the other cloud-* tools, which shell out and return RAW stdout for an LLM
// to read, this tool PARSES the AWS responses into typed structures and returns
// JSON. It captures the one thing nothing else does today: the
// image -> workload -> exposure mapping that lets a Trivy CVE on an image be tied
// to the deployed ECS service / Lambda running it and to whether that workload is
// internet-reachable. Downstream (W2-B) persists this; (W2-C) joins it against
// Trivy findings to emit "deployed + reachable + vulnerable" findings.
//
// v1 scope: AWS only (ECS services, Lambda functions, ECR images, ELBv2
// reachability). EKS workloads are W3 (gated on a live cluster); azure/gcp later.

import { executeInKali } from "../utils/docker-exec";
import { cloudRequest, hasCloudSession, CloudSessionError } from "../integrations/cloud-session";

export type ResourceType =
  | "ecs_service"
  | "lambda_function"
  | "ecr_image"
  | "load_balancer";

export type ExposureKind =
  | "alb"
  | "nlb"
  | "function_url"
  | "public_ip"
  | "api_gateway";

export interface ReachabilityRecord {
  id: string;
  exposed_via: ExposureKind;
  endpoint: string | null; // DNS name / URL when known
  internet_facing: boolean;
  source: string; // ARN of the LB / function-url / etc. that creates the exposure
  target_resource_arns: string[]; // assets this exposure fronts (best-effort)
}

export interface CloudAsset {
  resource_type: ResourceType;
  resource_arn: string;
  name: string;
  region: string | null;
  image_refs: string[]; // container image refs this asset runs (ecs / lambda)
  image_digests: string[];
  exposed: boolean; // derived: internet-reachable
  exposure_ids: string[]; // ReachabilityRecord.id values that expose this asset
  metadata: Record<string, any>;
}

export interface CloudInventory {
  provider: string;
  account_id: string;
  region: string | null;
  assets: CloudAsset[];
  reachability: ReachabilityRecord[];
  errors: string[]; // queries that failed (so a partial inventory is honest, not silent)
  counts: Record<string, number>;
  note: string;
}

/** Run an `aws ... --output json` command and JSON.parse it; null on any failure. */
async function awsJson(
  baseCmd: string,
  region: string | null,
  errors: string[],
): Promise<any | null> {
  const regionFlag = region ? ` --region ${region}` : "";
  const cmd = `aws ${baseCmd}${regionFlag} --output json 2>/dev/null`;
  let out = "";
  try {
    out = (await executeInKali(cmd)).trim();
  } catch (e) {
    errors.push(`${baseCmd}: exec error (${e instanceof Error ? e.message : String(e)})`);
    return null;
  }
  if (!out) {
    errors.push(`${baseCmd}: empty output (no resources, or missing/expired credentials)`);
    return null;
  }
  try {
    return JSON.parse(out);
  } catch {
    // Surface a short prefix so creds/permission errors are diagnosable (W1b spirit).
    errors.push(`${baseCmd}: non-JSON output: ${out.slice(0, 200)}`);
    return null;
  }
}

/** Chunk an array (AWS describe-* calls cap at ~10/100 ids per request). */
function chunk<T>(arr: T[], size: number): T[][] {
  const out: T[][] = [];
  for (let i = 0; i < arr.length; i += size) out.push(arr.slice(i, i + size));
  return out;
}

/**
 * Build ELBv2 reachability: map target-group -> load-balancer so an ECS service's
 * targetGroupArn resolves to a real LB DNS + internet-facing scheme.
 */
async function buildElbReachability(
  region: string | null,
  errors: string[],
): Promise<{
  records: ReachabilityRecord[];
  tgToLbArn: Map<string, string>;
  lbByArn: Map<string, { dns: string; scheme: string; arn: string }>;
}> {
  const records: ReachabilityRecord[] = [];
  const tgToLbArn = new Map<string, string>();
  const lbByArn = new Map<string, { dns: string; scheme: string; arn: string }>();

  const lbs = await awsJson("elbv2 describe-load-balancers", region, errors);
  for (const lb of lbs?.LoadBalancers ?? []) {
    const arn = lb.LoadBalancerArn as string;
    lbByArn.set(arn, { dns: lb.DNSName, scheme: lb.Scheme, arn });
    const internetFacing = lb.Scheme === "internet-facing";
    records.push({
      id: `lb:${arn}`,
      exposed_via: (lb.Type === "network" ? "nlb" : "alb") as ExposureKind,
      endpoint: lb.DNSName ?? null,
      internet_facing: internetFacing,
      source: arn,
      target_resource_arns: [],
    });
  }

  const tgs = await awsJson("elbv2 describe-target-groups", region, errors);
  for (const tg of tgs?.TargetGroups ?? []) {
    const lbArns: string[] = tg.LoadBalancerArns ?? [];
    if (lbArns.length > 0) tgToLbArn.set(tg.TargetGroupArn, lbArns[0]);
  }

  return { records, tgToLbArn, lbByArn };
}

/** ECS services -> container images (task defs) + LB exposure. */
async function collectEcs(
  region: string | null,
  errors: string[],
  elb: Awaited<ReturnType<typeof buildElbReachability>>,
): Promise<CloudAsset[]> {
  const assets: CloudAsset[] = [];
  const clusters = await awsJson("ecs list-clusters", region, errors);
  const clusterArns: string[] = clusters?.clusterArns ?? [];

  for (const cluster of clusterArns) {
    const svcList = await awsJson(
      `ecs list-services --cluster ${cluster}`,
      region,
      errors,
    );
    const serviceArns: string[] = svcList?.serviceArns ?? [];
    if (serviceArns.length === 0) continue;

    // Cache task-definition image lookups across services in the cluster.
    const taskDefImages = new Map<string, { refs: string[] }>();

    for (const batch of chunk(serviceArns, 10)) {
      const desc = await awsJson(
        `ecs describe-services --cluster ${cluster} --services ${batch.join(" ")}`,
        region,
        errors,
      );
      for (const svc of desc?.services ?? []) {
        const taskDefArn: string = svc.taskDefinition;
        if (taskDefArn && !taskDefImages.has(taskDefArn)) {
          const td = await awsJson(
            `ecs describe-task-definition --task-definition ${taskDefArn}`,
            region,
            errors,
          );
          const refs: string[] = (td?.taskDefinition?.containerDefinitions ?? [])
            .map((c: any) => c.image)
            .filter(Boolean);
          taskDefImages.set(taskDefArn, { refs });
        }
        const refs = taskDefImages.get(taskDefArn)?.refs ?? [];

        // Resolve LB exposure via the service's targetGroupArn(s).
        const exposureIds: string[] = [];
        for (const lbBinding of svc.loadBalancers ?? []) {
          const tgArn: string | undefined = lbBinding.targetGroupArn;
          if (!tgArn) continue;
          const lbArn = elb.tgToLbArn.get(tgArn);
          if (!lbArn) continue;
          const rec = elb.records.find((r) => r.source === lbArn);
          if (rec) {
            rec.target_resource_arns.push(svc.serviceArn);
            exposureIds.push(rec.id);
          }
        }

        assets.push({
          resource_type: "ecs_service",
          resource_arn: svc.serviceArn,
          name: svc.serviceName,
          region,
          image_refs: refs,
          image_digests: [],
          exposed: exposureIds.some(
            (id) => elb.records.find((r) => r.id === id)?.internet_facing,
          ),
          exposure_ids: exposureIds,
          metadata: {
            cluster,
            desired_count: svc.desiredCount,
            running_count: svc.runningCount,
            launch_type: svc.launchType,
            task_definition: taskDefArn,
          },
        });
      }
    }
  }
  return assets;
}

/** Lambda functions -> image refs (Code.ImageUri) + function-url exposure. */
async function collectLambda(
  region: string | null,
  errors: string[],
  reachability: ReachabilityRecord[],
): Promise<CloudAsset[]> {
  const assets: CloudAsset[] = [];
  const list = await awsJson("lambda list-functions", region, errors);
  for (const fn of list?.Functions ?? []) {
    const name: string = fn.FunctionName;
    const arn: string = fn.FunctionArn;
    const imageRefs: string[] = [];

    // list-functions omits Code.ImageUri; fetch it for image-packaged functions.
    if (fn.PackageType === "Image") {
      const got = await awsJson(`lambda get-function --function-name ${name}`, region, errors);
      const uri = got?.Code?.ImageUri;
      if (uri) imageRefs.push(uri);
    }

    // Function URL = direct internet reachability when AuthType is NONE.
    const exposureIds: string[] = [];
    const urlCfg = await awsJson(
      `lambda get-function-url-config --function-name ${name}`,
      region,
      errors,
    );
    if (urlCfg?.FunctionUrl) {
      const internetFacing = urlCfg.AuthType === "NONE";
      const rec: ReachabilityRecord = {
        id: `funcurl:${arn}`,
        exposed_via: "function_url",
        endpoint: urlCfg.FunctionUrl,
        internet_facing: internetFacing,
        source: arn,
        target_resource_arns: [arn],
      };
      reachability.push(rec);
      exposureIds.push(rec.id);
    }

    assets.push({
      resource_type: "lambda_function",
      resource_arn: arn,
      name,
      region,
      image_refs: imageRefs,
      image_digests: [],
      exposed: exposureIds.some(
        (id) => reachability.find((r) => r.id === id)?.internet_facing,
      ),
      exposure_ids: exposureIds,
      metadata: {
        runtime: fn.Runtime ?? null,
        package_type: fn.PackageType,
        last_modified: fn.LastModified,
      },
    });
  }
  return assets;
}

/** ECR images -> digest <-> tag resolution (so a Trivy-by-digest result maps to a deployed tag). */
async function collectEcr(
  region: string | null,
  errors: string[],
): Promise<CloudAsset[]> {
  const assets: CloudAsset[] = [];
  const repos = await awsJson("ecr describe-repositories", region, errors);
  for (const repo of repos?.repositories ?? []) {
    const repoName: string = repo.repositoryName;
    const repoUri: string = repo.repositoryUri;
    const images = await awsJson(
      `ecr describe-images --repository-name ${repoName}`,
      region,
      errors,
    );
    for (const img of images?.imageDetails ?? []) {
      const tags: string[] = img.imageTags ?? [];
      const digest: string = img.imageDigest;
      const refs = tags.length > 0 ? tags.map((t) => `${repoUri}:${t}`) : [`${repoUri}@${digest}`];
      assets.push({
        resource_type: "ecr_image",
        resource_arn: `${repo.repositoryArn}@${digest}`,
        name: tags.length > 0 ? `${repoName}:${tags.join(",")}` : `${repoName}@${digest.slice(0, 19)}`,
        region,
        image_refs: refs,
        image_digests: [digest],
        exposed: false, // an image is not itself reachable; its running workload is
        exposure_ids: [],
        metadata: {
          repository: repoName,
          pushed_at: img.imagePushedAt ?? null,
          size_bytes: img.imageSizeInBytes ?? null,
          scan_on_push: repo.imageScanningConfiguration?.scanOnPush ?? null,
        },
      });
    }
  }
  return assets;
}

export const cloudInventoryTools = [
  {
    name: "build_cloud_asset_inventory",
    description:
      "Build a TYPED inventory of deployed AWS assets with reachability and the image->workload mapping (ECS services + their container images + LB exposure, Lambda functions + image/URL, ECR images with digest<->tag). Returns structured JSON (not raw stdout) so a Trivy CVE on an image can be correlated to the deployed, internet-reachable workload running it. AWS only in v1; EKS workloads are added separately.",
    inputSchema: {
      type: "object",
      properties: {
        provider: {
          type: "string",
          enum: ["aws"],
          description: "Cloud provider (only 'aws' supported in v1)",
          default: "aws",
        },
        cloud_account_id: {
          type: "string",
          description: "Cloud account ID (used for scope validation + audit trail)",
        },
        region: {
          type: "string",
          description: "AWS region to inventory (defaults to the configured CLI region)",
        },
      },
      required: ["provider", "cloud_account_id"],
    },
  },
  {
    name: "promote_cloud_inventory",
    description:
      "Build the typed cloud asset inventory and PROMOTE it to the cloud backend (cloud_assets + asset_reachability tables) so the dashboard, trends, and the reachability-correlation join can query it. Mirrors complete_assessment (Shape A: local during the run, curated promotion at the end). No-op with ok:false if there is no active cloud session. Call at end-of-run for cloud assessments.",
    inputSchema: {
      type: "object",
      properties: {
        provider: {
          type: "string",
          enum: ["aws"],
          description: "Cloud provider (only 'aws' supported in v1)",
          default: "aws",
        },
        cloud_account_id: {
          type: "string",
          description: "Cloud account ID (used for scope validation, target resolution, audit trail)",
        },
        region: {
          type: "string",
          description: "AWS region to inventory (defaults to the configured CLI region)",
        },
        assessment_id: {
          type: "string",
          description:
            "Assessment run id to attach (defaults to the MAESTRO_ASSESSMENT_ID env var)",
        },
      },
      required: ["provider", "cloud_account_id"],
    },
  },
  {
    name: "correlate_cloud_findings",
    description:
      "Run the deployed+reachable+vulnerable correlation: joins the promoted cloud inventory (internet-reachable workloads + their images) against container-CVE findings and upserts a distinct correlation finding for each match. This is the differentiator vs CSPM — it PROVES the attack path from real deployed state. Call at end-of-run AFTER complete_assessment and promote_cloud_inventory.",
    inputSchema: {
      type: "object",
      properties: {
        provider: {
          type: "string",
          enum: ["aws"],
          description: "Cloud provider (only 'aws' supported in v1)",
          default: "aws",
        },
        cloud_account_id: {
          type: "string",
          description: "Cloud account ID (used for scope validation + target resolution)",
        },
        assessment_id: {
          type: "string",
          description:
            "Assessment run id to attach to correlation findings (defaults to MAESTRO_ASSESSMENT_ID)",
        },
      },
      required: ["provider", "cloud_account_id"],
    },
  },
  {
    name: "record_attack_paths",
    description:
      "Persist a structured escalation / attack-path graph (PMapper IAM-privesc paths from cloud-analysis, or chain-analysis multi-step chains) so the Coverage Dashboard W5 graph can render it. Assemble the graph as typed nodes + edges (the same shape the UI draws) and call this at end-of-run. Mirrors promote_cloud_inventory (Shape A). No-op with ok:false if there is no active cloud session.",
    inputSchema: {
      type: "object",
      properties: {
        provider: { type: "string", enum: ["aws"], description: "Cloud provider", default: "aws" },
        cloud_account_id: {
          type: "string",
          description: "Cloud account ID (scope validation + target resolution)",
        },
        source: {
          type: "string",
          enum: ["cloud-analysis", "chain-analysis"],
          description:
            "Which producer assembled the graph: cloud-analysis (IAM privesc) or chain-analysis (attack chains)",
        },
        label: { type: "string", description: "Optional human label for the graph" },
        nodes: {
          type: "array",
          description:
            "Graph nodes. Each: { id (unique string), label (string), kind (one of source/exposure/workload/vulnerability/identity/asset, or the post-exploitation kinds foothold/credential/loot), layer (number, 0=leftmost column — order steps left→right), severity? (critical/high/medium/low/info, for vulnerability nodes), sub? (subtitle string), grants? (capabilities landing on this node yields, e.g. a loot/credential node granting ['db_cred']) }",
          items: { type: "object" },
        },
        edges: {
          type: "array",
          description:
            "Graph edges. Each: { from (node id), to (node id), exploited? (true if the step was actually exploited — drawn solid red; else dashed detected-only), requires? (capabilities ⊆ held to traverse — the capability-gated planner reads these), grants? (capabilities this step yields) }",
          items: { type: "object" },
        },
        assessment_id: {
          type: "string",
          description: "Assessment run id (defaults to MAESTRO_ASSESSMENT_ID)",
        },
      },
      required: ["provider", "cloud_account_id", "source", "nodes", "edges"],
    },
  },
];

/**
 * Build the typed inventory. Shared by the `build_cloud_asset_inventory` tool
 * (returns it as JSON to the agent) and `promote_cloud_inventory` (persists it).
 */
export async function buildInventory(
  provider: string,
  cloud_account_id: string,
  region: string | null,
): Promise<CloudInventory> {
  const errors: string[] = [];

  if (provider !== "aws") {
    return {
      provider,
      account_id: cloud_account_id,
      region,
      assets: [],
      reachability: [],
      errors: [`provider '${provider}' not supported in v1 (AWS only)`],
      counts: {},
      note: "build_cloud_asset_inventory v1 supports AWS only; azure/gcp/EKS are planned.",
    };
  }

  const elb = await buildElbReachability(region, errors);
  const reachability: ReachabilityRecord[] = [...elb.records];

  const ecs = await collectEcs(region, errors, elb);
  const lambda = await collectLambda(region, errors, reachability);
  const ecr = await collectEcr(region, errors);

  const assets = [...ecs, ...lambda, ...ecr];

  // Drop LB reachability records that front nothing (noise), keep the rest.
  const usedLbRecords = reachability.filter(
    (r) => r.exposed_via === "function_url" || r.target_resource_arns.length > 0,
  );

  return {
    provider,
    account_id: cloud_account_id,
    region,
    assets,
    reachability: usedLbRecords,
    errors,
    counts: {
      ecs_services: ecs.length,
      lambda_functions: lambda.length,
      ecr_images: ecr.length,
      load_balancers: elb.records.length,
      internet_reachable_workloads: assets.filter(
        (a) => a.exposed && a.resource_type !== "ecr_image",
      ).length,
    },
    note:
      "Typed inventory. `assets[].image_refs` + `exposure_ids` + `reachability` give the " +
      "deployed->reachable->(image) mapping the correlation layer joins against Trivy CVEs.",
  };
}

export const cloudInventoryHandlers: Record<string, Function> = {
  build_cloud_asset_inventory: async (args: {
    provider: string;
    cloud_account_id: string;
    region?: string;
  }) => {
    const inventory = await buildInventory(
      args.provider,
      args.cloud_account_id,
      args.region ?? null,
    );
    return JSON.stringify(inventory, null, 2);
  },

  // Shape A promotion: build the inventory and push it to the cloud backend at
  // end-of-run, mirroring complete_assessment (hasCloudSession gate + cloudRequest).
  // Resolves the cloud_account target first so cloud_assets FK to a real targets row.
  promote_cloud_inventory: async (args: {
    provider: string;
    cloud_account_id: string;
    region?: string;
    assessment_id?: string;
  }) => {
    const { provider, cloud_account_id, region = null, assessment_id } = args;

    if (!hasCloudSession()) {
      return JSON.stringify({
        ok: false,
        error:
          "No active cloud session — inventory built but NOT promoted (local-only run). " +
          "Open Maestro / sign in to persist cloud inventory to the dashboard.",
      });
    }

    try {
      const inventory = await buildInventory(provider, cloud_account_id, region);

      // Resolve (or create) the cloud_account target so cloud_assets can FK to it.
      const target = await cloudRequest<{ id: string }>("/targets/resolve", {
        method: "POST",
        body: {
          raw_value: `${provider}:${cloud_account_id}`,
          target_type: "cloud_account",
          metadata: { provider, account_id: cloud_account_id },
        },
      });

      const resp = await cloudRequest<{
        assets_upserted: number;
        reachability_upserted: number;
      }>("/cloud/inventory", {
        method: "POST",
        body: {
          target_id: target.id,
          assessment_id: assessment_id ?? process.env.MAESTRO_ASSESSMENT_ID ?? null,
          observed_at: new Date().toISOString(),
          assets: inventory.assets,
          reachability: inventory.reachability,
        },
      });

      return JSON.stringify(
        {
          ok: true,
          target_id: target.id,
          assets_upserted: resp.assets_upserted,
          reachability_upserted: resp.reachability_upserted,
          collection_errors: inventory.errors,
        },
        null,
        2,
      );
    } catch (e) {
      const msg =
        e instanceof CloudSessionError
          ? `cloud request failed (${e.status}): ${e.message}`
          : e instanceof Error
            ? e.message
            : String(e);
      return JSON.stringify({ ok: false, error: msg });
    }
  },

  // W2-C: run the deployed+reachable+vulnerable correlation join in the backend.
  // Call at end-of-run AFTER complete_assessment (findings promoted) and
  // promote_cloud_inventory (assets promoted) — the backend joins the persisted
  // cloud_assets x findings(CVE) x reachability and upserts correlation findings.
  correlate_cloud_findings: async (args: {
    provider: string;
    cloud_account_id: string;
    assessment_id?: string;
  }) => {
    const { provider, cloud_account_id, assessment_id } = args;

    if (!hasCloudSession()) {
      return JSON.stringify({
        ok: false,
        error:
          "No active cloud session — correlation needs the promoted inventory + findings in " +
          "the cloud backend (run complete_assessment + promote_cloud_inventory first).",
      });
    }

    try {
      const target = await cloudRequest<{ id: string }>("/targets/resolve", {
        method: "POST",
        body: {
          raw_value: `${provider}:${cloud_account_id}`,
          target_type: "cloud_account",
          metadata: { provider, account_id: cloud_account_id },
        },
      });

      const resp = await cloudRequest<{ correlated: number; finding_ids: string[] }>(
        "/cloud/inventory/correlate",
        {
          method: "POST",
          body: {
            target_id: target.id,
            assessment_id: assessment_id ?? process.env.MAESTRO_ASSESSMENT_ID ?? null,
          },
        },
      );

      return JSON.stringify(
        {
          ok: true,
          target_id: target.id,
          correlated: resp.correlated,
          finding_ids: resp.finding_ids,
          note:
            resp.correlated === 0
              ? "No deployed+reachable+vulnerable correlations (no internet-facing workload runs a CVE-bearing image, or inventory/findings not yet promoted)."
              : `${resp.correlated} reachable vulnerable workload(s) correlated into findings.`,
        },
        null,
        2,
      );
    } catch (e) {
      const msg =
        e instanceof CloudSessionError
          ? `cloud request failed (${e.status}): ${e.message}`
          : e instanceof Error
            ? e.message
            : String(e);
      return JSON.stringify({ ok: false, error: msg });
    }
  },

  // Persist an assembled escalation graph (Shape A). Mirrors promote_cloud_inventory:
  // resolve the cloud_account target, then POST the typed nodes/edges to the backend.
  record_attack_paths: async (args: {
    provider: string;
    cloud_account_id: string;
    source: string;
    label?: string;
    nodes: unknown[];
    edges: unknown[];
    assessment_id?: string;
  }) => {
    const { provider, cloud_account_id, source, label, nodes, edges, assessment_id } = args;

    if (!hasCloudSession()) {
      return JSON.stringify({
        ok: false,
        error: "No active cloud session — attack-path graph not persisted (local-only run).",
      });
    }

    try {
      const target = await cloudRequest<{ id: string }>("/targets/resolve", {
        method: "POST",
        body: {
          raw_value: `${provider}:${cloud_account_id}`,
          target_type: "cloud_account",
          metadata: { provider, account_id: cloud_account_id },
        },
      });

      const resp = await cloudRequest<{ id: string }>("/cloud/attack-paths", {
        method: "POST",
        body: {
          target_id: target.id,
          assessment_id: assessment_id ?? process.env.MAESTRO_ASSESSMENT_ID ?? null,
          source,
          label: label ?? null,
          nodes: Array.isArray(nodes) ? nodes : [],
          edges: Array.isArray(edges) ? edges : [],
        },
      });

      return JSON.stringify(
        {
          ok: true,
          graph_id: resp.id,
          source,
          nodes: Array.isArray(nodes) ? nodes.length : 0,
          edges: Array.isArray(edges) ? edges.length : 0,
        },
        null,
        2,
      );
    } catch (e) {
      const msg =
        e instanceof CloudSessionError
          ? `cloud request failed (${e.status}): ${e.message}`
          : e instanceof Error
            ? e.message
            : String(e);
      return JSON.stringify({ ok: false, error: msg });
    }
  },
};
