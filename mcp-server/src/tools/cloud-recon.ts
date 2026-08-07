import { executeInKali } from "../utils/docker-exec";

export const cloudReconTools = [
  {
    name: "enum_cloud_account",
    description:
      "Enumerate all resources in an authorized cloud account using ScoutSuite. Discovers EC2, S3, Lambda, RDS, IAM roles, EKS, and more.",
    inputSchema: {
      type: "object",
      properties: {
        provider: {
          type: "string",
          enum: ["aws", "azure", "gcp"],
          description: "Cloud provider: 'aws', 'azure', or 'gcp'",
        },
        cloud_account_id: {
          type: "string",
          description: "Cloud account ID or project ID for audit trail logging",
        },
        services: {
          type: "array",
          items: { type: "string" },
          description: "Specific services to enumerate (e.g., ['ec2', 's3', 'iam', 'lambda']). Defaults to all.",
        },
        profile: {
          type: "string",
          description: "Named CLI profile to use for authentication (e.g., 'staging')",
        },
      },
      required: ["provider", "cloud_account_id"],
    },
  },
  {
    name: "audit_cloud_posture",
    description:
      "Run Prowler security audit against a cloud account. Returns categorized findings with CIS Benchmark mappings.",
    inputSchema: {
      type: "object",
      properties: {
        provider: {
          type: "string",
          enum: ["aws", "azure", "gcp"],
          description: "Cloud provider: 'aws', 'azure', or 'gcp'",
        },
        cloud_account_id: {
          type: "string",
          description: "Cloud account ID for audit trail logging",
        },
        severity: {
          type: "string",
          description: "Comma-separated severity levels to include",
          default: "critical,high",
        },
        checks: {
          type: "array",
          items: { type: "string" },
          description: "Specific Prowler check IDs to run (e.g., ['check11', 'check12']). Defaults to all checks at the given severity.",
        },
      },
      required: ["provider", "cloud_account_id"],
    },
  },
  {
    name: "enum_cloud_networking",
    description:
      "Map cloud networking: VPCs, subnets, security groups, NACLs, peering connections, public IPs, load balancers.",
    inputSchema: {
      type: "object",
      properties: {
        provider: {
          type: "string",
          enum: ["aws", "azure", "gcp"],
          description: "Cloud provider: 'aws', 'azure', or 'gcp'",
        },
        cloud_account_id: {
          type: "string",
          description: "Cloud account ID for audit trail logging",
        },
        vpc_ids: {
          type: "array",
          items: { type: "string" },
          description: "Specific VPC/VNet/Network IDs to scope the enumeration to. Defaults to all.",
        },
      },
      required: ["provider", "cloud_account_id"],
    },
  },
  {
    name: "discover_cloud_assets_external",
    description:
      "Discover cloud-hosted assets from external (unauthenticated) perspective. Finds S3 buckets, Azure blobs, GCS buckets by company/keyword.",
    inputSchema: {
      type: "object",
      properties: {
        keywords: {
          type: "array",
          items: { type: "string" },
          description: "Keywords to search for (company names, project names, etc.)",
        },
        providers: {
          type: "array",
          items: { type: "string" },
          description: "Cloud providers to target: 'aws', 'azure', 'gcp'. Defaults to all.",
          default: ["aws", "azure", "gcp"],
        },
        brute_force: {
          type: "boolean",
          description: "Enable brute-force bucket name generation and scanning",
          default: false,
        },
      },
      required: ["keywords"],
    },
  },
  {
    name: "enum_cloud_endpoints",
    description:
      "Discover public-facing cloud endpoints: API Gateways, CloudFront, ALB/ELB, Azure Front Door, GCP Load Balancers.",
    inputSchema: {
      type: "object",
      properties: {
        provider: {
          type: "string",
          enum: ["aws", "azure", "gcp"],
          description: "Cloud provider: 'aws', 'azure', or 'gcp'",
        },
        cloud_account_id: {
          type: "string",
          description: "Cloud account ID for audit trail logging",
        },
      },
      required: ["provider", "cloud_account_id"],
    },
  },
  {
    name: "enum_cloud_logging",
    description:
      "Check security logging configuration: CloudTrail, Azure Monitor, GCP Cloud Audit. Identifies gaps in audit coverage.",
    inputSchema: {
      type: "object",
      properties: {
        provider: {
          type: "string",
          enum: ["aws", "azure", "gcp"],
          description: "Cloud provider: 'aws', 'azure', or 'gcp'",
        },
        cloud_account_id: {
          type: "string",
          description: "Cloud account ID for audit trail logging",
        },
      },
      required: ["provider", "cloud_account_id"],
    },
  },
  {
    name: "check_cloud_storage_public",
    description:
      "Enumerate all storage buckets/containers in account and test each for public access, overpermissive ACLs, and sensitive content.",
    inputSchema: {
      type: "object",
      properties: {
        provider: {
          type: "string",
          enum: ["aws", "azure", "gcp"],
          description: "Cloud provider: 'aws', 'azure', or 'gcp'",
        },
        cloud_account_id: {
          type: "string",
          description: "Cloud account ID for audit trail logging",
        },
        sample_content: {
          type: "boolean",
          description: "If a bucket is public, list a sample of its contents",
          default: true,
        },
      },
      required: ["provider", "cloud_account_id"],
    },
  },
];

export const cloudReconHandlers: Record<string, Function> = {
  enum_cloud_account: async (args: {
    provider: string;
    cloud_account_id: string;
    services?: string[];
    profile?: string;
  }) => {
    const { provider, cloud_account_id, services, profile } = args;

    const commands: string[] = [
      `echo "=== Cloud Account Enumeration ==="`,
      `echo "Provider: ${provider}"`,
      `echo "Account: ${cloud_account_id}"`,
      `echo ""`,
    ];

    // Tool-availability preflight (see cloud-iam.ts): surfaces NOT-INSTALLED so a
    // packaging gap is not silently mistaken for an authentication failure.
    commands.push(
      `command -v scout >/dev/null 2>&1 && echo "scoutsuite: INSTALLED ($(scout --version 2>&1 | head -1))" || echo "scoutsuite: NOT INSTALLED"`
    );
    commands.push(`echo ""`);

    if (provider === "aws") {
      let scoutCmd = "scout aws";
      if (services && services.length > 0) {
        scoutCmd += ` --services ${services.join(",")}`;
      }
      if (profile) {
        scoutCmd += ` --profile ${profile}`;
      }
      scoutCmd += ` --report-dir /tmp/scoutsuite-report --no-browser 2>&1 || echo "ScoutSuite (AWS) run FAILED (see stderr above; auth failure vs not-installed)"`;
      commands.push(`echo "--- Running ScoutSuite (AWS) ---"`);
      commands.push(scoutCmd);
    } else if (provider === "azure") {
      let scoutCmd = `scout azure --no-browser --report-dir /tmp/scoutsuite-report 2>&1 || echo "ScoutSuite (Azure) run FAILED (see stderr above)"`;
      if (services && services.length > 0) {
        scoutCmd = `scout azure --services ${services.join(",")} --no-browser --report-dir /tmp/scoutsuite-report 2>&1 || echo "ScoutSuite (Azure) run FAILED (see stderr above)"`;
      }
      commands.push(`echo "--- Running ScoutSuite (Azure) ---"`);
      commands.push(scoutCmd);
    } else if (provider === "gcp") {
      let scoutCmd = `scout gcp --project-id ${cloud_account_id} --no-browser --report-dir /tmp/scoutsuite-report 2>&1 || echo "ScoutSuite (GCP) run FAILED (see stderr above)"`;
      if (services && services.length > 0) {
        scoutCmd = `scout gcp --project-id ${cloud_account_id} --services ${services.join(",")} --no-browser --report-dir /tmp/scoutsuite-report 2>&1 || echo "ScoutSuite (GCP) run FAILED (see stderr above)"`;
      }
      commands.push(`echo "--- Running ScoutSuite (GCP) ---"`);
      commands.push(scoutCmd);
    }

    commands.push(`echo ""`);
    commands.push(`echo "--- ScoutSuite Results ---"`);
    commands.push(
      `cat /tmp/scoutsuite-report/scoutsuite-results/scoutsuite_*.json 2>/dev/null | head -c 50000 || echo '{"error": "ScoutSuite produced no output or is not installed"}'`
    );
    commands.push(`echo ""`);
    commands.push(`echo "=== Cloud Account Enumeration Complete ==="`);

    return await executeInKali(commands.join(" && "));
  },

  audit_cloud_posture: async (args: {
    provider: string;
    cloud_account_id: string;
    severity?: string;
    checks?: string[];
  }) => {
    const { provider, cloud_account_id, severity = "critical,high", checks } = args;

    const commands: string[] = [
      `echo "=== Cloud Posture Audit (Prowler) ==="`,
      `echo "Provider: ${provider}"`,
      `echo "Account: ${cloud_account_id}"`,
      `echo "Severity: ${severity}"`,
      `echo ""`,
    ];

    let prowlerCmd = `prowler ${provider} --severity ${severity} -M json -o /tmp/prowler-output 2>&1 || echo "Prowler run FAILED (see stderr above; auth failure vs not-installed)"`;
    if (checks && checks.length > 0) {
      prowlerCmd = `prowler ${provider} --severity ${severity} --checks ${checks.join(" ")} -M json -o /tmp/prowler-output 2>&1 || echo "Prowler run FAILED (see stderr above)"`;
    }

    commands.push(`echo "--- Running Prowler ---"`);
    // Tool-availability preflight (see cloud-iam.ts).
    commands.push(
      `command -v prowler >/dev/null 2>&1 && echo "prowler: INSTALLED ($(prowler --version 2>&1 | head -1))" || echo "prowler: NOT INSTALLED"`
    );
    commands.push(`rm -rf /tmp/prowler-output 2>/dev/null`);
    commands.push(`mkdir -p /tmp/prowler-output`);
    commands.push(prowlerCmd);
    commands.push(`echo ""`);
    commands.push(`echo "--- Prowler Results ---"`);
    commands.push(
      `cat /tmp/prowler-output/*.json 2>/dev/null | head -c 50000 || echo '{"error": "Prowler produced no output or is not installed"}'`
    );
    commands.push(`echo ""`);
    commands.push(`echo "=== Cloud Posture Audit Complete ==="`);

    return await executeInKali(commands.join(" && "));
  },

  enum_cloud_networking: async (args: {
    provider: string;
    cloud_account_id: string;
    vpc_ids?: string[];
  }) => {
    const { provider, cloud_account_id, vpc_ids } = args;

    const commands: string[] = [
      `echo "=== Cloud Networking Enumeration ==="`,
      `echo "Provider: ${provider}"`,
      `echo "Account: ${cloud_account_id}"`,
      `echo ""`,
    ];

    if (provider === "aws") {
      const vpcFilter = vpc_ids && vpc_ids.length > 0
        ? ` --filters Name=vpc-id,Values=${vpc_ids.join(",")}`
        : "";

      commands.push(`echo "--- VPCs ---"`);
      commands.push(`aws ec2 describe-vpcs${vpcFilter} --output json 2>/dev/null | jq '.' || echo '{"error": "Failed to list VPCs"}'`);
      commands.push(`echo ""`);

      commands.push(`echo "--- Security Groups ---"`);
      commands.push(`aws ec2 describe-security-groups${vpcFilter} --output json 2>/dev/null | jq '.' || echo '{"error": "Failed to list security groups"}'`);
      commands.push(`echo ""`);

      commands.push(`echo "--- Subnets ---"`);
      commands.push(`aws ec2 describe-subnets${vpcFilter} --output json 2>/dev/null | jq '.' || echo '{"error": "Failed to list subnets"}'`);
      commands.push(`echo ""`);

      commands.push(`echo "--- Network ACLs ---"`);
      commands.push(`aws ec2 describe-network-acls${vpcFilter} --output json 2>/dev/null | jq '.' || echo '{"error": "Failed to list NACLs"}'`);
      commands.push(`echo ""`);

      commands.push(`echo "--- VPC Peering Connections ---"`);
      commands.push(`aws ec2 describe-vpc-peering-connections --output json 2>/dev/null | jq '.' || echo '{"error": "Failed to list VPC peering"}'`);
      commands.push(`echo ""`);

      commands.push(`echo "--- Elastic IPs ---"`);
      commands.push(`aws ec2 describe-addresses --output json 2>/dev/null | jq '.' || echo '{"error": "Failed to list Elastic IPs"}'`);
      commands.push(`echo ""`);

      commands.push(`echo "--- Load Balancers ---"`);
      commands.push(`aws elbv2 describe-load-balancers --output json 2>/dev/null | jq '.' || echo '{"error": "Failed to list load balancers"}'`);
    } else if (provider === "azure") {
      commands.push(`echo "--- Virtual Networks ---"`);
      commands.push(`az network vnet list --output json 2>/dev/null | jq '.' || echo '{"error": "Failed to list VNets"}'`);
      commands.push(`echo ""`);

      commands.push(`echo "--- Network Security Groups ---"`);
      commands.push(`az network nsg list --output json 2>/dev/null | jq '.' || echo '{"error": "Failed to list NSGs"}'`);
      commands.push(`echo ""`);

      commands.push(`echo "--- Public IPs ---"`);
      commands.push(`az network public-ip list --output json 2>/dev/null | jq '.' || echo '{"error": "Failed to list public IPs"}'`);
      commands.push(`echo ""`);

      commands.push(`echo "--- Load Balancers ---"`);
      commands.push(`az network lb list --output json 2>/dev/null | jq '.' || echo '{"error": "Failed to list load balancers"}'`);
    } else if (provider === "gcp") {
      commands.push(`echo "--- VPC Networks ---"`);
      commands.push(`gcloud compute networks list --format=json 2>/dev/null || echo '{"error": "Failed to list networks"}'`);
      commands.push(`echo ""`);

      commands.push(`echo "--- Firewall Rules ---"`);
      commands.push(`gcloud compute firewall-rules list --format=json 2>/dev/null || echo '{"error": "Failed to list firewall rules"}'`);
      commands.push(`echo ""`);

      commands.push(`echo "--- External IPs ---"`);
      commands.push(`gcloud compute addresses list --format=json 2>/dev/null || echo '{"error": "Failed to list addresses"}'`);
    }

    commands.push(`echo ""`);
    commands.push(`echo "=== Cloud Networking Enumeration Complete ==="`);

    return await executeInKali(commands.join(" && "));
  },

  discover_cloud_assets_external: async (args: {
    keywords: string[];
    providers?: string[];
    brute_force?: boolean;
  }) => {
    const { keywords, providers = ["aws", "azure", "gcp"], brute_force = false } = args;

    const commands: string[] = [
      `echo "=== External Cloud Asset Discovery ==="`,
      `echo "Keywords: ${keywords.join(", ")}"`,
      `echo "Providers: ${providers.join(", ")}"`,
      `echo "Brute Force: ${brute_force}"`,
      `echo ""`,
    ];

    for (const keyword of keywords) {
      commands.push(`echo "--- Scanning keyword: ${keyword} ---"`);

      const providerFlags: string[] = [];
      if (providers.includes("aws")) providerFlags.push("--aws");
      if (providers.includes("azure")) providerFlags.push("--azure");
      if (providers.includes("gcp")) providerFlags.push("--gcp");

      commands.push(
        `cloud_enum -k ${keyword} ${providerFlags.join(" ")} 2>/dev/null || echo "cloud_enum not available or returned no results for '${keyword}'"`
      );
      commands.push(`echo ""`);
    }

    if (brute_force) {
      commands.push(`echo "--- Brute-Force Bucket Scanning ---"`);

      const bucketNames: string[] = [];
      for (const keyword of keywords) {
        bucketNames.push(keyword);
        bucketNames.push(`${keyword}-backup`);
        bucketNames.push(`${keyword}-data`);
        bucketNames.push(`${keyword}-dev`);
        bucketNames.push(`${keyword}-staging`);
        bucketNames.push(`${keyword}-prod`);
        bucketNames.push(`${keyword}-assets`);
        bucketNames.push(`${keyword}-static`);
        bucketNames.push(`${keyword}-logs`);
        bucketNames.push(`${keyword}-uploads`);
      }

      commands.push(`echo '${bucketNames.join("\\n")}' > /tmp/bucket-names.txt`);
      commands.push(
        `s3scanner --bucket-file /tmp/bucket-names.txt 2>/dev/null || echo "s3scanner not available or returned no results"`
      );
      commands.push(`echo ""`);
    }

    commands.push(`echo "=== External Cloud Asset Discovery Complete ==="`);

    return await executeInKali(commands.join(" && "));
  },

  enum_cloud_endpoints: async (args: {
    provider: string;
    cloud_account_id: string;
  }) => {
    const { provider, cloud_account_id } = args;

    const commands: string[] = [
      `echo "=== Cloud Endpoint Discovery ==="`,
      `echo "Provider: ${provider}"`,
      `echo "Account: ${cloud_account_id}"`,
      `echo ""`,
    ];

    if (provider === "aws") {
      commands.push(`echo "--- API Gateway (REST APIs) ---"`);
      commands.push(`aws apigateway get-rest-apis --output json 2>/dev/null | jq '.' || echo '{"error": "Failed to list REST APIs"}'`);
      commands.push(`echo ""`);

      commands.push(`echo "--- API Gateway v2 (HTTP/WebSocket APIs) ---"`);
      commands.push(`aws apigatewayv2 get-apis --output json 2>/dev/null | jq '.' || echo '{"error": "Failed to list HTTP/WS APIs"}'`);
      commands.push(`echo ""`);

      commands.push(`echo "--- CloudFront Distributions ---"`);
      commands.push(`aws cloudfront list-distributions --output json 2>/dev/null | jq '.' || echo '{"error": "Failed to list CloudFront distributions"}'`);
      commands.push(`echo ""`);

      commands.push(`echo "--- Internet-Facing Load Balancers ---"`);
      commands.push(
        `aws elbv2 describe-load-balancers --query 'LoadBalancers[?Scheme==\`internet-facing\`]' --output json 2>/dev/null | jq '.' || echo '{"error": "Failed to list internet-facing LBs"}'`
      );
    } else if (provider === "azure") {
      commands.push(`echo "--- Azure Front Door ---"`);
      commands.push(`az network front-door list --output json 2>/dev/null | jq '.' || echo '{"error": "Failed to list Front Doors"}'`);
      commands.push(`echo ""`);

      commands.push(`echo "--- Application Gateways ---"`);
      commands.push(`az network application-gateway list --output json 2>/dev/null | jq '.' || echo '{"error": "Failed to list Application Gateways"}'`);
      commands.push(`echo ""`);

      commands.push(`echo "--- API Management Services ---"`);
      commands.push(`az apim list --output json 2>/dev/null | jq '.' || echo '{"error": "Failed to list APIM instances"}'`);
    } else if (provider === "gcp") {
      commands.push(`echo "--- Forwarding Rules (Load Balancers) ---"`);
      commands.push(`gcloud compute forwarding-rules list --format=json 2>/dev/null || echo '{"error": "Failed to list forwarding rules"}'`);
      commands.push(`echo ""`);

      commands.push(`echo "--- API Gateways ---"`);
      commands.push(`gcloud api-gateway gateways list --format=json 2>/dev/null || echo '{"error": "Failed to list API gateways"}'`);
    }

    commands.push(`echo ""`);
    commands.push(`echo "=== Cloud Endpoint Discovery Complete ==="`);

    return await executeInKali(commands.join(" && "));
  },

  enum_cloud_logging: async (args: {
    provider: string;
    cloud_account_id: string;
  }) => {
    const { provider, cloud_account_id } = args;

    const commands: string[] = [
      `echo "=== Cloud Logging Configuration Audit ==="`,
      `echo "Provider: ${provider}"`,
      `echo "Account: ${cloud_account_id}"`,
      `echo ""`,
    ];

    if (provider === "aws") {
      commands.push(`echo "--- CloudTrail Trails ---"`);
      commands.push(`aws cloudtrail describe-trails --output json 2>/dev/null | jq '.' || echo '{"error": "Failed to describe CloudTrail trails"}'`);
      commands.push(`echo ""`);

      commands.push(`echo "--- CloudTrail Trail Status ---"`);
      commands.push(
        `TRAILS=$(aws cloudtrail describe-trails --query 'trailList[].Name' --output text 2>/dev/null) && for trail in $TRAILS; do echo "Trail: $trail"; aws cloudtrail get-trail-status --name "$trail" --output json 2>/dev/null | jq '.'; echo ""; done || echo '{"error": "Failed to get trail status"}'`
      );
      commands.push(`echo ""`);

      commands.push(`echo "--- S3 Bucket Logging ---"`);
      commands.push(
        `BUCKETS=$(aws s3api list-buckets --query 'Buckets[].Name' --output text 2>/dev/null) && for bucket in $BUCKETS; do echo "Bucket: $bucket"; aws s3api get-bucket-logging --bucket "$bucket" --output json 2>/dev/null | jq '.' || echo "  No logging configured"; done || echo '{"error": "Failed to check S3 logging"}'`
      );
      commands.push(`echo ""`);

      commands.push(`echo "--- GuardDuty Detectors ---"`);
      commands.push(`aws guardduty list-detectors --output json 2>/dev/null | jq '.' || echo '{"error": "Failed to list GuardDuty detectors"}'`);
    } else if (provider === "azure") {
      commands.push(`echo "--- Diagnostic Settings ---"`);
      commands.push(`az monitor diagnostic-settings list --output json 2>/dev/null | jq '.' || echo '{"error": "Failed to list diagnostic settings"}'`);
      commands.push(`echo ""`);

      commands.push(`echo "--- Activity Log Alerts ---"`);
      commands.push(`az monitor activity-log alert list --output json 2>/dev/null | jq '.' || echo '{"error": "Failed to list activity log alerts"}'`);
    } else if (provider === "gcp") {
      commands.push(`echo "--- Logging Sinks ---"`);
      commands.push(`gcloud logging sinks list --format=json 2>/dev/null || echo '{"error": "Failed to list logging sinks"}'`);
      commands.push(`echo ""`);

      commands.push(`echo "--- Cloud Logging API Status ---"`);
      commands.push(
        `gcloud services list --filter='config.name:logging.googleapis.com' --format=json 2>/dev/null || echo '{"error": "Failed to check logging API status"}'`
      );
    }

    commands.push(`echo ""`);
    commands.push(`echo "=== Cloud Logging Configuration Audit Complete ==="`);

    return await executeInKali(commands.join(" && "));
  },

  check_cloud_storage_public: async (args: {
    provider: string;
    cloud_account_id: string;
    sample_content?: boolean;
  }) => {
    const { provider, cloud_account_id, sample_content = true } = args;

    const commands: string[] = [
      `echo "=== Cloud Storage Public Access Check ==="`,
      `echo "Provider: ${provider}"`,
      `echo "Account: ${cloud_account_id}"`,
      `echo "Sample Content: ${sample_content}"`,
      `echo ""`,
    ];

    if (provider === "aws") {
      commands.push(`echo "--- Listing S3 Buckets ---"`);
      commands.push(`aws s3api list-buckets --output json 2>/dev/null | jq '.Buckets[].Name' || echo '{"error": "Failed to list S3 buckets"}'`);
      commands.push(`echo ""`);

      commands.push(`echo "--- Checking Each Bucket ---"`);
      const sampleCmd = sample_content
        ? `if [ "$PUBLIC_BLOCK" = "false" ] || [ -z "$PUBLIC_BLOCK" ]; then echo "  Listing sample content:"; aws s3 ls "s3://$bucket/" --max-items 10 2>/dev/null || echo "  Could not list contents"; fi;`
        : "";

      commands.push(
        [
          `BUCKETS=$(aws s3api list-buckets --query 'Buckets[].Name' --output text 2>/dev/null)`,
          `for bucket in $BUCKETS; do`,
          `  echo "--- Bucket: $bucket ---"`,
          `  echo "  Public Access Block:"`,
          `  PUBLIC_BLOCK=$(aws s3api get-public-access-block --bucket "$bucket" --output json 2>/dev/null | jq -r '.PublicAccessBlockConfiguration.BlockPublicAcls' 2>/dev/null)`,
          `  aws s3api get-public-access-block --bucket "$bucket" --output json 2>/dev/null | jq '.' || echo "  No public access block configured (POTENTIAL RISK)"`,
          `  echo ""`,
          `  echo "  Bucket ACL:"`,
          `  aws s3api get-bucket-acl --bucket "$bucket" --output json 2>/dev/null | jq '.' || echo "  Could not retrieve ACL"`,
          `  echo ""`,
          `  echo "  Bucket Policy:"`,
          `  aws s3api get-bucket-policy --bucket "$bucket" --output json 2>/dev/null | jq '.Policy | fromjson' || echo "  No bucket policy configured"`,
          `  echo ""`,
          `  ${sampleCmd}`,
          `  echo ""`,
          `done`,
        ].join(" ")
      );
    } else if (provider === "azure") {
      commands.push(`echo "--- Listing Storage Accounts ---"`);
      commands.push(`az storage account list --output json 2>/dev/null | jq '.[].{name:.name, allowBlobPublicAccess:.allowBlobPublicAccess, httpsOnly:.enableHttpsTrafficOnly}' || echo '{"error": "Failed to list storage accounts"}'`);
      commands.push(`echo ""`);

      commands.push(`echo "--- Checking Public Blob Access ---"`);
      commands.push(
        [
          `ACCOUNTS=$(az storage account list --query '[].name' --output tsv 2>/dev/null)`,
          `for acct in $ACCOUNTS; do`,
          `  echo "--- Storage Account: $acct ---"`,
          `  echo "  Public blob access:"`,
          `  az storage account show --name "$acct" --query '{allowBlobPublicAccess:allowBlobPublicAccess, minimumTlsVersion:minimumTlsVersion}' --output json 2>/dev/null | jq '.' || echo "  Could not check"`,
          `  echo ""`,
          `done`,
        ].join(" ")
      );
    } else if (provider === "gcp") {
      commands.push(`echo "--- Listing GCS Buckets ---"`);
      commands.push(`gsutil ls 2>/dev/null || echo "Failed to list GCS buckets (gsutil not configured or no buckets)"`,);
      commands.push(`echo ""`);

      commands.push(`echo "--- Checking Bucket IAM & Public Access ---"`);
      const gcsSampleCmd = sample_content
        ? `echo "  Sample content:"; gsutil ls "$bucket" 2>/dev/null | head -10 || echo "  Could not list contents";`
        : "";

      commands.push(
        [
          `BUCKETS=$(gsutil ls 2>/dev/null)`,
          `for bucket in $BUCKETS; do`,
          `  echo "--- Bucket: $bucket ---"`,
          `  echo "  IAM Policy:"`,
          `  gsutil iam get "$bucket" 2>/dev/null || echo "  Could not retrieve IAM policy"`,
          `  echo ""`,
          `  echo "  Public access check:"`,
          `  gsutil iam get "$bucket" 2>/dev/null | grep -i "allUsers\\|allAuthenticatedUsers" && echo "  WARNING: Public access detected!" || echo "  No public access grants found"`,
          `  echo ""`,
          `  ${gcsSampleCmd}`,
          `  echo ""`,
          `done`,
        ].join(" ")
      );
    }

    commands.push(`echo ""`);
    commands.push(`echo "=== Cloud Storage Public Access Check Complete ==="`);

    return await executeInKali(commands.join(" && "));
  },
};
