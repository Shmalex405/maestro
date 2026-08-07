import { executeInKali } from "../utils/docker-exec";

export const cloudStorageTools = [
  {
    name: "exploit_storage_misconfig",
    description:
      "Exploit misconfigured cloud storage (S3/Blob/GCS). Tests authenticated access, bucket policy conditions, versioning, encryption status, and cross-account access.",
    inputSchema: {
      type: "object",
      properties: {
        provider: {
          type: "string",
          enum: ["aws", "azure", "gcp"],
          description: "Cloud provider: aws, azure, or gcp",
        },
        cloud_account_id: {
          type: "string",
          description: "Cloud account ID for the target environment",
        },
        bucket_name: {
          type: "string",
          description: "Specific bucket/container name to test. If omitted, tests all accessible buckets.",
        },
        actions: {
          type: "array",
          items: { type: "string" },
          description:
            "Actions to test: list, read, write_test, acl, policy, versioning, encryption. Defaults to the read-only set (omits write_test). Include \"write_test\" explicitly to opt into the active write probe (PUTs a temp object .maestro-write-test to each accessible bucket and deletes it).",
          default: ["list", "read", "acl", "policy", "versioning", "encryption"],
        },
      },
      required: ["provider", "cloud_account_id"],
    },
  },
  {
    name: "test_public_snapshots",
    description:
      "Find publicly shared RDS/EBS snapshots and disk images. Checks for accidental public sharing.",
    inputSchema: {
      type: "object",
      properties: {
        provider: {
          type: "string",
          enum: ["aws", "azure", "gcp"],
          description: "Cloud provider: aws, azure, or gcp",
        },
        cloud_account_id: {
          type: "string",
          description: "Cloud account ID for the target environment",
        },
        attempt_copy: {
          type: "boolean",
          description: "Whether to attempt copying public snapshots (requires user approval). Default false.",
          default: false,
        },
      },
      required: ["provider", "cloud_account_id"],
    },
  },
  {
    name: "test_secrets_manager",
    description:
      "Enumerate and attempt to read cloud secrets (Secrets Manager, SSM Parameter Store, Key Vault, Secret Manager).",
    inputSchema: {
      type: "object",
      properties: {
        provider: {
          type: "string",
          enum: ["aws", "azure", "gcp"],
          description: "Cloud provider: aws, azure, or gcp",
        },
        cloud_account_id: {
          type: "string",
          description: "Cloud account ID for the target environment",
        },
        attempt_read: {
          type: "boolean",
          description: "Whether to attempt reading secret values. Default true.",
          default: true,
        },
      },
      required: ["provider", "cloud_account_id"],
    },
  },
  {
    name: "test_database_exposure",
    description:
      "Test cloud database exposure: RDS/Aurora public access, Azure SQL firewall, GCP Cloud SQL authorized networks, ElastiCache security groups.",
    inputSchema: {
      type: "object",
      properties: {
        provider: {
          type: "string",
          enum: ["aws", "azure", "gcp"],
          description: "Cloud provider: aws, azure, or gcp",
        },
        cloud_account_id: {
          type: "string",
          description: "Cloud account ID for the target environment",
        },
        attempt_connect: {
          type: "boolean",
          description: "Whether to attempt TCP connections to publicly accessible databases. Default true.",
          default: true,
        },
      },
      required: ["provider", "cloud_account_id"],
    },
  },
  {
    name: "scan_storage_sensitive_data",
    description:
      "Scan accessible cloud storage for sensitive data: PII, credentials, config files, database dumps, private keys.",
    inputSchema: {
      type: "object",
      properties: {
        provider: {
          type: "string",
          enum: ["aws", "azure", "gcp"],
          description: "Cloud provider: aws, azure, or gcp",
        },
        cloud_account_id: {
          type: "string",
          description: "Cloud account ID for the target environment",
        },
        bucket_name: {
          type: "string",
          description: "Bucket/container name to scan for sensitive data",
        },
        max_objects: {
          type: "number",
          description: "Maximum number of objects to enumerate. Default 100.",
          default: 100,
        },
        patterns: {
          type: "array",
          items: { type: "string" },
          description: "Additional file name patterns to flag (beyond built-in sensitive patterns).",
        },
      },
      required: ["provider", "cloud_account_id", "bucket_name"],
    },
  },
];

export const cloudStorageHandlers: Record<string, Function> = {
  exploit_storage_misconfig: async (args: {
    provider: string;
    cloud_account_id: string;
    bucket_name?: string;
    actions?: string[];
  }) => {
    const {
      provider,
      cloud_account_id,
      bucket_name,
      actions = ["list", "read", "acl", "policy", "versioning", "encryption"],
    } = args;

    const commands: string[] = [
      `echo "=== Cloud Storage Misconfiguration Test ==="`,
      `echo "Provider: ${provider}"`,
      `echo "Account: ${cloud_account_id}"`,
      `echo ""`,
    ];

    if (provider === "aws") {
      // If no bucket specified, list all buckets first
      if (!bucket_name) {
        commands.push(`echo "--- Enumerating All Buckets ---"`);
        commands.push(`BUCKETS_JSON=$(aws s3api list-buckets --output json 2>&1)`);
        commands.push(`echo "$BUCKETS_JSON"`);
        commands.push(`echo ""`);
        commands.push(
          `BUCKET_NAMES=$(echo "$BUCKETS_JSON" | python3 -c "import sys,json; data=json.load(sys.stdin); [print(b['Name']) for b in data.get('Buckets',[])]" 2>/dev/null)`
        );
      } else {
        commands.push(`BUCKET_NAMES="${bucket_name}"`);
      }

      commands.push(`echo "--- Testing Buckets ---"`);
      commands.push(`for BUCKET in $BUCKET_NAMES; do`);
      commands.push(`  echo ""`);
      commands.push(`  echo "====== Bucket: $BUCKET ======"`);

      if (actions.includes("list")) {
        commands.push(`  echo "--- Action: list ---"`);
        commands.push(`  aws s3 ls "s3://$BUCKET/" --max-items 20 2>&1 || echo "  list: ACCESS DENIED"`);
      }
      if (actions.includes("read")) {
        commands.push(`  echo "--- Action: read ---"`);
        commands.push(
          `  FIRST_KEY=$(aws s3 ls "s3://$BUCKET/" --max-items 1 2>/dev/null | awk '{print $4}' | head -1)`
        );
        commands.push(
          `  if [ -n "$FIRST_KEY" ]; then aws s3 cp "s3://$BUCKET/$FIRST_KEY" - 2>&1 | head -c 500; echo ""; else echo "  read: No objects found or access denied"; fi`
        );
      }
      if (actions.includes("write_test")) {
        commands.push(`  echo "--- Action: write_test ---"`);
        commands.push(
          `  echo "maestro-pentest-check" | aws s3 cp - "s3://$BUCKET/.maestro-write-test" 2>&1 && echo "  WRITE SUCCEEDED - cleaning up" && aws s3 rm "s3://$BUCKET/.maestro-write-test" 2>&1 || echo "  write_test: ACCESS DENIED (expected)"`
        );
      }
      if (actions.includes("acl")) {
        commands.push(`  echo "--- Action: acl ---"`);
        commands.push(`  aws s3api get-bucket-acl --bucket "$BUCKET" 2>&1 || echo "  acl: ACCESS DENIED"`);
      }
      if (actions.includes("policy")) {
        commands.push(`  echo "--- Action: policy ---"`);
        commands.push(
          `  aws s3api get-bucket-policy --bucket "$BUCKET" 2>&1 || echo "  policy: ACCESS DENIED or no policy"`
        );
      }
      if (actions.includes("versioning")) {
        commands.push(`  echo "--- Action: versioning ---"`);
        commands.push(
          `  aws s3api get-bucket-versioning --bucket "$BUCKET" 2>&1 || echo "  versioning: ACCESS DENIED"`
        );
      }
      if (actions.includes("encryption")) {
        commands.push(`  echo "--- Action: encryption ---"`);
        commands.push(
          `  aws s3api get-bucket-encryption --bucket "$BUCKET" 2>&1 || echo "  encryption: ACCESS DENIED or not configured"`
        );
      }

      commands.push(`done`);
    } else if (provider === "azure") {
      commands.push(`echo "--- Azure Blob Storage ---"`);
      commands.push(`echo "Azure storage testing requires 'az' CLI with active login."`);
      if (bucket_name) {
        commands.push(`az storage container show --name "${bucket_name}" --account-name "${cloud_account_id}" 2>&1`);
        if (actions.includes("list")) {
          commands.push(
            `az storage blob list --container-name "${bucket_name}" --account-name "${cloud_account_id}" --num-results 20 2>&1`
          );
        }
      } else {
        commands.push(`az storage container list --account-name "${cloud_account_id}" 2>&1`);
      }
    } else if (provider === "gcp") {
      commands.push(`echo "--- GCP Cloud Storage ---"`);
      if (bucket_name) {
        if (actions.includes("list")) {
          commands.push(`gsutil ls "gs://${bucket_name}/" 2>&1 | head -20`);
        }
        if (actions.includes("acl")) {
          commands.push(`gsutil iam get "gs://${bucket_name}/" 2>&1`);
        }
      } else {
        commands.push(`gsutil ls 2>&1`);
      }
    }

    commands.push(`echo ""`);
    commands.push(`echo "=== Storage Misconfiguration Test Complete ==="`);

    return await executeInKali(commands.join("\n"));
  },

  test_public_snapshots: async (args: {
    provider: string;
    cloud_account_id: string;
    attempt_copy?: boolean;
  }) => {
    const { provider, cloud_account_id, attempt_copy = false } = args;

    const commands: string[] = [
      `echo "=== Public Snapshot Exposure Test ==="`,
      `echo "Provider: ${provider}"`,
      `echo "Account: ${cloud_account_id}"`,
      `echo ""`,
    ];

    if (provider === "aws") {
      commands.push(`echo "--- Public EBS Snapshots (owned by self) ---"`);
      commands.push(
        `aws ec2 describe-snapshots --owner-ids self --query 'Snapshots[?contains(to_string(CreateVolumePermissions),\`all\`)]' --output json 2>&1`
      );
      commands.push(`echo ""`);

      commands.push(`echo "--- Public RDS Snapshots ---"`);
      commands.push(
        `aws rds describe-db-snapshots --query 'DBSnapshots[?PubliclyAccessible==\`true\`]' --output json 2>&1`
      );
      commands.push(`echo ""`);

      commands.push(`echo "--- Public Aurora Cluster Snapshots ---"`);
      commands.push(
        `aws rds describe-db-cluster-snapshots --query 'DBClusterSnapshots[?contains(to_string(AttributeValues),\`all\`)]' --output json 2>&1`
      );
      commands.push(`echo ""`);

      if (attempt_copy) {
        commands.push(
          `echo "NOTE: attempt_copy=true but snapshot copying requires explicit user approval."`
        );
        commands.push(
          `echo "Use request_user_guidance to get approval before copying any public snapshots."`
        );
      }
    } else if (provider === "azure") {
      commands.push(`echo "--- Azure Managed Disk Snapshots ---"`);
      commands.push(
        `az snapshot list --query "[?networkAccessPolicy=='AllowAll']" --output json 2>&1`
      );
      commands.push(`echo ""`);
      commands.push(`echo "--- Azure Disk Images ---"`);
      commands.push(`az image list --output json 2>&1`);
    } else if (provider === "gcp") {
      commands.push(`echo "--- GCP Disk Snapshots ---"`);
      commands.push(`gcloud compute snapshots list --format json 2>&1`);
      commands.push(`echo ""`);
      commands.push(`echo "--- GCP Machine Images ---"`);
      commands.push(`gcloud compute machine-images list --format json 2>&1`);
      commands.push(`echo ""`);
      commands.push(`echo "--- Checking IAM policies for public access ---"`);
      commands.push(
        `for SNAP in $(gcloud compute snapshots list --format='value(name)' 2>/dev/null); do echo "Snapshot: $SNAP"; gcloud compute snapshots get-iam-policy "$SNAP" --format json 2>&1 | grep -i allUsers && echo "  WARNING: Public access detected!" || echo "  OK: No public access"; done`
      );
    }

    commands.push(`echo ""`);
    commands.push(`echo "=== Public Snapshot Test Complete ==="`);

    return await executeInKali(commands.join("\n"));
  },

  test_secrets_manager: async (args: {
    provider: string;
    cloud_account_id: string;
    attempt_read?: boolean;
  }) => {
    const { provider, cloud_account_id, attempt_read = true } = args;

    const commands: string[] = [
      `echo "=== Cloud Secrets Enumeration Test ==="`,
      `echo "Provider: ${provider}"`,
      `echo "Account: ${cloud_account_id}"`,
      `echo "Attempt Read: ${attempt_read}"`,
      `echo ""`,
    ];

    if (provider === "aws") {
      commands.push(`echo "--- AWS Secrets Manager ---"`);
      commands.push(`SECRETS_JSON=$(aws secretsmanager list-secrets --output json 2>&1)`);
      commands.push(`echo "$SECRETS_JSON"`);
      commands.push(`echo ""`);

      if (attempt_read) {
        commands.push(`echo "--- Attempting to Read Secret Values ---"`);
        commands.push(
          `SECRET_IDS=$(echo "$SECRETS_JSON" | python3 -c "import sys,json; data=json.load(sys.stdin); [print(s['Name']) for s in data.get('SecretList',[])]" 2>/dev/null)`
        );
        commands.push(`for SID in $SECRET_IDS; do`);
        commands.push(`  echo "Reading secret: $SID"`);
        commands.push(
          `  aws secretsmanager get-secret-value --secret-id "$SID" 2>&1 || echo "  ACCESS DENIED for $SID"`
        );
        commands.push(`  echo ""`);
        commands.push(`done`);
      }

      commands.push(`echo "--- AWS SSM Parameter Store ---"`);
      commands.push(`PARAMS_JSON=$(aws ssm describe-parameters --output json 2>&1)`);
      commands.push(`echo "$PARAMS_JSON"`);
      commands.push(`echo ""`);

      if (attempt_read) {
        commands.push(`echo "--- Attempting to Read Parameter Values ---"`);
        commands.push(
          `PARAM_NAMES=$(echo "$PARAMS_JSON" | python3 -c "import sys,json; data=json.load(sys.stdin); [print(p['Name']) for p in data.get('Parameters',[])]" 2>/dev/null)`
        );
        commands.push(`for PNAME in $PARAM_NAMES; do`);
        commands.push(`  echo "Reading parameter: $PNAME"`);
        commands.push(
          `  aws ssm get-parameter --name "$PNAME" --with-decryption 2>&1 || echo "  ACCESS DENIED for $PNAME"`
        );
        commands.push(`  echo ""`);
        commands.push(`done`);
      }
    } else if (provider === "azure") {
      commands.push(`echo "--- Azure Key Vaults ---"`);
      commands.push(`VAULTS_JSON=$(az keyvault list --output json 2>&1)`);
      commands.push(`echo "$VAULTS_JSON"`);
      commands.push(`echo ""`);

      commands.push(
        `VAULT_NAMES=$(echo "$VAULTS_JSON" | python3 -c "import sys,json; data=json.load(sys.stdin); [print(v['name']) for v in data]" 2>/dev/null)`
      );
      commands.push(`for VAULT in $VAULT_NAMES; do`);
      commands.push(`  echo "--- Vault: $VAULT ---"`);
      commands.push(`  az keyvault secret list --vault-name "$VAULT" 2>&1`);

      if (attempt_read) {
        commands.push(`  echo "  Attempting to read secrets..."`);
        commands.push(
          `  SECRET_NAMES=$(az keyvault secret list --vault-name "$VAULT" --query "[].name" -o tsv 2>/dev/null)`
        );
        commands.push(`  for SNAME in $SECRET_NAMES; do`);
        commands.push(`    echo "  Reading: $SNAME"`);
        commands.push(
          `    az keyvault secret show --vault-name "$VAULT" --name "$SNAME" 2>&1 || echo "    ACCESS DENIED"`
        );
        commands.push(`  done`);
      }

      commands.push(`  echo ""`);
      commands.push(`done`);
    } else if (provider === "gcp") {
      commands.push(`echo "--- GCP Secret Manager ---"`);
      commands.push(`SECRETS_JSON=$(gcloud secrets list --format json 2>&1)`);
      commands.push(`echo "$SECRETS_JSON"`);
      commands.push(`echo ""`);

      if (attempt_read) {
        commands.push(`echo "--- Attempting to Read Secret Values ---"`);
        commands.push(
          `SECRET_NAMES=$(echo "$SECRETS_JSON" | python3 -c "import sys,json; data=json.load(sys.stdin); [print(s['name'].split('/')[-1]) for s in data]" 2>/dev/null)`
        );
        commands.push(`for SNAME in $SECRET_NAMES; do`);
        commands.push(`  echo "Reading secret: $SNAME"`);
        commands.push(
          `  gcloud secrets versions access latest --secret="$SNAME" 2>&1 || echo "  ACCESS DENIED for $SNAME"`
        );
        commands.push(`  echo ""`);
        commands.push(`done`);
      }
    }

    commands.push(`echo ""`);
    commands.push(`echo "=== Secrets Enumeration Test Complete ==="`);

    return await executeInKali(commands.join("\n"));
  },

  test_database_exposure: async (args: {
    provider: string;
    cloud_account_id: string;
    attempt_connect?: boolean;
  }) => {
    const { provider, cloud_account_id, attempt_connect = true } = args;

    const commands: string[] = [
      `echo "=== Cloud Database Exposure Test ==="`,
      `echo "Provider: ${provider}"`,
      `echo "Account: ${cloud_account_id}"`,
      `echo ""`,
    ];

    if (provider === "aws") {
      commands.push(`echo "--- RDS/Aurora Instances ---"`);
      commands.push(
        `RDS_JSON=$(aws rds describe-db-instances --query 'DBInstances[].{Id:DBInstanceIdentifier,Public:PubliclyAccessible,Endpoint:Endpoint,Engine:Engine,SG:VpcSecurityGroups}' --output json 2>&1)`
      );
      commands.push(`echo "$RDS_JSON"`);
      commands.push(`echo ""`);

      commands.push(`echo "--- Publicly Accessible Instances ---"`);
      commands.push(
        `PUBLIC_DBS=$(echo "$RDS_JSON" | python3 -c "
import sys, json
data = json.load(sys.stdin)
for db in data:
    if db.get('Public'):
        ep = db.get('Endpoint', {})
        addr = ep.get('Address', 'unknown')
        port = ep.get('Port', 'unknown')
        print(f\"{db['Id']}|{addr}|{port}|{db.get('Engine','unknown')}\")
" 2>/dev/null)`
      );
      commands.push(
        `if [ -z "$PUBLIC_DBS" ]; then echo "  No publicly accessible RDS instances found."; fi`
      );

      if (attempt_connect) {
        commands.push(`echo ""`);
        commands.push(`echo "--- Connection Tests (publicly accessible instances) ---"`);
        commands.push(`IFS=$'\\n'`);
        commands.push(`for DB_INFO in $PUBLIC_DBS; do`);
        commands.push(`  DB_ID=$(echo "$DB_INFO" | cut -d'|' -f1)`);
        commands.push(`  DB_ADDR=$(echo "$DB_INFO" | cut -d'|' -f2)`);
        commands.push(`  DB_PORT=$(echo "$DB_INFO" | cut -d'|' -f3)`);
        commands.push(`  DB_ENGINE=$(echo "$DB_INFO" | cut -d'|' -f4)`);
        commands.push(`  echo "Testing $DB_ID ($DB_ENGINE) at $DB_ADDR:$DB_PORT"`);
        commands.push(
          `  nc -zw5 "$DB_ADDR" "$DB_PORT" 2>&1 && echo "  PORT OPEN - Database is network-reachable!" || echo "  Port closed or filtered (security group may block)"`
        );
        commands.push(`  echo ""`);
        commands.push(`done`);
        commands.push(`unset IFS`);
      }

      commands.push(`echo ""`);
      commands.push(`echo "--- ElastiCache Clusters ---"`);
      commands.push(`aws elasticache describe-cache-clusters --output json 2>&1`);
    } else if (provider === "azure") {
      commands.push(`echo "--- Azure SQL Servers ---"`);
      commands.push(`SERVERS_JSON=$(az sql server list --output json 2>&1)`);
      commands.push(`echo "$SERVERS_JSON"`);
      commands.push(`echo ""`);

      commands.push(`echo "--- Firewall Rules ---"`);
      commands.push(
        `SERVER_NAMES=$(echo "$SERVERS_JSON" | python3 -c "import sys,json; data=json.load(sys.stdin); [print(s['name']+'|'+s.get('resourceGroup','')) for s in data]" 2>/dev/null)`
      );
      commands.push(`for SRV_INFO in $SERVER_NAMES; do`);
      commands.push(`  SRV_NAME=$(echo "$SRV_INFO" | cut -d'|' -f1)`);
      commands.push(`  SRV_RG=$(echo "$SRV_INFO" | cut -d'|' -f2)`);
      commands.push(`  echo "--- Server: $SRV_NAME (RG: $SRV_RG) ---"`);
      commands.push(
        `  az sql server firewall-rule list --server "$SRV_NAME" --resource-group "$SRV_RG" --output table 2>&1`
      );
      commands.push(`  echo ""`);
      commands.push(`done`);

      if (attempt_connect) {
        commands.push(`echo "--- Connection Tests ---"`);
        commands.push(
          `for SRV_INFO in $SERVER_NAMES; do SRV_NAME=$(echo "$SRV_INFO" | cut -d'|' -f1); echo "Testing $SRV_NAME.database.windows.net:1433"; nc -zw5 "$SRV_NAME.database.windows.net" 1433 2>&1 && echo "  PORT OPEN" || echo "  Port closed/filtered"; done`
        );
      }
    } else if (provider === "gcp") {
      commands.push(`echo "--- GCP Cloud SQL Instances ---"`);
      commands.push(`SQL_JSON=$(gcloud sql instances list --format json 2>&1)`);
      commands.push(`echo "$SQL_JSON"`);
      commands.push(`echo ""`);

      commands.push(`echo "--- Checking Authorized Networks ---"`);
      commands.push(
        `echo "$SQL_JSON" | python3 -c "
import sys, json
data = json.load(sys.stdin)
for inst in data:
    name = inst.get('name', 'unknown')
    settings = inst.get('settings', {})
    ip_config = settings.get('ipConfiguration', {})
    auth_nets = ip_config.get('authorizedNetworks', [])
    public_ip = any(a.get('ipAddresses', [{}]) for a in [inst] if inst.get('ipAddresses'))
    print(f'Instance: {name}')
    if not auth_nets:
        print('  No authorized networks configured')
    for net in auth_nets:
        val = net.get('value', '')
        print(f'  Authorized: {val}')
        if val == '0.0.0.0/0':
            print('  WARNING: Open to entire internet!')
    print()
" 2>/dev/null`
      );

      if (attempt_connect) {
        commands.push(`echo "--- Connection Tests ---"`);
        commands.push(
          `echo "$SQL_JSON" | python3 -c "
import sys, json
data = json.load(sys.stdin)
for inst in data:
    for ip in inst.get('ipAddresses', []):
        if ip.get('type') == 'PRIMARY':
            print(ip.get('ipAddress', ''))
" 2>/dev/null | while read IP; do if [ -n "$IP" ]; then echo "Testing $IP:3306"; nc -zw5 "$IP" 3306 2>&1 && echo "  PORT OPEN" || echo "  Port closed/filtered"; echo "Testing $IP:5432"; nc -zw5 "$IP" 5432 2>&1 && echo "  PORT OPEN" || echo "  Port closed/filtered"; fi; done`
        );
      }
    }

    commands.push(`echo ""`);
    commands.push(`echo "=== Database Exposure Test Complete ==="`);

    return await executeInKali(commands.join("\n"));
  },

  scan_storage_sensitive_data: async (args: {
    provider: string;
    cloud_account_id: string;
    bucket_name: string;
    max_objects?: number;
    patterns?: string[];
  }) => {
    const { provider, cloud_account_id, bucket_name, max_objects = 100, patterns = [] } = args;

    // Built-in sensitive file patterns
    const sensitivePatterns = [
      "\\.env$",
      "\\.pem$",
      "\\.key$",
      "\\.sql$",
      "\\.dump$",
      "\\.bak$",
      "\\.csv$",
      "\\.xlsx$",
      "credentials",
      "config",
      "password",
      "secret",
      ...patterns,
    ];
    const grepPattern = sensitivePatterns.join("|");

    // Content grep pattern for sensitive data inside files
    const contentPattern =
      "(password|secret|token|api.key|AKIA[A-Z0-9]{16}|private.key|BEGIN.*(RSA|EC|PGP)|\\\\b\\\\d{3}-\\\\d{2}-\\\\d{4}\\\\b|[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\\\.[a-zA-Z]{2,})";

    const commands: string[] = [
      `echo "=== Cloud Storage Sensitive Data Scan ==="`,
      `echo "Provider: ${provider}"`,
      `echo "Account: ${cloud_account_id}"`,
      `echo "Bucket: ${bucket_name}"`,
      `echo "Max Objects: ${max_objects}"`,
      `echo ""`,
    ];

    if (provider === "aws") {
      commands.push(`echo "--- Listing Objects (max ${max_objects}) ---"`);
      commands.push(
        `OBJECTS_JSON=$(aws s3api list-objects-v2 --bucket "${bucket_name}" --max-keys ${max_objects} --output json 2>&1)`
      );
      commands.push(`echo "$OBJECTS_JSON" | python3 -c "
import sys, json
data = json.load(sys.stdin)
contents = data.get('Contents', [])
print(f'Total objects returned: {len(contents)}')
for obj in contents:
    print(f'  {obj[\"Key\"]}  ({obj.get(\"Size\",0)} bytes)')
" 2>/dev/null`);
      commands.push(`echo ""`);

      commands.push(`echo "--- Flagging Sensitive File Names ---"`);
      commands.push(
        `FLAGGED=$(echo "$OBJECTS_JSON" | python3 -c "
import sys, json, re
data = json.load(sys.stdin)
pattern = re.compile(r'(${grepPattern})', re.IGNORECASE)
contents = data.get('Contents', [])
flagged = [obj['Key'] for obj in contents if pattern.search(obj['Key'])]
for f in flagged[:20]:
    print(f)
print(f'---')
print(f'Flagged {len(flagged)} of {len(contents)} objects')
" 2>/dev/null)`
      );
      commands.push(`echo "$FLAGGED"`);
      commands.push(`echo ""`);

      commands.push(`echo "--- Scanning Flagged File Contents (max 20 files) ---"`);
      commands.push(`FILE_COUNT=0`);
      commands.push(
        `echo "$FLAGGED" | grep -v "^---" | grep -v "^Flagged" | head -20 | while read KEY; do`
      );
      commands.push(`  if [ -n "$KEY" ] && [ "$KEY" != "---" ]; then`);
      commands.push(`    echo ""`);
      commands.push(`    echo ">>> Scanning: $KEY"`);
      commands.push(
        `    MATCHES=$(aws s3 cp "s3://${bucket_name}/$KEY" - 2>/dev/null | head -c 2000 | grep -iE '${contentPattern}' 2>/dev/null)`
      );
      commands.push(
        `    if [ -n "$MATCHES" ]; then echo "  SENSITIVE DATA FOUND:"; echo "$MATCHES" | head -10; else echo "  No sensitive content patterns matched"; fi`
      );
      commands.push(`  fi`);
      commands.push(`done`);
    } else if (provider === "azure") {
      commands.push(`echo "--- Azure Blob Storage Scan ---"`);
      commands.push(
        `az storage blob list --container-name "${bucket_name}" --account-name "${cloud_account_id}" --num-results ${max_objects} --output json 2>&1 | python3 -c "
import sys, json, re
data = json.load(sys.stdin)
pattern = re.compile(r'(${grepPattern})', re.IGNORECASE)
for blob in data:
    name = blob.get('name', '')
    size = blob.get('properties', {}).get('contentLength', 0)
    flagged = '** FLAGGED **' if pattern.search(name) else ''
    print(f'  {name}  ({size} bytes) {flagged}')
" 2>/dev/null`
      );
    } else if (provider === "gcp") {
      commands.push(`echo "--- GCP Cloud Storage Scan ---"`);
      commands.push(
        `gsutil ls -l "gs://${bucket_name}/" 2>&1 | head -${max_objects}`
      );
      commands.push(`echo ""`);
      commands.push(`echo "--- Flagging Sensitive Names ---"`);
      commands.push(
        `gsutil ls "gs://${bucket_name}/" 2>/dev/null | grep -iE '(${grepPattern})' | head -20`
      );
      commands.push(`echo ""`);
      commands.push(`echo "--- Scanning Flagged File Contents ---"`);
      commands.push(
        `gsutil ls "gs://${bucket_name}/" 2>/dev/null | grep -iE '(${grepPattern})' | head -20 | while read OBJ; do echo ">>> Scanning: $OBJ"; gsutil cat "$OBJ" 2>/dev/null | head -c 2000 | grep -iE '${contentPattern}' && echo "  SENSITIVE DATA FOUND" || echo "  No matches"; done`
      );
    }

    commands.push(`echo ""`);
    commands.push(`echo "=== Sensitive Data Scan Complete ==="`);

    return await executeInKali(commands.join("\n"));
  },
};
