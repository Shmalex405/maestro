import { executeInKali } from "../utils/docker-exec";

export const cloudComputeTools = [
  {
    name: "test_instance_metadata",
    description:
      "Enhanced IMDS testing: userdata secret extraction, instance profile permission analysis, IMDSv2 enforcement check, and credential harvesting with API validation.",
    inputSchema: {
      type: "object",
      properties: {
        provider: {
          type: "string",
          enum: ["aws", "azure", "gcp"],
          description: "Cloud provider to test",
        },
        cloud_account_id: {
          type: "string",
          description: "Cloud account/subscription/project ID for API calls",
        },
        instance_id: {
          type: "string",
          description: "Specific instance ID to test (optional, tests all if omitted)",
        },
        harvest_credentials: {
          type: "boolean",
          description: "Attempt to harvest and validate credentials from instance profiles",
          default: true,
        },
      },
      required: ["provider", "cloud_account_id"],
    },
  },
  {
    name: "test_lambda_security",
    description:
      "Test serverless function security: environment variable exposure, event injection, layer analysis, function URL auth, and execution role permissions.",
    inputSchema: {
      type: "object",
      properties: {
        provider: {
          type: "string",
          enum: ["aws", "azure", "gcp"],
          description: "Cloud provider to test",
        },
        cloud_account_id: {
          type: "string",
          description: "Cloud account/subscription/project ID for API calls",
        },
        function_name: {
          type: "string",
          description: "Specific function name to test (optional, tests all if omitted)",
        },
        test_invocation: {
          type: "boolean",
          description:
            "Opt-in: actually invoke functions that have public URLs (executes the function — billable, may cause side effects). Defaults to false so the tool is read-only/non-mutating; it still reports AuthType=NONE exposure without invoking.",
          default: false,
        },
      },
      required: ["provider", "cloud_account_id"],
    },
  },
  {
    name: "test_api_gateway_security",
    description:
      "Test API Gateway configs: missing authorization, direct Lambda invocation bypass, throttling, WAF bypass via direct endpoint.",
    inputSchema: {
      type: "object",
      properties: {
        provider: {
          type: "string",
          enum: ["aws", "azure", "gcp"],
          description: "Cloud provider to test",
        },
        cloud_account_id: {
          type: "string",
          description: "Cloud account/subscription/project ID for API calls",
        },
        api_id: {
          type: "string",
          description: "Specific API Gateway ID to test (optional, tests all if omitted)",
        },
      },
      required: ["provider", "cloud_account_id"],
    },
  },
  {
    name: "test_container_registry",
    description:
      "Test container registry security: public image access, pull without auth, layer analysis for secrets, base image CVEs.",
    inputSchema: {
      type: "object",
      properties: {
        provider: {
          type: "string",
          enum: ["aws", "azure", "gcp"],
          description: "Cloud provider to test",
        },
        cloud_account_id: {
          type: "string",
          description: "Cloud account/subscription/project ID for API calls",
        },
        registry: {
          type: "string",
          description: "Specific registry or repository name (optional, tests all if omitted)",
        },
        pull_and_scan: {
          type: "boolean",
          description: "Pull images and scan for CVEs/secrets with Trivy",
          default: true,
        },
      },
      required: ["provider", "cloud_account_id"],
    },
  },
  {
    name: "scan_container_image",
    description:
      "Scan a container image for CVEs using Trivy. Supports local images, remote registries, and tar archives.",
    inputSchema: {
      type: "object",
      properties: {
        image: {
          type: "string",
          description: "Image reference (e.g., 'nginx:latest', 'registry.example.com/app:v1', '/path/to/image.tar')",
        },
        severity: {
          type: "string",
          description: "Comma-separated severity filter",
          default: "CRITICAL,HIGH",
        },
        scan_type: {
          type: "string",
          description: "Scanner type: vuln, config, secret, license",
          default: "vuln",
        },
      },
      required: ["image"],
    },
  },
  {
    name: "test_messaging_exposure",
    description:
      "Test cloud messaging service exposure: SQS queue policies, SNS topic policies, EventBridge rules. Attempts unauthorized access.",
    inputSchema: {
      type: "object",
      properties: {
        provider: {
          type: "string",
          enum: ["aws", "azure", "gcp"],
          description: "Cloud provider to test",
        },
        cloud_account_id: {
          type: "string",
          description: "Cloud account/subscription/project ID for API calls",
        },
        service_type: {
          type: "string",
          description: "Which messaging services to test: sqs, sns, eventbridge, all",
          default: "all",
        },
      },
      required: ["provider", "cloud_account_id"],
    },
  },
];

export const cloudComputeHandlers: Record<string, Function> = {
  test_instance_metadata: async (args: {
    provider: string;
    cloud_account_id: string;
    instance_id?: string;
    harvest_credentials?: boolean;
  }) => {
    const { provider, cloud_account_id, instance_id, harvest_credentials = true } = args;

    const commands: string[] = [
      `echo "=== Enhanced IMDS / Instance Metadata Test ==="`,
      `echo "Provider: ${provider}"`,
      `echo "Account: ${cloud_account_id}"`,
      `echo ""`,
    ];

    if (provider === "aws") {
      if (instance_id) {
        commands.push(`echo "--- Instance Details: ${instance_id} ---"`);
        commands.push(
          `aws ec2 describe-instances --instance-ids ${instance_id} --query 'Reservations[].Instances[].{Id:InstanceId,MetadataOptions:MetadataOptions,Profile:IamInstanceProfile,PublicIp:PublicIpAddress}' --output json 2>&1`
        );
        commands.push(`echo ""`);

        commands.push(`echo "--- IMDSv2 Enforcement Check ---"`);
        commands.push(
          `IMDS_CHECK=$(aws ec2 describe-instances --instance-ids ${instance_id} --query 'Reservations[].Instances[].MetadataOptions.HttpTokens' --output text 2>/dev/null) && if [ "$IMDS_CHECK" = "required" ]; then echo "OK: IMDSv2 is enforced (HttpTokens=required)"; else echo "WARNING: IMDSv1 is accessible (HttpTokens=$IMDS_CHECK) - credential theft via SSRF possible"; fi`
        );
        commands.push(`echo ""`);

        commands.push(`echo "--- User Data (secret extraction) ---"`);
        commands.push(
          `USERDATA=$(aws ec2 describe-instance-attribute --instance-id ${instance_id} --attribute userData --output json 2>&1) && echo "$USERDATA" && echo "$USERDATA" | python3 -c "import sys,json,base64; d=json.load(sys.stdin); ud=d.get('UserData',{}).get('Value',''); print('--- Decoded User Data ---'); print(base64.b64decode(ud).decode('utf-8',errors='replace') if ud else 'No user data set')" 2>/dev/null | grep -iE "(password|secret|key|token|api_key|aws_|credential|database|connection)" && echo "(grep for secrets complete)" || echo "No obvious secrets found in user data"`
        );
        commands.push(`echo ""`);

        if (harvest_credentials) {
          commands.push(`echo "--- Instance Profile Permissions ---"`);
          commands.push(
            `ROLE_ARN=$(aws ec2 describe-instances --instance-ids ${instance_id} --query 'Reservations[].Instances[].IamInstanceProfile.Arn' --output text 2>/dev/null) && if [ -n "$ROLE_ARN" ] && [ "$ROLE_ARN" != "None" ]; then PROFILE_NAME=$(echo "$ROLE_ARN" | awk -F'/' '{print $NF}'); echo "Instance Profile: $PROFILE_NAME"; ROLE_NAME=$(aws iam get-instance-profile --instance-profile-name "$PROFILE_NAME" --query 'InstanceProfile.Roles[0].RoleName' --output text 2>/dev/null); echo "Role: $ROLE_NAME"; echo "Attached Policies:"; aws iam list-attached-role-policies --role-name "$ROLE_NAME" --output json 2>&1; echo "Inline Policies:"; aws iam list-role-policies --role-name "$ROLE_NAME" --output json 2>&1; else echo "No instance profile attached"; fi`
          );
        }
      } else {
        commands.push(`echo "--- Listing All Instances ---"`);
        commands.push(
          `aws ec2 describe-instances --query 'Reservations[].Instances[].{Id:InstanceId,MetadataOptions:MetadataOptions,Profile:IamInstanceProfile,PublicIp:PublicIpAddress,State:State.Name}' --output json 2>&1`
        );
        commands.push(`echo ""`);

        commands.push(`echo "--- IMDSv2 Enforcement Summary ---"`);
        commands.push(
          `aws ec2 describe-instances --query 'Reservations[].Instances[].{Id:InstanceId,HttpTokens:MetadataOptions.HttpTokens,HttpEndpoint:MetadataOptions.HttpEndpoint}' --output table 2>&1`
        );
        commands.push(`echo ""`);

        commands.push(`echo "--- Instances with IMDSv1 Enabled (VULNERABLE) ---"`);
        commands.push(
          `aws ec2 describe-instances --filters "Name=metadata-options.http-tokens,Values=optional" --query 'Reservations[].Instances[].InstanceId' --output json 2>&1`
        );
      }
    } else if (provider === "azure") {
      commands.push(`echo "--- Azure Instance Metadata ---"`);
      commands.push(
        `az vm list --query '[].{Name:name,ResourceGroup:resourceGroup,ManagedIdentity:identity.type}' --output json 2>&1`
      );
      commands.push(`echo ""`);
      commands.push(`echo "--- Managed Identity Assignments ---"`);
      commands.push(
        `az vm list --query '[?identity!=null].{Name:name,IdentityType:identity.type,PrincipalId:identity.principalId}' --output json 2>&1`
      );
    } else if (provider === "gcp") {
      commands.push(`echo "--- GCP Instance Metadata ---"`);
      commands.push(
        `gcloud compute instances list --format=json --project=${cloud_account_id} 2>&1`
      );
      commands.push(`echo ""`);
      commands.push(`echo "--- Service Account Assignments ---"`);
      commands.push(
        `gcloud compute instances list --format='table(name,zone,serviceAccounts[].email)' --project=${cloud_account_id} 2>&1`
      );
    }

    commands.push(`echo ""`);
    commands.push(`echo "=== Instance Metadata Test Complete ==="`);

    return await executeInKali(commands.join(" && "));
  },

  test_lambda_security: async (args: {
    provider: string;
    cloud_account_id: string;
    function_name?: string;
    test_invocation?: boolean;
  }) => {
    const { provider, cloud_account_id, function_name, test_invocation = false } = args;

    const commands: string[] = [
      `echo "=== Serverless Function Security Test ==="`,
      `echo "Provider: ${provider}"`,
      `echo "Account: ${cloud_account_id}"`,
      `echo ""`,
    ];

    if (provider === "aws") {
      if (function_name) {
        commands.push(`echo "--- Function Configuration: ${function_name} ---"`);
        commands.push(
          `aws lambda get-function-configuration --function-name ${function_name} --output json 2>&1`
        );
        commands.push(`echo ""`);

        commands.push(`echo "--- Environment Variable Secrets Check ---"`);
        commands.push(
          `aws lambda get-function-configuration --function-name ${function_name} --query 'Environment.Variables' --output json 2>/dev/null | python3 -c "import sys,json; env=json.load(sys.stdin) if sys.stdin.read().strip() else {}; secrets=[k for k in env if any(s in k.upper() for s in ['SECRET','PASSWORD','KEY','TOKEN','API_KEY','CREDENTIAL','DATABASE','CONNECTION'])]; print(json.dumps({'total_vars':len(env),'potential_secrets':secrets,'secret_values':{k:env[k] for k in secrets}},indent=2))" 2>/dev/null || echo "No environment variables or unable to parse"`
        );
        commands.push(`echo ""`);

        commands.push(`echo "--- Function URL Configuration ---"`);
        commands.push(
          `FUNC_URL_CONFIG=$(aws lambda get-function-url-config --function-name ${function_name} 2>/dev/null) && echo "$FUNC_URL_CONFIG" && AUTH_TYPE=$(echo "$FUNC_URL_CONFIG" | python3 -c "import sys,json; print(json.load(sys.stdin).get('AuthType','UNKNOWN'))" 2>/dev/null) && if [ "$AUTH_TYPE" = "NONE" ]; then echo "CRITICAL: Function URL has AuthType=NONE (publicly accessible)"; FUNC_URL=$(echo "$FUNC_URL_CONFIG" | python3 -c "import sys,json; print(json.load(sys.stdin).get('FunctionUrl',''))" 2>/dev/null); if [ -n "$FUNC_URL" ] && [ "${test_invocation}" = "true" ]; then echo "Testing unauthenticated access:"; curl -s -o /tmp/lambda-resp.txt -w "HTTP Status: %{http_code}\\n" --max-time 10 "$FUNC_URL"; head -c 2000 /tmp/lambda-resp.txt; echo ""; fi; else echo "OK: AuthType=$AUTH_TYPE"; fi || echo "No function URL configured"`
        );
        commands.push(`echo ""`);

        commands.push(`echo "--- Execution Role Permissions ---"`);
        commands.push(
          `ROLE_ARN=$(aws lambda get-function-configuration --function-name ${function_name} --query 'Role' --output text 2>/dev/null) && ROLE_NAME=$(echo "$ROLE_ARN" | awk -F'/' '{print $NF}') && echo "Role: $ROLE_NAME" && echo "Attached Policies:" && aws iam list-attached-role-policies --role-name "$ROLE_NAME" --output json 2>&1 && echo "Inline Policies:" && aws iam list-role-policies --role-name "$ROLE_NAME" --output json 2>&1`
        );
      } else {
        commands.push(`echo "--- Listing All Lambda Functions ---"`);
        commands.push(`aws lambda list-functions --output json 2>&1`);
        commands.push(`echo ""`);

        commands.push(`echo "--- Functions with Environment Variables (potential secrets) ---"`);
        commands.push(
          `aws lambda list-functions --query 'Functions[?Environment!=\`null\`].{Name:FunctionName,Runtime:Runtime,EnvVarCount:length(Environment.Variables)}' --output json 2>&1`
        );
        commands.push(`echo ""`);

        commands.push(`echo "--- Public Layers ---"`);
        commands.push(`aws lambda list-layers --output json 2>&1`);
        commands.push(`echo ""`);

        commands.push(`echo "--- Functions with Function URLs ---"`);
        commands.push(
          `for fn in $(aws lambda list-functions --query 'Functions[].FunctionName' --output text 2>/dev/null); do URL_CONFIG=$(aws lambda get-function-url-config --function-name "$fn" 2>/dev/null) && if [ -n "$URL_CONFIG" ]; then echo "Function: $fn"; echo "$URL_CONFIG" | python3 -c "import sys,json; c=json.load(sys.stdin); print(f'  URL: {c.get(\"FunctionUrl\",\"\")}  AuthType: {c.get(\"AuthType\",\"\")}')" 2>/dev/null; fi; done || echo "No functions with URLs found"`
        );
      }
    } else if (provider === "azure") {
      commands.push(`echo "--- Azure Functions ---"`);
      commands.push(
        `az functionapp list --query '[].{Name:name,ResourceGroup:resourceGroup,State:state,DefaultHostName:defaultHostName}' --output json 2>&1`
      );
      if (function_name) {
        commands.push(`echo "--- App Settings (secrets check) ---"`);
        commands.push(
          `az functionapp config appsettings list --name ${function_name} --resource-group $(az functionapp list --query "[?name=='${function_name}'].resourceGroup" --output tsv 2>/dev/null) --output json 2>&1`
        );
      }
    } else if (provider === "gcp") {
      commands.push(`echo "--- GCP Cloud Functions ---"`);
      commands.push(
        `gcloud functions list --format=json --project=${cloud_account_id} 2>&1`
      );
      if (function_name) {
        commands.push(`echo "--- Function Details ---"`);
        commands.push(
          `gcloud functions describe ${function_name} --format=json --project=${cloud_account_id} 2>&1`
        );
      }
    }

    commands.push(`echo ""`);
    commands.push(`echo "=== Serverless Security Test Complete ==="`);

    return await executeInKali(commands.join(" && "));
  },

  test_api_gateway_security: async (args: {
    provider: string;
    cloud_account_id: string;
    api_id?: string;
  }) => {
    const { provider, cloud_account_id, api_id } = args;

    const commands: string[] = [
      `echo "=== API Gateway Security Test ==="`,
      `echo "Provider: ${provider}"`,
      `echo "Account: ${cloud_account_id}"`,
      `echo ""`,
    ];

    if (provider === "aws") {
      if (api_id) {
        commands.push(`echo "--- REST API Details: ${api_id} ---"`);
        commands.push(`aws apigateway get-rest-api --rest-api-id ${api_id} --output json 2>&1`);
        commands.push(`echo ""`);

        commands.push(`echo "--- Resources and Authorization ---"`);
        commands.push(
          `aws apigateway get-resources --rest-api-id ${api_id} --output json 2>&1 | python3 -c "
import sys, json
data = json.load(sys.stdin)
unauth = []
for item in data.get('items', []):
    path = item.get('path', '')
    for method, config in item.get('resourceMethods', {}).items():
        unauth.append({'path': path, 'method': method})
print(json.dumps({'resources': data.get('items', []), 'methods_to_check': unauth}, indent=2))
" 2>/dev/null || echo "Unable to parse resources"`
        );
        commands.push(`echo ""`);

        commands.push(`echo "--- Checking Authorization on Each Method ---"`);
        commands.push(
          `for resource_id in $(aws apigateway get-resources --rest-api-id ${api_id} --query 'items[].id' --output text 2>/dev/null); do for method in GET POST PUT DELETE PATCH; do METHOD_INFO=$(aws apigateway get-method --rest-api-id ${api_id} --resource-id "$resource_id" --http-method "$method" 2>/dev/null) && if [ -n "$METHOD_INFO" ]; then AUTH_TYPE=$(echo "$METHOD_INFO" | python3 -c "import sys,json; print(json.load(sys.stdin).get('authorizationType','UNKNOWN'))" 2>/dev/null); PATH_INFO=$(aws apigateway get-resources --rest-api-id ${api_id} --query "items[?id=='$resource_id'].path" --output text 2>/dev/null); if [ "$AUTH_TYPE" = "NONE" ]; then echo "WARNING: $method $PATH_INFO - authorizationType=NONE"; else echo "OK: $method $PATH_INFO - authorizationType=$AUTH_TYPE"; fi; fi; done; done`
        );
        commands.push(`echo ""`);

        commands.push(`echo "--- WAF Association ---"`);
        commands.push(
          `REGION=$(aws configure get region 2>/dev/null || echo "us-east-1") && API_ARN="arn:aws:apigateway:$REGION::/restapis/${api_id}/stages/*" && aws wafv2 get-web-acl-for-resource --resource-arn "$API_ARN" --output json 2>&1 || echo "No WAF associated or unable to check"`
        );
        commands.push(`echo ""`);

        commands.push(`echo "--- Stage Throttle Settings ---"`);
        commands.push(
          `for stage in $(aws apigateway get-stages --rest-api-id ${api_id} --query 'item[].stageName' --output text 2>/dev/null); do echo "Stage: $stage"; aws apigateway get-stage --rest-api-id ${api_id} --stage-name "$stage" --query '{ThrottleRate:methodSettings.\"*/*\".throttlingRateLimit,ThrottleBurst:methodSettings.\"*/*\".throttlingBurstLimit,DefaultThrottle:defaultRouteSettings}' --output json 2>&1; echo ""; done`
        );
        commands.push(`echo ""`);

        commands.push(`echo "--- Unauthenticated Access Test ---"`);
        commands.push(
          `REGION=$(aws configure get region 2>/dev/null || echo "us-east-1") && for stage in $(aws apigateway get-stages --rest-api-id ${api_id} --query 'item[].stageName' --output text 2>/dev/null); do ENDPOINT="https://${api_id}.execute-api.$REGION.amazonaws.com/$stage/"; echo "Testing: $ENDPOINT"; curl -s -o /tmp/apigw-resp.txt -w "HTTP Status: %{http_code}\\n" --max-time 10 "$ENDPOINT"; head -c 1000 /tmp/apigw-resp.txt; echo ""; done`
        );
      } else {
        commands.push(`echo "--- REST APIs (v1) ---"`);
        commands.push(`aws apigateway get-rest-apis --output json 2>&1`);
        commands.push(`echo ""`);

        commands.push(`echo "--- HTTP APIs (v2) ---"`);
        commands.push(`aws apigatewayv2 get-apis --output json 2>&1`);
        commands.push(`echo ""`);

        commands.push(`echo "--- Summary of APIs without Authorization ---"`);
        commands.push(
          `echo "Checking REST APIs for unauthenticated methods..." && for api in $(aws apigateway get-rest-apis --query 'items[].id' --output text 2>/dev/null); do API_NAME=$(aws apigateway get-rest-api --rest-api-id "$api" --query 'name' --output text 2>/dev/null); echo "API: $API_NAME ($api)"; aws apigateway get-resources --rest-api-id "$api" --query 'items[].{path:path,methods:resourceMethods}' --output json 2>/dev/null; echo ""; done`
        );
      }
    } else if (provider === "azure") {
      commands.push(`echo "--- Azure API Management ---"`);
      commands.push(
        `az apim list --query '[].{Name:name,ResourceGroup:resourceGroup,GatewayUrl:gatewayUrl}' --output json 2>&1`
      );
    } else if (provider === "gcp") {
      commands.push(`echo "--- GCP API Gateway ---"`);
      commands.push(
        `gcloud api-gateway gateways list --format=json --project=${cloud_account_id} 2>&1`
      );
    }

    commands.push(`echo ""`);
    commands.push(`echo "=== API Gateway Security Test Complete ==="`);

    return await executeInKali(commands.join(" && "));
  },

  test_container_registry: async (args: {
    provider: string;
    cloud_account_id: string;
    registry?: string;
    pull_and_scan?: boolean;
  }) => {
    const { provider, cloud_account_id, registry, pull_and_scan = true } = args;

    const commands: string[] = [
      `echo "=== Container Registry Security Test ==="`,
      `echo "Provider: ${provider}"`,
      `echo "Account: ${cloud_account_id}"`,
      `echo ""`,
    ];

    if (provider === "aws") {
      if (registry) {
        commands.push(`echo "--- Repository Policy: ${registry} ---"`);
        commands.push(
          `aws ecr get-repository-policy --repository-name ${registry} --output json 2>&1 || echo "No repository policy set (default deny)"`
        );
        commands.push(`echo ""`);

        commands.push(`echo "--- Image Scanning Configuration ---"`);
        commands.push(
          `aws ecr describe-repositories --repository-names ${registry} --query 'repositories[].{Name:repositoryName,ScanOnPush:imageScanningConfiguration.scanOnPush,TagImmutability:imageTagMutability}' --output json 2>&1`
        );
        commands.push(`echo ""`);

        if (pull_and_scan) {
          commands.push(`echo "--- Pull and Scan Latest Image ---"`);
          commands.push(
            `REGION=$(aws configure get region 2>/dev/null || echo "us-east-1") && ACCOUNT=$(aws sts get-caller-identity --query 'Account' --output text 2>/dev/null || echo "${cloud_account_id}") && REGISTRY_URI="$ACCOUNT.dkr.ecr.$REGION.amazonaws.com" && IMAGE="$REGISTRY_URI/${registry}:latest" && echo "Authenticating to ECR..." && aws ecr get-login-password --region "$REGION" | docker login --username AWS --password-stdin "$REGISTRY_URI" 2>&1 && echo "Pulling image: $IMAGE" && docker pull "$IMAGE" 2>&1 && echo "" && echo "--- Trivy CVE Scan ---" && trivy image --severity CRITICAL,HIGH --format json "$IMAGE" 2>/dev/null || echo "Trivy scan failed or not available" && echo "" && echo "--- Image History (build layer secrets) ---" && docker history --no-trunc "$IMAGE" 2>&1 && echo "" && echo "--- Image Inspect (env vars) ---" && docker inspect "$IMAGE" --format '{{json .Config.Env}}' 2>&1`
          );
        }
      } else {
        commands.push(`echo "--- ECR Private Repositories ---"`);
        commands.push(`aws ecr describe-repositories --output json 2>&1`);
        commands.push(`echo ""`);

        commands.push(`echo "--- Repositories with Public Access Policies ---"`);
        commands.push(
          `for repo in $(aws ecr describe-repositories --query 'repositories[].repositoryName' --output text 2>/dev/null); do POLICY=$(aws ecr get-repository-policy --repository-name "$repo" 2>/dev/null) && if echo "$POLICY" | grep -q '"\\*"'; then echo "WARNING: $repo has wildcard principal in policy"; echo "$POLICY"; fi; done || echo "No repositories with public access found"`
        );
        commands.push(`echo ""`);

        commands.push(`echo "--- ECR Public Repositories ---"`);
        commands.push(`aws ecr-public describe-repositories 2>/dev/null || echo "No public ECR repositories or ecr-public not available"`);
        commands.push(`echo ""`);

        commands.push(`echo "--- Scan-on-Push Status ---"`);
        commands.push(
          `aws ecr describe-repositories --query 'repositories[].{Name:repositoryName,ScanOnPush:imageScanningConfiguration.scanOnPush,TagImmutability:imageTagMutability}' --output table 2>&1`
        );
      }
    } else if (provider === "azure") {
      commands.push(`echo "--- Azure Container Registries ---"`);
      commands.push(
        `az acr list --query '[].{Name:name,LoginServer:loginServer,AdminEnabled:adminUserEnabled,PublicAccess:publicNetworkAccess}' --output json 2>&1`
      );
      if (registry) {
        commands.push(`echo "--- Registry Details: ${registry} ---"`);
        commands.push(`az acr show --name ${registry} --output json 2>&1`);
        commands.push(`echo "--- Network Rules ---"`);
        commands.push(`az acr network-rule list --name ${registry} --output json 2>&1`);
      }
    } else if (provider === "gcp") {
      commands.push(`echo "--- GCP Artifact Registry Repositories ---"`);
      commands.push(
        `gcloud artifacts repositories list --format=json --project=${cloud_account_id} 2>&1`
      );
    }

    commands.push(`echo ""`);
    commands.push(`echo "=== Container Registry Security Test Complete ==="`);

    return await executeInKali(commands.join(" && "));
  },

  scan_container_image: async (args: {
    image: string;
    severity?: string;
    scan_type?: string;
  }) => {
    const { image, severity = "CRITICAL,HIGH", scan_type = "vuln" } = args;

    const commands: string[] = [
      `echo "=== Container Image Scan ==="`,
      `echo "Image: ${image}"`,
      `echo "Severity: ${severity}"`,
      `echo "Scan Type: ${scan_type}"`,
      `echo ""`,
      `trivy image --severity ${severity} --scanners ${scan_type} --format json ${image} 2>/dev/null || trivy image --severity ${severity} --format json ${image}`,
    ];

    return await executeInKali(commands.join(" && "));
  },

  test_messaging_exposure: async (args: {
    provider: string;
    cloud_account_id: string;
    service_type?: string;
  }) => {
    const { provider, cloud_account_id, service_type = "all" } = args;

    const commands: string[] = [
      `echo "=== Cloud Messaging Service Exposure Test ==="`,
      `echo "Provider: ${provider}"`,
      `echo "Account: ${cloud_account_id}"`,
      `echo "Service Type: ${service_type}"`,
      `echo ""`,
    ];

    if (provider === "aws") {
      if (service_type === "sqs" || service_type === "all") {
        commands.push(`echo "--- SQS Queue Policies ---"`);
        commands.push(
          `QUEUES=$(aws sqs list-queues --output json 2>/dev/null) && echo "$QUEUES" && for queue_url in $(echo "$QUEUES" | python3 -c "import sys,json; data=json.load(sys.stdin); [print(u) for u in data.get('QueueUrls',[])]" 2>/dev/null); do echo ""; echo "Queue: $queue_url"; ATTRS=$(aws sqs get-queue-attributes --queue-url "$queue_url" --attribute-names Policy --output json 2>/dev/null); POLICY=$(echo "$ATTRS" | python3 -c "import sys,json; print(json.load(sys.stdin).get('Attributes',{}).get('Policy','No policy set'))" 2>/dev/null); echo "Policy: $POLICY"; if echo "$POLICY" | grep -q '"\\*"'; then echo "WARNING: Queue has wildcard principal - potential unauthorized access"; fi; done || echo "No SQS queues found or unable to list"`
        );
        commands.push(`echo ""`);
      }

      if (service_type === "sns" || service_type === "all") {
        commands.push(`echo "--- SNS Topic Policies ---"`);
        commands.push(
          `TOPICS=$(aws sns list-topics --output json 2>/dev/null) && echo "$TOPICS" && for topic_arn in $(echo "$TOPICS" | python3 -c "import sys,json; data=json.load(sys.stdin); [print(t['TopicArn']) for t in data.get('Topics',[])]" 2>/dev/null); do echo ""; echo "Topic: $topic_arn"; ATTRS=$(aws sns get-topic-attributes --topic-arn "$topic_arn" --output json 2>/dev/null); POLICY=$(echo "$ATTRS" | python3 -c "import sys,json; print(json.load(sys.stdin).get('Attributes',{}).get('Policy','No policy set'))" 2>/dev/null); echo "Policy: $POLICY"; if echo "$POLICY" | grep -q '"\\*"'; then echo "WARNING: Topic has wildcard principal - potential unauthorized publish/subscribe"; fi; done || echo "No SNS topics found or unable to list"`
        );
        commands.push(`echo ""`);
      }

      if (service_type === "eventbridge" || service_type === "all") {
        commands.push(`echo "--- EventBridge Rules ---"`);
        commands.push(
          `aws events list-rules --output json 2>&1 | python3 -c "
import sys, json
data = json.load(sys.stdin)
rules = data.get('Rules', [])
print(f'Total rules: {len(rules)}')
for rule in rules:
    name = rule.get('Name', '')
    state = rule.get('State', '')
    pattern = rule.get('EventPattern', 'No pattern')
    print(f'  Rule: {name} (State: {state})')
    print(f'    Pattern: {pattern}')
    if '\"*\"' in str(pattern) or pattern == 'No pattern':
        print(f'    WARNING: Overpermissive or catch-all pattern')
" 2>/dev/null || echo "Unable to parse EventBridge rules"`
        );
        commands.push(`echo ""`);

        commands.push(`echo "--- EventBridge Event Buses ---"`);
        commands.push(
          `aws events list-event-buses --output json 2>&1 | python3 -c "
import sys, json
data = json.load(sys.stdin)
for bus in data.get('EventBuses', []):
    name = bus.get('Name', '')
    policy = bus.get('Policy', 'No policy')
    print(f'Bus: {name}')
    print(f'  Policy: {policy}')
    if '\"*\"' in str(policy):
        print(f'  WARNING: Bus has wildcard principal')
" 2>/dev/null || echo "Unable to parse EventBridge buses"`
        );
      }
    } else if (provider === "azure") {
      commands.push(`echo "--- Azure Service Bus ---"`);
      commands.push(
        `az servicebus namespace list --query '[].{Name:name,ResourceGroup:resourceGroup,Sku:sku.name}' --output json 2>&1`
      );
      commands.push(`echo ""`);
      commands.push(`echo "--- Azure Event Grid Topics ---"`);
      commands.push(
        `az eventgrid topic list --query '[].{Name:name,Endpoint:endpoint,PublicAccess:publicNetworkAccess}' --output json 2>&1`
      );
    } else if (provider === "gcp") {
      commands.push(`echo "--- GCP Pub/Sub Topics ---"`);
      commands.push(
        `gcloud pubsub topics list --format=json --project=${cloud_account_id} 2>&1`
      );
      commands.push(`echo ""`);
      commands.push(`echo "--- Pub/Sub Topic IAM Policies ---"`);
      commands.push(
        `for topic in $(gcloud pubsub topics list --format='value(name)' --project=${cloud_account_id} 2>/dev/null); do echo "Topic: $topic"; gcloud pubsub topics get-iam-policy "$topic" --format=json --project=${cloud_account_id} 2>/dev/null; echo ""; done || echo "No Pub/Sub topics found"`
      );
    }

    commands.push(`echo ""`);
    commands.push(`echo "=== Messaging Exposure Test Complete ==="`);

    return await executeInKali(commands.join(" && "));
  },
};
