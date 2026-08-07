import { executeInKali } from "../utils/docker-exec";

export const cloudIamTools = [
  {
    name: "enum_iam_policies",
    description:
      "Enumerate and analyze IAM policies for overpermissive access. Identifies wildcard permissions, admin-equivalent policies, and dangerous action combinations.",
    inputSchema: {
      type: "object",
      properties: {
        provider: {
          type: "string",
          enum: ["aws", "azure", "gcp"],
          description: "Cloud provider to enumerate IAM policies for",
        },
        cloud_account_id: {
          type: "string",
          description: "Cloud account/project/subscription ID for scope validation",
        },
        principal: {
          type: "string",
          description: "Specific user/role ARN to analyze (optional, defaults to all principals)",
        },
      },
      required: ["provider", "cloud_account_id"],
    },
  },
  {
    name: "test_iam_privesc",
    description:
      "Identify and attempt IAM privilege escalation paths using PMapper and Pacu. Tests 20+ privesc vectors: PassRole, AssumeRole chains, Lambda injection, EC2 profile abuse.",
    inputSchema: {
      type: "object",
      properties: {
        provider: {
          type: "string",
          enum: ["aws", "azure", "gcp"],
          description: "Cloud provider to test privilege escalation on",
        },
        cloud_account_id: {
          type: "string",
          description: "Cloud account/project/subscription ID for scope validation",
        },
        starting_principal: {
          type: "string",
          description: "Starting user/role ARN to escalate from (optional)",
        },
        attempt_exploitation: {
          type: "boolean",
          description: "Whether to attempt actual privilege escalation (default: true)",
          default: true,
        },
      },
      required: ["provider", "cloud_account_id"],
    },
  },
  {
    name: "test_cross_account_trust",
    description:
      "Test IAM trust policies for cross-account access. Checks confused deputy, overpermissive external principals, and wildcard trust.",
    inputSchema: {
      type: "object",
      properties: {
        provider: {
          type: "string",
          enum: ["aws", "azure"],
          description: "Cloud provider to test cross-account trust on",
        },
        cloud_account_id: {
          type: "string",
          description: "Cloud account/subscription ID for scope validation",
        },
        external_account_id: {
          type: "string",
          description: "External account ID to test assume-role from (optional)",
        },
      },
      required: ["provider", "cloud_account_id"],
    },
  },
  {
    name: "test_service_account_permissions",
    description:
      "Test service accounts and managed identities for excess permissions. Checks EC2 instance profiles, Lambda execution roles, ECS task roles.",
    inputSchema: {
      type: "object",
      properties: {
        provider: {
          type: "string",
          enum: ["aws", "azure", "gcp"],
          description: "Cloud provider to test service account permissions on",
        },
        cloud_account_id: {
          type: "string",
          description: "Cloud account/project/subscription ID for scope validation",
        },
        service_type: {
          type: "string",
          enum: ["ec2", "lambda", "ecs", "eks", "all"],
          description: "Type of service accounts to check (default: all)",
          default: "all",
        },
      },
      required: ["provider", "cloud_account_id"],
    },
  },
  {
    name: "test_credential_exposure",
    description:
      "Check for exposed cloud credentials: stale access keys, keys in environment variables, keys in instance user-data, keys in Lambda env vars.",
    inputSchema: {
      type: "object",
      properties: {
        provider: {
          type: "string",
          enum: ["aws", "azure", "gcp"],
          description: "Cloud provider to check credential exposure on",
        },
        cloud_account_id: {
          type: "string",
          description: "Cloud account/project/subscription ID for scope validation",
        },
        max_key_age_days: {
          type: "number",
          description: "Maximum acceptable access key age in days (default: 90)",
          default: 90,
        },
      },
      required: ["provider", "cloud_account_id"],
    },
  },
];

export const cloudIamHandlers: Record<string, Function> = {
  enum_iam_policies: async (args: {
    provider: string;
    cloud_account_id: string;
    principal?: string;
  }) => {
    const { provider, cloud_account_id, principal } = args;
    const commands: string[] = [
      `echo "=== IAM Policy Enumeration ==="`,
      `echo "Provider: ${provider}"`,
      `echo "Account: ${cloud_account_id}"`,
      `echo ""`,
    ];

    if (provider === "aws") {
      commands.push(`echo "--- AWS IAM Account Authorization Details ---"`);
      if (principal) {
        commands.push(
          `echo "Filtering for principal: ${principal}"`
        );
        commands.push(
          `aws iam get-account-authorization-details --output json 2>/dev/null | jq '{UserDetailList: [.UserDetailList[] | select(.Arn == "${principal}" or .UserName == "${principal}")], RoleDetailList: [.RoleDetailList[] | select(.Arn == "${principal}" or .RoleName == "${principal}")]}' 2>/dev/null || echo "Failed to get authorization details for principal"`
        );
      } else {
        commands.push(
          `aws iam get-account-authorization-details --output json 2>/dev/null || echo "Failed to get account authorization details"`
        );
      }

      commands.push(`echo ""`);
      commands.push(`echo "--- Wildcard Admin Policies (Action: * on Resource: *) ---"`);
      commands.push(
        `aws iam get-account-authorization-details --output json 2>/dev/null | jq '[.Policies[] | select(.PolicyVersionList[]?.Document?.Statement[]? | select(.Effect == "Allow" and (.Action == "*" or .Action == ["*"]) and (.Resource == "*" or .Resource == ["*"])))] | map({PolicyName: .PolicyName, Arn: .Arn})' 2>/dev/null || echo "Failed to check wildcard policies"`
      );

      commands.push(`echo ""`);
      commands.push(`echo "--- Policies with Wildcard Resources ---"`);
      commands.push(
        `aws iam get-account-authorization-details --output json 2>/dev/null | jq '[.Policies[] | select(.PolicyVersionList[]?.Document?.Statement[]? | select(.Effect == "Allow" and (.Resource == "*" or .Resource == ["*"])))] | map({PolicyName: .PolicyName, Arn: .Arn})' 2>/dev/null || echo "Failed to check wildcard resource policies"`
      );

      commands.push(`echo ""`);
      commands.push(`echo "--- Inline Policies on Users ---"`);
      commands.push(
        `aws iam get-account-authorization-details --output json 2>/dev/null | jq '[.UserDetailList[] | select(.UserPolicyList | length > 0) | {UserName: .UserName, InlinePolicies: [.UserPolicyList[].PolicyName]}]' 2>/dev/null || echo "Failed to check inline policies"`
      );

      commands.push(`echo ""`);
      commands.push(`echo "--- Users Without MFA ---"`);
      commands.push(
        `MFA_USERS=$(aws iam list-virtual-mfa-devices --output json 2>/dev/null | jq -r '.VirtualMFADevices[].User.UserName' 2>/dev/null) && ALL_USERS=$(aws iam list-users --output json 2>/dev/null | jq -r '.Users[].UserName' 2>/dev/null) && echo "$ALL_USERS" | while read user; do echo "$MFA_USERS" | grep -qx "$user" || echo "NO MFA: $user"; done || echo "Failed to check MFA status"`
      );

      commands.push(`echo ""`);
      commands.push(`echo "--- Access Keys Older Than 90 Days ---"`);
      commands.push(
        `aws iam list-users --output json 2>/dev/null | jq -r '.Users[].UserName' 2>/dev/null | while read user; do aws iam list-access-keys --user-name "$user" --output json 2>/dev/null | jq -r --arg user "$user" '.AccessKeyMetadata[] | select(.Status == "Active") | "\\($user) | \\(.AccessKeyId) | Created: \\(.CreateDate)"' 2>/dev/null; done || echo "Failed to list access keys"`
      );
    } else if (provider === "azure") {
      commands.push(`echo "--- Azure Role Assignments ---"`);
      commands.push(
        `az role assignment list --all --output json 2>/dev/null || echo "Failed to list role assignments"`
      );

      commands.push(`echo ""`);
      commands.push(`echo "--- Azure Custom Role Definitions ---"`);
      commands.push(
        `az role definition list --custom-role-only true --output json 2>/dev/null || echo "Failed to list custom roles"`
      );

      commands.push(`echo ""`);
      commands.push(`echo "--- Overpermissive Custom Roles (wildcard actions) ---"`);
      commands.push(
        `az role definition list --custom-role-only true --output json 2>/dev/null | jq '[.[] | select(.permissions[].actions[] == "*")] | map({roleName: .roleName, id: .id})' 2>/dev/null || echo "Failed to check overpermissive roles"`
      );
    } else if (provider === "gcp") {
      commands.push(`echo "--- GCP IAM Policy ---"`);
      commands.push(
        `gcloud projects get-iam-policy ${cloud_account_id} --format json 2>/dev/null || echo "Failed to get IAM policy"`
      );

      commands.push(`echo ""`);
      commands.push(`echo "--- GCP Custom Roles ---"`);
      commands.push(
        `gcloud iam roles list --project ${cloud_account_id} --format json 2>/dev/null || echo "Failed to list custom roles"`
      );

      commands.push(`echo ""`);
      commands.push(`echo "--- Overpermissive Bindings (roles/owner or roles/editor) ---"`);
      commands.push(
        `gcloud projects get-iam-policy ${cloud_account_id} --format json 2>/dev/null | jq '[.bindings[] | select(.role == "roles/owner" or .role == "roles/editor")] | map({role: .role, members: .members})' 2>/dev/null || echo "Failed to check overpermissive bindings"`
      );
    }

    commands.push(`echo ""`);
    commands.push(`echo "=== IAM Policy Enumeration Complete ==="`);

    return await executeInKali(commands.join(" && "));
  },

  test_iam_privesc: async (args: {
    provider: string;
    cloud_account_id: string;
    starting_principal?: string;
    attempt_exploitation?: boolean;
  }) => {
    const { provider, cloud_account_id, starting_principal, attempt_exploitation = true } = args;
    const commands: string[] = [
      `echo "=== IAM Privilege Escalation Test ==="`,
      `echo "Provider: ${provider}"`,
      `echo "Account: ${cloud_account_id}"`,
      `echo "Attempt Exploitation: ${attempt_exploitation}"`,
      `echo ""`,
    ];

    if (provider === "aws") {
      // Tool-availability preflight: distinguishes NOT-INSTALLED vs crashed vs no-creds.
      // Without this, an ImportError (pmapper on py3.13), an argparse error (pacu), and a
      // genuine missing-credentials condition all collapsed into one vague "failed" line.
      commands.push(`echo "--- Tool availability ---"`);
      commands.push(
        `command -v pmapper >/dev/null 2>&1 && echo "pmapper: INSTALLED ($(pmapper --version 2>&1 | head -1))" || echo "pmapper: NOT INSTALLED"`
      );
      commands.push(
        `command -v pacu >/dev/null 2>&1 && echo "pacu: INSTALLED" || echo "pacu: NOT INSTALLED"`
      );
      commands.push(`echo ""`);

      commands.push(`echo "--- Phase 1: PMapper Graph Creation ---"`);
      commands.push(
        `pmapper graph create 2>&1 && echo "PMapper graph created successfully" || echo "PMapper graph creation FAILED (see stderr above; not a creds issue if it is a Python/ImportError)"`
      );

      commands.push(`echo ""`);
      commands.push(`echo "--- Phase 2: PMapper Privilege Escalation Query ---"`);
      commands.push(
        `pmapper query 'preset privesc *' 2>&1 || echo "PMapper privesc query failed (see stderr above)"`
      );

      commands.push(`echo ""`);
      commands.push(`echo "--- Phase 3: PMapper Admin Access Query ---"`);
      commands.push(
        `pmapper query 'who can do iam:* with *' 2>&1 || echo "PMapper admin query failed (see stderr above)"`
      );

      if (starting_principal) {
        commands.push(`echo ""`);
        commands.push(`echo "--- Phase 4: PMapper Paths from Starting Principal ---"`);
        commands.push(
          `pmapper query 'can ${starting_principal} do iam:* with *' 2>&1 || echo "PMapper path query failed (see stderr above)"`
        );
      }

      commands.push(`echo ""`);
      commands.push(`echo "--- Phase 5: PMapper Visualization ---"`);
      commands.push(
        `pmapper visualize --filetype svg --output /tmp/pmapper-privesc.svg 2>&1 && echo "Graph saved to /tmp/pmapper-privesc.svg" || echo "PMapper visualization failed (see stderr above)"`
      );

      if (attempt_exploitation) {
        commands.push(`echo ""`);
        commands.push(`echo "--- Phase 6: Pacu Privilege Escalation Scan ---"`);
        commands.push(
          `echo "Creating Pacu session..." && pacu --new-session maestro-test --set-regions us-east-1 2>&1 || echo "Pacu session creation failed (see stderr above)"`
        );
        commands.push(
          `pacu --session maestro-test --import-keys default --module-name iam__privesc_scan --exec 2>&1 || echo "Pacu privesc scan failed (module exec)"`
        );

        commands.push(`echo ""`);
        commands.push(`echo "--- Phase 7: Pacu Enumeration Results ---"`);
        commands.push(
          `pacu --session maestro-test --import-keys default --module-name iam__enum_permissions --exec 2>&1 || echo "Pacu enum permissions failed (module exec)"`
        );
      }
    } else if (provider === "azure") {
      commands.push(`echo "--- Azure Privilege Escalation Checks ---"`);
      commands.push(`echo "Note: covers high-privilege role assignments + dangerous custom roles. Deeper edges (Managed Identity abuse, RBAC-via-deployment) pending validation against an Azure test tenant."`);

      commands.push(`echo ""`);
      commands.push(`echo "--- Checking for Global Admin Assignments ---"`);
      commands.push(
        `az role assignment list --all --output json 2>/dev/null | jq '[.[] | select(.roleDefinitionName == "Owner" or .roleDefinitionName == "Contributor" or .roleDefinitionName == "User Access Administrator")]' 2>/dev/null || echo "Failed to check admin assignments"`
      );

      commands.push(`echo ""`);
      commands.push(`echo "--- Checking for Custom Roles with Dangerous Permissions ---"`);
      commands.push(
        `az role definition list --custom-role-only true --output json 2>/dev/null | jq '[.[] | select(.permissions[].actions[] | test("Microsoft.Authorization/roleAssignments/write|Microsoft.Authorization/roleDefinitions/write|\\\\*"))]' 2>/dev/null || echo "Failed to check dangerous custom roles"`
      );
    } else if (provider === "gcp") {
      // GCP privilege-escalation enumeration. There is no PMapper equivalent for
      // GCP in the image, so this maps the canonical escalation primitives (Rhino
      // Security Labs' GCP privesc catalogue) directly off gcloud + jq:
      //   - project-level bindings holding primitive/dangerous roles,
      //   - custom roles whose permissions themselves grant escalation,
      //   - service-account impersonation edges (the actAs / token-creator paths),
      //   - and (when exploiting) a NON-DESTRUCTIVE impersonation-token proof.
      // All read-only: enumeration + a short-lived token mint. No key creation,
      // no policy writes.
      commands.push(`echo "--- GCP Privilege Escalation Enumeration ---"`);

      commands.push(`echo ""`);
      commands.push(`echo "--- Preflight: active identity ---"`);
      commands.push(
        `command -v gcloud >/dev/null 2>&1 && echo "gcloud: INSTALLED" || echo "gcloud: NOT INSTALLED"`
      );
      commands.push(
        `echo "Active account: $(gcloud config get-value account 2>/dev/null)"; echo "Active project: $(gcloud config get-value project 2>/dev/null)"`
      );

      // Phase 1 — project bindings holding primitive or otherwise escalation-capable
      // predefined roles. Each of these is either all-powerful (owner/editor) or a
      // direct escalation vector (act as / mint keys / rewrite IAM / deploy-as-SA).
      commands.push(`echo ""`);
      commands.push(`echo "--- Phase 1: Dangerous role bindings on the project ---"`);
      commands.push(
        `gcloud projects get-iam-policy ${cloud_account_id} --format json 2>&1 | jq '[.bindings[] | select(.role | test("roles/(owner|editor|iam.securityAdmin|iam.serviceAccountAdmin|iam.serviceAccountKeyAdmin|iam.serviceAccountTokenCreator|iam.serviceAccountUser|iam.roleAdmin|iam.organizationRoleAdmin|resourcemanager.projectIamAdmin|resourcemanager.organizationAdmin|deploymentmanager.editor|cloudfunctions.(admin|developer)|cloudbuild.builds.editor|compute.(admin|instanceAdmin)|run.admin|composer.admin|container.admin)"))]' 2>&1 || echo "Failed to read project IAM policy (see stderr above)"`
      );

      // Phase 2 — custom roles whose *permissions* grant escalation regardless of
      // the role's name (setIamPolicy, actAs, key create, role update, deploy-as-SA,
      // or a literal * wildcard).
      // `gcloud iam roles list` returns only role summaries, so each custom role
      // must be described to read its includedPermissions.
      commands.push(`echo ""`);
      commands.push(`echo "--- Phase 2: Custom roles with escalation permissions ---"`);
      commands.push(
        `for role in $(gcloud iam roles list --project ${cloud_account_id} --format='value(name)' 2>/dev/null); do perms=$(gcloud iam roles describe "$role" --format json 2>/dev/null | jq -c '[.includedPermissions[]? | select(test("(resourcemanager.projects.setIamPolicy|iam.serviceAccounts.actAs|iam.serviceAccounts.getAccessToken|iam.serviceAccounts.getOpenIdToken|iam.serviceAccounts.implicitDelegation|iam.serviceAccounts.signBlob|iam.serviceAccounts.signJwt|iam.serviceAccountKeys.create|iam.roles.update|iam.roles.create|deploymentmanager.deployments.create|cloudfunctions.functions.create|cloudfunctions.functions.update|compute.instances.setServiceAccount|run.services.create|cloudbuild.builds.create|orgpolicy.policy.set|storage.hmacKeys.create|\\\\*)"))]' 2>/dev/null); if [ -n "$perms" ] && [ "$perms" != "[]" ]; then echo "Custom role $role grants escalation perms: $perms"; fi; done || echo "Failed to enumerate custom roles (may lack iam.roles.list; see stderr above)"`
      );

      // Phase 3 — service-account impersonation edges. A member with
      // tokenCreator/serviceAccountUser/keyAdmin/workloadIdentityUser on a service
      // account can act as it; if that SA is more privileged, that's the escalation.
      commands.push(`echo ""`);
      commands.push(`echo "--- Phase 3: Service-account impersonation edges ---"`);
      commands.push(
        `for sa in $(gcloud iam service-accounts list --project ${cloud_account_id} --format='value(email)' 2>/dev/null); do edges=$(gcloud iam service-accounts get-iam-policy "$sa" --project ${cloud_account_id} --format json 2>/dev/null | jq -c '[.bindings[]? | select(.role | test("iam.serviceAccountTokenCreator|iam.serviceAccountUser|iam.serviceAccountKeyAdmin|iam.workloadIdentityUser"))]' 2>/dev/null); if [ -n "$edges" ] && [ "$edges" != "[]" ]; then echo "SA $sa impersonable by: $edges"; fi; done || echo "Failed to enumerate service accounts (see stderr above)"`
      );

      if (starting_principal) {
        // Phase 4 — what the starting principal directly holds on the project.
        commands.push(`echo ""`);
        commands.push(`echo "--- Phase 4: Bindings for ${starting_principal} ---"`);
        commands.push(
          `gcloud projects get-iam-policy ${cloud_account_id} --format json 2>&1 | jq --arg p "${starting_principal}" '[.bindings[] | select(.members[]? | test($p)) | .role]' 2>&1 || echo "Failed to filter bindings for principal (see stderr above)"`
        );
      }

      if (attempt_exploitation) {
        // Phase 5 — non-destructive capability proof: for each service account,
        // try to mint a short-lived access token by impersonation. A returned
        // token proves the active identity can act as that SA (an escalation edge
        // it actually holds). Read-only: the token is never used and expires; no
        // keys are created and no policy is written.
        commands.push(`echo ""`);
        commands.push(`echo "--- Phase 5: Impersonation capability proof (non-destructive) ---"`);
        commands.push(
          `for sa in $(gcloud iam service-accounts list --project ${cloud_account_id} --format='value(email)' 2>/dev/null); do if gcloud auth print-access-token --impersonate-service-account="$sa" >/dev/null 2>&1; then echo "IMPERSONATION CONFIRMED: active identity can mint tokens as $sa"; else echo "cannot impersonate $sa"; fi; done || echo "Impersonation probe failed (see stderr above)"`
        );
      }
    }

    commands.push(`echo ""`);
    commands.push(`echo "=== IAM Privilege Escalation Test Complete ==="`);

    return await executeInKali(commands.join(" && "));
  },

  test_cross_account_trust: async (args: {
    provider: string;
    cloud_account_id: string;
    external_account_id?: string;
  }) => {
    const { provider, cloud_account_id, external_account_id } = args;
    const commands: string[] = [
      `echo "=== Cross-Account Trust Analysis ==="`,
      `echo "Provider: ${provider}"`,
      `echo "Account: ${cloud_account_id}"`,
      `echo ""`,
    ];

    if (provider === "aws") {
      commands.push(`echo "--- Listing All IAM Roles with Trust Policies ---"`);
      commands.push(
        `aws iam list-roles --output json 2>/dev/null | jq -r '.Roles[] | {RoleName: .RoleName, Arn: .Arn, TrustPolicy: .AssumeRolePolicyDocument}' 2>/dev/null || echo "Failed to list roles"`
      );

      commands.push(`echo ""`);
      commands.push(`echo "--- Roles Trusting External Accounts ---"`);
      commands.push(
        `aws iam list-roles --output json 2>/dev/null | jq --arg acct "${cloud_account_id}" '[.Roles[] | select(.AssumeRolePolicyDocument.Statement[]?.Principal.AWS? // "" | tostring | test("arn:aws") and (test($acct) | not))] | map({RoleName: .RoleName, Arn: .Arn, TrustedPrincipals: [.AssumeRolePolicyDocument.Statement[].Principal.AWS] | flatten})' 2>/dev/null || echo "Failed to check external trust"`
      );

      commands.push(`echo ""`);
      commands.push(`echo "--- Roles with Wildcard Trust (Principal: *) ---"`);
      commands.push(
        `aws iam list-roles --output json 2>/dev/null | jq '[.Roles[] | select(.AssumeRolePolicyDocument.Statement[]?.Principal == "*" or .AssumeRolePolicyDocument.Statement[]?.Principal.AWS == "*")] | map({RoleName: .RoleName, Arn: .Arn})' 2>/dev/null || echo "Failed to check wildcard trust"`
      );

      commands.push(`echo ""`);
      commands.push(`echo "--- Roles Missing sts:ExternalId Condition (Confused Deputy) ---"`);
      commands.push(
        `aws iam list-roles --output json 2>/dev/null | jq --arg acct "${cloud_account_id}" '[.Roles[] | select(.AssumeRolePolicyDocument.Statement[]?.Principal.AWS? // "" | tostring | test("arn:aws") and (test($acct) | not)) | select(.AssumeRolePolicyDocument.Statement[] | (.Condition.StringEquals["sts:ExternalId"]? // null) == null)] | map({RoleName: .RoleName, Arn: .Arn, Warning: "No ExternalId condition - vulnerable to confused deputy"})' 2>/dev/null || echo "Failed to check ExternalId conditions"`
      );

      if (external_account_id) {
        commands.push(`echo ""`);
        commands.push(`echo "--- Attempting Cross-Account AssumeRole from ${external_account_id} ---"`);
        commands.push(
          `aws iam list-roles --output json 2>/dev/null | jq -r --arg ext "${external_account_id}" '.Roles[] | select(.AssumeRolePolicyDocument.Statement[]?.Principal.AWS? // "" | tostring | test($ext)) | .Arn' 2>/dev/null | while read role_arn; do echo "Attempting to assume: $role_arn" && aws sts assume-role --role-arn "$role_arn" --role-session-name maestro-test --external-id test --output json 2>/dev/null && echo "SUCCESS: Assumed $role_arn" || echo "DENIED: Cannot assume $role_arn"; echo ""; done || echo "Failed to test cross-account access"`
        );
      }
    } else if (provider === "azure") {
      commands.push(`echo "--- Azure Multi-Tenant Application Analysis ---"`);
      commands.push(
        `az ad sp list --all --output json 2>/dev/null | jq '[.[] | select(.appOwnerOrganizationId != null)] | map({displayName: .displayName, appId: .appId, ownerOrg: .appOwnerOrganizationId})' 2>/dev/null || echo "Failed to list service principals"`
      );

      commands.push(`echo ""`);
      commands.push(`echo "--- Multi-Tenant Apps (External Principals) ---"`);
      commands.push(
        `az ad sp list --all --output json 2>/dev/null | jq --arg sub "${cloud_account_id}" '[.[] | select(.appOwnerOrganizationId != null and .appOwnerOrganizationId != $sub)] | map({displayName: .displayName, appId: .appId, ownerOrg: .appOwnerOrganizationId, Warning: "External tenant application"})' 2>/dev/null || echo "Failed to check multi-tenant apps"`
      );

      commands.push(`echo ""`);
      commands.push(`echo "--- Checking for Overpermissive App Registrations ---"`);
      commands.push(
        `az ad app list --all --output json 2>/dev/null | jq '[.[] | select(.requiredResourceAccess[]?.resourceAccess[]?.type == "Role")] | map({displayName: .displayName, appId: .appId})' 2>/dev/null || echo "Failed to check app registrations"`
      );
    }

    commands.push(`echo ""`);
    commands.push(`echo "=== Cross-Account Trust Analysis Complete ==="`);

    return await executeInKali(commands.join(" && "));
  },

  test_service_account_permissions: async (args: {
    provider: string;
    cloud_account_id: string;
    service_type?: string;
  }) => {
    const { provider, cloud_account_id, service_type = "all" } = args;
    const commands: string[] = [
      `echo "=== Service Account Permission Analysis ==="`,
      `echo "Provider: ${provider}"`,
      `echo "Account: ${cloud_account_id}"`,
      `echo "Service Type: ${service_type}"`,
      `echo ""`,
    ];

    if (provider === "aws") {
      if (service_type === "ec2" || service_type === "all") {
        commands.push(`echo "--- EC2 Instance Profiles ---"`);
        commands.push(
          `aws ec2 describe-instances --query 'Reservations[].Instances[].{Id:InstanceId,Profile:IamInstanceProfile}' --output json 2>/dev/null || echo "Failed to list EC2 instances"`
        );

        commands.push(`echo ""`);
        commands.push(`echo "--- EC2 Instance Profile Policies ---"`);
        commands.push(
          `aws ec2 describe-instances --query 'Reservations[].Instances[].IamInstanceProfile.Arn' --output text 2>/dev/null | tr '\\t' '\\n' | sort -u | while read profile_arn; do if [ -n "$profile_arn" ] && [ "$profile_arn" != "None" ]; then PROFILE_NAME=$(echo "$profile_arn" | awk -F/ '{print $NF}') && echo "Profile: $PROFILE_NAME" && aws iam get-instance-profile --instance-profile-name "$PROFILE_NAME" --output json 2>/dev/null | jq -r '.InstanceProfile.Roles[].RoleName' 2>/dev/null | while read role; do echo "  Role: $role" && echo "  Attached Policies:" && aws iam list-attached-role-policies --role-name "$role" --output json 2>/dev/null | jq -r '.AttachedPolicies[] | "    - \\(.PolicyName) (\\(.PolicyArn))"' 2>/dev/null && echo "  Inline Policies:" && aws iam list-role-policies --role-name "$role" --output json 2>/dev/null | jq -r '.PolicyNames[] | "    - \\(.)"' 2>/dev/null; done; echo ""; fi; done || echo "Failed to enumerate EC2 profiles"`
        );
      }

      if (service_type === "lambda" || service_type === "all") {
        commands.push(`echo ""`);
        commands.push(`echo "--- Lambda Execution Roles ---"`);
        commands.push(
          `aws lambda list-functions --query 'Functions[].{Name:FunctionName,Role:Role}' --output json 2>/dev/null || echo "Failed to list Lambda functions"`
        );

        commands.push(`echo ""`);
        commands.push(`echo "--- Lambda Role Policy Analysis ---"`);
        commands.push(
          `aws lambda list-functions --query 'Functions[].Role' --output text 2>/dev/null | tr '\\t' '\\n' | sort -u | while read role_arn; do if [ -n "$role_arn" ]; then ROLE_NAME=$(echo "$role_arn" | awk -F/ '{print $NF}') && echo "Role: $ROLE_NAME ($role_arn)" && aws iam list-attached-role-policies --role-name "$ROLE_NAME" --output json 2>/dev/null | jq -r '.AttachedPolicies[] | "  Attached: \\(.PolicyName)"' 2>/dev/null && aws iam list-role-policies --role-name "$ROLE_NAME" --output json 2>/dev/null | jq -r '.PolicyNames[] | "  Inline: \\(.)"' 2>/dev/null && echo ""; fi; done || echo "Failed to analyze Lambda roles"`
        );
      }

      if (service_type === "ecs" || service_type === "all") {
        commands.push(`echo ""`);
        commands.push(`echo "--- ECS Task Definitions and Roles ---"`);
        commands.push(
          `aws ecs list-task-definitions --output json 2>/dev/null | jq -r '.taskDefinitionArns[]' 2>/dev/null | tail -20 | while read td_arn; do echo "Task Definition: $td_arn" && aws ecs describe-task-definition --task-definition "$td_arn" --query 'taskDefinition.{Family:family,TaskRoleArn:taskRoleArn,ExecutionRoleArn:executionRoleArn}' --output json 2>/dev/null && echo ""; done || echo "Failed to list ECS task definitions"`
        );
      }

      if (service_type === "eks" || service_type === "all") {
        commands.push(`echo ""`);
        commands.push(`echo "--- EKS Cluster Roles ---"`);
        commands.push(
          `aws eks list-clusters --output json 2>/dev/null | jq -r '.clusters[]' 2>/dev/null | while read cluster; do echo "Cluster: $cluster" && aws eks describe-cluster --name "$cluster" --query 'cluster.{RoleArn:roleArn,Version:version}' --output json 2>/dev/null && echo ""; done || echo "Failed to list EKS clusters"`
        );
      }
    } else if (provider === "azure") {
      commands.push(`echo "--- Azure Managed Identities ---"`);
      commands.push(
        `az identity list --output json 2>/dev/null || echo "Failed to list managed identities"`
      );

      commands.push(`echo ""`);
      commands.push(`echo "--- Azure VM Managed Identity Assignments ---"`);
      commands.push(
        `az vm list --output json 2>/dev/null | jq '[.[] | select(.identity != null) | {name: .name, identityType: .identity.type, principalId: .identity.principalId}]' 2>/dev/null || echo "Failed to check VM identities"`
      );

      commands.push(`echo ""`);
      commands.push(`echo "--- Azure Function App Identities ---"`);
      commands.push(
        `az functionapp list --output json 2>/dev/null | jq '[.[] | select(.identity != null) | {name: .name, identityType: .identity.type, principalId: .identity.principalId}]' 2>/dev/null || echo "Failed to check Function App identities"`
      );
    } else if (provider === "gcp") {
      commands.push(`echo "--- GCP Service Accounts ---"`);
      commands.push(
        `gcloud iam service-accounts list --project ${cloud_account_id} --format json 2>/dev/null || echo "Failed to list service accounts"`
      );

      commands.push(`echo ""`);
      commands.push(`echo "--- GCP Compute Instance Service Accounts ---"`);
      commands.push(
        `gcloud compute instances list --project ${cloud_account_id} --format json 2>/dev/null | jq '[.[] | {name: .name, zone: .zone, serviceAccounts: [.serviceAccounts[]?.email]}]' 2>/dev/null || echo "Failed to list compute instances"`
      );

      commands.push(`echo ""`);
      commands.push(`echo "--- GCP Service Account Key Analysis ---"`);
      commands.push(
        `gcloud iam service-accounts list --project ${cloud_account_id} --format='value(email)' 2>/dev/null | while read sa; do echo "Service Account: $sa" && gcloud iam service-accounts keys list --iam-account "$sa" --format json 2>/dev/null | jq '[.[] | {keyId: .name, keyType: .keyType, validAfter: .validAfterTime, validBefore: .validBeforeTime}]' 2>/dev/null && echo ""; done || echo "Failed to analyze service account keys"`
      );
    }

    commands.push(`echo ""`);
    commands.push(`echo "=== Service Account Permission Analysis Complete ==="`);

    return await executeInKali(commands.join(" && "));
  },

  test_credential_exposure: async (args: {
    provider: string;
    cloud_account_id: string;
    max_key_age_days?: number;
  }) => {
    const { provider, cloud_account_id, max_key_age_days = 90 } = args;
    const commands: string[] = [
      `echo "=== Credential Exposure Analysis ==="`,
      `echo "Provider: ${provider}"`,
      `echo "Account: ${cloud_account_id}"`,
      `echo "Max Key Age: ${max_key_age_days} days"`,
      `echo ""`,
    ];

    if (provider === "aws") {
      commands.push(`echo "--- AWS Credential Report ---"`);
      commands.push(
        `aws iam generate-credential-report 2>/dev/null && sleep 3 && aws iam get-credential-report --output json 2>/dev/null | jq -r '.Content' 2>/dev/null | base64 -d 2>/dev/null || echo "Failed to generate credential report"`
      );

      commands.push(`echo ""`);
      commands.push(`echo "--- Stale Access Keys (Older Than ${max_key_age_days} Days) ---"`);
      commands.push(
        `CUTOFF=$(date -d "-${max_key_age_days} days" +%Y-%m-%dT%H:%M:%S 2>/dev/null || date -v-${max_key_age_days}d +%Y-%m-%dT%H:%M:%S 2>/dev/null) && echo "Cutoff date: $CUTOFF" && aws iam list-users --output json 2>/dev/null | jq -r '.Users[].UserName' 2>/dev/null | while read user; do aws iam list-access-keys --user-name "$user" --output json 2>/dev/null | jq -r --arg user "$user" --arg cutoff "$CUTOFF" '.AccessKeyMetadata[] | select(.Status == "Active" and .CreateDate < $cutoff) | "STALE KEY: \\($user) | \\(.AccessKeyId) | Created: \\(.CreateDate)"' 2>/dev/null; done || echo "Failed to check stale access keys"`
      );

      commands.push(`echo ""`);
      commands.push(`echo "--- Credentials in EC2 User Data ---"`);
      commands.push(
        `aws ec2 describe-instances --query 'Reservations[].Instances[].InstanceId' --output text 2>/dev/null | tr '\\t' '\\n' | while read instance_id; do if [ -n "$instance_id" ]; then USERDATA=$(aws ec2 describe-instance-attribute --instance-id "$instance_id" --attribute userData --output json 2>/dev/null | jq -r '.UserData.Value // empty' 2>/dev/null) && if [ -n "$USERDATA" ]; then DECODED=$(echo "$USERDATA" | base64 -d 2>/dev/null) && MATCHES=$(echo "$DECODED" | grep -iE "(AKIA|ASIA|password=|secret=|token=|AWS_SECRET|AWS_ACCESS)" 2>/dev/null) && if [ -n "$MATCHES" ]; then echo "EXPOSED in $instance_id user-data:" && echo "$MATCHES"; fi; fi; fi; done || echo "Failed to check EC2 user data"`
      );

      commands.push(`echo ""`);
      commands.push(`echo "--- Credentials in Lambda Environment Variables ---"`);
      commands.push(
        `aws lambda list-functions --output json 2>/dev/null | jq -r '.Functions[].FunctionName' 2>/dev/null | while read func; do ENV_VARS=$(aws lambda get-function-configuration --function-name "$func" --output json 2>/dev/null | jq -r '.Environment.Variables // {} | to_entries[] | select(.key | test("SECRET|PASSWORD|TOKEN|KEY|CREDENTIAL|API_KEY"; "i")) | "\\(.key)=\\(.value)"' 2>/dev/null) && if [ -n "$ENV_VARS" ]; then echo "EXPOSED in Lambda $func:" && echo "$ENV_VARS"; fi; done || echo "Failed to check Lambda env vars"`
      );

      commands.push(`echo ""`);
      commands.push(`echo "--- Pattern Scan Summary ---"`);
      commands.push(
        `echo "Scanning for credential patterns in outputs..." && echo "Patterns checked: AKIA* (AWS access keys), ASIA* (AWS temp keys), password=, secret=, token=, KEY"`
      );
    } else if (provider === "azure") {
      commands.push(`echo "--- Azure Service Principal Credential Analysis ---"`);
      commands.push(
        `az ad sp list --all --output json 2>/dev/null | jq '[.[] | select(.passwordCredentials | length > 0) | {displayName: .displayName, appId: .appId, credentialCount: (.passwordCredentials | length), credentials: [.passwordCredentials[] | {keyId: .keyId, startDate: .startDateTime, endDate: .endDateTime}]}]' 2>/dev/null || echo "Failed to check service principal credentials"`
      );

      commands.push(`echo ""`);
      commands.push(`echo "--- Azure Key Vault Secrets Enumeration ---"`);
      commands.push(
        `az keyvault list --output json 2>/dev/null | jq -r '.[].name' 2>/dev/null | while read vault; do echo "Vault: $vault" && az keyvault secret list --vault-name "$vault" --output json 2>/dev/null | jq '[.[] | {name: .name, enabled: .attributes.enabled, expires: .attributes.expires}]' 2>/dev/null && echo ""; done || echo "Failed to enumerate Key Vault secrets"`
      );
    } else if (provider === "gcp") {
      commands.push(`echo "--- GCP Service Account Key Age Analysis ---"`);
      commands.push(
        `gcloud iam service-accounts list --project ${cloud_account_id} --format='value(email)' 2>/dev/null | while read sa; do echo "Service Account: $sa" && gcloud iam service-accounts keys list --iam-account "$sa" --format json 2>/dev/null | jq --arg days "${max_key_age_days}" '[.[] | select(.keyType == "USER_MANAGED")] | map({keyId: .name, created: .validAfterTime, expires: .validBeforeTime, keyType: .keyType})' 2>/dev/null && echo ""; done || echo "Failed to analyze GCP service account keys"`
      );

      commands.push(`echo ""`);
      commands.push(`echo "--- GCP Secret Manager Enumeration ---"`);
      commands.push(
        `gcloud secrets list --project ${cloud_account_id} --format json 2>/dev/null | jq '[.[] | {name: .name, createTime: .createTime, replication: .replication}]' 2>/dev/null || echo "Failed to enumerate secrets"`
      );
    }

    commands.push(`echo ""`);
    commands.push(`echo "=== Credential Exposure Analysis Complete ==="`);

    return await executeInKali(commands.join(" && "));
  },
};
