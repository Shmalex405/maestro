# AWS

Recipes for connecting an AWS account — CLI profile, assume-role, or access keys.

> [!NOTE] At a glance
> - **Most teams want managed, not these recipes.** Managed mode is the default and needs no per-operator credentials — see [Managed Setup](./managed-setup.md). The recipes on this page are the **self-managed** fallback (an operator assumes the role from their own identity).
> - **Three self-managed methods:** CLI Profile, Assume Role *(best of the three)*, and Access Keys.
> - **Shared permission set:** all three attach `SecurityAudit` plus a small read-only addendum.
> - **These require `trust_mode = "assume_role"` on the role AND switching the assessment's "Assume from" picker off "Maestro cloud — managed".** A self-managed (external-ID) role cannot be assumed by the managed broker — match the role's trust mode to the picker.

> [!TIP] New here?
> Start with the [Cloud Accounts overview](./overview.md) for the managed-vs-self-managed decision and the method matrix. Setting up **managed mode** for your org — including the cross-account case where Maestro runs in one account and assesses another — is in [Managed Setup](./managed-setup.md).

> [!NOTE] The permission set below is intentionally read-only
> `SecurityAudit` + `MaestroReadOnlyAddendum` grant only reads — no `PutObject`, `InvokeFunction`, `GetSecretValue`, or `AssumeRole`-out. This pairs with the assessment tools, which default to non-mutating: the active probes (Lambda URL invocation, the S3 public-write test, secret-*value* reads) are opt-in. So even if a probe is enabled, this role denies the authenticated calls it would make — and the tool default is what holds back the probes that target a resource's *public* endpoint, which no IAM policy can gate. Do **not** widen this policy to "make a test pass": a denied write is the role working as designed.

### AWS — CLI Profile

A CLI profile is a *local* config in your shell — there's nothing to provision in AWS itself unless you also need to grant the user/role the profile authenticates as the right read permissions.

::: tabs
::: tab Terraform
The profile itself is a `~/.aws/config` / `~/.aws/credentials` entry, not a Terraform resource. Use Terraform here to provision the IAM user (or attach to an existing one) that the profile authenticates as:

```hcl
resource "aws_iam_user" "maestro_operator" {
  name = "maestro-operator"
  tags = { Purpose = "maestro-cloud-assessment" }
}

resource "aws_iam_user_policy_attachment" "maestro_security_audit" {
  user       = aws_iam_user.maestro_operator.name
  policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"
}

# Same MaestroReadOnlyAddendum as the Assume Role recipe below.
resource "aws_iam_user_policy" "maestro_read_only_addendum" {
  name = "MaestroReadOnlyAddendum"
  user = aws_iam_user.maestro_operator.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = ["lambda:GetFunction", "lambda:GetFunctionCodeSigningConfig", "lambda:GetLayerVersion", "lambda:ListAliases"], Resource = "*" },
      { Effect = "Allow", Action = ["secretsmanager:GetResourcePolicy", "secretsmanager:ListSecrets", "secretsmanager:DescribeSecret"], Resource = "*" },
      { Effect = "Allow", Action = ["s3:GetBucketPolicy", "s3:GetBucketPolicyStatus", "s3:GetBucketPublicAccessBlock", "s3:GetAccountPublicAccessBlock"], Resource = "*" },
      { Effect = "Allow", Action = ["states:ListStateMachines", "states:DescribeStateMachine", "events:ListRules", "events:DescribeRule"], Resource = "*" },
    ]
  })
}
```

The user's access keys still need to be generated separately (see the Access Keys recipe) and configured in your local `~/.aws/credentials` under a profile name. Maestro then reads from that profile.

::: tab Manual
**If you already use AWS SSO** (typical for org accounts):

```bash
aws configure sso
# SSO start URL: https://your-org.awsapps.com/start
# SSO Region: us-west-2
# Pick the account + permission set (must include SecurityAudit-level read)
# Profile name: maestro-prod    ← this is what you paste into the form
aws sso login --profile maestro-prod
```

**If you use long-lived IAM user keys:**

```bash
aws configure --profile maestro-prod
# AWS Access Key ID: AKIA...
# AWS Secret Access Key: ...
# Default region: us-west-2
# Default output: json
```

In the Add Cloud Account form, paste `maestro-prod` (or whatever profile name you chose) into **AWS Profile Name**.
:::

---

### AWS — Assume Role *(best self-managed option)*

The strongest self-managed path: a role in the target AWS account, a trust policy that gates assumption on your principal ARN + an external ID, attached to `SecurityAudit` plus a curated read-only addendum. (For the default managed experience, use [Managed Setup](./managed-setup.md) instead — this recipe is `trust_mode = "assume_role"` and requires switching **Assume from** off "managed".)

This is the recipe published as a standalone Terraform stack at `kali-mcp-pentest-infra/infra/terraform/customer-cloud-assessment/`. The Terraform tab below shows the same thing condensed.

::: tabs
::: tab Terraform
```hcl
variable "assumer_principal_arn" {
  description = "ARN of the IAM principal Maestro authenticates as. Get from `aws sts get-caller-identity`."
  type        = string
}

variable "external_id" {
  description = "Shared secret; at least 16 chars. Generate with `openssl rand -hex 24`."
  type        = string
  sensitive   = true
}

data "aws_iam_policy_document" "trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "AWS"
      identifiers = [var.assumer_principal_arn]
    }
    condition {
      test     = "StringEquals"
      variable = "sts:ExternalId"
      values   = [var.external_id]
    }
  }
}

resource "aws_iam_role" "maestro_audit" {
  name                 = "MaestroSecurityAudit"
  assume_role_policy   = data.aws_iam_policy_document.trust.json
  max_session_duration = 3600
}

resource "aws_iam_role_policy_attachment" "security_audit" {
  role       = aws_iam_role.maestro_audit.name
  policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"
}

resource "aws_iam_role_policy" "read_only_addendum" {
  name = "MaestroReadOnlyAddendum"
  role = aws_iam_role.maestro_audit.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Sid = "LambdaSourceReads", Effect = "Allow", Action = ["lambda:GetFunction", "lambda:GetFunctionCodeSigningConfig", "lambda:GetLayerVersion", "lambda:ListAliases"], Resource = "*" },
      { Sid = "SecretsMetadata",   Effect = "Allow", Action = ["secretsmanager:GetResourcePolicy", "secretsmanager:ListSecrets", "secretsmanager:DescribeSecret"], Resource = "*" },
      { Sid = "S3PolicyReads",     Effect = "Allow", Action = ["s3:GetBucketPolicy", "s3:GetBucketPolicyStatus", "s3:GetBucketPublicAccessBlock", "s3:GetAccountPublicAccessBlock"], Resource = "*" },
      { Sid = "WorkflowEnum",      Effect = "Allow", Action = ["states:ListStateMachines", "states:DescribeStateMachine", "events:ListRules", "events:DescribeRule"], Resource = "*" },
    ]
  })
}

output "role_arn"    { value = aws_iam_role.maestro_audit.arn }
output "role_name"   { value = aws_iam_role.maestro_audit.name }
```

After `terraform apply`, paste the `role_arn` output into **Role ARN** and the `external_id` you used into **External ID**.
::: tab Manual
1. Sign in to the AWS Console **in the account you want assessed**.
2. **IAM → Roles → Create role**.
3. Trusted entity type: **Custom trust policy**. Paste:
   ```json
   {
     "Version": "2012-10-17",
     "Statement": [{
       "Effect": "Allow",
       "Principal": { "AWS": "<YOUR_PRINCIPAL_ARN>" },
       "Action": "sts:AssumeRole",
       "Condition": {
         "StringEquals": { "sts:ExternalId": "<RANDOM_16_CHAR_STRING>" }
       }
     }]
   }
   ```
   Replace `<YOUR_PRINCIPAL_ARN>` with what `aws sts get-caller-identity` returns for your operator identity. Replace `<RANDOM_16_CHAR_STRING>` with `openssl rand -hex 24`.
4. **Next**. Permissions policies: search **SecurityAudit** and tick it.
5. **Next**. Role name: `MaestroSecurityAudit`. Create.
6. Open the new role → **Add permissions → Create inline policy → JSON tab**, paste the `MaestroReadOnlyAddendum` JSON (same as the Terraform tab), name it `MaestroReadOnlyAddendum`, **Create**.
7. Copy the role ARN from the role's summary page.
8. Paste the role ARN + the external ID into the form.
:::

---

### AWS — Access Keys

Last-resort path: long-lived IAM user credentials. Pick this only when role-assumption isn't possible.

::: tabs
::: tab Terraform
```hcl
resource "aws_iam_user" "maestro_operator" {
  name = "maestro-operator"
  tags = { Purpose = "maestro-cloud-assessment" }
}

resource "aws_iam_user_policy_attachment" "security_audit" {
  user       = aws_iam_user.maestro_operator.name
  policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"
}

resource "aws_iam_user_policy" "read_only_addendum" {
  name = "MaestroReadOnlyAddendum"
  user = aws_iam_user.maestro_operator.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = ["lambda:GetFunction", "lambda:GetFunctionCodeSigningConfig", "lambda:GetLayerVersion", "lambda:ListAliases"], Resource = "*" },
      { Effect = "Allow", Action = ["secretsmanager:GetResourcePolicy", "secretsmanager:ListSecrets", "secretsmanager:DescribeSecret"], Resource = "*" },
      { Effect = "Allow", Action = ["s3:GetBucketPolicy", "s3:GetBucketPolicyStatus", "s3:GetBucketPublicAccessBlock", "s3:GetAccountPublicAccessBlock"], Resource = "*" },
      { Effect = "Allow", Action = ["states:ListStateMachines", "states:DescribeStateMachine", "events:ListRules", "events:DescribeRule"], Resource = "*" },
    ]
  })
}

resource "aws_iam_access_key" "maestro_operator" {
  user = aws_iam_user.maestro_operator.name
}

output "access_key_id" {
  value = aws_iam_access_key.maestro_operator.id
}

output "secret_access_key" {
  value     = aws_iam_access_key.maestro_operator.secret
  sensitive = true
}
```

After `terraform apply`, `terraform output -raw secret_access_key` to get the secret value. Paste both into the form. **Rotate quarterly** — long-lived keys are the riskiest of the three AWS paths.
::: tab Manual
1. **IAM → Users → Create user**. Name: `maestro-operator`. Do **not** enable console access.
2. **Permissions options → Attach policies directly → SecurityAudit**, tick.
3. After the user is created, open it → **Permissions → Add permissions → Create inline policy → JSON**, paste the `MaestroReadOnlyAddendum` JSON, name it `MaestroReadOnlyAddendum`.
4. **Security credentials → Access keys → Create access key**. Use case: *Application running outside AWS*. Acknowledge the recommendation. Create.
5. Copy the **Access key ID** and **Secret access key** immediately — the secret is shown once.
6. Paste both into the form.
:::

## Troubleshooting

> [!WARNING] Saved an AWS Assume Role config but the next assessment says AccessDenied
> Three usual suspects:
> 1. Trust policy lists the wrong principal — copy the `Arn` from `aws sts get-caller-identity` verbatim. SSO callers will see an `assumed-role` ARN; that's correct.
> 2. External ID typo or whitespace.
> 3. SSO session expired — re-run `aws sso login`.
