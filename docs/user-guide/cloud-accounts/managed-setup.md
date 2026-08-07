# Managed Setup (Teams & Multiple Accounts)

How an infrastructure owner makes the per-org Maestro backend broker read-only credentials for one or several AWS accounts — so operators run cloud assessments with **zero AWS keys on their laptops**.

> [!NOTE] At a glance
> - **Who this is for:** the person who owns your Maestro deployment (the `customer-deploy` Terraform stack). Day-to-day operators do nothing — they just launch assessments.
> - **One-time setup:** wire two Terraform stacks together so the backend's task role can assume a read-only role in each account you want assessed.
> - **Two shapes:** *single account* (assess the account Maestro runs in) and *cross-account* (deploy once, assess a sibling account in the same org). The second is the multi-environment case.

> [!TIP] New here?
> Read [Cloud Accounts overview](./overview.md) first for the managed-vs-self-managed decision. This page is the hands-on setup for the **managed** model.

## How managed mode works

When an operator launches a cloud assessment, the desktop asks your backend for short-lived credentials. The backend — running in your AWS account and already knowing the user's org from their login — assumes a read-only `MaestroSecurityAudit` role using its **ECS task role**, then hands the temporary session to the assessment. Tenant isolation is enforced in the backend (AWS IAM can't gate role assumption on an org claim), and every assumption is attributed to the real user in CloudTrail as `maestro-<email>-<org>-…`.

The setup is just establishing that trust:

- The **assessment role** (`MaestroSecurityAudit`) in the *target* account trusts your backend's task role.
- Your **deployment** grants its task role `sts:AssumeRole` on that assessment role, and records it as the default broker role.

Both stacks live in the infrastructure repo:

| Stack | Where you apply it | What it does |
| --- | --- | --- |
| `customer-deploy` | The account Maestro **runs in** | Deploys the backend; outputs `task_role_arn`. |
| `customer-cloud-assessment` | Each account you want **assessed** | Creates `MaestroSecurityAudit` and its trust policy. |

## Before you start

1. **`customer-deploy` is already applied** in your deployment account and the backend is healthy. (See the customer deployment guide.) You'll need its `task_role_arn` output — it follows the predictable form `arn:aws:iam::<deploy-account-id>:role/pentest-<environment>-ecs-task` (`environment` defaults to `prod`).
2. **Terraform with IAM-admin permissions** in every account you'll create the assessment role in.
3. Decide your topology: are you assessing the **same** account Maestro runs in, or a **separate** account? Pick the matching section below.

> [!IMPORTANT] The assessment role is strictly read-only
> `MaestroSecurityAudit` attaches the AWS-managed `SecurityAudit` policy plus a small read-only addendum (Lambda source, secret *metadata* — never `GetSecretValue`, S3 bucket policies, Step Functions / EventBridge, CodeBuild). It grants **no** write, delete, or create permissions anywhere. The assessment tools mirror this — they default to non-mutating, with the few active probes (Lambda URL invocation, S3 public-write test, secret-value reads) opt-in — so the role and the tooling are read-only on both ends.

## Single account — Maestro assesses the account it runs in

This is the common case for an org with one AWS account.

### Step 1 — Provision the assessment role in backend mode

Apply `customer-cloud-assessment` in your account. The key choice is `trust_mode = "backend"` (the default is the legacy `assume_role` mode — you **must** set this) and pointing `backend_role_arn` at your deployment's task role.

::: tabs
::: tab Terraform
```bash
cd infra/terraform/customer-cloud-assessment/

terraform apply \
  -var 'trust_mode=backend' \
  -var "backend_role_arn=arn:aws:iam::<deploy-account-id>:role/pentest-prod-ecs-task"

# Note the role_arn output — that's your MaestroSecurityAudit ARN.
terraform output -raw role_arn
```
Backend mode is a same-account principal, so **no external ID is needed** — the trust is the task-role ARN itself.
::: tab Manual
1. **IAM → Roles → Create role → Custom trust policy.** Paste (no external ID in backend mode):
   ```json
   {
     "Version": "2012-10-17",
     "Statement": [{
       "Effect": "Allow",
       "Principal": { "AWS": "arn:aws:iam::<deploy-account-id>:role/pentest-prod-ecs-task" },
       "Action": "sts:AssumeRole"
     }]
   }
   ```
2. **Next.** Attach **SecurityAudit**.
3. **Next.** Name the role `MaestroSecurityAudit`. Create.
4. Open the role → **Add permissions → Create inline policy → JSON**, paste the `MaestroReadOnlyAddendum` JSON (see the [AWS Assume Role recipe](./aws.md)), name it `MaestroReadOnlyAddendum`.
5. Copy the role ARN from the summary page.
:::

### Step 2 — Let the backend assume it

Back in your `customer-deploy` stack, set `assessment_role_arn` to that ARN and re-apply. This grants the task role `sts:AssumeRole` on the assessment role **and** tells the backend which role to broker by default:

```hcl
# add to your customer-deploy .tfvars
assessment_role_arn = "arn:aws:iam::<deploy-account-id>:role/MaestroSecurityAudit"
```
```bash
cd infra/terraform/customer-deploy/
terraform apply
```

### Step 3 — Add the account in the desktop

Sidebar → **Config → Cloud Accounts → Add Account** → **AWS**, paste the `MaestroSecurityAudit` Role ARN, save. At assessment time, leave the **Assume from** picker on **"Maestro cloud — managed"** (the default) and launch.

## Multiple accounts — deploy in one, assess another

This is the cross-account / multi-environment case: the backend runs in account **A** (your deployment account) and assesses a separate account **B** owned by the same org. It works exactly like the single-account case, except the two stacks live in different accounts and reference each other across the account boundary.

In this example: **A = `<deploy-account-id>`** (runs the backend), **B = `<target-account-id>`** (the environment you want assessed).

### Step 1 — Provision the assessment role in account B

Apply `customer-cloud-assessment` **in account B**, trusting account A's task role:

```bash
cd infra/terraform/customer-cloud-assessment/

terraform apply \
  -var 'trust_mode=backend' \
  -var 'aws_profile=<profile-with-iam-admin-in-B>' \
  -var "backend_role_arn=arn:aws:iam::<deploy-account-id>:role/pentest-prod-ecs-task"

terraform output -raw role_arn
# -> arn:aws:iam::<target-account-id>:role/MaestroSecurityAudit
```

Cross-account `sts:AssumeRole` is fully supported — the task role lives in A, the assessment role in B, and B's trust policy simply names A's task role. (A leaked role ARN alone can't be assumed: only A's task role is trusted, and only your org's users reach the broker.)

### Step 2 — Grant the backend (account A) permission to assume it

In your `customer-deploy` stack (account A), set `assessment_role_arn` to **B's** role ARN and re-apply:

```hcl
# customer-deploy .tfvars (account A)
assessment_role_arn = "arn:aws:iam::<target-account-id>:role/MaestroSecurityAudit"
```
```bash
terraform apply
```

> [!TIP] Order doesn't matter for cross-account
> Both ARNs are predictable from their names, and AWS doesn't validate a *cross-account* principal in a trust policy — so you can apply the two stacks in either order. (For the same-account case above, apply `customer-deploy` first so the task role exists before the trust policy references it.)

### Step 3 — Add account B in the desktop

**Config → Cloud Accounts → Add Account → AWS**, friendly ID e.g. `aws-prod-b`, AWS Account Number `<target-account-id>`, paste B's `MaestroSecurityAudit` Role ARN. Leave **Assume from** on "Maestro cloud — managed".

> [!WARNING] One default broker role per deployment today
> `customer-deploy`'s `assessment_role_arn` is a single value — the deployment's task role is granted `sts:AssumeRole` on exactly **one** assessment role, which is also the default the backend brokers. That's all you need to assess **one** target account.
>
> To broker for **several** target accounts from a single deployment, the task role needs an `sts:AssumeRole` grant on **each** account's `MaestroSecurityAudit` role. The module doesn't yet take a list, so either add an extra inline policy statement to the task role for each additional account, or ask Groovy to widen `assessment_role_arn` to a list. Create one `MaestroSecurityAudit` role per target account regardless — never share a single role across accounts.

> [!CAUTION] "Verify connection" uses a different identity than the broker
> The Add Account form's **Verify connection** button assumes the role from a *local* source credential inside the Kali container — not through the backend broker. If B's role only trusts the backend task role, Verify will fail even though the real (brokered) assessment succeeds. Either skip Verify for managed roles, or temporarily add your operator identity as a second trusted principal while testing.

## Verify it end to end

The honest test is a real assessment:

1. **New Assessment → Step 1**, enable the **Cloud** tile, pick the account you added, choose regions.
2. Launch with **Assume from = "Maestro cloud — managed"**.
3. Confirm in the target account's **CloudTrail** that you see `AssumeRole` events with a session name like `maestro-<email>-<org>-…`. That's proof the broker hop worked and is attributed to the right user.

## Troubleshooting

> [!WARNING] Assessment fails with AccessDenied on AssumeRole
> In backend mode, check in this order:
> 1. **`trust_mode` isn't `backend`.** The default is `assume_role`, which expects an external ID the broker never sends. Re-apply `customer-cloud-assessment` with `-var 'trust_mode=backend'`.
> 2. **`backend_role_arn` is wrong.** It must be the deployment's `task_role_arn` output exactly — `arn:aws:iam::<deploy-account-id>:role/pentest-<environment>-ecs-task`.
> 3. **The task role lacks the grant.** `customer-deploy`'s `assessment_role_arn` must be set to the role you're assuming and re-applied, or the task role has no `sts:AssumeRole` on it.
> 4. **Cross-account:** confirm *both* ends — B's trust policy names A's task role, and A's task role is granted `sts:AssumeRole` on B's role ARN.

## Next steps

- Per-method operator recipes (self-managed SSO / keys / profile): [AWS](./aws.md)
- The managed-vs-self-managed decision and field matrix: [Overview](./overview.md)
- Deeper security model and finding shapes: `CLOUD-ACCOUNTS.md` at the repo root
