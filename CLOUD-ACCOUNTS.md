# Cloud Accounts — Setup Guide

This guide walks through connecting a cloud account to Maestro so the
desktop app can run read-only cloud red team assessments against it.
Covers AWS, Azure, GCP, and Kubernetes — each provider supports
multiple authentication methods so you can match your existing access
posture.

> **Status note.** As of v0.1.84 the **credential probe** is live —
> click **Verify connection** in the Add Cloud Account dialog before
> saving and Maestro will run a non-mutating test call inside the Kali
> container to confirm the credential resolves. The Add Account button
> stays disabled until the probe passes. **Service / region
> auto-discovery** (auto-populating `services_in_scope` from what the
> credential can reach) ships in a later release.

---

## Table of Contents

1. [Why connect a cloud account](#why-connect-a-cloud-account)
2. [Before you start](#before-you-start)
3. [The Add Cloud Account form](#the-add-cloud-account-form)
4. [AWS](#aws)
   - [Method 1 — AWS CLI Profile](#aws-method-1--aws-cli-profile)
   - [Method 2 — Assume Role (recommended)](#aws-method-2--assume-role-recommended)
   - [Method 3 — Access Keys](#aws-method-3--access-keys)
5. [Azure](#azure)
   - [Method 1 — Azure CLI (`az login`)](#azure-method-1--azure-cli-az-login)
   - [Method 2 — Service Principal](#azure-method-2--service-principal)
   - [Method 3 — Managed Identity](#azure-method-3--managed-identity)
6. [GCP](#gcp)
   - [Method 1 — Application Default Credentials](#gcp-method-1--application-default-credentials)
   - [Method 2 — Service Account JSON](#gcp-method-2--service-account-json)
7. [Kubernetes](#kubernetes)
   - [Method 1 — Kubeconfig file](#k8s-method-1--kubeconfig-file)
   - [Method 2 — In-cluster service account](#k8s-method-2--in-cluster-service-account)
8. [Minimum permissions reference](#minimum-permissions-reference)
9. [What the credential probe will check](#what-the-credential-probe-will-check)
10. [Troubleshooting](#troubleshooting)
11. [Security model](#security-model)

---

## Why connect a cloud account

A connected cloud account lets Maestro:

- **Enumerate cloud resources** — buckets, lambdas, IAM principals,
  RDS instances, K8s workloads, secret stores, etc.
- **Analyze IAM** — find over-privileged roles, public buckets,
  cross-account trust policies that shouldn't exist.
- **Test exploitation paths** — non-destructive probes that *prove*
  whether a misconfiguration is reachable (e.g. forging a JWT against
  an exposed Lambda URL, or assuming a chained role).
- **Map attack chains** — combine cloud findings with web/API findings
  from the same assessment to surface "this S3 bucket is reachable from
  that Lambda is reachable from that public endpoint" chains.

**Maestro never performs destructive actions.** It never writes,
deletes, or grants. It never reads secret values (only secret
*metadata*: who can access what). See [Security model](#security-model)
below.

---

## Before you start

You'll need three things:

1. **Maestro v0.1.82 or later.** Older builds have the single-pick
   "Cloud" tile but not the auth-method-driven form.
2. **A credential** for the cloud you want to test. See the per-provider
   sections below — different providers expect different credential
   shapes.
3. **Authorization to test the account.** Maestro is built for red team
   work, but the work still has to be legal. Don't connect anyone
   else's cloud.

Open the form: navigate to **Config → Cloud Accounts → Add Account**.
The form fields you'll see depend on Provider and Authentication Method.

---

## The Add Cloud Account form

Every cloud account has these top-level fields regardless of provider:

| Field | Required | What it's for |
|---|---|---|
| **Provider** | Yes | AWS / Azure / GCP. Switches the rest of the form. |
| **Account ID** | Yes | A name *you* pick (e.g. `aws-staging`, `azure-dev-eu`). Maestro uses this in scope rules and reports. Not the cloud's account number. |
| **AWS Account Number** / **Subscription ID** / **Project ID** | Yes | The cloud's own identifier — `123456789012` for AWS, GUID for Azure, project string for GCP. |
| **Authentication Method** | Yes | Which credential shape Maestro will use. Drives the field block below. |
| **Notes** | No | Free text. Useful for "owner: platform team" or "expires 2026-09-01". |

Kubernetes clusters live in a separate **K8s Clusters** section on the
same page with the same form pattern.

---

## AWS

Maestro supports three AWS authentication methods. The recommended one
for shared environments is **Assume Role**, because the role lives in
the target account, the secret (external ID) is short-lived to rotate,
and CloudTrail records every Maestro action as its own principal.

### AWS Method 1 — AWS CLI Profile

Use when you already have an `aws sso login` session or a profile in
`~/.aws/credentials` that grants read-only access.

**Field on the form:**

- **AWS Profile Name** — the profile string from `~/.aws/credentials`
  or `~/.aws/config`, e.g. `default` or `groovy-staging-readonly`.

**How Maestro uses it:** sets `AWS_PROFILE=<value>` in the Kali
container before running tools. Any SDK calls inherit credentials from
the profile.

**Caveat:** if the profile uses SSO, you'll need to re-run
`aws sso login` whenever the session expires. The probe (next release)
will catch expired sessions before saving.

### AWS Method 2 — Assume Role (recommended)

Use when you can provision an IAM role in the target account and grant
yourself permission to assume it. This is the production-grade path.

**Fields on the form:**

- **Role ARN** — full ARN, e.g.
  `arn:aws:iam::123456789012:role/MaestroSecurityAudit`
- **External ID** *(optional but recommended)* — shared secret enforced
  by the role's trust policy.

**Minimum role setup** (copy-paste into Terraform / CloudFormation):

Trust policy — controls *who* can assume:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "AWS": "arn:aws:iam::<YOUR_AUTH_ACCOUNT>:user/<YOUR_USER>"
    },
    "Action": "sts:AssumeRole",
    "Condition": {
      "StringEquals": { "sts:ExternalId": "<RANDOM_16_CHAR_STRING>" }
    }
  }]
}
```

Attached policies — what the role *can do once assumed*:

| Policy | Why |
|---|---|
| `arn:aws:iam::aws:policy/SecurityAudit` (AWS-managed) | Broad read-only baseline across most services |
| `MaestroReadOnlyAddendum` (inline, see below) | Lambda source reads, Secrets Manager metadata, S3 bucket policies, workflow enumeration |

Addendum inline policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "LambdaSourceReads",
      "Effect": "Allow",
      "Action": [
        "lambda:GetFunction",
        "lambda:GetFunctionCodeSigningConfig",
        "lambda:GetLayerVersion",
        "lambda:ListAliases"
      ],
      "Resource": "*"
    },
    {
      "Sid": "SecretsMetadata",
      "Effect": "Allow",
      "Action": [
        "secretsmanager:ListSecrets",
        "secretsmanager:DescribeSecret",
        "secretsmanager:GetResourcePolicy"
      ],
      "Resource": "*"
    },
    {
      "Sid": "S3PolicyReads",
      "Effect": "Allow",
      "Action": [
        "s3:GetBucketPolicy",
        "s3:GetBucketPolicyStatus",
        "s3:GetBucketPublicAccessBlock",
        "s3:GetAccountPublicAccessBlock"
      ],
      "Resource": "*"
    },
    {
      "Sid": "WorkflowEnumeration",
      "Effect": "Allow",
      "Action": [
        "states:ListStateMachines",
        "states:DescribeStateMachine",
        "events:ListRules",
        "events:DescribeRule",
        "events:ListTargetsByRule"
      ],
      "Resource": "*"
    }
  ]
}
```

Note: `secretsmanager:GetSecretValue` is **intentionally not granted**.
Maestro reads which secrets *exist* and who can access them, never the
secret material itself.

> **Reference Terraform**: this exact role + trust policy + addendum
> is published at
> `kali-mcp-pentest-infra/infra/terraform/customer-cloud-assessment/`.
> Fork the directory into your own IaC repo, swap the backend block to
> your state bucket, fill in the tfvars, and apply. Outputs map
> directly to the form fields above.

### AWS Method 3 — Access Keys

Use when you can't provision a role (third-party account, legacy IAM
user, etc.). **Least preferred** because long-lived keys hang around
forever once issued.

**Fields on the form:**

- **Access Key ID** — `AKIA...` (20 chars, public half)
- **Secret Access Key** — 40-char secret. Stored locally; never sent
  off your machine.

**Recommended:** attach `SecurityAudit` + the addendum above to the
IAM user directly. Same scope, just a different credential shape.

---

## Azure

### Azure Method 1 — Azure CLI (`az login`)

Use when you have an existing `az login` session.

**Fields on the form:** none beyond Subscription ID. Maestro shells
out to the `az` CLI inside the Kali container, which will use the
authenticated session.

**Caveat:** the `az login` session must be active inside the container,
not just on your host. Run `az login --use-device-code` from the
Maestro terminal tab once before launching an assessment.

### Azure Method 2 — Service Principal

Use when you can register an Azure AD application. Production-grade
shared-environment path.

**Fields on the form:**

- **Tenant ID** — your Azure AD tenant GUID
- **Client ID** — the App Registration's Application (client) ID
- **Client Secret** — the App Registration's secret

**Minimum role assignment:**

| Built-in role | Why |
|---|---|
| `Reader` (subscription scope) | Read every resource property |
| `Security Reader` (subscription scope) | Defender / Sentinel findings |
| `Key Vault Reader` (per-Key Vault scope) | Key Vault metadata + access policies. Vault values are not granted. |

Custom permissions if you'd rather not use built-in roles: see
[Minimum permissions reference](#minimum-permissions-reference).

### Azure Method 3 — Managed Identity

Use when Maestro runs *inside* Azure (a test VM, App Service, etc.)
that has a system-assigned or user-assigned identity. Rare for the
desktop app but supported for parity.

**Fields on the form:** none. Maestro uses
`DefaultAzureCredential()` which picks up the identity automatically.

**Setup:** assign the same built-in roles as Method 2 to the managed
identity instead of a service principal.

---

## GCP

### GCP Method 1 — Application Default Credentials

Use after running `gcloud auth application-default login` inside the
Kali container.

**Fields on the form:** Project ID only.

**Caveat:** ADC tokens have a short lifetime. Refresh by re-running
`gcloud auth application-default login` in the Maestro terminal tab
when you start to see 401s.

### GCP Method 2 — Service Account JSON

Use when you can create a service account with read-only roles. The
production path.

**Fields on the form:**

- **Service Account JSON** — paste the full key file contents. Looks
  like:
  ```json
  {
    "type": "service_account",
    "project_id": "groovy-prod",
    "private_key_id": "...",
    "private_key": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n",
    "client_email": "maestro-audit@groovy-prod.iam.gserviceaccount.com",
    ...
  }
  ```

**Minimum role grants on the service account:**

| Role | Why |
|---|---|
| `roles/iam.securityReviewer` | IAM policy enumeration |
| `roles/cloudasset.viewer` | Cross-service asset inventory |
| `roles/secretmanager.viewer` | Secret metadata (not values) |
| `roles/logging.viewer` | Audit log read |
| `roles/compute.viewer` | Compute / network metadata |
| `roles/storage.objectViewer` (optional) | Bucket object listing — grant only if you want object-level scanning |

**Do not grant** `roles/secretmanager.secretAccessor` or
`roles/owner` / `roles/editor`. Maestro doesn't need them.

---

## Kubernetes

K8s clusters configure separately from cloud accounts (different page
section, same dialog pattern).

### K8s Method 1 — Kubeconfig file

Use when you have a kubeconfig file pointing at the target cluster.

**Fields on the form:**

- **Kubeconfig Path** — host path to the file, e.g. `~/.kube/config`.
  Defaults to `~/.kube/config` if blank.

**Minimum RBAC:** create a `ClusterRole` granting `get`/`list`/`watch`
on the resources Maestro reads, plus a `ClusterRoleBinding` to the
service account or user the kubeconfig authenticates as.

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: maestro-audit
rules:
  - apiGroups: ["", "apps", "batch", "networking.k8s.io", "rbac.authorization.k8s.io"]
    resources: ["*"]
    verbs: ["get", "list", "watch"]
  - apiGroups: ["policy"]
    resources: ["podsecuritypolicies"]
    verbs: ["get", "list", "watch"]
```

(`secrets` *are* in the `""` apiGroup, so this binding lets Maestro
list and inspect them. Secret *values* are read; this is intentional
on K8s because secrets routinely contain misconfig'd values worth
flagging — and there's no equivalent of cloud "metadata only" mode.
If you'd rather Maestro skip secrets entirely, omit `secrets` from the
binding by adjusting the rule.)

### K8s Method 2 — In-cluster service account

Use when Maestro itself runs as a pod inside the target cluster.

**Fields on the form:** none.

**Setup:** create the same `ClusterRole` as Method 1, bind to the
service account assigned to Maestro's pod.

---

## Minimum permissions reference

A compressed view of the smallest set that lets Maestro do useful work
per provider. Use this when you can't grant a built-in role.

| Provider | Method | Floor |
|---|---|---|
| AWS | any | `SecurityAudit` managed policy + addendum (see above) |
| Azure | any | `Reader` + `Security Reader` on the subscription |
| GCP | any | `iam.securityReviewer` + `cloudasset.viewer` + `secretmanager.viewer` |
| K8s | any | ClusterRole granting `get`/`list`/`watch` on `*` |

You can scope down further (per-region, per-resource-group, per-
namespace) — Maestro will report which checks were blocked and you can
loosen as needed.

---

## What the credential probe checks

Live as of v0.1.84. When you click **Verify connection** on the form,
Maestro runs a single non-mutating call inside the Kali container
appropriate to the provider + auth method:

| Provider | Method | Probe call |
|---|---|---|
| AWS | profile | `aws sts get-caller-identity --profile <name>` |
| AWS | access_key | `aws sts get-caller-identity` with env vars set |
| AWS | assume_role | `aws sts assume-role` (using the container's default credential chain as the source identity) |
| Azure | cli | `az account show` |
| Azure | service_principal | OAuth token request against `login.microsoftonline.com` |
| Azure | managed_identity | IMDS probe — only succeeds when Maestro is running inside Azure |
| GCP | adc | `gcloud auth application-default print-access-token` |
| GCP | service_account | Same, after writing the pasted JSON to a tempfile via `GOOGLE_APPLICATION_CREDENTIALS` |

**Editing any credential field after a successful verify** resets the
state and re-disables the Add Account button — a stale "ok" can't
slip a different credential through the form.

**Two cells can't be probed from the desktop** (they require Maestro
to be running inside the target environment): Azure × Managed Identity
and K8s × In-cluster. Saving these still works, with no probe gate;
you should validate them out-of-band before launching an assessment.

On success the form will show the resolved identity (account ID, ARN,
subscription, etc.) and the regions/services the credential can actually
reach. **Add Account** stays disabled until the probe returns OK.

---

## Troubleshooting

**"AccessDenied" when probing AWS Assume Role**
- Check the trust policy lists *your specific* principal ARN (the one
  from `aws sts get-caller-identity`), not the account root.
- If using SSO, the ARN you see is an `assumed-role` ARN —
  `aws_iam_role.assume_role_policy` accepts these. Don't translate it
  to the underlying user ARN.
- External ID must match exactly. Whitespace, case.

**Azure Service Principal returns 401**
- The App Registration needs the role assigned at the subscription
  scope, not just the resource group.
- After role assignment, allow ~30 seconds for Azure RBAC to
  propagate before retrying.

**GCP Service Account: "Permission iam.serviceAccountKeys.create denied"**
- You're trying to create a *new* key, not use an existing one. Use the
  Cloud Console → Service Accounts → Keys → Add Key flow once, paste
  the JSON into the form, and never regenerate unless rotating.

**Kubeconfig path resolves to nothing inside the container**
- Maestro mounts `~/.kube/` from your host into the container by
  default. If you've put kubeconfig somewhere else, give the *host*
  path, not a container path.

---

## Security model

Maestro's cloud testing is **strictly read-only**. The recommended IAM
configurations omit every write or destructive action. Specifically:

- **No mutating actions are ever called.** No `Put*`, `Create*`,
  `Delete*`, `Update*`. The credential probe is `GetCallerIdentity` /
  equivalent — read-only by definition.
- **No secret *values* are read on AWS or GCP.** Maestro reads
  `secretsmanager:DescribeSecret` and `GetResourcePolicy` but
  intentionally not `GetSecretValue`. Same for GCP — `viewer` not
  `accessor`.
- **All credentials live locally.** Profile names, access keys, service
  principal secrets, service account JSON — none of these leave your
  machine. They're stored in `scope.yml` (and, in a future release,
  promoted to the macOS Keychain).
- **Every API call is logged.** The MCP server records every tool
  invocation including the provider and method. Audit your assessment
  history at `~/.kali-mcp-pentest/` / via the Maestro UI.

If anything in this guide doesn't match what Maestro is actually doing,
that's a bug — file it.
