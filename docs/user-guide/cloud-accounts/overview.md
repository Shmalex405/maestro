# Overview

How to connect an AWS, Azure, GCP, or Kubernetes target to Maestro so the cloud assessment phase has something to test.

> [!NOTE] At a glance
> - **What it unlocks:** the **Cloud** capability on a new assessment — resource enumeration, IAM/policy analysis, and non-destructive exploitation paths.
> - **Two ways to authenticate:** *managed* (the backend brokers credentials — nothing on your laptop) or *self-managed* (your own keys/profile/SSO). **Most teams want managed.**
> - **Always read-only:** Maestro never writes, deletes, or reads secret *material* — only secret *metadata*.

## Pick your provider

Once you've read the decision and method matrix below, jump to your provider's recipes:

- [AWS](./aws.md) — CLI profile, assume-role, or access keys
- [Azure](./azure.md) — Azure CLI, service principal, or managed identity
- [GCP](./gcp.md) — application default credentials or service account key
- [Kubernetes](./kubernetes.md) — kubeconfig or in-cluster

## What connecting an account gives you

With a cloud account configured, Maestro can:

- **Enumerate** cloud resources — buckets, lambdas, IAM principals, secrets, K8s workloads.
- **Analyze** IAM and resource policies for public access, over-privilege, and cross-account drift.
- **Test** exploitation paths against findings — non-destructive only.
- **Chain** cloud findings with web/API findings from the same assessment (*"this endpoint reaches this Lambda reaches this S3 bucket"*).

> [!IMPORTANT] The connection is strictly read-only — enforced in two layers
> Maestro never writes, deletes, creates, or reads secret material — only secret *metadata* (who can access what). This is enforced twice over:
> 1. **The role** (`MaestroSecurityAudit`) grants only read permissions — no `PutObject`, `InvokeFunction`, `GetSecretValue`, or `AssumeRole`-out. Any authenticated mutating call fails closed with `AccessDenied`.
> 2. **The tools** default to non-mutating. The few *active* probes — invoking a Lambda function URL, the S3 public-write test, reading secret *values* — are **opt-in** (off by default). This second layer matters because some probes hit a resource's own *public* endpoint (a Lambda function URL, a world-writable bucket) rather than an IAM-gated API, so no role policy can stop them — the read-only tool default is the only control, which is why it ships off.

## Step 1 — Choose how Maestro gets credentials

There are two models. Read this before you fill in the form — it decides which fields you'll see.

### Option A — Maestro cloud, managed *(recommended, the default)*

If your team runs the standard Maestro deployment (a per-org backend in your own AWS account), cloud assessments authenticate **through that backend**. You put **no AWS keys, profiles, or SSO sessions on the operator's laptop at all.**

When you launch a cloud assessment, the desktop asks your backend for short-lived credentials. The backend already knows your org (it validated your login), so it assumes the read-only assessment role using its **own task role** and hands the temporary session to the assessment.

| Benefit | Why it matters |
| --- | --- |
| **No AWS creds on the laptop** | The machine only ever holds your Maestro login token. |
| **Tenant-isolated in the backend** | The backend brokers only for *your* org (enforced server-side, since AWS IAM can't gate role assumption on an org claim). |
| **Real per-user audit** | Every assumption shows up in CloudTrail as `maestro-<your-email>-<org>-…`. |

> [!TIP] To use managed mode, do nothing special
> Just leave the assessment's **Assume from** picker on **"Maestro cloud — managed"** (the default) and launch.

> [!NOTE] One-time infrastructure setup
> Whoever runs your Maestro infrastructure makes the assessment role trust your backend: in the `customer-cloud-assessment` Terraform stack, set `trust_mode = "backend"` and point `backend_role_arn` at your deployment's backend task role. (The `customer-deploy` stack outputs it as `task_role_arn`; set `assessment_role_arn` there to grant the backend `sts:AssumeRole`.) The [Managed Setup walkthrough](./managed-setup.md) covers this step by step — for both a single account and the **cross-account** case where Maestro runs in one account and assesses a sibling account in the same org.

### Option B — Self-managed credentials *(alternative)*

If you're not on the managed deployment — or you want an operator to use their own identity — configure a **source credential** directly: AWS SSO, access keys, or a CLI profile (or the Azure / GCP / K8s equivalents). These live in your OS keychain, and Maestro assumes the target role *from* them. The per-provider recipes are the cookbook for those methods.

## Step 2 — Add the account

Sidebar → **Config** → **Cloud Accounts** → **Add Account**. The form has two layers:

1. **Provider** (AWS / Azure / GCP / K8s) and a **friendly Account ID** you pick — e.g. `aws-prod`, `azure-eu-staging`. The friendly ID is what shows up in scope rules and reports, *not* the cloud's own account number.
2. **Authentication Method** — switches the form to show only the fields that method needs.

> [!WARNING] Switching provider clears the form
> Changing the provider wipes every credential field by design, so a stale AWS key can't ride into an Azure config. Always pick the auth method *after* choosing the provider.

## Step 3 — Pick your method (quick-reference matrix)

Find the row that matches how you already grant read access elsewhere, then jump to its recipe on the linked provider page.

| Provider | Method | Use when | Fields you fill in |
| --- | --- | --- | --- |
| [AWS](./aws.md) | **Maestro cloud — managed** *(recommended, default)* | Standard Maestro deployment (per-org backend). No laptop creds. | Nothing — the backend brokers it. One-time `trust_mode=backend` setup on the role. |
| [AWS](./aws.md) | Assume Role *(self-managed)* | No per-org backend; an operator assumes the role from their own identity. | Role ARN + External ID. Role must be `trust_mode=assume_role`, and you must switch **Assume from** off "managed". |
| [AWS](./aws.md) | CLI Profile *(self-managed)* | You already have `aws sso login` or `~/.aws/credentials`. | Profile name. |
| [AWS](./aws.md) | Access Keys *(self-managed)* | Long-lived IAM user credentials only. | Access Key ID + Secret Access Key. |
| [Azure](./azure.md) | Azure CLI | Active `az login` session. | Subscription ID. |
| [Azure](./azure.md) | Service Principal | You can register an Azure AD application. | Tenant ID + Client ID + Client Secret. |
| [Azure](./azure.md) | Managed Identity | Maestro runs inside Azure. | Subscription ID. |
| [GCP](./gcp.md) | ADC | Recent `gcloud auth application-default login`. | Project ID. |
| [GCP](./gcp.md) | Service Account Key | You have or can create a JSON key. | Paste full JSON. |
| [Kubernetes](./kubernetes.md) | Kubeconfig | Standard case. | Kubeconfig path (defaults to `~/.kube/config`). |
| [Kubernetes](./kubernetes.md) | In-cluster | Maestro runs as a pod in the target cluster. | None. |

> [!WARNING] The role's trust mode must match the assessment's "Assume from" picker
> This is the #1 cause of `AccessDenied` at launch. The two must agree:
> - **Managed** ("Assume from" → *Maestro cloud — managed*, the default) needs a role built with `trust_mode = "backend"` — it trusts your deployment's backend task role. This is the default of the `customer-cloud-assessment` stack.
> - **Self-managed** (Assume Role / CLI Profile / Access Keys) needs `trust_mode = "assume_role"` — it trusts an operator principal + external ID, and you must switch **Assume from** off "managed" to your source credential.
>
> A role built for one mode cannot be assumed in the other. If you set up an Assume-Role (external-ID) role but leave the picker on "managed", the backend broker can't assume it and the run fails to authenticate.

> [!TIP] How to read each recipe
> Each recipe has two tabs: follow **Terraform** if you manage infra as code, or **Manual** if you'd rather click through the console.

## Step 4 — Follow your recipe

Pick the recipe matching your matrix row, on the [AWS](./aws.md), [Azure](./azure.md), [GCP](./gcp.md), or [Kubernetes](./kubernetes.md) page. The AWS recipes share a read-only permission set (`SecurityAudit` plus a small addendum); the Azure/GCP/K8s recipes grant equivalent read-only roles.

### Common Terraform scaffold

Every Terraform snippet in the provider recipes assumes the provider and required-providers blocks are already set in a parent `main.tf`. If you're starting fresh, paste this once at the top of your file:

```hcl
terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws        = { source = "hashicorp/aws",       version = "~> 5.0" }
    azurerm    = { source = "hashicorp/azurerm",   version = "~> 4.0" }
    azuread    = { source = "hashicorp/azuread",   version = "~> 3.0" }
    google     = { source = "hashicorp/google",    version = "~> 6.0" }
    kubernetes = { source = "hashicorp/kubernetes", version = "~> 2.0" }
  }
}
```

(Drop the providers you don't need.)

## Step 5 — Verify the credential before saving

> [!TIP] Click "Verify connection" first (v0.1.84+)
> Once the credential fields are filled, hit **Verify connection**. Maestro runs a single non-mutating call inside the Kali container to confirm the credential actually works — far better than discovering a typo mid-assessment.

The probe call depends on the provider + method:

| Provider | Method | Probe call |
| --- | --- | --- |
| AWS | profile | `aws sts get-caller-identity --profile <name>` |
| AWS | access_key | `aws sts get-caller-identity` with env vars |
| AWS | assume_role | `aws sts assume-role …` using the container's default credential chain as the source |
| Azure | cli | `az account show` |
| Azure | service_principal | OAuth2 token request to `login.microsoftonline.com/{tenant}/oauth2/v2.0/token` |
| Azure | managed_identity | IMDS probe at `169.254.169.254` (only succeeds inside Azure) |
| GCP | adc | `gcloud auth application-default print-access-token` |
| GCP | service_account | Same, after writing the pasted JSON to a tempfile via `GOOGLE_APPLICATION_CREDENTIALS` |

On success, the form shows the resolved identity (STS ARN for AWS, subscription + tenant for Azure, service-account email for GCP) and the **Add Account** button enables. On failure, the trimmed CLI error appears inline.

> [!NOTE] A successful verify can't be bypassed
> Editing any credential field after a green "ok" resets the state to idle and disables save again — so a stale success can't slip a different credential through.

> [!WARNING] Two methods can't be probed from the desktop
> **Azure × Managed Identity** and **K8s × In-cluster** both require Maestro to run *inside* the target environment. They return "credential will be tested at assessment runtime" and save without a probe — validate them out-of-band before your first run.

## Step 6 — Use it in an assessment

Once saved, the account appears in the table at the top of the page with its provider, friendly ID, auth method, and a **Scope** column reading "Auto-discover" (scope discovery happens at assessment runtime).

Now the **Cloud** tile in **New Assessment → Step 1** is selectable. Pick it (or combine with Web / API), and Step 2 lets you choose which account and which regions to scope the assessment to.

## Where the deeper reference lives

| What you need | Where it lives |
| --- | --- |
| Set up managed mode for a team — single or multiple accounts | [Managed Setup walkthrough](./managed-setup.md) |
| Stand-alone Terraform stack for the AWS Assume Role recipe | `kali-mcp-pentest-infra/infra/terraform/customer-cloud-assessment/` |
| Per-provider security model, evidence standards, finding shapes | `CLOUD-ACCOUNTS.md` at the repo root |
| Architecture: where credentials live in transit and at rest | The [Architecture doc page](../architecture.md) |

## Troubleshooting

**Form won't let me save — auth method field is empty.** Switching provider clears every credential field by design (so a stale AWS key doesn't ride into an Azure config). Re-pick the auth method after changing provider.
