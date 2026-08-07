# GCP

Recipes for connecting a GCP project — application default credentials or a service account key.

> [!NOTE] At a glance
> - **Two methods:** Application Default Credentials *(interactive)* and Service Account Key *(production-grade)*.
> - **Shared roles:** both grant Security Reviewer, Cloud Asset Viewer, Secret Manager Viewer, Logs Viewer, and Compute Viewer.
> - **JSON keys are sensitive** — store them safely; GCP key rotation is manual.

> [!TIP] New here?
> Start with the [Cloud Accounts overview](./overview.md) for the managed-vs-self-managed decision and the method matrix.

### GCP — Application Default Credentials

Uses ADC from `gcloud auth application-default login`. Good for interactive work; not for headless / CI.

::: tabs
::: tab Terraform
ADC tokens come from your `gcloud` session — Terraform isn't involved in minting them, but it is involved in granting your user the required roles:

```hcl
variable "project_id" { type = string }
variable "user_email" {
  description = "Email of the user whose ADC will be used by Maestro."
  type        = string
}

locals {
  required_roles = [
    "roles/iam.securityReviewer",
    "roles/cloudasset.viewer",
    "roles/secretmanager.viewer",
    "roles/logging.viewer",
    "roles/compute.viewer",
  ]
}

resource "google_project_iam_member" "maestro_user" {
  for_each = toset(local.required_roles)
  project  = var.project_id
  role     = each.value
  member   = "user:${var.user_email}"
}
```
::: tab Manual
1. Authenticate ADC:
   ```bash
   gcloud auth application-default login
   ```
2. Grant your user the read roles (admin runs this once):
   ```bash
   for role in roles/iam.securityReviewer roles/cloudasset.viewer roles/secretmanager.viewer roles/logging.viewer roles/compute.viewer; do
     gcloud projects add-iam-policy-binding <project-id> \
       --member="user:<your-email>" \
       --role="$role"
   done
   ```
3. Paste `<project-id>` into **Project ID** in the form.
:::

---

### GCP — Service Account Key

Production-grade GCP path: a dedicated service account, scoped via project IAM bindings, authenticated via a downloaded JSON key file.

::: tabs
::: tab Terraform
```hcl
variable "project_id" { type = string }

resource "google_service_account" "maestro" {
  account_id   = "maestro-audit"
  display_name = "Maestro Security Audit"
  project      = var.project_id
}

locals {
  required_roles = [
    "roles/iam.securityReviewer",
    "roles/cloudasset.viewer",
    "roles/secretmanager.viewer",
    "roles/logging.viewer",
    "roles/compute.viewer",
  ]
}

resource "google_project_iam_member" "maestro" {
  for_each = toset(local.required_roles)
  project  = var.project_id
  role     = each.value
  member   = "serviceAccount:${google_service_account.maestro.email}"
}

resource "google_service_account_key" "maestro" {
  service_account_id = google_service_account.maestro.name
  key_algorithm      = "KEY_ALG_RSA_2048"
}

output "service_account_key" {
  description = "JSON key — paste the full value into the form."
  value       = base64decode(google_service_account_key.maestro.private_key)
  sensitive   = true
}
```

`terraform output -raw service_account_key` prints the JSON. Paste the whole thing into the form's **Service Account JSON** field. **Store the key somewhere safe**; key rotation in GCP is manual.
::: tab Manual
1. **Cloud Console → IAM & Admin → Service Accounts → Create service account**.
2. Name: `maestro-audit`. Create.
3. **Grant this service account access to project** — add each role:
   - Security Reviewer
   - Cloud Asset Viewer
   - Secret Manager Viewer
   - Logs Viewer
   - Compute Viewer
4. **Done**. Open the new service account → **Keys → Add key → Create new key → JSON**. The browser downloads the JSON file.
5. Open the JSON in a text editor, copy the entire contents (including the outer `{` and `}`), paste into the form's **Service Account JSON** field.
:::

## Troubleshooting

> [!WARNING] GCP service account JSON gets rejected
> Make sure you pasted the **whole** file including the outer `{` and `}`. The `private_key` field must keep its `\n` escapes intact — pasting through a chat app that "helpfully" reformats newlines is the usual culprit.
