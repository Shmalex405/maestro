# Google Workspace

Scope a Google Workspace domain — a domain-wide-delegated service account, its key JSON, a delegated super-admin subject, and the primary domain.

> [!NOTE] At a glance
> - **`kind`:** `google_workspace`.
> - **You provide:** a GCP **Service Account** with **domain-wide delegation**, the SA key JSON, a **delegated super-admin subject** email, and the **primary domain** (or customer ID).
> - **Authorize in the Admin console:** the SA's client ID must be granted the three read scopes under Security → API Controls → Domain-wide delegation.
> - **Capabilities:** domain/user/admin-role enum (Admin SDK Directory), domain-wide-delegation OAuth abuse, SAML SSO testing, OAuth token replay.

> [!TIP] New here?
> Start with the [Identity overview](./overview.md) for the provider matrix and the two safety rails.

## What you provide

| Form field | Maps to | Notes |
|---|---|---|
| **Primary domain / customer ID** | `tenant_id` | The Workspace primary domain (e.g. `corp.example.com`) or customer ID — the in-scope identifier the tools validate against. |
| **Delegated admin email** | `delegated_subject` | A **super-admin** user the service account impersonates via domain-wide delegation. |
| **Service Account key (JSON)** | stored as a `0600` file, referenced by path | Paste the **whole** JSON key for the delegated service account. |

The three read scopes you authorize for the SA's client ID in the Admin console:

```
https://www.googleapis.com/auth/admin.directory.user.readonly
https://www.googleapis.com/auth/admin.directory.domain.readonly
https://www.googleapis.com/auth/admin.directory.rolemanagement.readonly
```

## Set up the service account

::: tabs
::: tab Terraform
```hcl
variable "project_id" { type = string }

resource "google_service_account" "maestro_ws" {
  account_id   = "maestro-ws-audit"
  display_name = "Maestro Workspace Audit"
  project      = var.project_id
}

resource "google_service_account_key" "maestro_ws" {
  service_account_id = google_service_account.maestro_ws.name
  key_algorithm      = "KEY_ALG_RSA_2048"
}

# The unique client ID you authorize in the Admin console for domain-wide delegation.
output "delegation_client_id" {
  value = google_service_account.maestro_ws.unique_id
}

output "service_account_key" {
  description = "JSON key — paste the full value into the form's Service Account key (JSON) field."
  value       = base64decode(google_service_account_key.maestro_ws.private_key)
  sensitive   = true
}
```

`terraform output -raw service_account_key` prints the JSON; paste the whole thing into the form's **Service Account key (JSON)** field.

> [!WARNING] Terraform can't authorize domain-wide delegation
> Terraform creates the service account and its key, but the **scope authorization** — granting the SA's client ID those three read scopes — happens in the **Workspace Admin console** (Security → API Controls → Domain-wide delegation), not in Terraform. Take the `delegation_client_id` output and complete the Admin-console step in the Manual tab.
::: tab Manual
1. **GCP Console → IAM & Admin → Service Accounts → Create service account.** Name: `maestro-ws-audit`. Create. (No project roles are needed — Workspace access comes from delegation, not project IAM.)
2. Open the new SA → **Keys → Add key → Create new key → JSON.** The browser downloads the JSON key file. Note the SA's **Unique ID** (the numeric client ID) from its details page.
3. **Workspace Admin console → Security → API Controls → Domain-wide delegation → Add new.** Enter the SA's **Unique ID** as the **Client ID** and, in **OAuth scopes**, paste the three read scopes comma-separated:
   ```
   https://www.googleapis.com/auth/admin.directory.user.readonly,https://www.googleapis.com/auth/admin.directory.domain.readonly,https://www.googleapis.com/auth/admin.directory.rolemanagement.readonly
   ```
   Authorize.
4. Open the downloaded JSON in a text editor, copy the entire contents (including the outer `{` and `}`), and paste it into the form's **Service Account key (JSON)** field.
5. Put a **super-admin** user's email in **Delegated admin email**, and the **primary domain** (or customer ID) in **Primary domain / customer ID**.
:::

## Add it — the UI flow

Sidebar → **Config** → **Identity Targets** → **Add**.

1. **Provider** → **Google Workspace**.
2. **Primary domain / customer ID** → `corp.example.com` (or the customer ID).
3. **Delegated admin email** → the super-admin the SA impersonates.
4. **Service Account key (JSON)** → paste the whole JSON key.
5. **Verify** → structural config check.
6. **Save** → the SA key JSON is written to a `0600` file and referenced by path; the rest goes to scope.

> [!NOTE] Under the hood (scope.yml)
> ```yaml
> identity_targets:
>   - id: corp-gworkspace
>     kind: google_workspace
>     tenant_id: corp.example.com           # primary domain or customer ID
>     delegated_subject: admin@corp.example.com
> ```
> The Service Account key JSON is **not** inlined — it's stored as a `0600` file under `config/credentials.yml`'s `identity_credentials` and referenced by path.

## What it does

- **Read-only, runs freely:** domain, user, and admin-role enumeration via the Admin SDK Directory API; SAML SSO configuration inspection.
- **State-changing (opt-in, pauses for confirmation):** domain-wide-delegation OAuth abuse, SAML SSO assertion testing, OAuth token replay.

## Safety rails (always on)

- **Account-lockout mandate.** Any user-credential spray honors the target's `lockout_threshold` — below threshold, one attempt per user per window, jitter, abort on first lockout; `exclusions` never touched.
- **Non-destructive by default.** Enumeration runs freely; delegation OAuth abuse and SAML testing are gated behind explicit opt-in and pause for confirmation.

## Troubleshooting

> [!WARNING] Service Account JSON gets rejected
> Make sure you pasted the **whole** file including the outer `{` and `}`. The `private_key` field must keep its `\n` escapes intact — pasting through a chat app that "helpfully" reformats newlines is the usual culprit.

> [!WARNING] `401` / `403 unauthorized_client`
> This almost always means the SA's **client ID isn't authorized for those exact scopes** in the Admin console yet, or domain-wide delegation hasn't propagated (it can take a few minutes). Re-check Security → API Controls → Domain-wide delegation lists the SA's **Unique ID** against the three `admin.directory.*.readonly` scopes verbatim, confirm the **Delegated admin email** is a real super-admin, then wait a few minutes and retry.
