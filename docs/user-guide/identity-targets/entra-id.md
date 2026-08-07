# Entra ID

Scope an Entra ID (Azure AD) tenant — its tenant id plus a test user or a read-scoped app registration.

> [!NOTE] At a glance
> - **`kind`:** `entra_id`.
> - **You provide:** the tenant id (or primary domain), and either a test user **or** an app registration with `Directory.Read.All`-class read scopes.
> - **Set before spraying:** `lockout_threshold`.
> - **Capabilities:** tenant/user/directory enum, password spray, illicit consent, device-code phishing, token replay, conditional-access & service-principal abuse, primary-refresh-token attacks.

> [!TIP] New here?
> Start with the [Identity overview](./overview.md) for the provider matrix and the two safety rails.

## What you provide

| Field | Required | Notes |
|---|---|---|
| **Tenant ID** | yes | The tenant GUID (or its primary domain) — the in-scope identifier the tools validate against. |
| **Client ID** | optional | App-registration (service principal) client id for app-based auth. |
| **Client Secret** | optional | Paired with the client id. |

Read-only enumeration needs `Directory.Read.All`-class scopes. A test user works for user-context tests; an app registration works for headless enumeration.

## Add it — the UI flow

Sidebar → **Config** → **Identity Targets** → **Add**.

1. **Provider** → **Entra ID**.
2. **Tenant ID** → the tenant GUID or primary domain.
3. **Client ID / Client Secret** *(optional)* → if using an app registration.
4. Set **Lockout threshold** before any spray.
5. **Verify** → structural config check.
6. **Save**.

> [!NOTE] Under the hood (scope.yml)
> ```yaml
> identity_targets:
>   - id: corp-entra
>     kind: entra_id
>     tenant_id: "11111111-2222-3333-4444-555555555555"
>     lockout_threshold: 10
> ```

## Create the app registration (if using one)

::: tabs
::: tab Terraform
```hcl
data "azuread_client_config" "current" {}

resource "azuread_application" "maestro" {
  display_name = "maestro-identity-audit"

  required_resource_access {
    resource_app_id = "00000003-0000-0000-c000-000000000000" # Microsoft Graph

    resource_access {
      id   = "7ab1d382-f21e-4acd-a863-ba3e13f7da61" # Directory.Read.All (application)
      type = "Role"
    }
  }
}

resource "azuread_service_principal" "maestro" {
  client_id = azuread_application.maestro.client_id
}

resource "azuread_application_password" "maestro" {
  application_id = azuread_application.maestro.id
}

output "client_id"     { value = azuread_application.maestro.client_id }
output "client_secret" {
  value     = azuread_application_password.maestro.value
  sensitive = true
}
```

A Global Admin still has to **grant admin consent** for the application permission (`az ad app permission admin-consent --id <client-id>` or the Portal "Grant admin consent" button). Then paste the `client_id` and `client_secret` into the form.
::: tab Manual
1. **Entra admin center → App registrations → New registration**. Name: `maestro-identity-audit`. Register.
2. **API permissions → Add a permission → Microsoft Graph → Application permissions** → add `Directory.Read.All` (and only the other read scopes you authorize).
3. **Grant admin consent** for the tenant.
4. **Certificates & secrets → New client secret** → copy the value immediately.
5. Paste the **Application (client) ID** and the secret into the form's **Client ID** / **Client Secret** fields.
:::

> [!WARNING] Grant only authorized scopes
> Add `Directory.Read.All`-class **read** scopes only. Data-access scopes (mailbox, SharePoint) belong to the [Microsoft 365](./m365.md) target on the same tenant — keep the Entra registration to directory-read so an over-broad grant can't widen the blast radius beyond what you authorized.

## What it does

- **Read-only, runs freely:** tenant, user, group, role, and service-principal enumeration; conditional-access policy read.
- **Spray (lockout-gated):** password spray below `lockout_threshold`, one attempt per user per window, with jitter, aborting on first lockout.
- **State-changing (opt-in, pauses for confirmation):** illicit consent grants, device-code phishing, token replay, service-principal credential abuse, primary-refresh-token attacks.

## Safety rails (always on)

- **Account-lockout mandate.** No spray without `lockout_threshold`. Below threshold, one attempt per user per window, jitter, abort on first lockout. Accounts in `exclusions` are never touched.
- **Non-destructive by default.** Enumeration runs freely; consent grants, device-code phishing, and SP abuse are gated behind explicit opt-in.

## Troubleshooting

> [!WARNING] App-based enumeration returns 403 / insufficient privileges
> The app registration needs its application permissions **admin-consented** — adding the permission isn't enough on its own. Re-check **API permissions** shows a green "Granted for <tenant>" against `Directory.Read.All`, and that you pasted the **Application (client) ID** (not the object id) and a current, non-expired secret.
