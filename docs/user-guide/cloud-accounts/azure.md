# Azure

Recipes for connecting an Azure subscription — Azure CLI session, service principal, or managed identity.

> [!NOTE] At a glance
> - **Three methods:** Azure CLI *(simplest)*, Service Principal *(production-grade)*, and Managed Identity *(Maestro runs inside Azure)*.
> - **Shared roles:** all three grant `Reader` + `Security Reader` at subscription scope.
> - **Managed Identity can't be probed from the desktop** — it validates at assessment runtime.

> [!TIP] New here?
> Start with the [Cloud Accounts overview](./overview.md) for the managed-vs-self-managed decision and the method matrix.

### Azure — Azure CLI

Uses your `az login` session. Simplest Azure path when an operator's user account already has read access to the subscription.

::: tabs
::: tab Terraform
There's nothing to provision for the CLI itself — but if your user needs read permissions, grant them via Terraform:

```hcl
data "azurerm_subscription" "current" {}
data "azuread_client_config" "current" {}

resource "azurerm_role_assignment" "reader" {
  scope                = data.azurerm_subscription.current.id
  role_definition_name = "Reader"
  principal_id         = data.azuread_client_config.current.object_id
}

resource "azurerm_role_assignment" "security_reader" {
  scope                = data.azurerm_subscription.current.id
  role_definition_name = "Security Reader"
  principal_id         = data.azuread_client_config.current.object_id
}
```

These grant the currently-authenticated Azure CLI user `Reader` + `Security Reader` on the current subscription. Run after `az login`.
::: tab Manual
1. From any terminal:
   ```bash
   az login --use-device-code
   # follow the prompt
   ```
2. Verify which subscription is active:
   ```bash
   az account show --query id -o tsv
   ```
3. If you don't already have read access on that subscription, an admin needs to grant you `Reader` + `Security Reader` at subscription scope:
   ```bash
   az role assignment create \
     --assignee <your-user-upn> \
     --role "Reader" \
     --scope /subscriptions/<subscription-id>
   az role assignment create \
     --assignee <your-user-upn> \
     --role "Security Reader" \
     --scope /subscriptions/<subscription-id>
   ```
4. Paste the subscription ID into **Subscription ID** in the form.
:::

---

### Azure — Service Principal

Production-grade: a dedicated Azure AD application identity, scoped via role assignment. Survives staff changes.

::: tabs
::: tab Terraform
```hcl
data "azurerm_subscription" "current" {}

resource "azuread_application" "maestro" {
  display_name = "Maestro Security Audit"
}

resource "azuread_service_principal" "maestro" {
  client_id = azuread_application.maestro.client_id
}

resource "azuread_application_password" "maestro" {
  application_id = azuread_application.maestro.id
  display_name   = "maestro-audit-secret"
  end_date_relative = "8760h" # 1 year — rotate annually
}

resource "azurerm_role_assignment" "reader" {
  scope                = data.azurerm_subscription.current.id
  role_definition_name = "Reader"
  principal_id         = azuread_service_principal.maestro.object_id
}

resource "azurerm_role_assignment" "security_reader" {
  scope                = data.azurerm_subscription.current.id
  role_definition_name = "Security Reader"
  principal_id         = azuread_service_principal.maestro.object_id
}

output "tenant_id"     { value = data.azurerm_subscription.current.tenant_id }
output "client_id"     { value = azuread_application.maestro.client_id }
output "client_secret" {
  value     = azuread_application_password.maestro.value
  sensitive = true
}
```

After `terraform apply`, paste the three outputs into the form. Rotate `azuread_application_password.maestro` annually (or sooner if compromised).
::: tab Manual
1. **Azure Portal → Azure Active Directory → App registrations → New registration**.
2. Name: `Maestro Security Audit`. Supported account types: *single tenant*. Register.
3. From the app's **Overview** page, copy **Application (client) ID** and **Directory (tenant) ID**.
4. **Certificates & secrets → Client secrets → New client secret**. Description: `maestro-audit-secret`. Expires: 12 months. **Add**. Copy the **Value** immediately — it's only shown once.
5. Switch to **Subscriptions → \<your subscription\> → Access control (IAM) → Add → Add role assignment**.
6. Role: **Reader**. Members: search for `Maestro Security Audit`, select it. **Review + assign**.
7. Repeat step 6 with role **Security Reader**.
8. Paste Tenant ID, Client ID, and the client-secret value into the form.
:::

---

### Azure — Managed Identity

For when Maestro runs inside Azure (an Azure VM, an App Service, etc.) and you want the identity to be tied to that compute rather than a separate AAD app.

::: tabs
::: tab Terraform
```hcl
data "azurerm_subscription" "current" {}

resource "azurerm_user_assigned_identity" "maestro" {
  name                = "maestro-audit-identity"
  resource_group_name = var.resource_group_name
  location            = var.location
}

resource "azurerm_role_assignment" "reader" {
  scope                = data.azurerm_subscription.current.id
  role_definition_name = "Reader"
  principal_id         = azurerm_user_assigned_identity.maestro.principal_id
}

resource "azurerm_role_assignment" "security_reader" {
  scope                = data.azurerm_subscription.current.id
  role_definition_name = "Security Reader"
  principal_id         = azurerm_user_assigned_identity.maestro.principal_id
}
```

Then assign `azurerm_user_assigned_identity.maestro` to the VM / App Service where Maestro runs (e.g. via `azurerm_linux_virtual_machine.identity { type = "UserAssigned"; identity_ids = [...] }`).
::: tab Manual
1. **Azure Portal → Managed Identities → Create**. Subscription / resource group / region as appropriate. Name: `maestro-audit-identity`. Create.
2. Open the identity → copy the **Object (principal) ID**.
3. **Subscriptions → \<your subscription\> → Access control (IAM) → Add role assignment**.
4. Role: **Reader**. Members: search by the identity's name, select. **Review + assign**.
5. Repeat with **Security Reader**.
6. Assign the managed identity to whichever compute hosts Maestro: VM → **Identity → User assigned → Add**, then pick `maestro-audit-identity`.
7. Paste the subscription ID into the form. No client secret needed.
:::

## Troubleshooting

> [!WARNING] Azure Service Principal returns 401
> Wait 30 seconds after assigning roles; Azure RBAC propagation is eventually consistent. Also confirm the role assignment scope is *Subscription*, not *Resource Group*.
