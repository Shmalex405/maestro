# Ping

Scope a PingOne environment or PingFederate deployment — its base URL plus an OAuth worker client or read-scoped API token.

> [!NOTE] At a glance
> - **`kind`:** `ping`.
> - **You provide:** the PingOne **environment ID** (or PingFederate base URL) and an OAuth worker/app client (client id/secret) or an API token with read scopes.
> - **Set before spraying:** `lockout_threshold`.
> - **Capabilities:** SSO endpoint & federation enum, lockout-aware spray, OAuth/OIDC + SAML federation abuse, token testing.

> [!TIP] New here?
> Start with the [Identity overview](./overview.md) for the provider matrix and the two safety rails.

## What you provide

| Field | Required | Notes |
|---|---|---|
| **Base URL** | yes | The PingOne API/auth base URL or the PingFederate base URL. |
| **Environment ID** | yes | The PingOne environment ID — the in-scope identifier the tools validate against (`tenant_id`). For PingFederate, the base URL is the identifier. |
| **Client ID / Client Secret** *(or token)* | yes | An OAuth worker/app client with read scopes, or a read-scoped API token. |

## Create the worker client

1. **PingOne Admin console → Connections → Applications → Add application → Worker.**
2. Grant it the **read** roles you authorize (e.g. Identity Data Read-Only) — keep it least-privilege.
3. Copy the **Client ID** and **Client Secret**.
4. For PingFederate, create an OAuth client / API token with read scopes in the PingFederate admin console instead.

## Add it — the UI flow

Sidebar → **Config** → **Identity Targets** → **Add**.

1. **Provider** → **Ping**.
2. **Base URL** → the PingOne or PingFederate base URL.
3. **Environment ID** → the PingOne environment ID (skip for pure PingFederate, where the base URL is the identifier).
4. **Client ID / Client Secret** (or **token**) → the read-scoped worker client / token.
5. Set **Lockout threshold** before any spray.
6. **Verify** → structural config check.
7. **Save**.

> [!NOTE] Under the hood (scope.yml)
> ```yaml
> identity_targets:
>   - id: corp-ping
>     kind: ping
>     base_url: "https://auth.pingone.com"
>     tenant_id: "envid-1111-2222-3333"      # PingOne environment ID
>     lockout_threshold: 8
> ```
> The client secret / token is stored separately in `config/credentials.yml` under `identity_credentials` — never inlined into scope.

There's no Terraform path here — setup is creating the worker client / token in the Ping admin console and pasting it into the form.

## What it does

- **Read-only, runs freely:** SSO endpoint, application, and federation-connection enumeration; OAuth/OIDC and SAML configuration inspection.
- **Spray (lockout-gated):** password spray below `lockout_threshold`, one attempt per user per window, with jitter, aborting on first lockout.
- **State-changing (opt-in, pauses for confirmation):** OAuth/OIDC + SAML federation abuse, token manipulation.

## Safety rails (always on)

- **Account-lockout mandate.** No spray without `lockout_threshold`. Below threshold, one attempt per user per window, jitter, abort on first lockout. Accounts in `exclusions` are never touched.
- **Non-destructive by default.** Enumeration runs freely; federation abuse and token manipulation are gated behind explicit opt-in.

## Troubleshooting

> [!WARNING] Token requests return `invalid_client`
> Confirm the **Base URL** matches your region's PingOne auth host (PingOne uses regional hosts — `.com`, `.eu`, `.asia`, `.ca`), the **Environment ID** is correct, and the worker client's secret is current. For PingFederate, confirm the OAuth client is enabled and the base URL points at the runtime (not the admin) port.
