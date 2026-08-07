# Okta

Scope an Okta org — its org URL plus a read-access API token.

> [!NOTE] At a glance
> - **`kind`:** `okta`.
> - **You provide:** the Okta org URL (e.g. `https://corp.okta.com`) and an API token with read access.
> - **Set before spraying:** `lockout_threshold`.
> - **Capabilities:** org/user enum, lockout-aware spray, OAuth/OIDC consent abuse, SAML assertion testing, API-token & MFA-factor enumeration.

> [!TIP] New here?
> Start with the [Identity overview](./overview.md) for the provider matrix and the two safety rails.

## What you provide

| Field | Required | Notes |
|---|---|---|
| **Okta org URL** | yes | The org base URL, e.g. `https://corp.okta.com` — the in-scope identifier the tools validate against. |
| **API token** | yes | An Okta API token with read access (Admin → Security → API → Tokens → Create Token). |

## Create the API token

1. **Okta Admin console → Security → API → Tokens → Create Token**.
2. Name it (e.g. `maestro-identity-audit`), create it, and copy the token value immediately — Okta shows it once.
3. Paste it into the form's **API token** field.

> [!WARNING] Okta API tokens inherit the creator's admin role
> An Okta API token carries the **full privileges of the admin who created it** — there's no per-token scoping. Create the token while signed in as a **least-privilege, read-only admin** (a custom Read-Only Administrator role), not a Super Admin, so the token can only read.

## Add it — the UI flow

Sidebar → **Config** → **Identity Targets** → **Add**.

1. **Provider** → **Okta**.
2. **Okta org URL** → `https://corp.okta.com`.
3. **API token** → the token you created.
4. Set **Lockout threshold** before any spray.
5. **Verify** → structural config check.
6. **Save**.

> [!NOTE] Under the hood (scope.yml)
> ```yaml
> identity_targets:
>   - id: corp-okta
>     kind: okta
>     base_url: "https://corp.okta.com"
>     lockout_threshold: 8
> ```
> The API token is stored separately in `config/credentials.yml` under `identity_credentials` — never inlined into scope.

There's no Terraform path here — the setup is creating the read-only API token in the Admin console and pasting it into the form.

## What it does

- **Read-only, runs freely:** org, user, group, application, and policy enumeration; API-token and MFA-factor enumeration; SAML assertion inspection.
- **Spray (lockout-gated):** password spray below `lockout_threshold`, one attempt per user per window, with jitter, aborting on first lockout.
- **State-changing (opt-in, pauses for confirmation):** OAuth/OIDC consent abuse, SAML assertion manipulation.

## Safety rails (always on)

- **Account-lockout mandate.** No spray without `lockout_threshold`. Below threshold, one attempt per user per window, jitter, abort on first lockout. Accounts in `exclusions` are never touched.
- **Non-destructive by default.** Enumeration runs freely; consent abuse and SAML manipulation are gated behind explicit opt-in.

## Troubleshooting

> [!WARNING] 401 Unauthorized on every call
> Okta API tokens expire after 30 days of inactivity and are revoked if the creating admin is deactivated. Confirm the token is current, that you pasted the whole value, and that the **Okta org URL** is the real org base URL (e.g. `https://corp.okta.com`) — not a custom vanity domain that 302-redirects.
