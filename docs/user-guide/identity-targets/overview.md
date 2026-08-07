# Identity Targets

Maestro red-teams your **identity layer** — Active Directory, Entra ID, Microsoft 365, Okta, Google Workspace, and Ping — the surface attackers use to turn one foothold into tenant-wide takeover.

> [!NOTE] At a glance
> - **What it unlocks:** the identity-recon → identity-exploit → identity-analysis phases on every assessment where `identity_targets` is in scope.
> - **Six providers, one surface:** on-prem AD, Entra ID / Azure AD, Microsoft 365, Okta, Google Workspace, and PingOne / PingFederate.
> - **Fail-closed:** with nothing scoped, every identity tool is rejected — Maestro never touches identity infrastructure you haven't explicitly authorized.
> - **Two safety rails, always on:** the account-lockout mandate and non-destructive-by-default gating.
> - **Output:** an **Identity Companion Report** PDF — the analog of the Cloud and SAST companion reports.

> Identity testing runs **only** when at least one `identity_targets` entry is in
> scope. With nothing in scope, every identity tool is rejected (fail-closed), and
> the identity phases are skipped entirely — no behavior change for non-identity
> engagements.

## Pick your provider

Each identity target has a `kind`. Pick yours, then follow its walkthrough — every page leads with the **Config → Identity Targets → Add** UI flow and lists exactly what you provide.

| `kind` | Provider | Walkthrough |
|---|---|---|
| `active_directory` | On-prem Active Directory | [Active Directory](./active-directory.md) |
| `entra_id` | Entra ID / Azure AD | [Entra ID](./entra-id.md) |
| `m365` | Microsoft 365 | [Microsoft 365](./m365.md) |
| `okta` | Okta | [Okta](./okta.md) |
| `google_workspace` | Google Workspace | [Google Workspace](./google-workspace.md) |
| `ping` | PingOne / PingFederate | [Ping](./ping.md) |

## What scoping an identity target gives you

- **Active Directory** — BloodHound attack-path mapping, Kerberoasting / AS-REP
  roasting, ADCS abuse (ESC1–13), DCSync, ACL & delegation abuse, LAPS read, NTLM
  relay.
- **Entra ID** — tenant/user/directory enumeration, password spray, illicit
  consent grants, device-code phishing, token replay, conditional-access &
  service-principal abuse, primary-refresh-token attacks.
- **Microsoft 365** — mailbox / SharePoint / OneDrive / Teams access, eDiscovery &
  app-registration abuse, AADInternals / Golden SAML.
- **Okta** — org/user enumeration, lockout-aware spray, OAuth/OIDC consent abuse,
  SAML assertion testing, API-token & MFA-factor enumeration.
- **Google Workspace** — domain/user/admin-role enumeration, domain-wide-delegation
  OAuth abuse, SAML SSO testing, OAuth token replay.
- **Ping** — SSO endpoint & federation enumeration, lockout-aware spray,
  OAuth/OIDC + SAML federation abuse, token testing.
- An **Identity Companion Report** with the privilege-escalation graph (every path
  tagged EXPLOITED / DETECTED-ONLY / GATED), the analog of the SAST and Cloud
  companion reports.

## Add a target — the UI flow

Sidebar → **Config** → **Identity Targets** → **Add**. The form is provider-driven:

1. **Provider** — pick the `kind`. The form then shows only the fields that provider needs.
2. **Per-provider fields** — fill them in (each walkthrough lists the exact labels).
3. **Verify** — Maestro runs a structural config check to confirm the entry is well-formed before you commit it.
4. **Save** — writes the target to scope and stores its credential.

> [!TIP] Lead with the UI
> The **Config → Identity Targets → Add** form is the primary path. Each
> walkthrough page is organized around it. The YAML below is just what the form
> writes under the hood, for the YAML-inclined.

## Under the hood (scope.yml)

Saving a target writes a `config/scope.yml` `identity_targets[]` entry plus a
matching `config/credentials.yml` `identity_credentials` entry. (For Google
Workspace, the service-account key JSON is stored as a `0600` file and referenced
by path — never inlined.) A representative scope entry:

```yaml
identity_targets:
  # On-prem Active Directory
  - id: corp-ad
    kind: active_directory
    domain: corp.example.com
    domain_controllers: ["10.0.0.10"]
    lockout_threshold: 5          # REQUIRED before any spray
    exclusions: ["krbtgt", "svc-breakglass"]   # never touched

  # Entra ID / Azure AD
  - id: corp-entra
    kind: entra_id
    tenant_id: "11111111-2222-3333-4444-555555555555"
    lockout_threshold: 10

  # Okta
  - id: corp-okta
    kind: okta
    base_url: "https://corp.okta.com"
    lockout_threshold: 8
```

`id`, `tenant_id`, `domain`, and `base_url` are all accepted as the in-scope
identifier the tools validate against.

## Safety rails (built in, always on)

These apply on **every** provider page — they are stated again per page because they are non-negotiable.

- **Account-lockout mandate.** Set `lockout_threshold` on any target you'll spray.
  Maestro sprays **below** the threshold (with a safety margin), **one attempt per
  user per window**, with jitter, and **aborts on the first observed lockout**.
  Break-glass / executive accounts in `exclusions` are never touched. A spray tool
  with no threshold is **blocked**, not guessed.
- **Non-destructive by default.** Enumeration and read-only access run freely.
  Anything that changes state — a consent grant, an app registration, a DCSync, a
  ticket forge, an NTLM relay — is **gated behind an explicit opt-in** and, for
  infrastructure-changing steps, pauses for your confirmation first.

## Run it

Once a target is saved, an assessment automatically includes the identity phases
(recon → exploit → analysis). Findings appear under the **Identity / IDP**
findings tab, and an **Identity Companion Report** PDF is produced at the end.
With no `identity_targets` in scope, those phases are skipped entirely.

## Where the deeper reference lives

The full attack-surface taxonomy, tool list, and the IDENTITY-01..60 test matrix
are in `docs/identity-redteam-plan.md`.
