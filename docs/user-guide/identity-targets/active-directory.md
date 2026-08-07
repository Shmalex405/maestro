# Active Directory

Scope an on-prem AD domain — a reachable Domain Controller plus a low-priv domain credential for the authenticated tests.

> [!NOTE] At a glance
> - **`kind`:** `active_directory`.
> - **You provide:** the domain FQDN, a reachable Domain Controller, and (for authenticated tests) one low-priv domain credential.
> - **Set before spraying:** `lockout_threshold`, plus `exclusions` for `krbtgt` and any break-glass/service accounts.
> - **Capabilities:** BloodHound paths, Kerberoast / AS-REP, ADCS ESC1–13, DCSync, ACL & delegation abuse, LAPS read, NTLM relay.

> [!TIP] New here?
> Start with the [Identity overview](./overview.md) for the provider matrix and the two safety rails.

## What you provide

| Field | Required | Notes |
|---|---|---|
| **AD domain FQDN** | yes | e.g. `corp.example.com` — the in-scope identifier the tools validate against. |
| **Domain Controller** | yes | A reachable DC IP/host (the Kali container must have network reachability to it). |
| **Username** | optional | A **low-privilege** domain account. Unauthenticated enumeration runs without it; most attack-path tests need it. |
| **Password** | optional | Paired with the username. |

## Add it — the UI flow

Sidebar → **Config** → **Identity Targets** → **Add**.

1. **Provider** → **Active Directory**.
2. **AD domain FQDN** → `corp.example.com`.
3. **Domain Controller** → the reachable DC (e.g. `10.0.0.10`).
4. **Username / Password** *(optional)* → a low-priv domain credential for authenticated tests.
5. Set **Lockout threshold** and add **Exclusions** (`krbtgt`, `svc-breakglass`, executives) before any spray.
6. **Verify** → Maestro runs a structural config check.
7. **Save**.

> [!NOTE] Under the hood (scope.yml)
> ```yaml
> identity_targets:
>   - id: corp-ad
>     kind: active_directory
>     domain: corp.example.com
>     domain_controllers: ["10.0.0.10"]
>     lockout_threshold: 5
>     exclusions: ["krbtgt", "svc-breakglass"]
> ```
> The credential is stored separately in `config/credentials.yml` under `identity_credentials` — never inlined into scope.

There's no Terraform path for AD — it's an on-prem directory, so setup is the manual UI flow above plus making sure the DC is reachable from the Kali container.

## What it does

- **Read-only, runs freely:** BloodHound collection & attack-path mapping, user/group/computer/ACL enumeration, LAPS readability checks, ADCS template enumeration (ESC1–13 detection).
- **Spray (lockout-gated):** password spray, AS-REP roasting, Kerberoasting — only below the configured `lockout_threshold`, one attempt per user per window, with jitter, aborting on the first lockout.
- **State-changing (opt-in, pauses for confirmation):** DCSync, ticket forging, ACL/delegation abuse that writes, and NTLM relay.

## Safety rails (always on)

- **Account-lockout mandate.** No spray without `lockout_threshold`. Maestro stays below it, one attempt per user per window, with jitter, and aborts on the first observed lockout. `krbtgt` and accounts in `exclusions` are never touched.
- **Non-destructive by default.** Enumeration runs freely; DCSync, ticket forging, and relay are gated behind explicit opt-in and pause for confirmation.

## Troubleshooting

> [!WARNING] Authenticated tests are skipped / "no credential"
> AD attack-path tests need a domain credential and DC reachability. Confirm the **Domain Controller** is reachable from the Kali container (try it from a shell inside the container) and that the **Username / Password** were saved. Unauthenticated enumeration will still run, but Kerberoast/DCSync/BloodHound-with-creds need the foothold credential.
