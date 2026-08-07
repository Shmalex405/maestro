# modules/oast — self-hosted Interactsh OAST listener

The out-of-band interaction server behind Maestro's `oast` verification oracle.

Blind vulnerability classes — blind SSRF, blind SQLi, XXE, blind SSTI — put nothing in the HTTP response. The only evidence a payload landed is the target reaching out to a host we control. That callback *is* the proof, which is why the oracle refuses to return a verdict without a listener rather than guessing.

**Self-hosted only.** A callback carries the target's IP and frequently whatever a blind payload exfiltrated. Sending that to a public instance (`oast.fun` and friends) would break the guarantee that assessment data stays with the customer — the whole reason Maestro runs in their account. When no listener is configured the oracle reports `oast_unavailable` and the finding stays an honest unverified candidate.

## Status

**Not yet deployed.** The terraform validates and the boot template renders, but nothing has been applied. The interactsh CLI flags in `user-data.sh.tftpl` match the documented v1.x interface and have **not** been confirmed against a running server — that is the most likely thing to need correcting on first apply. See the header of that file.

## What it creates

| Resource | Why |
|---|---|
| `aws_eip` | NS delegation needs glue A records, which need an address that survives instance replacement |
| `aws_instance` (AL2023, IMDSv2, no SSH key) | See "Why EC2" below |
| Security group | udp/53, tcp/53, tcp/80, tcp/443, optional tcp/25 — from anywhere |
| `aws_secretsmanager_secret` | Polling token, created **empty** |
| IAM role + instance profile | SSM Session Manager access, CloudWatch logs, read of its own token |
| CloudWatch log group | `/oast/<name>-<env>` |
| Route 53 NS + glue A records | Only when `create_ns_delegation = true` |

## Why EC2, in a 100%-Fargate estate

Three requirements defeat Fargate:

1. **udp/53.** An ALB is L7-HTTP only. An NLB with UDP listeners could front Fargate, but see (3).
2. **A stable public IP.** Glue A records need an address that survives task replacement; Fargate public IPs are ephemeral.
3. **Certificate persistence.** Interactsh obtains its own wildcard cert via ACME (ACM private keys cannot be exported to a host). A Fargate task with no persistent volume would re-issue on every restart and hit Let's Encrypt's duplicate-certificate rate limit of 5 per week. An EBS root volume makes this a non-issue.

It is deliberately a single instance, not an ASG: two servers would answer DNS with divergent ACME account state and fight over the EIP. **Availability expectation: single-AZ, single-instance, minutes of downtime on replacement.** That is acceptable because an unavailable listener degrades to `oast_unavailable`, which the oracle reports as a coverage gap rather than a wrong answer.

## DNS: how the delegation works

Interactsh must be *authoritative* for its own subdomain, so the parent zone delegates to it:

```
oast.maestro.groovysec.com      NS   ns1.oast.maestro.groovysec.com
                                     ns2.oast.maestro.groovysec.com
ns1.oast.maestro.groovysec.com  A    <EIP>     ← glue, mandatory
ns2.oast.maestro.groovysec.com  A    <EIP>     ← glue, mandatory
```

The glue is not optional: the nameservers for `oast.maestro…` live *inside* `oast.maestro…`, so without A records in the parent zone a resolver can never bootstrap the delegation.

`ns1` and `ns2` resolve to the same address. Interactsh serves one nameserver; two NS records exist because some resolvers and registrars object to a single-NS delegation.

**Groovy-operated** (`create_ns_delegation = true`): the module writes both record sets into `maestro.groovysec.com` through the `aws.dns` provider, which has assumed `MaestroDNSWriter` in the master account. No Namecheap change is needed — `maestro` is already delegated to Route 53, so sub-delegating `oast.maestro` is entirely within our control.

**Customer-hosted** (`create_ns_delegation = false`): the module cannot reach the customer's DNS. Take the `nameserver_glue` output and create the records in whatever zone is the parent of `oast_domain`.

## After apply — the listener will not start until you do this

The token secret is created empty, and the boot script **refuses to start an unauthenticated listener** rather than leaving the polling API open to anyone. Populate it, then restart:

```bash
aws secretsmanager put-secret-value \
  --secret-id "$(terraform output -raw token_secret_name)" \
  --secret-string "$(openssl rand -hex 32)"

aws ssm start-session --target "$(terraform output -raw instance_id)"
sudo systemctl restart interactsh
sudo tail -f /var/log/interactsh.log
```

Verify the delegation resolves before trusting it:

```bash
dig +short NS oast.maestro.groovysec.com
dig @<EIP> +short test.oast.maestro.groovysec.com
```

## Wiring it to Maestro

The MCP server reads two values (`mcp-server/src/verification/oast.ts`):

| Variable | Value |
|---|---|
| `MAESTRO_OAST_SERVER` | the `oast_domain` output |
| `MAESTRO_OAST_TOKEN` | the token you generated above |

For a container, thread them through `modules/ecs`'s existing `environment_variables` / `secrets` maps — the domain as plaintext, the token as a Secrets Manager ARN. For the desktop app, add an `oast` block to the customer registry secret in `customer-onboarding/main.tf`, surface it in `/api/discover`, and bump `BOOTSTRAP_SCHEMA_VERSION` so existing installs re-discover.

## Operational notes

- **Reputation.** This is a wildcard catch-all that accepts arbitrary inbound and whose subdomains will appear in other people's logs and occasionally on blocklists. Hosting it under the same apex that serves `login.` and `app.` couples those reputations. A dedicated apex costs one domain registration and is the safer choice.
- **SMTP is off by default.** An open `:25` attracts abuse reports and blocklisting, and few payloads need it.
- **Log retention defaults to 30 days.** Interaction bodies can contain target data; do not raise this without a reason.
- **Cost:** roughly one `t3.small` plus an EIP. There is deliberately no NAT gateway — the listener lives in a public subnet and has no private-subnet component to route for.
