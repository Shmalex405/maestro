# maestro-self-host

The open-core deployment path. Runs Maestro entirely in your AWS account, under
your domain, with **no runtime dependency on Groovy Security**.

Use this module if you are running Maestro from the Apache-2.0 open core. If you
hold a Maestro subscription, use [`../customer-deploy`](../customer-deploy)
instead — it is less work, because Groovy operates identity and DNS for you.

---

## How this differs from `customer-deploy`

| Concern | `customer-deploy` (managed) | `maestro-self-host` |
|---|---|---|
| API domain | `{org_id}.maestro.groovysec.com` | your `api_domain` |
| ACM validation | you email records to Groovy; apply blocks up to **2h** | written here, **automatic** |
| Final DNS record | Groovy adds it in their zone | written here |
| Cognito | Groovy's shared pool, cross-account | your own pool, created here |
| Desktop discovery | Groovy's `/api/discover` | a local `self-host.json` |
| Backend image | Groovy's private ECR, cross-account pull | your own registry |
| Toolkit image | Groovy's private GHCR | built from source |
| Apply shape | two passes with a human in the middle | **one pass, unattended** |
| Licensing | subscription | Apache-2.0 core |

The single biggest practical difference is the apply. `customer-deploy` cannot
finish on its own: it issues a certificate for a name in a zone the customer
cannot write, so `aws_acm_certificate_validation` sits in a 2-hour timeout
waiting for someone at Groovy to add CNAMEs. Because `api_domain` here is in
**your** hosted zone, this module writes the validation records itself and
finishes in one go.

---

## Requirements

- A Route 53 hosted zone in **this** AWS account, authoritative for `api_domain`
- A backend image you have built and pushed (see below)
- Terraform >= 1.5, AWS provider ~> 5.0

If your DNS is not in Route 53, see *DNS outside Route 53* below.

---

## Quick start

```bash
cp terraform.tfvars.example terraform.tfvars
# fill in: api_domain, route53_zone_id, container_image, admin_email

terraform init
terraform apply
```

Then hand the config to the desktop app:

```bash
mkdir -p ~/.kali-mcp-pentest
terraform output -raw desktop_self_host_json > ~/.kali-mcp-pentest/self-host.json
chmod 600 ~/.kali-mcp-pentest/self-host.json
```

`terraform output next_steps` prints the rest.

---

## Building the backend image

The module does not build anything — it consumes an image URI. Same-account ECR
is simplest:

```bash
aws ecr create-repository --repository-name maestro-backend

ACCT=$(aws sts get-caller-identity --query Account --output text)
REG="$ACCT.dkr.ecr.us-west-2.amazonaws.com"

# from the application repo root
docker build -t maestro-backend backend-rs/
docker tag maestro-backend:latest "$REG/maestro-backend:1.12.0"
aws ecr get-login-password | docker login --username AWS --password-stdin "$REG"
docker push "$REG/maestro-backend:1.12.0"
```

Set `container_image` to that URI. Because the repository is in the same account,
no cross-account ECR policy is involved — leave `ecr_pull_repo_arn` empty.

The backend applies its own sqlx migrations on startup, so a version bump is just
a new image tag plus `terraform apply`. Ship migrations in ascending order; do
not skip a release when several are pending.

---

## What you get

- VPC (new, or bring your own via `create_vpc = false`)
- RDS PostgreSQL in private subnets
- S3 bucket for reports
- ECS Fargate service behind an ALB
- ACM certificate for `api_domain`, DNS-validated automatically
- Cognito user pool, desktop + web app clients, role groups, Hosted UI prefix
  domain, and optionally a first admin user
- Optionally, an OAST listener

Typical cost: **$55–150/month** depending on RDS and ECS sizing, plus ~$8/month
if you enable OAST.

---

## Verifying the deploy

```bash
curl -s -o /dev/null -w '%{http_code}\n' https://YOUR_DOMAIN/api/v1/footholds
# 401 = correct. The route exists and is refusing an unauthenticated caller.
```

Do **not** probe `/api/v1/version` to verify a deploy — it returns a static
string and reports healthy against a stale task.

---

## Adding users

Cognito users need a `custom:org_id` attribute matching `org_id`. Without it the
user authenticates to Cognito successfully and then gets a 403 from every API
call, which is a confusing failure to debug.

`terraform output add_user_command` prints the exact command with the right
attributes filled in.

---

## Blind-vulnerability verification (OAST)

The `oast` oracle proves blind SSRF / SQLi / XXE / SSTI, where the target's
out-of-band callback is the only evidence available. It needs a listener.

In the managed arrangement Groovy operates a shared one and issues per-org
polling tokens. **There is no shared listener when you self-host.** Your options:

1. `oast_enabled = false` (default) — the oracle reports `oast_unavailable` and
   blind findings are recorded as honest unverified candidates. Nothing is
   silently dropped or guessed at.
2. `oast_enabled = true` — run your own. Needs a delegatable domain, and after
   apply you must publish the `oast_nameserver_glue` records in that name's
   **parent** zone. Terraform cannot do that step when the parent is
   registrar-managed.

Then populate the token secret (`oast_token_secret_name`), restart the listener,
and add the token to `self-host.json` as `oastToken`. The token is deliberately
kept out of the terraform output so it never enters state.

---

## DNS outside Route 53

`route53_zone_id` is required, so a zone hosted at Cloudflare/NS1/etc. does not
work directly. Two ways around it:

- **Delegate a subdomain.** Create a Route 53 hosted zone for
  `security.example.com`, add its NS records at your existing provider, and point
  `api_domain` beneath it. This is the clean option and keeps the apply
  single-pass.
- **Fork the module.** Replace `aws_route53_record.cert_validation` and
  `aws_route53_record.api` with your provider's equivalents, or with a manual
  hand-off like `customer-deploy` uses. You lose the unattended apply.

---

## Not included

**The Scheduled DAST runner.** It needs a second container image and an
always-on Fargate poll task, and it has only ever been exercised against the
managed topology. To add it, wire [`../modules/dast-runner`](../modules/dast-runner)
in yourself once you have a runner image built from `docker/Dockerfile.dast-runner`.

**A web frontend.** `platform/` deploys Groovy's multi-tenant Next.js frontend,
which exists to serve `/api/discover` and license checks across many orgs. A
self-hosted deployment does not need it — the desktop app talks straight to this
backend. Those routes are proprietary in any case; see `COMMERCIAL-COMPONENTS`
in the application repo.

---

## Before your first assessment

Read the **Anthropic Cyber Verification Program** section of `SELF-HOSTING.md`
in the application repo. Groovy's org is enrolled so the assessment agents don't
trip Anthropic's cyber safeguards; enrollment is per-organization and does not
transfer. It is the one limitation of self-hosting with no workaround at the
infrastructure layer.
