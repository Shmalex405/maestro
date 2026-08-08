# Self-Hosting Maestro

How to run Maestro entirely on your own infrastructure, from the Apache-2.0 open
core, with no runtime dependency on Groovy Security.

Two modes: **local** (everything on this machine, no AWS) and **team** (your own
backend, multiple users). Start at [Two ways to run it](#two-ways-to-run-it).

**Read [Limitations](#limitations) before you start.** One of them — Anthropic's
Cyber Verification Program — has no self-host workaround, and it is better to
know that now than after you have built the toolkit image.

---

## Contents

- [Two ways to run it](#two-ways-to-run-it)
- [Prerequisites](#prerequisites)
- [Local mode: the short path](#local-mode-the-short-path)
- [1. Deploy the backend](#1-deploy-the-backend) *(team only)*
- [2. Build the toolkit image](#2-build-the-toolkit-image)
- [3. Build the desktop app](#3-build-the-desktop-app)
- [4. Configure the desktop](#4-configure-the-desktop-team-mode-only) *(team only)*
- [5. First assessment](#5-first-assessment)
- [Limitations](#limitations)
- [Tightening the CSP](#tightening-the-csp)
- [Updates](#updates)
- [Troubleshooting](#troubleshooting)

---

## Two ways to run it

Pick one. You can start local and move to team later without losing data —
findings live in different stores, so plan the switch before you accumulate work
you care about.

### Local — everything on this machine

**For:** a single operator. The default, and the fastest way to a first
assessment.

Findings, assessments, reports and projects live in a local SQLite DB
(`~/.pentest/data/pentest.db`). No AWS account, no Cognito, no terraform, no
sign-in. Clone, build, run.

### Team — your own backend, shared

**For:** several people who need to see the same findings.

You deploy Postgres + an API into your own AWS account
(`deploy/terraform/maestro-self-host`). Users sign in against **your** Cognito
pool. One unattended `terraform apply`, roughly 15 minutes.

### What each one gives you

| | Local | Team |
|---|---|---|
| Run assessments, all five surfaces | ✅ | ✅ |
| Findings, triage, evidence, severity calibration | ✅ | ✅ |
| Reports + PDF | ✅ | ✅ |
| Projects, imports, scan history | ✅ | ✅ |
| Oracle verification | ✅ | ✅ |
| Multi-user shared data | ❌ | ✅ |
| Attack-graph explorer | ❌ | ✅ |
| Post-exploitation footholds | ❌ | ✅ |
| Cross-assessment caching, scheduled DAST, user roles | ❌ | ✅ |

The four team-only rows need Postgres-native schema the local DB has no
equivalent for — the attack graph in particular relies on an accumulating
node/edge union plus a recursive-CTE pathfinder. Where a feature is unavailable
locally the UI says so and explains why, rather than showing an empty panel.

Everything else is identical: the same ~227 tools, the same Kali container, the
same agents, the same report pipeline. **Local is a smaller product, not a
degraded one** — severity calibration and the exploitable filter both work.

### What neither changes

Scanners and the Kali container always run on your machine. The only thing that
ever leaves it is the orchestration prompts to your LLM provider.

---

## Prerequisites

Both modes:

- Docker with ~20 GB free (amd64; Apple Silicon works under emulation)
- Node 20+ and Rust stable
- An Anthropic or OpenAI account for the LLM (each user brings their own)
- This repository

Team mode additionally:

- An AWS account, and a **Route 53 hosted zone in it** for the domain you'll use
- Terraform ≥ 1.5

---

## Local mode: the short path

Three commands, no AWS.

```bash
# 1. Build the toolkit image (30-60 min, ~15 GB) — see step 2 below for detail
./scripts/build-self-host-toolkit.sh

# 2. Build the desktop app
cd frontend && npm ci
KALI_IMAGE=maestro-toolkit:local \
MAESTRO_DISTRIBUTION=self-host \
  npm run tauri:build -- --config src-tauri/tauri.self-host.conf.json

# 3. Run it. It comes up in local mode with no further configuration.
```

`MAESTRO_DISTRIBUTION=self-host` is what makes local the default: with it set and
no config file present, the app skips discovery and sign-in entirely and stores
everything locally. There is no mode to choose and no file to write.

Then skip to [First assessment](#5-first-assessment). Steps 1 and 4 below are
team-mode only.

To move to team mode later, deploy the backend (step 1) and paste
`terraform output -raw desktop_self_host_json` into **Settings → Data & Sync**.

---

## 1. Deploy the backend

Build and push the backend image to your own ECR:

```bash
aws ecr create-repository --repository-name maestro-backend

ACCT=$(aws sts get-caller-identity --query Account --output text)
REG="$ACCT.dkr.ecr.us-west-2.amazonaws.com"

docker build -t maestro-backend backend-rs/
docker tag maestro-backend:latest "$REG/maestro-backend:1.13.0"
aws ecr get-login-password | docker login --username AWS --password-stdin "$REG"
docker push "$REG/maestro-backend:1.13.0"
```

Then apply the terraform module, which ships in this repo:

```bash
cd deploy/terraform/maestro-self-host
cp terraform.tfvars.example terraform.tfvars
# fill in: api_domain, route53_zone_id, container_image, admin_email

terraform init
terraform apply
```

This is a **single unattended pass** — roughly 15 minutes, most of it RDS. It
creates a VPC, RDS Postgres, an S3 report bucket, ECS Fargate behind an ALB, a
Cognito user pool with a Hosted UI, an ACM certificate validated automatically in
your zone, and the DNS record pointing at the load balancer.

Verify:

```bash
curl -s -o /dev/null -w '%{http_code}\n' https://YOUR_DOMAIN/api/v1/footholds
# 401 is the correct answer — the route exists and is refusing an
# unauthenticated caller.
```

Do **not** use `/api/v1/version` to verify a deploy. It returns a static string
and looks healthy even against a stale task.

Full module reference:
[`deploy/terraform/maestro-self-host/README.md`](deploy/terraform/maestro-self-host/README.md).

---

## 2. Build the toolkit image

The Kali toolkit image is published to a private registry for subscribers. Its
definition — `docker/Dockerfile.kali` — is Apache-2.0 and complete, so you build
the identical image yourself:

```bash
./scripts/build-self-host-toolkit.sh          # → maestro-toolkit:local
./scripts/build-self-host-toolkit.sh my:tag   # or a tag of your choice
```

Expect 30–60 minutes and ~15 GB. The script forces `linux/amd64` on purpose: a
native arm64 build fails partway through, because Kali's systemd segfaults under
QEMU. Apple Silicon runs the amd64 image fine under Docker Desktop's emulation,
just slower.

When it finishes it verifies that `nmap`, `nuclei`, `sqlmap`, `semgrep`, `nikto`,
`gitleaks`, `trivy`, and `grype` are all present, and **fails if any are
missing**. That check matters: a toolkit missing a scanner produces assessments
where the affected tests report BLOCKED rather than PASS. The provenance gate
(`check_tool_provenance`) enforces that at report time — a silently absent
scanner can never masquerade as clean coverage — but it is far better to catch it
here.

---

## 3. Build the desktop app

```bash
cd frontend
npm ci
KALI_IMAGE=maestro-toolkit:local \
MAESTRO_DISTRIBUTION=self-host \
  npm run tauri:build -- --config src-tauri/tauri.self-host.conf.json
```

`MAESTRO_DISTRIBUTION=self-host` makes the build default to local mode when no
config file exists. Omit it and the app falls back to managed email-discovery,
which will not resolve for a self-hoster.

The `--config` overlay is required. It changes three things relative to a managed
build:

- **CSP** — the stock build's `connect-src` allows only `*.maestro.groovysec.com`,
  so a self-hosted backend on your own domain would be blocked by the webview
  with no obvious error. The overlay opens `connect-src` to `https:`. See
  [Tightening the CSP](#tightening-the-csp).
- **Updater** — the endpoint list is emptied. Left pointing at Groovy's CDN, the
  app would try to install Groovy-signed builds over your fork.
- **`createUpdaterArtifacts: false`** — without this the build *fails*, because
  producing updater artifacts requires a signing key you don't have.

`KALI_IMAGE` is baked in at compile time. The startup gate checks for the image
locally before attempting any registry pull, so a local-only tag is used as-is
and never fetched.

---

## 4. Configure the desktop (team mode only)

Local mode needs none of this — skip to the next section.

The managed app discovers its backend by sending the user's email to Groovy's
`/api/discover`. In team mode you supply the same values directly:

```bash
mkdir -p ~/.kali-mcp-pentest
cd deploy/terraform/maestro-self-host
terraform output -raw desktop_self_host_json > ~/.kali-mcp-pentest/self-host.json
chmod 600 ~/.kali-mcp-pentest/self-host.json
```

The file looks like:

```json
{
  "mode": "team",
  "orgId": "self-hosted",
  "customerName": "Example Corp Security",
  "backendUrl": "https://maestro.security.example.com",
  "cognitoRegion": "us-west-2",
  "cognitoUserPoolId": "us-west-2_AbC123",
  "cognitoClientId": "1a2b3c4d5e6f7g8h9i0j",
  "cognitoDomain": "maestro-self-hosted-prod.auth.us-west-2.amazoncognito.com",
  "oastServer": "",
  "oastToken": ""
}
```

Every user on the team needs this file. It carries no secrets — a Cognito pool ID
and a public app client ID are meant to be public, and each user still
authenticates individually — so normal internal distribution is fine. The one
exception is `oastToken`; see [OAST](#blind-vulnerability-verification-oast).

Environment variables override the file, which is handy for CI:

```bash
export MAESTRO_SELF_HOSTED=1
export MAESTRO_MODE=team
export MAESTRO_BACKEND_URL=https://maestro.security.example.com
export MAESTRO_COGNITO_REGION=us-west-2
export MAESTRO_COGNITO_USER_POOL_ID=us-west-2_AbC123
export MAESTRO_COGNITO_CLIENT_ID=1a2b3c4d5e6f7g8h9i0j
```

`MAESTRO_SELF_HOSTED=1` is the opt-in — without it the other variables are
ignored entirely, so a stray `MAESTRO_BACKEND_URL` in a shell profile can never
silently redirect a managed install.

A self-hosted app never calls Groovy's platform: discovery, the schema-refresh
re-discovery, and the license check are all bypassed.

### Adding users

Cognito users need a `custom:org_id` attribute matching your `org_id`. Without it
the user signs in to Cognito fine and then gets a 403 from every API call — a
confusing failure. `terraform output add_user_command` prints the command with
the right attributes already filled in.

---

## 5. First assessment

Launch the app, sign in, and confirm the startup gate reaches **ready**: Docker
running, toolkit image found, MCP server connected with a non-zero tool count.

Then edit `config/scope.yml` to your authorized targets and run an assessment.
Start with something small and known-vulnerable rather than production.

You must hold documented authorization for every target. Maestro sends real
payloads, forges tokens, and reads data — see [`NOTICE`](NOTICE).

---

## Limitations

### Anthropic's Cyber Verification Program

**This is the one with no workaround.**

Anthropic applies safeguards to cyber-offensive use of Claude. Sustained
exploitation work — which is exactly what the assessment agents do — can trip
them, and the agents then refuse mid-run. Groovy's organization is enrolled in
Anthropic's Cyber Verification Program, which is what makes long assessments run
cleanly on the managed product.

**Enrollment is per-organization and does not transfer with the source code.** A
self-hosted deployment runs against your own Anthropic account, which is not
enrolled. Consequences:

- Some agents may refuse or partially refuse, especially exploitation-heavy ones
  (`web-security`, `api-graphql`, `cloud-exploit`, `identity-exploit`,
  `post-exploit-operator`)
- Failures look like an agent declining rather than an error, which is confusing
  to debug — check the agent transcript before suspecting a tool problem
- Recon, SAST, compliance mapping, and reporting are generally unaffected

Options: apply to Anthropic's programme for your own organization (independent of
Maestro); use the Codex/OpenAI brain, subject to OpenAI's own policies; or accept
partial coverage. None of these are things Groovy can grant you.

This is not a licensing restriction and not an artificial limitation — it is a
model-provider policy that applies to the operator of the account.

### Blind-vulnerability verification (OAST)

The `oast` oracle proves blind SSRF / SQLi / XXE / SSTI, where the target's
out-of-band callback is the only available evidence. It needs a listener.

Managed deployments use a Groovy-operated listener with per-org polling tokens.
**There is no shared listener when you self-host.** Either set
`oast_enabled = true` in the terraform module and run your own — which needs a
delegatable domain plus a manual NS/glue hand-off in the parent zone — or leave
it off, in which case the oracle reports `oast_unavailable` and blind findings are
recorded as honest unverified candidates. Nothing is silently dropped or guessed.

### Not included

- **Scheduled DAST runner** — needs a second image and an always-on Fargate poll
  task, only ever exercised against the managed topology. Wire in
  `modules/dast-runner` yourself if you want it.
- **Auto-update** — see [Updates](#updates).
- **The multi-tenant web frontend** — exists to serve discovery and licensing
  across many orgs; a self-host doesn't need it, and those routes are proprietary
  in any case.
- **Support and the signed attestation.** The managed product includes a
  human-signed pentest attestation, which is the deliverable most compliance
  regimes actually want. Self-hosting gives you the tooling, not the signature.

### Commercially-licensed files

Some paths in this repository are proprietary and present only because the app
won't run without them — notably `.claude/agents/` (the agent prompt corpus) and
`skills/`. Using them requires an active subscription or written authorization.
See [`COMMERCIAL-COMPONENTS`](COMMERCIAL-COMPONENTS) and
[`LICENSE-COMMERCIAL`](LICENSE-COMMERCIAL).

Your Apache-2.0 rights to the open core are unconditional either way, and you are
free to write your own agent definitions and skill protocols to replace them.

---

## Tightening the CSP

`tauri.self-host.conf.json` opens `connect-src` to `https:` because your domains
are not known at build time. Everything else stays locked down — notably
`script-src`, which is where the real XSS protection lives.

To narrow it, replace `https: wss:` in that file with your actual origins:

```
connect-src 'self' ipc: http://ipc.localhost
  http://localhost:* https://localhost:* ws://localhost:* wss://localhost:*
  https://maestro.security.example.com
  https://cognito-idp.us-west-2.amazonaws.com
  https://maestro-self-hosted-prod.auth.us-west-2.amazoncognito.com
  https://api.anthropic.com
  https://api.github.com
  https://YOUR-REPORTS-BUCKET.s3.us-west-2.amazonaws.com
  https://fonts.googleapis.com https://fonts.gstatic.com
```

Also narrow `frame-src` from `https:` to your reports bucket — that's what the
in-app PDF viewer loads.

If you tighten it and the app shows blank data panels, open devtools and look for
CSP violations in the console before assuming a backend problem: a blocked
`connect-src` fails silently from the UI's point of view.

---

## Updates

Self-hosted builds have no auto-update. To upgrade:

```bash
git pull
./scripts/build-self-host-toolkit.sh              # if docker/ changed
cd frontend && KALI_IMAGE=maestro-toolkit:local npm run tauri:build -- \
  --config src-tauri/tauri.self-host.conf.json
```

Then rebuild and push the backend image and `terraform apply` the new tag. The
backend applies its own sqlx migrations on startup, so ship releases in order and
don't skip one with pending migrations.

To wire up your own auto-update, generate a Tauri signing keypair, set
`plugins.updater.endpoints` and `pubkey` in your own config overlay, set
`createUpdaterArtifacts: true`, and host the manifest yourself.

Managed installs pull a fresh toolkit image whenever the desktop version changes.
Self-hosted installs deliberately skip that — the image is yours, and a forced
pull of a local-only tag would fail and fall through to a 30–60 minute rebuild on
every upgrade.

---

## Troubleshooting

**"Toolkit image not found locally"** — you built the desktop with a `KALI_IMAGE`
tag that doesn't exist on this machine. Run
`./scripts/build-self-host-toolkit.sh` with the matching tag. Self-hosted installs
never pull from a registry.

**Startup fails with a self-host config error** — the file exists but is
incomplete. The error names the missing fields. Required: `backendUrl`,
`cognitoRegion`, `cognitoUserPoolId`, `cognitoClientId`. This is deliberately a
hard error rather than a fallback to managed discovery, which would point you at
a Groovy endpoint you have no account on.

**Login succeeds, then every API call 403s** — the Cognito user is missing
`custom:org_id`, or its value doesn't match `org_id`/`ALLOWED_ORG_ID`. Use
`terraform output add_user_command`.

**Blank data panels, no errors** — usually a CSP `connect-src` block. Check
devtools. Also confirm `backendUrl` in `self-host.json` has no trailing slash and
no `/api/v1` suffix — the app appends paths itself. (The config loader strips
trailing slashes for you, but a stale hand-edited file may predate that.)

**Agents refuse mid-assessment** — see
[the Cyber Verification Program](#anthropics-cyber-verification-program). Check
the agent transcript to distinguish a model refusal from a tool failure.

**`terraform apply` hangs on certificate validation** — `route53_zone_id` is not
the zone actually authoritative for `api_domain`, so the validation records went
somewhere ACM can't see. Confirm with
`aws route53 list-hosted-zones-by-name --dns-name example.com`.

---

## Getting help

Self-hosted deployments are not covered by Groovy Security support. Open an issue
on the repository for bugs in the open core.

For the managed product — including the signed attestation, the Cyber
Verification Program enrollment, and the hosted OAST listener —
<support@groovysec.com>.
