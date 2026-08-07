# =============================================================================
# Maestro Self-Host — Outputs
# =============================================================================

output "api_url" {
  description = "Base URL of your backend API. This is backendUrl in the desktop config."
  value       = "https://${var.api_domain}"
}

# -----------------------------------------------------------------------------
# The desktop handoff
# -----------------------------------------------------------------------------
#
# In the managed arrangement the desktop learns all of this by POSTing a user's
# email to Groovy's /api/discover. There is no such endpoint here, so this output
# IS the discovery response — write it to the file the app reads at startup:
#
#   mkdir -p ~/.kali-mcp-pentest
#   terraform output -raw desktop_self_host_json \
#     > ~/.kali-mcp-pentest/self-host.json
#   chmod 600 ~/.kali-mcp-pentest/self-host.json
#
# Every user on the team needs this file. It contains no secrets — a Cognito
# pool ID and public app client ID are meant to be public, and each user still
# authenticates individually — so distributing it over normal internal channels
# is fine. The one exception is oastToken, which is why the chmod is here and why
# the token is omitted below unless you have set one.
#
# Consumed by frontend/lib/self-host.ts via the get_self_host_config Tauri
# command. Field names are load-bearing: they must match the Rust
# SelfHostConfig serde contract.

output "desktop_self_host_json" {
  description = "Contents of ~/.kali-mcp-pentest/self-host.json for the desktop app."
  value = jsonencode({
    orgId        = var.org_id
    customerName = var.org_name
    backendUrl   = "https://${var.api_domain}"

    cognitoRegion     = var.aws_region
    cognitoUserPoolId = module.cognito.user_pool_id
    cognitoClientId   = module.cognito.desktop_client_id
    # The module emits a full URL; the desktop wants a bare host. It normalizes
    # either form (see SelfHostConfig::normalize), so pass it through as-is
    # rather than parsing it here where a regex could silently produce "".
    cognitoDomain = module.cognito.domain

    # Hostname only. The polling token lives in Secrets Manager — see
    # oast_token_secret_name — and is added to this file by hand, deliberately,
    # so it never lands in terraform state or CI logs.
    oastServer = var.oast_enabled ? var.oast_domain : ""
    oastToken  = ""
  })
}

# -----------------------------------------------------------------------------
# Identity
# -----------------------------------------------------------------------------

output "cognito_user_pool_id" {
  description = "Your Cognito user pool ID."
  value       = module.cognito.user_pool_id
}

output "cognito_desktop_client_id" {
  description = "App client ID the desktop app authenticates against."
  value       = module.cognito.desktop_client_id
}

output "cognito_hosted_ui_domain" {
  description = "Hosted UI base URL, used by the desktop's browser sign-in flow."
  value       = module.cognito.domain
}

output "admin_user_created" {
  description = "Whether a first admin user was created (admin_email was set). Cognito emails it a temporary password; check spam if it doesn't arrive."
  value       = var.admin_email != ""
}

output "add_user_command" {
  description = "Ready-to-run command for adding another user. The custom:org_id attribute is required — without it the backend returns 403 despite a successful login."
  value = join(" ", [
    "aws cognito-idp admin-create-user",
    "--region ${var.aws_region}",
    "--user-pool-id ${module.cognito.user_pool_id}",
    "--username USER@EXAMPLE.COM",
    "--user-attributes Name=email,Value=USER@EXAMPLE.COM Name=email_verified,Value=true Name=custom:org_id,Value=${var.org_id}",
  ])
}

# -----------------------------------------------------------------------------
# Infrastructure
# -----------------------------------------------------------------------------

output "alb_dns_name" {
  description = "ALB hostname. The api_domain ALIAS record already points here — informational."
  value       = module.ecs.alb_dns_name
}

output "certificate_arn" {
  description = "ARN of the ACM certificate for api_domain."
  value       = aws_acm_certificate_validation.api.certificate_arn
}

output "rds_endpoint" {
  description = "RDS endpoint. Not publicly reachable — it sits in private subnets."
  value       = module.rds.db_endpoint
}

output "db_password_secret_arn" {
  description = "Secrets Manager ARN holding the database master password."
  value       = module.rds.db_password_secret_arn
}

output "s3_bucket_name" {
  description = "S3 bucket holding assessment reports."
  value       = module.s3.bucket_name
}

output "ecs_cluster_name" {
  description = "ECS cluster name, for `aws ecs update-service --force-new-deployment`."
  value       = module.ecs.cluster_name
}

output "ecs_service_name" {
  description = "ECS service name."
  value       = module.ecs.service_name
}

output "task_role_arn" {
  description = "ECS task role ARN. A cloud-assessment role brokered via POST /cloud/assume must trust this principal."
  value       = module.ecs.task_role_arn
}

output "aws_account_id" {
  description = "Account this deployment landed in — worth confirming against the profile you meant to use."
  value       = data.aws_caller_identity.current.account_id
}

# -----------------------------------------------------------------------------
# OAST
# -----------------------------------------------------------------------------

output "oast_nameserver_glue" {
  description = <<-EOT
    NS + glue records to create in the PARENT zone of oast_domain. Until these
    exist the listener resolves for nobody and the oast oracle keeps reporting
    oast_unavailable. Empty when oast_enabled = false.
  EOT
  value       = var.oast_enabled ? module.oast[0].nameserver_glue : {}
}

output "oast_domain" {
  description = "Domain the OAST listener is authoritative for. Empty when disabled."
  value       = var.oast_enabled ? module.oast[0].oast_domain : ""
}

output "oast_token_secret_name" {
  description = <<-EOT
    Secrets Manager secret holding the listener's polling token. Created EMPTY —
    populate it, restart the listener, then copy the value into the oastToken
    field of ~/.kali-mcp-pentest/self-host.json. It is kept out of the
    desktop_self_host_json output on purpose so it never enters terraform state.
  EOT
  value       = var.oast_enabled ? module.oast[0].token_secret_name : ""
}

# -----------------------------------------------------------------------------
# Next steps
# -----------------------------------------------------------------------------

output "next_steps" {
  description = "What to do after a successful apply."
  value       = <<-EOT

    Deployed. https://${var.api_domain}

    1. Confirm the backend is up (a 401 is the correct answer here — the route
       exists and is refusing an unauthenticated caller):

         curl -s -o /dev/null -w '%%{http_code}\n' https://${var.api_domain}/api/v1/footholds

       Do NOT probe /api/v1/version to check a deploy — it returns a static
       string and will look healthy even against a stale task.

    2. Write the desktop config, for every user on the team:

         mkdir -p ~/.kali-mcp-pentest
         terraform output -raw desktop_self_host_json \
           > ~/.kali-mcp-pentest/self-host.json
         chmod 600 ~/.kali-mcp-pentest/self-host.json

    3. Build the toolkit image and the desktop app (application repo):

         ./scripts/build-self-host-toolkit.sh
         cd frontend && KALI_IMAGE=maestro-toolkit:local npm run tauri:build -- \
           --config src-tauri/tauri.self-host.conf.json

    4. Sign in as ${var.admin_email != "" ? var.admin_email : "the user you create with add_user_command"}.

    ${var.oast_enabled ? "5. Publish the oast_nameserver_glue records in the parent zone, then\n       populate ${module.oast[0].token_secret_name} and add the token to\n       self-host.json as oastToken." : "5. Blind-vulnerability verification is OFF (oast_enabled = false). The oast\n       oracle will report oast_unavailable and blind findings stay unverified\n       candidates. Set oast_enabled = true to change that."}

    Read the Anthropic Cyber Verification Program section of SELF-HOSTING.md
    before your first assessment. It is the one limitation with no self-host
    workaround.

  EOT
}
