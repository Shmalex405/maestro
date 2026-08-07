# =============================================================================
# Maestro Self-Host — Variables
# =============================================================================
#
# Compare with customer-deploy/variables.tf: every `groovy_*` variable is gone.
# There is nothing here that Groovy Security has to provide, and nothing that
# blocks waiting on a human at Groovy to add a DNS record.
# =============================================================================

# -----------------------------------------------------------------------------
# Identity and DNS — all yours
# -----------------------------------------------------------------------------

variable "org_id" {
  description = <<-EOT
    Short slug for this deployment. Flows into resource names, report metadata,
    and the ALLOWED_ORG_ID tenancy guard on the backend.

    Single-tenant self-hosts can leave the default. It still matters: the
    backend rejects any JWT whose custom:org_id claim doesn't match, so changing
    it after users exist invalidates their tokens until the Cognito attribute is
    updated to match.
  EOT
  type        = string
  default     = "self-hosted"

  validation {
    condition     = can(regex("^[a-z0-9]([a-z0-9-]{1,30}[a-z0-9])?$", var.org_id))
    error_message = "org_id must be 3-32 chars, lowercase alphanumeric with hyphens, no leading/trailing hyphen."
  }
}

variable "org_name" {
  description = "Display name shown in the desktop UI and on report cover pages."
  type        = string
  default     = "Self-Hosted"
}

variable "api_domain" {
  description = <<-EOT
    Fully-qualified domain for your backend API, e.g.
    maestro.security.example.com.

    This is the whole point of the self-host module: it is YOUR name in YOUR
    hosted zone. Nothing here touches maestro.groovysec.com, and the ACM
    certificate validates without anyone at Groovy adding a record.
  EOT
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9]([a-z0-9.-]*[a-z0-9])?\\.[a-z]{2,}$", var.api_domain))
    error_message = "api_domain must be a lowercase fully-qualified domain name, e.g. maestro.security.example.com."
  }
}

variable "route53_zone_id" {
  description = <<-EOT
    Route 53 hosted zone ID that is authoritative for api_domain (e.g.
    Z1234567890ABC for example.com).

    Required. This is what makes the apply single-shot: terraform writes the ACM
    validation records itself, waits for issuance, and then writes the ALIAS to
    the load balancer. The managed path instead emits validation records for
    Groovy to add by hand and blocks for up to two hours.

    Your DNS must be in Route 53 in THIS account for this to work. If it isn't,
    see the "DNS outside Route 53" section of SELF-HOSTING.md.
  EOT
  type        = string

  validation {
    condition     = can(regex("^Z[A-Z0-9]+$", var.route53_zone_id))
    error_message = "route53_zone_id must be a Route 53 hosted zone ID, e.g. Z1234567890ABC."
  }
}

# -----------------------------------------------------------------------------
# Container image — built by you, from the open core
# -----------------------------------------------------------------------------

variable "container_image" {
  description = <<-EOT
    Image URI for the Maestro backend API.

    Build it from backend-rs/ in the application repo and push it to your own
    registry — most simply your own ECR in this account:

      <account>.dkr.ecr.<region>.amazonaws.com/maestro-backend:<tag>

    Because the repository is in the same account, no cross-account ECR policy
    is involved and no `groovy_ecr_repo_arn` equivalent is needed. If you push to
    a private registry OUTSIDE this account, grant the execution role pull
    access yourself — see ecr_pull_repo_arn.
  EOT
  type        = string
}

variable "ecr_pull_repo_arn" {
  description = <<-EOT
    Only needed when container_image lives in a DIFFERENT AWS account than this
    deployment. Grants the ECS execution role cross-account pull on that
    repository. Leave empty for a same-account ECR (the normal case).
  EOT
  type        = string
  default     = ""
}

# -----------------------------------------------------------------------------
# Cognito — your own user pool, created here
# -----------------------------------------------------------------------------

variable "admin_email" {
  description = <<-EOT
    Email address of the first admin user. A Cognito user is created with this
    address and a temporary password is emailed to it, so it must be an address
    you can receive at.

    Left empty, no user is created and you add the first one yourself with
    `aws cognito-idp admin-create-user`.
  EOT
  type        = string
  default     = ""
}

variable "ses_email_arn" {
  description = <<-EOT
    Optional SES verified-identity ARN for Cognito's outbound email.

    Empty (the default) uses Cognito's built-in sender: no SES setup, but capped
    at 50 messages/day and sent from a generic address. The pool only sends
    invites and password resets, so for a team that is normally fine. Set this if
    you outgrow the cap or want branded mail.
  EOT
  type        = string
  default     = ""
}

# -----------------------------------------------------------------------------
# AWS general
# -----------------------------------------------------------------------------

variable "environment" {
  description = "Environment name (prod, staging, dev)."
  type        = string
  default     = "prod"
}

variable "aws_region" {
  description = "AWS region to deploy into."
  type        = string
  default     = "us-west-2"
}

variable "aws_profile" {
  description = "AWS profile for local terraform runs. Leave empty in CI to use the default credential chain."
  type        = string
  default     = ""
}

# -----------------------------------------------------------------------------
# Networking
# -----------------------------------------------------------------------------

variable "create_vpc" {
  description = "Create a new VPC. Set false to use an existing one."
  type        = bool
  default     = true
}

variable "vpc_cidr" {
  description = "CIDR block for the new VPC (used when create_vpc = true)."
  type        = string
  default     = "10.50.0.0/16"
}

variable "availability_zones" {
  description = "AZs for the new VPC. Needs at least 2 for ALB + RDS. Empty auto-picks the first two in aws_region."
  type        = list(string)
  default     = []
}

variable "existing_vpc_id" {
  description = "Existing VPC ID (used when create_vpc = false)."
  type        = string
  default     = ""
}

variable "existing_public_subnet_ids" {
  description = "Existing public subnet IDs for the ALB (create_vpc = false). Must span 2+ AZs."
  type        = list(string)
  default     = []
}

variable "existing_private_subnet_ids" {
  description = "Existing private subnet IDs for RDS + ECS (create_vpc = false). Must span 2+ AZs."
  type        = list(string)
  default     = []
}

# -----------------------------------------------------------------------------
# Database
# -----------------------------------------------------------------------------

variable "db_instance_class" {
  description = "RDS instance class. db.t3.small is a reasonable start for <25 users."
  type        = string
  default     = "db.t3.small"
}

variable "db_name" {
  description = "Initial database name."
  type        = string
  default     = "maestro"
}

variable "db_username" {
  description = "Master database username."
  type        = string
  default     = "maestro_admin"
}

# -----------------------------------------------------------------------------
# Backend sizing
# -----------------------------------------------------------------------------

variable "ecs_cpu" {
  description = "Fargate task CPU units (1024 = 1 vCPU)."
  type        = number
  default     = 512
}

variable "ecs_memory" {
  description = "Fargate task memory (MB)."
  type        = number
  default     = 1024
}

variable "ecs_desired_count" {
  description = "Number of backend tasks. 2 for HA, 1 for lowest cost."
  type        = number
  default     = 2
}

# -----------------------------------------------------------------------------
# Report storage
# -----------------------------------------------------------------------------

variable "s3_bucket_name" {
  description = "S3 bucket for assessment reports. Empty auto-generates maestro-{org_id}-{env}-reports."
  type        = string
  default     = ""
}

# -----------------------------------------------------------------------------
# Cloud-assessment credential broker
# -----------------------------------------------------------------------------

variable "assessment_role_arn" {
  description = <<-EOT
    ARN of the read-only role the backend brokers via POST /cloud/assume for
    cloud assessments. The task role is granted sts:AssumeRole on it, and that
    role must trust this deployment's `task_role_arn` output.

    Empty disables the broker — cloud assessments then need credentials supplied
    desktop-side instead.
  EOT
  type        = string
  default     = ""
}

# -----------------------------------------------------------------------------
# OAST listener (optional)
# -----------------------------------------------------------------------------
#
# Unlike the managed arrangement there is no shared Groovy-operated listener to
# fall back on. Either you run one here, or the `oast` oracle reports
# oast_unavailable and blind findings stay honest unverified candidates.

variable "oast_enabled" {
  description = <<-EOT
    Run an out-of-band interaction listener for blind-vulnerability verification
    (blind SSRF / SQLi / XXE / SSTI, where the target's callback is the only
    proof).

    Self-hosters who want the `oast` oracle to return verdicts must enable this
    — there is no shared listener in this arrangement. Requires oast_domain (a
    name you can delegate) and a manual NS + glue hand-off after apply.
  EOT
  type        = bool
  default     = false
}

variable "oast_domain" {
  description = "Domain the listener is authoritative for, e.g. oast.security.example.com. Required when oast_enabled = true."
  type        = string
  default     = ""
}

variable "oast_instance_type" {
  description = "EC2 instance type for the listener. Interactsh is IO-bound on DNS, not CPU-bound."
  type        = string
  default     = "t3.small"
}

variable "oast_interactsh_version" {
  description = "Pinned interactsh-server release. Pin it — a floating version means an unattended reboot can change the server's CLI flags."
  type        = string
  default     = "1.2.0"
}

variable "oast_acme_contact_email" {
  description = "Contact address for Let's Encrypt expiry notices on the listener's wildcard cert. Required when oast_enabled = true."
  type        = string
  default     = ""
}
