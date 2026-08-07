# =============================================================================
# Maestro — Self-Hosted Deployment
# =============================================================================
#
# The open-core deployment path. Everything runs in YOUR AWS account under YOUR
# domain, with no runtime dependency on Groovy Security.
#
# How this differs from customer-deploy/ (the managed subscription path):
#
#   | Concern    | customer-deploy                  | this module                 |
#   |------------|----------------------------------|-----------------------------|
#   | Domain     | {org}.maestro.groovysec.com      | your api_domain             |
#   | ACM        | Groovy adds validation CNAMEs    | written here, automatically |
#   | DNS record | Groovy adds the final A record   | written here                |
#   | Cognito    | Groovy's shared pool             | your own pool, created here |
#   | Discovery  | Groovy's /api/discover           | a local config file         |
#   | Image      | Groovy's private ECR             | your own registry           |
#   | Apply      | two passes, blocks up to 2h      | one pass, unattended        |
#
# What gets deployed:
#   - VPC (new, or bring your own)
#   - RDS PostgreSQL
#   - S3 bucket for reports
#   - ECS Fargate running the Maestro backend + an ALB
#   - ACM certificate for api_domain, DNS-validated in your zone
#   - A Cognito user pool, app clients, groups, and a Hosted UI prefix domain
#   - Optionally, an OAST listener for blind-vulnerability verification
#
# Cost (typical): ~$55-150/month depending on RDS/ECS sizing, plus ~$8/month if
# you enable the OAST listener.
#
# Quick start:
#   1. cp terraform.tfvars.example terraform.tfvars
#   2. Fill in api_domain, route53_zone_id, container_image, admin_email
#   3. terraform init && terraform apply
#   4. terraform output -raw desktop_self_host_json \
#        > ~/.kali-mcp-pentest/self-host.json
#   5. Launch the desktop app — it reads that file instead of calling discovery
#
# NOT included, deliberately: the Scheduled DAST runner. It needs a second
# container image and an always-on Fargate poll task, and it has only ever been
# exercised against the managed topology. Enable it by adding modules/dast-runner
# yourself once you have a runner image; see modules/dast-runner/README.md.
#
# Full walkthrough: SELF-HOSTING.md in the application repo.
# =============================================================================

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.5"
    }
  }

  # No backend block on purpose.
  #
  # customer-deploy/ hardcodes Groovy's state bucket and AWS profile, which is
  # correct for a stack Groovy operates and wrong for one you operate. Left
  # unset, terraform keeps state in a local file — fine for a first apply, not
  # fine for a team.
  #
  # To use remote state, create a bucket and uncomment:
  #
  #   backend "s3" {
  #     bucket       = "my-tfstate"
  #     key          = "maestro/self-host/terraform.tfstate"
  #     region       = "us-west-2"
  #     encrypt      = true
  #     use_lockfile = true
  #   }
}

provider "aws" {
  region  = var.aws_region
  profile = var.aws_profile != "" ? var.aws_profile : null

  default_tags {
    tags = {
      Project     = "maestro"
      OrgId       = var.org_id
      Environment = var.environment
      ManagedBy   = "terraform"
      Deployment  = "self-hosted"
    }
  }
}

locals {
  availability_zones = length(var.availability_zones) > 0 ? var.availability_zones : slice(data.aws_availability_zones.available.names, 0, 2)
}

data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_caller_identity" "current" {}

# =============================================================================
# NETWORKING
# =============================================================================

module "vpc" {
  source = "../modules/vpc"
  count  = var.create_vpc ? 1 : 0

  environment        = var.environment
  vpc_cidr           = var.vpc_cidr
  availability_zones = local.availability_zones
}

locals {
  vpc_id             = var.create_vpc ? module.vpc[0].vpc_id : var.existing_vpc_id
  public_subnet_ids  = var.create_vpc ? module.vpc[0].public_subnet_ids : var.existing_public_subnet_ids
  private_subnet_ids = var.create_vpc ? module.vpc[0].private_subnet_ids : var.existing_private_subnet_ids
}

# =============================================================================
# STORAGE
# =============================================================================

module "s3" {
  source = "../modules/s3"

  environment = var.environment
  bucket_name = var.s3_bucket_name != "" ? var.s3_bucket_name : "maestro-${var.org_id}-${var.environment}-reports"
}

# =============================================================================
# DATABASE
# =============================================================================

module "rds" {
  source = "../modules/rds"

  environment        = var.environment
  vpc_id             = local.vpc_id
  private_subnet_ids = local.private_subnet_ids
  db_instance_class  = var.db_instance_class
  db_name            = var.db_name
  db_username        = var.db_username
}

# =============================================================================
# IDENTITY — your own Cognito user pool
# =============================================================================
#
# The managed path points every customer backend at Groovy's shared pool and
# validates JWTs against Groovy's JWKS. Here the pool is yours: your users, your
# password policy, your MFA settings, and nothing to revoke if a subscription
# lapses.
#
# The pool ships with a Hosted UI PREFIX domain
# (maestro-{env}.auth.{region}.amazoncognito.com), which needs no certificate
# and no DNS. That is enough for the desktop's browser sign-in. A custom
# login.* domain is possible but requires a us-east-1 certificate and is not
# worth it for an internal tool.
#
# ses_email_arn is optional here — see the variable description.

module "cognito" {
  source = "../modules/cognito"

  environment   = var.environment
  app_name      = "maestro-${var.org_id}"
  web_domain    = var.api_domain
  ses_email_arn = var.ses_email_arn

  # M2M clients exist for Groovy's cross-tenant cache-stats Lambda. There is no
  # cross-tenant anything in a single-tenant self-host.
  enable_m2m_clients = false
}

# Tag every user in this deployment with the org this backend accepts. The
# backend rejects any JWT whose custom:org_id claim doesn't match ALLOWED_ORG_ID,
# so a user created without it can authenticate to Cognito and still be refused
# by the API — which reads as a confusing 403 rather than a login failure.
resource "aws_cognito_user_group" "org" {
  name         = var.org_id
  user_pool_id = module.cognito.user_pool_id
  description  = "Users belonging to ${var.org_name}"
}

resource "aws_cognito_user" "admin" {
  count = var.admin_email != "" ? 1 : 0

  user_pool_id = module.cognito.user_pool_id
  username     = var.admin_email

  attributes = {
    email          = var.admin_email
    email_verified = true
    # The tenancy guard above. Must match ALLOWED_ORG_ID on the backend.
    "custom:org_id" = var.org_id
  }

  # Cognito emails a temporary password. With the built-in sender that arrives
  # from a generic address and can land in spam — check there before assuming
  # the apply failed.
  desired_delivery_mediums = ["EMAIL"]

  # A password reset outside terraform must not look like drift.
  lifecycle {
    ignore_changes = [attributes["email_verified"], temporary_password]
  }
}

resource "aws_cognito_user_in_group" "admin_in_org" {
  count = var.admin_email != "" ? 1 : 0

  user_pool_id = module.cognito.user_pool_id
  group_name   = aws_cognito_user_group.org.name
  username     = aws_cognito_user.admin[0].username
}

# =============================================================================
# TLS CERTIFICATE — issued AND validated here
# =============================================================================
#
# This is the block that makes self-hosting practical. customer-deploy issues the
# certificate and then blocks in aws_acm_certificate_validation for up to two
# hours while a human at Groovy adds CNAMEs to a zone the customer cannot write.
# Because api_domain lives in a zone you control, terraform writes the records
# itself and validation completes in a minute or two, unattended.

resource "aws_acm_certificate" "api" {
  domain_name       = var.api_domain
  validation_method = "DNS"

  lifecycle {
    create_before_destroy = true
  }

  tags = {
    Name = "maestro-${var.org_id}-api"
  }
}

resource "aws_route53_record" "cert_validation" {
  for_each = {
    for dvo in aws_acm_certificate.api.domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  }

  zone_id = var.route53_zone_id
  name    = each.value.name
  type    = each.value.type
  records = [each.value.record]
  ttl     = 60

  # Re-applying over an existing validation record is expected, not a conflict:
  # ACM reuses the same record name across renewals.
  allow_overwrite = true
}

resource "aws_acm_certificate_validation" "api" {
  certificate_arn         = aws_acm_certificate.api.arn
  validation_record_fqdns = [for r in aws_route53_record.cert_validation : r.fqdn]

  # Minutes, not hours — no human is in this loop.
  timeouts {
    create = "15m"
  }
}

# =============================================================================
# BACKEND API — ECS Fargate
# =============================================================================

resource "random_password" "jwt_secret" {
  length  = 64
  special = true
}

module "ecs" {
  source = "../modules/ecs"

  environment        = var.environment
  vpc_id             = local.vpc_id
  public_subnet_ids  = local.public_subnet_ids
  private_subnet_ids = local.private_subnet_ids

  container_image = var.container_image
  container_port  = 8000
  cpu             = var.ecs_cpu
  memory          = var.ecs_memory
  desired_count   = var.ecs_desired_count

  environment_variables = {
    DATABASE_URL = "postgresql+asyncpg://${var.db_username}:${module.rds.db_password}@${module.rds.db_endpoint}/${var.db_name}"

    AUTH_PROVIDER = "cognito"

    # Your pool, not Groovy's. The backend fetches JWKS from this issuer.
    COGNITO_REGION        = var.aws_region
    COGNITO_USER_POOL_ID  = module.cognito.user_pool_id
    COGNITO_APP_CLIENT_ID = module.cognito.desktop_client_id

    # Tenancy guard — rejects any JWT whose custom:org_id doesn't match.
    # Single-tenant here, but it still stops a token minted for another org's
    # pool from being replayed if you ever add a second deployment.
    ALLOWED_ORG_ID = var.org_id

    JWT_SECRET       = random_password.jwt_secret.result
    STORAGE_PROVIDER = "s3"
    S3_BUCKET        = module.s3.bucket_name
    S3_REGION        = var.aws_region
    DEBUG            = var.environment == "dev" ? "true" : "false"

    ASSESSMENT_ROLE_ARN = var.assessment_role_arn
  }

  # No `secrets` map. Those exist in customer-deploy solely to broker pulls of
  # Groovy's private toolkit image from GHCR (GHCR_PAT / GITHUB_APP_*). A
  # self-hoster builds the toolkit locally from docker/Dockerfile.kali — see
  # scripts/build-self-host-toolkit.sh — so there is no registry to authenticate
  # against and the desktop never calls the toolkit-credentials endpoint.

  rds_security_group_id = module.rds.security_group_id
  s3_bucket_arn         = module.s3.bucket_arn

  certificate_arn = aws_acm_certificate_validation.api.certificate_arn

  # Only set for a registry in a different account; same-account ECR needs no
  # cross-account grant.
  cross_account_ecr_repo_arn = var.ecr_pull_repo_arn

  # Cognito admin permissions for /api/v1/users, scoped to this pool only.
  cognito_user_pool_arn = module.cognito.user_pool_arn

  assessment_role_arn = var.assessment_role_arn
}

# =============================================================================
# DNS — the final record, written here rather than requested from Groovy
# =============================================================================

resource "aws_route53_record" "api" {
  zone_id = var.route53_zone_id
  name    = var.api_domain
  type    = "A"

  # ALIAS rather than CNAME so api_domain may be a zone apex, and so resolution
  # doesn't take an extra hop.
  alias {
    name                   = module.ecs.alb_dns_name
    zone_id                = module.ecs.alb_zone_id
    evaluate_target_health = true
  }
}

# =============================================================================
# OAST listener (optional)
# =============================================================================
#
# There is no shared listener in this arrangement, so this is the only way to get
# verdicts out of the `oast` oracle. Left off, blind findings are reported as
# honest unverified candidates rather than being quietly dropped or guessed at.
#
# After apply, take the `oast_nameserver_glue` output and create the NS + glue
# records in the PARENT zone of oast_domain. This stack cannot do it for you when
# the parent is registrar-managed. A half-configured opt-in fails during plan
# inside modules/oast rather than leaving an instance serving nothing.

module "oast" {
  count  = var.oast_enabled ? 1 : 0
  source = "../modules/oast"

  providers = {
    aws = aws
    # The module's required_providers declares a DNS alias for the managed
    # cross-account delegation path. Unused here — create_ns_delegation is
    # false — but the alias must still be supplied.
    aws.dns = aws
  }

  name        = "maestro-oast"
  environment = var.environment
  aws_region  = var.aws_region

  vpc_id           = local.vpc_id
  public_subnet_id = local.public_subnet_ids[0]

  oast_domain          = var.oast_domain
  create_ns_delegation = false

  instance_type      = var.oast_instance_type
  interactsh_version = var.oast_interactsh_version
  acme_contact_email = var.oast_acme_contact_email
}
