# Cognito Module

variable "environment" {
  type = string
}

variable "app_name" {
  type = string
}

variable "web_domain" {
  description = "Domain for the web frontend (used for Cognito callback URLs)"
  type        = string
  default     = "localhost:3000"
}

variable "ses_email_arn" {
  description = <<-EOT
    ARN of the SES verified domain identity (e.g.
    arn:aws:ses:us-west-2:<account-id>:identity/example.com).

    Leave empty to use Cognito's built-in email sender instead. That is capped
    at 50 messages/day and sends from a generic no-reply address, which is fine
    for a self-hosted team (the pool only sends invites and password resets) but
    not for a customer-facing platform. The managed platform always passes a
    real SES identity.
  EOT
  type        = string
  default     = ""
}

variable "ses_from_email" {
  description = "From email address for Cognito emails"
  type        = string
  default     = "Maestro by Groovy Security <no-reply@groovysec.com>"
}

variable "ses_reply_to_email" {
  description = "Reply-to email address"
  type        = string
  default     = "support@groovysec.com"
}

variable "enable_m2m_clients" {
  description = <<-EOT
    Provision the M2M Cognito clients used by cross-tenant service
    Lambdas (currently: cache-stats-router for the caching plan).
    Off by default so existing environments don't pick up the new
    resource server + client until ops explicitly enables them.
  EOT
  type        = bool
  default     = false
}

# NOTE: The Hosted UI *custom* domain (login.maestro.groovysec.com) is created in
# the platform root module, not here — it must depend on the apex A record, which
# aliases the frontend ALB, and the frontend module already depends on this
# module. Defining the custom domain at the platform layer breaks that cycle.

# User Pool
resource "aws_cognito_user_pool" "main" {
  name = "${var.app_name}-${var.environment}"

  # Username configuration
  username_attributes      = ["email"]
  auto_verified_attributes = ["email"]

  # Password policy
  password_policy {
    minimum_length                   = 12
    require_lowercase                = true
    require_numbers                  = true
    require_symbols                  = true
    require_uppercase                = true
    temporary_password_validity_days = 7
  }

  # MFA configuration
  mfa_configuration = "OPTIONAL"

  software_token_mfa_configuration {
    enabled = true
  }

  # Account recovery
  account_recovery_setting {
    recovery_mechanism {
      name     = "verified_email"
      priority = 1
    }
  }

  # Email via SES — branded sender instead of default Cognito no-reply.
  #
  # With SES ("DEVELOPER") the other three fields are required. Without it
  # ("COGNITO_DEFAULT") they must all be ABSENT — Cognito rejects a source_arn
  # or from_email_address paired with its built-in sender — hence null rather
  # than empty string. Self-hosted deployments take the COGNITO_DEFAULT path so
  # they don't have to verify a domain in SES to get a working login.
  email_configuration {
    email_sending_account  = var.ses_email_arn != "" ? "DEVELOPER" : "COGNITO_DEFAULT"
    source_arn             = var.ses_email_arn != "" ? var.ses_email_arn : null
    from_email_address     = var.ses_email_arn != "" ? var.ses_from_email : null
    reply_to_email_address = var.ses_email_arn != "" ? var.ses_reply_to_email : null
  }

  # Schema - custom attributes
  schema {
    name                     = "org_id"
    attribute_data_type      = "String"
    developer_only_attribute = false
    mutable                  = true
    required                 = false

    string_attribute_constraints {
      min_length = 1
      max_length = 256
    }
  }

  # Admin create user config
  admin_create_user_config {
    # Enterprise model: Groovy provisions every account (invite flow below).
    # Disabling self-service signup also removes the "Sign up" link from the
    # Hosted UI, which is the desired professional/enterprise behavior.
    allow_admin_create_user_only = true

    invite_message_template {
      email_subject = "Welcome to Maestro — your account is ready"
      email_message = "Your Maestro account has been created.\n\nLog in with your email ({username}) and this temporary password:\n\n\"{####}\"\n\nYou'll be prompted to set a permanent password on first login."
      sms_message   = "Your Maestro username is {username} and temporary password is {####}."
    }
  }

  tags = {
    Name = "${var.app_name}-${var.environment}-user-pool"
  }
}

# User Pool Domain (Amazon-managed prefix). Kept for backward compatibility —
# the web NextAuth client and any existing links continue to resolve here. The
# custom domain (login.maestro.groovysec.com) is added at the platform layer and
# coexists with this prefix domain.
resource "aws_cognito_user_pool_domain" "main" {
  domain       = "${var.app_name}-${var.environment}"
  user_pool_id = aws_cognito_user_pool.main.id
}

# Hosted UI branding (classic) — all-black login page with the greyscale Maestro
# mark for the desktop browser-OAuth flow. Replaces the stock, unbranded AWS
# page. The white input fields are the only light "spots". Requires a domain.
# NOTE: the classic Hosted UI's OUTER page background (behind the form panel) is
# not an exposed `-customizable` class, so it may stay grey; full-page black
# would require switching the domain to Managed Login (managed_login_version=2).
resource "aws_cognito_user_pool_ui_customization" "desktop" {
  user_pool_id = aws_cognito_user_pool.main.id
  client_id    = aws_cognito_user_pool_client.desktop.id

  # Greyscale Maestro sunburst MARK only (no "Whiteout AI" wordmark), brightened
  # so it reads on black. Generated from frontend/public/maestro-icon.png.
  #
  # Conditional on the asset being present, rather than an unconditional
  # filebase64(): the open-core distribution of this module ships WITHOUT the
  # Groovy mark (it is a trademark, and Apache-2.0 grants no trademark rights —
  # a self-hoster wants their own logo or none). An unconditional filebase64 on
  # a missing file is a hard plan error, so this keeps one module definition
  # working in both trees. Drop your own PNG at the same path to brand the
  # Hosted UI; leave it absent for the stock AWS page.
  image_file = fileexists("${path.module}/assets/maestro-logo-gray.png") ? filebase64("${path.module}/assets/maestro-logo-gray.png") : null

  css = <<-CSS
    .background-customizable { background-color: #000000; }
    .banner-customizable { background-color: #000000; padding: 28px 0 14px; }
    .logo-customizable { max-width: 112px; max-height: 112px; }
    .textDescription-customizable { color: #a1a1aa; }
    .label-customizable { color: #d4d4d8; font-weight: 500; }
    .inputField-customizable { background-color: #ffffff; border: 1px solid #3f3f46; border-radius: 6px; color: #18181b; }
    .inputField-customizable:focus { border-color: #e0913c; box-shadow: 0 0 0 1px #e0913c; outline: 0; }
    .submitButton-customizable { background-color: #e0913c; color: #1a1206; font-weight: 600; border-radius: 6px; }
    .submitButton-customizable:hover { background-color: #d2832f; }
    .errorMessage-customizable { color: #fca5a5; border-radius: 6px; }
    .redirect-customizable { display: none; }
  CSS

  depends_on = [aws_cognito_user_pool_domain.main]
}

# App Client (for desktop app)
resource "aws_cognito_user_pool_client" "desktop" {
  name         = "${var.app_name}-desktop"
  user_pool_id = aws_cognito_user_pool.main.id

  generate_secret = false

  explicit_auth_flows = [
    "ALLOW_USER_PASSWORD_AUTH",
    "ALLOW_REFRESH_TOKEN_AUTH",
    "ALLOW_USER_SRP_AUTH",
  ]

  supported_identity_providers = ["COGNITO"]

  # maestro://auth/* — custom-scheme deep link captured by the desktop app for
  # the browser-OAuth (Hosted UI + PKCE) sign-in. The localhost entries are kept
  # for local dev / older flows.
  callback_urls = [
    "maestro://auth/callback",
    "tauri://localhost/callback",
    "http://localhost:3000/callback",
  ]

  logout_urls = [
    "maestro://auth/logout",
    "tauri://localhost/logout",
    "http://localhost:3000/logout",
  ]

  allowed_oauth_flows                  = ["code"]
  allowed_oauth_flows_user_pool_client = true
  allowed_oauth_scopes                 = ["email", "openid", "profile"]

  # Enterprise sign-out: lets the desktop app revoke the refresh token via
  # /oauth2/revoke so a cached/stolen token can't mint new sessions.
  enable_token_revocation = true

  access_token_validity  = 24
  id_token_validity      = 24
  refresh_token_validity = 30

  token_validity_units {
    access_token  = "hours"
    id_token      = "hours"
    refresh_token = "days"
  }

  prevent_user_existence_errors = "ENABLED"
}

# App Client (for web frontend — requires client secret for NextAuth)
resource "aws_cognito_user_pool_client" "web" {
  name         = "${var.app_name}-web"
  user_pool_id = aws_cognito_user_pool.main.id

  generate_secret = true

  explicit_auth_flows = [
    "ALLOW_USER_SRP_AUTH",
    "ALLOW_REFRESH_TOKEN_AUTH",
  ]

  supported_identity_providers = ["COGNITO"]

  callback_urls = [
    "https://${var.web_domain}/api/auth/callback/cognito",
  ]

  logout_urls = [
    "https://${var.web_domain}",
  ]

  allowed_oauth_flows                  = ["code"]
  allowed_oauth_flows_user_pool_client = true
  allowed_oauth_scopes                 = ["email", "openid", "profile"]

  access_token_validity  = 24
  id_token_validity      = 24
  refresh_token_validity = 30

  token_validity_units {
    access_token  = "hours"
    id_token      = "hours"
    refresh_token = "days"
  }

  prevent_user_existence_errors = "ENABLED"
}

# =============================================================================
# M2M service-account clients (Phase 6 caching plan)
# =============================================================================
#
# Cognito user-pool clients with `client_credentials` grant — i.e. they
# get an access_token via the OAuth `/oauth2/token` endpoint using their
# own client_id+secret, no human user involved. Tokens issued to these
# clients carry a `custom:service_caller` claim that backend-rs
# recognizes as a cross-tenant service identity (see
# `backend-rs/src/auth/middleware.rs::is_cache_stats_router`).
#
# Resource server: defines the OAuth scope the M2M client requests.
# Cognito requires a resource server for any client_credentials grant.
# =============================================================================

resource "aws_cognito_resource_server" "maestro_api" {
  count        = var.enable_m2m_clients ? 1 : 0
  identifier   = "maestro-api"
  name         = "Maestro Backend API"
  user_pool_id = aws_cognito_user_pool.main.id

  scope {
    scope_name        = "cache-stats.write"
    scope_description = "Cross-tenant write access to /cache-stats (cache-stats-router only)"
  }
}

# cache-stats-router service identity. The router Lambda exchanges
# (client_id, client_secret) for a JWT at /oauth2/token and uses that
# JWT to call backend-rs /cache-stats?service_org_id=<tenant>.
#
# The `custom:service_caller` claim is NOT settable on this client_credentials
# token by Cognito alone — it requires a Pre-Token Generation Lambda
# trigger on the user pool. The trigger Lambda inspects
# `event.callerContext.clientId` and sets the custom claim when it
# matches one of the configured service client IDs. See
# `lambdas/cognito-token-customizer/` for the trigger source.
resource "aws_cognito_user_pool_client" "cache_stats_router" {
  count        = var.enable_m2m_clients ? 1 : 0
  name         = "${var.app_name}-cache-stats-router"
  user_pool_id = aws_cognito_user_pool.main.id

  generate_secret = true

  # ALLOW_CUSTOM_AUTH is intentionally NOT set — this client only
  # supports the client_credentials grant; no user-side flow.
  explicit_auth_flows = []

  allowed_oauth_flows                  = ["client_credentials"]
  allowed_oauth_flows_user_pool_client = true
  allowed_oauth_scopes                 = ["maestro-api/cache-stats.write"]

  # Short access-token lifetime — the router refreshes per-invocation,
  # and a leaked token is high-impact (cross-tenant write).
  access_token_validity = 1
  token_validity_units {
    access_token  = "hours"
    id_token      = "hours"
    refresh_token = "days"
  }

  prevent_user_existence_errors = "ENABLED"

  depends_on = [aws_cognito_resource_server.maestro_api]
}

output "cache_stats_router_client_id" {
  value     = var.enable_m2m_clients ? aws_cognito_user_pool_client.cache_stats_router[0].id : null
  sensitive = true
}

output "cache_stats_router_client_secret" {
  value     = var.enable_m2m_clients ? aws_cognito_user_pool_client.cache_stats_router[0].client_secret : null
  sensitive = true
}

# User Groups
resource "aws_cognito_user_group" "admin" {
  name         = "admin"
  user_pool_id = aws_cognito_user_pool.main.id
  description  = "Administrators with full access"
}

resource "aws_cognito_user_group" "pentester" {
  name         = "pentester"
  user_pool_id = aws_cognito_user_pool.main.id
  description  = "Security testers with assessment access"
}

resource "aws_cognito_user_group" "viewer" {
  name         = "viewer"
  user_pool_id = aws_cognito_user_pool.main.id
  description  = "Read-only access to reports"
}

# Canonical view-only role. Members can sign in and view everything but cannot
# mutate any state — enforced both in the desktop client and server-side in the
# backend (any mutating request from this group is rejected with 403). The
# legacy "viewer" group above is honored as an alias by the same enforcement.
resource "aws_cognito_user_group" "read_only" {
  name         = "read_only"
  user_pool_id = aws_cognito_user_pool.main.id
  description  = "View-only access — can see everything, mutate nothing"
}

# Outputs
output "user_pool_id" {
  value = aws_cognito_user_pool.main.id
}

output "user_pool_arn" {
  value = aws_cognito_user_pool.main.arn
}

output "app_client_id" {
  value = aws_cognito_user_pool_client.web.id
}

output "app_client_secret" {
  value     = aws_cognito_user_pool_client.web.client_secret
  sensitive = true
}

output "desktop_client_id" {
  value = aws_cognito_user_pool_client.desktop.id
}

output "domain" {
  value = "https://${aws_cognito_user_pool_domain.main.domain}.auth.${data.aws_region.current.name}.amazoncognito.com"
}

data "aws_region" "current" {}
