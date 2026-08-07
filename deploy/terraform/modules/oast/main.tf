# =============================================================================
# OAST Module — self-hosted Interactsh out-of-band interaction server
# =============================================================================
#
# The listener behind the `oast` oracle in the Maestro verification layer
# (kali-mcp-pentest/docs/oracle-verification-layer.md). Blind vulnerability
# classes — blind SSRF, blind SQLi, XXE, blind SSTI — put nothing in the HTTP
# response. The only evidence the payload landed is the target calling back to a
# host we control. That callback IS the oracle's proof.
#
# We self-host because a callback carries the target's IP and frequently
# exfiltrated data. Sending that to a public instance (oast.fun and friends)
# would break the guarantee that assessment data stays with the customer, which
# is the whole reason Maestro runs in the customer's own account.
#
# -----------------------------------------------------------------------------
# WHY EC2, in a 100%-Fargate estate
# -----------------------------------------------------------------------------
# Three requirements defeat Fargate here:
#
#   1. udp/53. An ALB is L7-HTTP only. Every other service in this repo sits
#      behind an ALB; none of them need UDP. An NLB with UDP listeners could
#      front Fargate, but see (3).
#   2. A STABLE public IP. NS delegation needs glue A records, and an A record
#      needs an address that survives task replacement. Fargate public IPs are
#      ephemeral.
#   3. Certificate persistence. Interactsh obtains its own wildcard cert via
#      ACME — ACM keys cannot be exported to a host, so ACM is not an option.
#      A Fargate task with no persistent volume would re-issue on every restart
#      and hit Let's Encrypt's duplicate-certificate rate limit (5/week). EBS
#      makes this a non-problem; the EFS alternative is more moving parts than
#      the single instance it would be protecting.
#
# So: one instance, one EIP, one EBS volume. It is deliberately NOT an ASG —
# a second instance would answer DNS with a different ACME account state and
# fight over the EIP. Availability expectation is documented in README.md.
#
# -----------------------------------------------------------------------------
# ACCESS
# -----------------------------------------------------------------------------
# No SSH key, no port 22. Operator access is SSM Session Manager only, which is
# why the instance carries AmazonSSMManagedInstanceCore and needs egress 443.
# =============================================================================

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source = "hashicorp/aws"
      # The Route 53 zone lives in the master billing account; the caller passes
      # a provider that has assumed MaestroDNSWriter. Same shape as
      # modules/frontend/main.tf.
      configuration_aliases = [aws.dns]
    }
  }
}

locals {
  prefix = "${var.name}-${var.environment}"
  tags = merge(var.tags, {
    Component   = "oast"
    Environment = var.environment
  })

  # ns1/ns2 both resolve to the same address. Interactsh serves a single
  # authoritative nameserver; two NS records exist because some resolvers and
  # registrars are unhappy with a delegation that names only one.
  nameservers = [
    "ns1.${var.oast_domain}",
    "ns2.${var.oast_domain}",
  ]
}

# -----------------------------------------------------------------------------
# Auth token — gates who may poll for interactions.
#
# Created empty on purpose, exactly like the Anthropic master key in
# platform/main.tf: terraform should never hold the plaintext, because the value
# ends up in state. Populate out of band after apply (see README).
# -----------------------------------------------------------------------------
resource "aws_secretsmanager_secret" "token" {
  name        = "maestro-${var.environment}/oast/${var.name}-token"
  description = "Interactsh polling auth token for ${var.oast_domain}"
  tags        = local.tags
}

# -----------------------------------------------------------------------------
# Static address. Allocated as its own resource (not the instance's
# associate_public_ip_address) so the glue A records can reference it in the
# SAME apply, and so replacing the instance never changes the delegation.
# -----------------------------------------------------------------------------
resource "aws_eip" "oast" {
  domain = "vpc"
  tags   = merge(local.tags, { Name = "${local.prefix}-eip" })
}

# -----------------------------------------------------------------------------
# Security group.
#
# This is the only host in the estate that intentionally accepts arbitrary
# inbound traffic from anywhere — that is its function. It holds no customer
# data: interactions are ephemeral, in-memory, and polled out by correlation id.
# -----------------------------------------------------------------------------
resource "aws_security_group" "oast" {
  name        = "${local.prefix}-sg"
  description = "Interactsh OAST listener — authoritative DNS + HTTP(S) interaction capture"
  vpc_id      = var.vpc_id
  tags        = merge(local.tags, { Name = "${local.prefix}-sg" })
}

resource "aws_vpc_security_group_ingress_rule" "dns_udp" {
  security_group_id = aws_security_group.oast.id
  description       = "Authoritative DNS. The primary OAST signal — most blind payloads only ever resolve a name."
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 53
  to_port           = 53
  ip_protocol       = "udp"
}

resource "aws_vpc_security_group_ingress_rule" "dns_tcp" {
  security_group_id = aws_security_group.oast.id
  description       = "DNS over TCP — required for responses over 512 bytes and for resolvers that retry via TCP."
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 53
  to_port           = 53
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "http" {
  security_group_id = aws_security_group.oast.id
  description       = "HTTP interaction capture, and the ACME http-01 fallback."
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 80
  to_port           = 80
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "https" {
  security_group_id = aws_security_group.oast.id
  description       = "HTTPS interaction capture, and the polling API the oracle reads."
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "smtp" {
  count             = var.enable_smtp ? 1 : 0
  security_group_id = aws_security_group.oast.id
  description       = "SMTP interaction capture. Off by default — an open :25 attracts abuse reports."
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 25
  to_port           = 25
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "all" {
  security_group_id = aws_security_group.oast.id
  description       = "Outbound: ACME, SSM, CloudWatch, package installs."
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
}

# -----------------------------------------------------------------------------
# Instance role — SSM for access, CloudWatch for logs, and read of its own token.
# -----------------------------------------------------------------------------
resource "aws_iam_role" "oast" {
  name = "${local.prefix}-instance"
  tags = local.tags
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "ssm" {
  role       = aws_iam_role.oast.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role_policy_attachment" "cloudwatch" {
  role       = aws_iam_role.oast.name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
}

resource "aws_iam_role_policy" "read_token" {
  name = "read-own-token"
  role = aws_iam_role.oast.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["secretsmanager:GetSecretValue"]
      Resource = [aws_secretsmanager_secret.token.arn]
    }]
  })
}

resource "aws_iam_instance_profile" "oast" {
  name = "${local.prefix}-instance"
  role = aws_iam_role.oast.name
  tags = local.tags
}

resource "aws_cloudwatch_log_group" "oast" {
  name              = "/oast/${local.prefix}"
  retention_in_days = var.log_retention_days
  tags              = local.tags
}

data "aws_ami" "al2023" {
  most_recent = true
  owners      = ["amazon"]
  filter {
    name   = "name"
    values = ["al2023-ami-2023.*-kernel-6.1-x86_64"]
  }
}

resource "aws_instance" "oast" {
  ami                    = data.aws_ami.al2023.id
  instance_type          = var.instance_type
  subnet_id              = var.public_subnet_id
  vpc_security_group_ids = [aws_security_group.oast.id]
  iam_instance_profile   = aws_iam_instance_profile.oast.name

  # No key_name: access is SSM Session Manager only.

  metadata_options {
    http_tokens                 = "required" # IMDSv2 — this host is internet-facing
    http_endpoint               = "enabled"
    http_put_response_hop_limit = 1
  }

  root_block_device {
    volume_size           = var.root_volume_gb
    volume_type           = "gp3"
    encrypted             = true
    delete_on_termination = true
  }

  user_data = templatefile("${path.module}/user-data.sh.tftpl", {
    oast_domain        = var.oast_domain
    public_ip          = aws_eip.oast.public_ip
    token_secret_id    = aws_secretsmanager_secret.token.id
    interactsh_version = var.interactsh_version
    aws_region         = var.aws_region
    log_group          = aws_cloudwatch_log_group.oast.name
    acme_contact_email = var.acme_contact_email
    enable_smtp        = var.enable_smtp
  })

  # The EIP must exist before user_data renders (it bakes in the address), and
  # the token secret before the boot script tries to read it.
  depends_on = [aws_secretsmanager_secret.token]

  tags = merge(local.tags, { Name = "${local.prefix}" })
}

resource "aws_eip_association" "oast" {
  instance_id   = aws_instance.oast.id
  allocation_id = aws_eip.oast.id
}

# -----------------------------------------------------------------------------
# DNS delegation.
#
# Written into the PARENT zone (maestro.groovysec.com) via the aws.dns provider,
# which has assumed MaestroDNSWriter in the master account. Two record sets:
#
#   oast.maestro.groovysec.com      NS  ns1/ns2.oast.maestro.groovysec.com
#   ns1|ns2.oast.maestro...         A   <EIP>        ← in-zone glue
#
# The glue is mandatory: the nameservers for oast.maestro… live *inside*
# oast.maestro…, so without A records in the parent zone a resolver can never
# bootstrap the delegation.
#
# Gated because a customer-hosted deployment does not own this zone — see
# README "Customer-hosted".
# -----------------------------------------------------------------------------
resource "aws_route53_record" "delegation" {
  count           = var.create_ns_delegation ? 1 : 0
  provider        = aws.dns
  zone_id         = var.hosted_zone_id
  name            = var.oast_domain
  type            = "NS"
  ttl             = 300
  records         = local.nameservers
  allow_overwrite = true
}

resource "aws_route53_record" "glue" {
  for_each        = var.create_ns_delegation ? toset(local.nameservers) : toset([])
  provider        = aws.dns
  zone_id         = var.hosted_zone_id
  name            = each.value
  type            = "A"
  ttl             = 300
  records         = [aws_eip.oast.public_ip]
  allow_overwrite = true
}
