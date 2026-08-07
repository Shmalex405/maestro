# --- Identity -----------------------------------------------------------------

variable "name" {
  description = "Short module name; combines with environment into the resource prefix (e.g. maestro-oast-prod)."
  type        = string
  default     = "maestro-oast"
}

variable "environment" {
  description = "Deployment environment (prod / staging). Part of every resource name and tag."
  type        = string
}

variable "tags" {
  description = "Extra tags merged onto every resource."
  type        = map(string)
  default     = {}
}

variable "aws_region" {
  description = "Region the instance runs in. Used by the CloudWatch agent and the boot script's secret fetch."
  type        = string
}

# --- Networking ---------------------------------------------------------------

variable "vpc_id" {
  description = "VPC to place the listener in. Give OAST its own VPC unless you are comfortable with an accept-anything host sharing a network with identity-adjacent services."
  type        = string
}

variable "public_subnet_id" {
  description = "A PUBLIC subnet (route to an internet gateway). The listener must be directly reachable; there is no load balancer in front of it."
  type        = string
}

# --- DNS ----------------------------------------------------------------------

variable "oast_domain" {
  description = "Fully-qualified domain the listener is authoritative for, e.g. oast.maestro.groovysec.com. Interactsh mints per-session subdomains beneath it."
  type        = string

  # A caller that gates this module behind an *_enabled bool will pass its empty
  # default straight through. Without this the apply succeeds, the instance
  # boots, and the listener serves nothing — validation errors in seconds
  # instead. (A `check` block would only WARN and let the apply proceed.)
  validation {
    condition     = trimspace(var.oast_domain) != ""
    error_message = "oast_domain is required: a name beneath a domain you can delegate, e.g. oast.security.example.com. See modules/oast/README.md."
  }
}

variable "hosted_zone_id" {
  description = "Route 53 zone id of the PARENT zone that will hold the NS delegation and glue records. Ignored when create_ns_delegation is false."
  type        = string
  default     = ""
}

variable "create_ns_delegation" {
  description = <<-EOT
    Create the NS + glue records in the parent zone. True for a Groovy-operated
    listener (we own maestro.groovysec.com). False for a customer-hosted
    listener whose domain lives in a zone this stack cannot write to — in that
    case take `nameserver_glue` from the outputs and create the delegation
    wherever the parent zone actually lives.
  EOT
  type        = bool
  default     = true
}

# --- Instance -----------------------------------------------------------------

variable "instance_type" {
  description = "EC2 instance type. Interactsh is light; the listener is IO-bound on DNS, not CPU-bound."
  type        = string
  default     = "t3.small"
}

variable "root_volume_gb" {
  description = "Root EBS size. Holds the ACME account + issued certificates, which is the only state worth keeping."
  type        = number
  default     = 20
}

variable "interactsh_version" {
  description = "Pinned interactsh release to install. Pin it — a floating 'latest' means an unattended reboot can change the server's behaviour and its CLI flags."
  type        = string
  default     = "1.2.0"
}

variable "acme_contact_email" {
  description = "Contact address Let's Encrypt uses for expiry warnings. Required by the ACME account registration."
  type        = string

  validation {
    condition     = can(regex("^[^@[:space:]]+@[^@[:space:]]+\\.[^@[:space:]]+$", trimspace(var.acme_contact_email)))
    error_message = "acme_contact_email must be a real address: Let's Encrypt registers an ACME account with it, and registration fails against an empty or malformed value."
  }
}

# --- Optional surfaces --------------------------------------------------------

variable "enable_smtp" {
  description = "Also capture SMTP interactions on :25. Off by default — an open :25 attracts abuse reports and blocklisting, and very few payloads need it."
  type        = bool
  default     = false
}

variable "log_retention_days" {
  description = "CloudWatch retention for the listener log. Interaction bodies can contain target data; keep this short."
  type        = number
  default     = 30
}
