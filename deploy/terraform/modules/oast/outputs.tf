output "oast_domain" {
  description = "The domain the listener is authoritative for. This is MAESTRO_OAST_SERVER for the MCP server."
  value       = var.oast_domain
}

output "public_ip" {
  description = "Static EIP the delegation's glue records point at."
  value       = aws_eip.oast.public_ip
}

output "nameservers" {
  description = "NS record values for the delegation."
  value       = local.nameservers
}

output "nameserver_glue" {
  description = <<-EOT
    The delegation a parent zone must publish, as {name => address}. When
    create_ns_delegation is false this is the hand-off payload: send it to
    whoever operates the parent zone so they can create the NS set plus these
    glue A records. Without the glue, resolvers cannot bootstrap the delegation.
  EOT
  value       = { for ns in local.nameservers : ns => aws_eip.oast.public_ip }
}

output "token_secret_arn" {
  description = "Secrets Manager ARN holding the polling auth token. Created EMPTY — populate it out of band, then restart the listener (see README)."
  value       = aws_secretsmanager_secret.token.arn
}

output "token_secret_name" {
  description = "Secret name, for the put-secret-value call in the README."
  value       = aws_secretsmanager_secret.token.name
}

output "instance_id" {
  description = "Instance id, for `aws ssm start-session --target <id>`."
  value       = aws_instance.oast.id
}

output "log_group" {
  description = "CloudWatch log group carrying the listener log."
  value       = aws_cloudwatch_log_group.oast.name
}
