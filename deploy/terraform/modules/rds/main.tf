# RDS Module

variable "environment" {
  type = string
}

variable "vpc_id" {
  type = string
}

data "aws_vpc" "current" {
  id = var.vpc_id
}

variable "private_subnet_ids" {
  type = list(string)
}

variable "db_instance_class" {
  type = string
}

variable "db_name" {
  type = string
}

variable "db_username" {
  type = string
}

# Generate random password
resource "random_password" "db_password" {
  length  = 32
  special = false
}

# Store password in Secrets Manager
resource "aws_secretsmanager_secret" "db_password" {
  name = "pentest-${var.environment}-db-password"

  tags = {
    Name = "pentest-${var.environment}-db-password"
  }
}

resource "aws_secretsmanager_secret_version" "db_password" {
  secret_id     = aws_secretsmanager_secret.db_password.id
  secret_string = random_password.db_password.result
}

# Security Group
resource "aws_security_group" "rds" {
  name        = "pentest-${var.environment}-rds-sg"
  description = "Security group for RDS PostgreSQL"
  vpc_id      = var.vpc_id

  ingress {
    description = "PostgreSQL from VPC"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = [data.aws_vpc.current.cidr_block]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "pentest-${var.environment}-rds-sg"
  }
}

# DB Subnet Group
resource "aws_db_subnet_group" "main" {
  name       = "pentest-${var.environment}-db-subnet"
  subnet_ids = var.private_subnet_ids

  tags = {
    Name = "pentest-${var.environment}-db-subnet"
  }
}

# RDS Instance
resource "aws_db_instance" "main" {
  identifier = "pentest-${var.environment}"

  engine         = "postgres"
  engine_version = "16.13"
  instance_class = var.db_instance_class

  db_name  = var.db_name
  username = var.db_username
  password = random_password.db_password.result

  allocated_storage     = 20
  max_allocated_storage = 100
  storage_type          = "gp3"
  storage_encrypted     = true

  vpc_security_group_ids = [aws_security_group.rds.id]
  db_subnet_group_name   = aws_db_subnet_group.main.name

  multi_az            = var.environment == "prod"
  publicly_accessible = false
  skip_final_snapshot = var.environment != "prod"
  deletion_protection = var.environment == "prod"

  backup_retention_period = var.environment == "prod" ? 7 : 1
  backup_window           = "03:00-04:00"
  maintenance_window      = "Mon:04:00-Mon:05:00"

  performance_insights_enabled = var.environment == "prod"

  tags = {
    Name = "pentest-${var.environment}-db"
  }
}

# Outputs
output "db_endpoint" {
  value = aws_db_instance.main.endpoint
}

output "db_password" {
  value     = random_password.db_password.result
  sensitive = true
}

output "db_password_secret_arn" {
  value = aws_secretsmanager_secret.db_password.arn
}

output "security_group_id" {
  value = aws_security_group.rds.id
}
