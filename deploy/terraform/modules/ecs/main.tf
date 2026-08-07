# ECS Module

variable "environment" {
  type = string
}

variable "vpc_id" {
  type = string
}

variable "public_subnet_ids" {
  type = list(string)
}

variable "private_subnet_ids" {
  type = list(string)
}

variable "container_image" {
  type = string
}

variable "container_port" {
  type = number
}

variable "cpu" {
  type = number
}

variable "memory" {
  type = number
}

variable "desired_count" {
  type = number
}

variable "environment_variables" {
  type = map(string)
}

variable "secrets" {
  type    = map(string)
  default = {}
}

variable "rds_security_group_id" {
  type = string
}

variable "s3_bucket_arn" {
  type = string
}

variable "certificate_arn" {
  type    = string
  default = ""
}

variable "enable_https" {
  description = "Whether to create an HTTPS listener on the ALB. When true, certificate_arn must be set. Use this instead of deriving from certificate_arn so the value is known at plan time (cert ARNs from aws_acm_certificate_validation are unknown until apply)."
  type        = bool
  default     = true
}

variable "cross_account_ecr_repo_arn" {
  description = "ARN of a cross-account ECR repository the execution role should be allowed to pull from. Empty string = same-account pulls only (AmazonECSTaskExecutionRolePolicy suffices)."
  type        = string
  default     = ""
}

variable "cognito_user_pool_arn" {
  description = "ARN of the Cognito user pool the backend administers via /api/v1/users. Empty string disables user-management IAM entirely — appropriate for local-auth deployments. Required when auth_provider=cognito."
  type        = string
  default     = ""
}

variable "assessment_role_arn" {
  description = "ARN of the read-only cloud-assessment role the backend may assume to broker creds to the desktop (POST /cloud/assume). Empty string disables the assume-role grant. The assessment role's trust policy must name this task role in return (customer-cloud-assessment trust_mode=backend)."
  type        = string
  default     = ""
}

# ECS Cluster
resource "aws_ecs_cluster" "main" {
  name = "pentest-${var.environment}"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }

  tags = {
    Name = "pentest-${var.environment}-cluster"
  }
}

# CloudWatch Log Group
resource "aws_cloudwatch_log_group" "main" {
  name              = "/ecs/pentest-${var.environment}"
  retention_in_days = 30

  tags = {
    Name = "pentest-${var.environment}-logs"
  }
}

# IAM Role for ECS Task Execution
resource "aws_iam_role" "ecs_execution" {
  name = "pentest-${var.environment}-ecs-execution"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "ecs_execution" {
  role       = aws_iam_role.ecs_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role_policy" "ecs_execution_secrets" {
  count = length(var.secrets) > 0 ? 1 : 0

  name = "secrets-access"
  role = aws_iam_role.ecs_execution.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue"
        ]
        Resource = values(var.secrets)
      }
    ]
  })
}

# Cross-account ECR pull. Required when the container image lives in a
# different AWS account than the one running this ECS task (the standard
# Maestro customer deployment — image is in Groovy's ECR).
#
# Both ends must agree: Groovy's ECR repo policy must also list this
# account's ID. See deploy/terraform/platform-ecr/.
resource "aws_iam_role_policy" "ecs_execution_cross_account_ecr" {
  count = var.cross_account_ecr_repo_arn != "" ? 1 : 0

  name = "cross-account-ecr-pull"
  role = aws_iam_role.ecs_execution.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "GetAuthToken"
        Effect   = "Allow"
        Action   = ["ecr:GetAuthorizationToken"]
        Resource = "*"
      },
      {
        Sid    = "PullImage"
        Effect = "Allow"
        Action = [
          "ecr:BatchCheckLayerAvailability",
          "ecr:BatchGetImage",
          "ecr:GetDownloadUrlForLayer",
          "ecr:DescribeImages",
          "ecr:DescribeRepositories",
        ]
        Resource = var.cross_account_ecr_repo_arn
      },
    ]
  })
}

# IAM Role for ECS Task
resource "aws_iam_role" "ecs_task" {
  name = "pentest-${var.environment}-ecs-task"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "ecs_task_s3" {
  name = "s3-access"
  role = aws_iam_role.ecs_task.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject",
          "s3:ListBucket"
        ]
        Resource = [
          var.s3_bucket_arn,
          "${var.s3_bucket_arn}/*"
        ]
      }
    ]
  })
}

# Cloud-assessment credential broker: lets the backend assume the
# read-only assessment role so it can hand short-lived creds to the
# desktop (POST /cloud/assume). Scoped to the single configured role ARN —
# the assessment role's trust policy must name THIS task role in return.
# Disabled (count 0) when no assessment role is configured.
resource "aws_iam_role_policy" "ecs_task_assume_assessment" {
  count = var.assessment_role_arn != "" ? 1 : 0

  name = "assume-assessment-role"
  role = aws_iam_role.ecs_task.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "sts:AssumeRole"
        Resource = var.assessment_role_arn
      }
    ]
  })
}

# Cognito admin permissions for the /api/v1/users backend routes
# (invite, list, disable, resend, change role). Scoped to the single
# Groovy-owned user pool — the tenancy guard `ALLOWED_ORG_ID` still
# prevents one org's admin from touching another org's users.
resource "aws_iam_role_policy" "ecs_task_cognito_admin" {
  count = var.cognito_user_pool_arn != "" ? 1 : 0

  name = "cognito-admin"
  role = aws_iam_role.ecs_task.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "cognito-idp:AdminCreateUser",
          "cognito-idp:AdminDisableUser",
          "cognito-idp:AdminEnableUser",
          "cognito-idp:AdminGetUser",
          "cognito-idp:AdminListGroupsForUser",
          "cognito-idp:AdminAddUserToGroup",
          "cognito-idp:AdminRemoveUserFromGroup",
          "cognito-idp:ListUsers",
          "cognito-idp:ListUsersInGroup",
        ]
        Resource = var.cognito_user_pool_arn
      },
    ]
  })
}

# Security Group for ECS Tasks
resource "aws_security_group" "ecs" {
  name        = "pentest-${var.environment}-ecs-sg"
  description = "Security group for ECS tasks"
  vpc_id      = var.vpc_id

  ingress {
    description     = "HTTP from ALB"
    from_port       = var.container_port
    to_port         = var.container_port
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "pentest-${var.environment}-ecs-sg"
  }
}

# Allow ECS to connect to RDS
resource "aws_security_group_rule" "rds_from_ecs" {
  type                     = "ingress"
  from_port                = 5432
  to_port                  = 5432
  protocol                 = "tcp"
  security_group_id        = var.rds_security_group_id
  source_security_group_id = aws_security_group.ecs.id
}

# Security Group for ALB
resource "aws_security_group" "alb" {
  name        = "pentest-${var.environment}-alb-sg"
  description = "Security group for ALB"
  vpc_id      = var.vpc_id

  ingress {
    description = "HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTP (redirect)"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "pentest-${var.environment}-alb-sg"
  }
}

# Application Load Balancer
resource "aws_lb" "main" {
  name               = "pentest-${var.environment}"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = var.public_subnet_ids

  enable_deletion_protection = var.environment == "prod"

  tags = {
    Name = "pentest-${var.environment}-alb"
  }
}

# ALB Target Group
resource "aws_lb_target_group" "main" {
  name        = "pentest-${var.environment}"
  port        = var.container_port
  protocol    = "HTTP"
  vpc_id      = var.vpc_id
  target_type = "ip"

  health_check {
    enabled             = true
    healthy_threshold   = 2
    unhealthy_threshold = 3
    timeout             = 5
    interval            = 30
    path                = "/health"
    matcher             = "200"
  }

  tags = {
    Name = "pentest-${var.environment}-tg"
  }
}

# ALB Listener (HTTPS)
resource "aws_lb_listener" "https" {
  count = var.enable_https ? 1 : 0

  load_balancer_arn = aws_lb.main.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.main.arn
  }
}

# ALB Listener (HTTP - redirect to HTTPS or direct if no cert)
resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.main.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = var.enable_https ? "redirect" : "forward"

    dynamic "redirect" {
      for_each = var.enable_https ? [1] : []
      content {
        port        = "443"
        protocol    = "HTTPS"
        status_code = "HTTP_301"
      }
    }

    target_group_arn = var.enable_https ? null : aws_lb_target_group.main.arn
  }
}

# ECS Task Definition
resource "aws_ecs_task_definition" "main" {
  family                   = "pentest-${var.environment}"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.cpu
  memory                   = var.memory
  execution_role_arn       = aws_iam_role.ecs_execution.arn
  task_role_arn            = aws_iam_role.ecs_task.arn

  container_definitions = jsonencode([
    {
      name  = "api"
      image = var.container_image

      portMappings = [
        {
          containerPort = var.container_port
          hostPort      = var.container_port
          protocol      = "tcp"
        }
      ]

      environment = [
        for key, value in var.environment_variables : {
          name  = key
          value = value
        }
      ]

      secrets = [
        for key, arn in var.secrets : {
          name      = key
          valueFrom = arn
        }
      ]

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.main.name
          "awslogs-region"        = data.aws_region.current.name
          "awslogs-stream-prefix" = "api"
        }
      }

      # No container-level healthCheck. The ALB target group already
      # health-checks `/health`, and that check is authoritative for ECS
      # service health. Dropping this block makes the task definition
      # language-agnostic — the previous Python `import httpx` variant
      # only worked on the Python image. Any backend that serves 200 on
      # `/health` (Rust, Python, or otherwise) is now valid.
    }
  ])

  tags = {
    Name = "pentest-${var.environment}-task"
  }
}

# ECS Service
resource "aws_ecs_service" "main" {
  name            = "pentest-${var.environment}"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.main.arn
  desired_count   = var.desired_count
  launch_type     = "FARGATE"

  network_configuration {
    security_groups  = [aws_security_group.ecs.id]
    subnets          = var.private_subnet_ids
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.main.arn
    container_name   = "api"
    container_port   = var.container_port
  }

  deployment_maximum_percent         = 200
  deployment_minimum_healthy_percent = 100

  lifecycle {
    ignore_changes = [desired_count]
  }

  tags = {
    Name = "pentest-${var.environment}-service"
  }
}

# Auto Scaling
resource "aws_appautoscaling_target" "main" {
  max_capacity       = 10
  min_capacity       = var.desired_count
  resource_id        = "service/${aws_ecs_cluster.main.name}/${aws_ecs_service.main.name}"
  scalable_dimension = "ecs:service:DesiredCount"
  service_namespace  = "ecs"
}

resource "aws_appautoscaling_policy" "cpu" {
  name               = "pentest-${var.environment}-cpu"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.main.resource_id
  scalable_dimension = aws_appautoscaling_target.main.scalable_dimension
  service_namespace  = aws_appautoscaling_target.main.service_namespace

  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageCPUUtilization"
    }
    target_value = 70.0
  }
}

data "aws_region" "current" {}

# Outputs
output "alb_dns_name" {
  value = aws_lb.main.dns_name
}

# Canonical hosted zone of the ALB itself — needed to write a Route 53 ALIAS
# record at the caller. An ALIAS (rather than a CNAME) is what lets the API
# domain be an apex, and it resolves without an extra DNS hop. The managed
# The managed path doesn't use this because Groovy writes those records in
# its own zone; maestro-self-host does, in the operator's zone.
output "alb_zone_id" {
  value = aws_lb.main.zone_id
}

output "cluster_name" {
  value = aws_ecs_cluster.main.name
}

output "cluster_arn" {
  value = aws_ecs_cluster.main.arn
}

output "service_name" {
  value = aws_ecs_service.main.name
}

output "task_role_arn" {
  description = "ARN of the ECS task role. Use as backend_role_arn in customer-cloud-assessment (trust_mode=backend) so the assessment role trusts this backend."
  value       = aws_iam_role.ecs_task.arn
}
