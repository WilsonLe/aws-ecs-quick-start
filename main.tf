terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.16"
    }
  }
  required_version = ">= 1.2.0"
}

provider "aws" {
  region = var.region
}

# Setup VPC, Subnets, Internet Gateways
resource "aws_vpc" "terraform-test-vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true
  tags = {
    Name = "terraform-test-vpc"
  }
}

resource "aws_subnet" "terraform-test-subnet-1" {
  vpc_id            = aws_vpc.terraform-test-vpc.id
  cidr_block        = "10.0.0.0/24"
  availability_zone = "ap-southeast-3a"
  tags = {
    Name = "terraform-test-subnet-1"
  }
}

resource "aws_subnet" "terraform-test-subnet-2" {
  vpc_id            = aws_vpc.terraform-test-vpc.id
  cidr_block        = "10.0.1.0/24"
  availability_zone = "ap-southeast-3b"
  tags = {
    Name = "terraform-test-subnet-2"
  }
}

resource "aws_internet_gateway" "terraform-test-vpc-gateway" {
  vpc_id = aws_vpc.terraform-test-vpc.id
  tags = {
    Name = "terraform-test-vpc-gateway"
  }
}

resource "aws_security_group" "terraform-test-security-group" {
  name        = "terraform-test-security-group"
  description = "Allow terraform-test-security-group ports"
  vpc_id      = aws_vpc.terraform-test-vpc.id

  ingress {
    description = "TLS from VPC"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "NFS from VPC"
    from_port   = 2049
    to_port     = 2049
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.terraform-test-vpc.cidr_block]
  }

  ingress {
    description = "HTTP from VPC"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "Strapi from VPC"
    from_port   = 1337
    to_port     = 1337
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "PostgreSQL from VPC"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["140.141.4.62/32"]
    self        = true
  }

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  tags = {
    Name = "terraform-test-security-group"
  }
}

resource "aws_db_subnet_group" "terraform-test-subnet-group" {
  name       = "terraform-test-subnet-group"
  subnet_ids = [aws_subnet.terraform-test-subnet-1.id, aws_subnet.terraform-test-subnet-2.id]

  tags = {
    Name = "terraform-test-subnet-group"
  }
}

resource "aws_route_table" "terraform-test-route-table" {
  vpc_id = aws_vpc.terraform-test-vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.terraform-test-vpc-gateway.id
  }

  tags = {
    Name = "terraform-test-route-table"
  }
}

resource "aws_route_table_association" "terraform-test-route-table-assoc-1" {
  subnet_id      = aws_subnet.terraform-test-subnet-1.id
  route_table_id = aws_route_table.terraform-test-route-table.id
}

resource "aws_route_table_association" "terraform-test-route-table-assoc-2" {
  subnet_id      = aws_subnet.terraform-test-subnet-2.id
  route_table_id = aws_route_table.terraform-test-route-table.id
}

# Setup Database
resource "aws_db_instance" "terraform-test-database" {
  allocated_storage      = 10
  identifier             = "terraform-test-database"
  db_name                = var.terraform-test-database-secrets.DATABASE_NAME
  engine                 = "postgres"
  engine_version         = "13.7"
  instance_class         = "db.t3.micro"
  username               = var.terraform-test-database-secrets.DATABASE_USERNAME
  password               = var.terraform-test-database-secrets.DATABASE_PASSWORD
  parameter_group_name   = "default.postgres13"
  publicly_accessible    = true
  skip_final_snapshot    = true
  apply_immediately      = true
  vpc_security_group_ids = [aws_security_group.terraform-test-security-group.id]
  db_subnet_group_name   = aws_db_subnet_group.terraform-test-subnet-group.name
}

# Setup Secret Manager
resource "aws_secretsmanager_secret" "terraform-test-storage-secrets" {
  name        = "terraform-test-storage-secrets"
  description = "access to terraform-test storage secrets"
}

resource "aws_secretsmanager_secret_version" "terraform-test-storage-secrets" {
  secret_id     = aws_secretsmanager_secret.terraform-test-storage-secrets.id
  secret_string = jsonencode(var.terraform-test-storage-secrets)
}

resource "aws_secretsmanager_secret" "terraform-test-database-secrets" {
  name        = "terraform-test-database-secrets"
  description = "access to terraform-test database secrets"
}

resource "aws_secretsmanager_secret_version" "terraform-test-database-secrets" {
  secret_id = aws_secretsmanager_secret.terraform-test-database-secrets.id
  secret_string = jsonencode({
    DATABASE_HOST     = "${aws_db_instance.terraform-test-database.address}"
    DATABASE_PORT     = "${var.terraform-test-database-secrets.DATABASE_PORT}"
    DATABASE_NAME     = "${var.terraform-test-database-secrets.DATABASE_NAME}"
    DATABASE_USERNAME = "${var.terraform-test-database-secrets.DATABASE_USERNAME}"
    DATABASE_PASSWORD = "${var.terraform-test-database-secrets.DATABASE_PASSWORD}"
    }
  )
}

resource "aws_secretsmanager_secret" "terraform-test-strapi-secrets" {
  name        = "terraform-test-strapi-secrets"
  description = "access to terraform-test strapi secrets"
}

resource "aws_secretsmanager_secret_version" "terraform-test-strapi-secrets" {
  secret_id     = aws_secretsmanager_secret.terraform-test-strapi-secrets.id
  secret_string = jsonencode(var.terraform-test-strapi-secrets)
}

# Setup bucket
resource "aws_s3_bucket" "wilsonle-terraform-test-bucket" {
  bucket = "wilsonle-terraform-test-bucket"
  tags = {
    Name = "wilsonle-terraform-test-bucket"
  }
}

resource "aws_iam_user" "terraform-test-bucket-user" {
  name = "terraform-test-bucket-user"
  tags = {
    Name = "terraform-test-bucket-user"
  }
}

resource "aws_iam_group" "terraform-test-bucket-user-group" {
  name = "terraform-test-bucket-user-group"
}

resource "aws_iam_user_group_membership" "terraform-test-user-group-membership" {
  user = aws_iam_user.terraform-test-bucket-user.name
  groups = [
    aws_iam_group.terraform-test-bucket-user-group.name,
  ]
}

data "aws_iam_policy_document" "bucket-user" {
  statement {
    actions = [
      "s3:PutObject",
      "s3:GetObject",
      "s3:ListBucket",
      "s3:DeleteObject",
      "s3:PutObjectAcl"
    ]
    resources = [
      aws_s3_bucket.wilsonle-terraform-test-bucket.arn,
      "${aws_s3_bucket.wilsonle-terraform-test-bucket.arn}/*",
    ]
  }
}

resource "aws_iam_policy" "terraform-test-bucket-user-policy" {
  name        = "terraform-test-bucket-user-policy"
  description = "Policy for bucket user"
  policy      = data.aws_iam_policy_document.bucket-user.json
}

resource "aws_iam_group_policy_attachment" "terraform-test-bucket-user-attach" {
  group      = aws_iam_group.terraform-test-bucket-user-group.name
  policy_arn = aws_iam_policy.terraform-test-bucket-user-policy.arn
}

resource "aws_s3_bucket_acl" "terraform-test-bucket-acl" {
  bucket = aws_s3_bucket.wilsonle-terraform-test-bucket.id
  acl    = "private"
}

data "aws_iam_policy_document" "allow_access_from_terraform_test_user" {
  statement {
    principals {
      type        = "AWS"
      identifiers = [aws_iam_user.terraform-test-bucket-user.arn]
    }
    actions = [
      "s3:PutObject",
      "s3:GetObject",
      "s3:ListBucket",
      "s3:DeleteObject",
      "s3:PutObjectAcl"
    ]
    resources = [
      aws_s3_bucket.wilsonle-terraform-test-bucket.arn,
      "${aws_s3_bucket.wilsonle-terraform-test-bucket.arn}/*",
    ]
  }
}

resource "aws_s3_bucket_policy" "allow_access_from_terraform_test_user" {
  bucket = aws_s3_bucket.wilsonle-terraform-test-bucket.id
  policy = data.aws_iam_policy_document.allow_access_from_terraform_test_user.json
}

resource "aws_s3_bucket_public_access_block" "terraform-test-bucket-public-access" {
  bucket                  = aws_s3_bucket.wilsonle-terraform-test-bucket.id
  block_public_acls       = false
  ignore_public_acls      = false
  block_public_policy     = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_cors_configuration" "terraform-test-bucket-cors" {
  bucket = aws_s3_bucket.wilsonle-terraform-test-bucket.id
  cors_rule {
    allowed_headers = ["*"]
    allowed_methods = ["GET"]
    allowed_origins = ["localhost"]
    expose_headers  = []
    max_age_seconds = 3000
  }
}

# Setup ECR
resource "aws_ecr_repository" "terraform-test-repo" {
  name                 = "terraform-test-repo"
  image_tag_mutability = "MUTABLE"
}

# Setup EFS
resource "aws_efs_file_system" "terraform-test-efs" {
  tags = {
    Name = "terraform-test-efs"
  }
}

resource "aws_efs_mount_target" "terraform-test-efs-mount-1" {
  file_system_id  = aws_efs_file_system.terraform-test-efs.id
  subnet_id       = aws_subnet.terraform-test-subnet-1.id
  security_groups = [aws_security_group.terraform-test-security-group.id]
}

resource "aws_efs_mount_target" "terraform-test-efs-mount-2" {
  file_system_id  = aws_efs_file_system.terraform-test-efs.id
  subnet_id       = aws_subnet.terraform-test-subnet-2.id
  security_groups = [aws_security_group.terraform-test-security-group.id]
}


# Setup ECS
resource "aws_ecs_cluster" "terraform-test-cluster" {
  name = "terraform-test-cluster"
  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}

data "aws_ecs_container_definition" "terraform-test-container-definition" {
  task_definition = aws_ecs_task_definition.terraform-test-task-definition.id
  container_name  = "terraform-test-container"
}

data "aws_iam_policy_document" "terraform-test-assume-task-exec" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "terraform-test-secret-reader" {
  statement {
    actions = [
      "secretsmanager:GetSecretValue",
      "secretsmanager:DescribeSecret"
    ]
    resources = [
      aws_secretsmanager_secret.terraform-test-storage-secrets.arn,
      aws_secretsmanager_secret.terraform-test-database-secrets.arn,
      aws_secretsmanager_secret.terraform-test-strapi-secrets.arn
    ]
  }
}

resource "aws_iam_policy" "terraform-test-secret-reader" {
  name        = "terraform-test-secret-reader"
  description = "Policy for task execution to read container secrets"
  policy      = data.aws_iam_policy_document.terraform-test-secret-reader.json
}

data "aws_iam_policy" "AmazonECSTaskExecutionRolePolicy" {
  name = "AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role" "terraform-test-task-exec-role" {
  name               = "terraform-test-task-exec-role"
  assume_role_policy = data.aws_iam_policy_document.terraform-test-assume-task-exec.json
  managed_policy_arns = [
    data.aws_iam_policy.AmazonECSTaskExecutionRolePolicy.arn,
    aws_iam_policy.terraform-test-secret-reader.arn
  ]
}

resource "aws_cloudwatch_log_group" "terraform-test-cloudwatch" {
  name = "terraform-test-cloudwatch"
  tags = {
    Name = "terraform-test-cloudwatch"
  }
}

resource "aws_ecs_task_definition" "terraform-test-task-definition" {
  family                   = "terraform-test-task-definition"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 256
  memory                   = 512
  task_role_arn            = aws_iam_role.terraform-test-task-exec-role.arn
  execution_role_arn       = aws_iam_role.terraform-test-task-exec-role.arn
  container_definitions = jsonencode([
    {
      "name"              = "terraform-test-container",
      "image"             = "dummy-image-tag",
      "memoryReservation" = 512,
      "workingDirectory"  = "/app",
      "mountPoints" = [
        {
          "readOnly"      = null,
          "containerPath" = "/app/public",
          "sourceVolume"  = "${aws_efs_file_system.terraform-test-efs.tags["Name"]}"
        },
        {
          "readOnly"      = null,
          "containerPath" = "/app/public/uploads",
          "sourceVolume"  = "${aws_efs_file_system.terraform-test-efs.tags["Name"]}"
        }
      ],
      "secrets" = [
        {
          "valueFrom" = "${aws_secretsmanager_secret.terraform-test-storage-secrets.arn}:AWS_ACCESS_KEY_ID::",
          "name"      = "AWS_ACCESS_KEY_ID"
        },
        {
          "valueFrom" = "${aws_secretsmanager_secret.terraform-test-storage-secrets.arn}:AWS_ACCESS_SECRET::",
          "name"      = "AWS_ACCESS_SECRET"
        },
        {
          "valueFrom" = "${aws_secretsmanager_secret.terraform-test-storage-secrets.arn}:AWS_BUCKET_NAME::",
          "name"      = "AWS_BUCKET_NAME"
        },
        {
          "valueFrom" = "${aws_secretsmanager_secret.terraform-test-storage-secrets.arn}:AWS_REGION::",
          "name"      = "AWS_REGION"
        },
        {
          "valueFrom" = "${aws_secretsmanager_secret.terraform-test-database-secrets.arn}:DATABASE_HOST::",
          "name"      = "DATABASE_HOST"
        },
        {
          "valueFrom" = "${aws_secretsmanager_secret.terraform-test-database-secrets.arn}:DATABASE_NAME::",
          "name"      = "DATABASE_NAME"
        },
        {
          "valueFrom" = "${aws_secretsmanager_secret.terraform-test-database-secrets.arn}:DATABASE_PASSWORD::",
          "name"      = "DATABASE_PASSWORD"
        },
        {
          "valueFrom" = "${aws_secretsmanager_secret.terraform-test-database-secrets.arn}:DATABASE_PORT::",
          "name"      = "DATABASE_PORT"
        },
        {
          "valueFrom" = "${aws_secretsmanager_secret.terraform-test-database-secrets.arn}:DATABASE_USERNAME::",
          "name"      = "DATABASE_USERNAME"
        },
        {
          "valueFrom" = "${aws_secretsmanager_secret.terraform-test-strapi-secrets.arn}:HOST::",
          "name"      = "HOST"
        },
        {
          "valueFrom" = "${aws_secretsmanager_secret.terraform-test-strapi-secrets.arn}:JWT_SECRET::",
          "name"      = "JWT_SECRET"
        },
        {
          "valueFrom" = "${aws_secretsmanager_secret.terraform-test-strapi-secrets.arn}:PORT::",
          "name"      = "PORT"
        },
        {
          "valueFrom" = "${aws_secretsmanager_secret.terraform-test-strapi-secrets.arn}:ADMIN_JWT_SECRET::",
          "name"      = "ADMIN_JWT_SECRET"
        },
        {
          "valueFrom" = "${aws_secretsmanager_secret.terraform-test-strapi-secrets.arn}:API_TOKEN_SALT::",
          "name"      = "API_TOKEN_SALT"
        },
        {
          "valueFrom" = "${aws_secretsmanager_secret.terraform-test-strapi-secrets.arn}:APP_KEYS::",
          "name"      = "APP_KEYS"
        },
      ],
      "logConfiguration" = {
        "logDriver" = "awslogs"
        "options" = {
          "awslogs-group"         = "${aws_cloudwatch_log_group.terraform-test-cloudwatch.tags["Name"]}"
          "awslogs-region"        = "${var.region}"
          "awslogs-stream-prefix" = "ecs"
        }
      }
    }
  ])
  volume {
    name = "terraform-test-efs"
    efs_volume_configuration {
      file_system_id     = aws_efs_file_system.terraform-test-efs.id
      root_directory     = "/"
      transit_encryption = "ENABLED"
      authorization_config {
        iam = "ENABLED"
      }
    }
  }
}

resource "aws_ecs_service" "terraform-test-service" {
  launch_type             = "FARGATE"
  name                    = "terraform-test-service"
  cluster                 = aws_ecs_cluster.terraform-test-cluster.id
  task_definition         = aws_ecs_task_definition.terraform-test-task-definition.arn
  desired_count           = 1
  enable_ecs_managed_tags = true
  network_configuration {
    subnets          = [aws_subnet.terraform-test-subnet-1.id, aws_subnet.terraform-test-subnet-2.id]
    security_groups  = [aws_security_group.terraform-test-security-group.id]
    assign_public_ip = true
  }
}


# Setup cloud build user
resource "aws_iam_user" "terraform-test-cloud-build" {
  name = "terraform-test-cloud-build"
  tags = {
    Name = "terraform-test-cloud-build"
  }
}

resource "aws_iam_group" "terraform-test-cloud-build-group" {
  name = "terraform-test-cloud-build-user-group"
}

resource "aws_iam_user_group_membership" "terraform-test-cloud-build-group-membership" {
  user = aws_iam_user.terraform-test-cloud-build.name
  groups = [
    aws_iam_group.terraform-test-cloud-build-group.name,
  ]
}

data "aws_iam_policy_document" "cloud-build" {
  statement {
    actions = [
      "ecr:GetAuthorizationToken",
      "ecs:DescribeTaskDefinition",
      "ecs:DescribeServices",
      "ecs:RegisterTaskDefinition",
      "ecs:UpdateService"
    ]
    resources = ["*"]
  }

  statement {
    actions = [
      "iam:PassRole"
    ]
    resources = [aws_iam_role.terraform-test-task-exec-role.arn]
  }

  statement {
    actions = [
      "ecr:GetDownloadUrlForLayer",
      "ecr:BatchGetImage",
      "ecr:CompleteLayerUpload",
      "ecr:DescribeImages",
      "ecr:UploadLayerPart",
      "ecr:InitiateLayerUpload",
      "ecr:BatchCheckLayerAvailability",
      "ecr:PutImage"
    ]
    resources = [aws_ecr_repository.terraform-test-repo.arn]
  }
}

resource "aws_iam_policy" "terraform-test-cloud-build-policy" {
  name        = "terraform-test-cloud-build-policy"
  description = "Policy for cloud builder"
  policy      = data.aws_iam_policy_document.cloud-build.json
}

resource "aws_iam_group_policy_attachment" "terraform-test-cloud-build-attach" {
  group      = aws_iam_group.terraform-test-cloud-build-group.name
  policy_arn = aws_iam_policy.terraform-test-cloud-build-policy.arn
}
