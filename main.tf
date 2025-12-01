terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

locals {
  name = var.project_name
  tags = var.tags
}

# ------------------------------------------------------------------------------
# NETWORKING MODULE
# Deploys a VPC, subnets, and gateways using a local wrapper module.
# ------------------------------------------------------------------------------
module "networking" {
  source = "./modules/networking"

  project_name = local.name
  aws_region   = var.aws_region
  vpc_cidr     = "10.0.0.0/16"
  tags         = local.tags
}

# ------------------------------------------------------------------------------
# SECURITY GROUPS
# ------------------------------------------------------------------------------

# ALB Security Group: Allows inbound HTTP/HTTPS from anywhere
resource "aws_security_group" "alb_sg" {
  name        = "${local.name}-alb-sg"
  description = "Allow HTTP/HTTPS inbound traffic"
  vpc_id      = module.networking.vpc_id

  ingress {
    protocol    = "tcp"
    from_port   = 80
    to_port     = 80
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    protocol    = "tcp"
    from_port   = 443
    to_port     = 443
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.tags, { Name = "${local.name}-alb-sg" })
}

# EC2 Security Group: Allows inbound traffic from ALB and SSH from a specific CIDR
resource "aws_security_group" "ec2_sg" {
  name        = "${local.name}-ec2-sg"
  description = "Allow traffic from ALB and SSH"
  vpc_id      = module.networking.vpc_id

  ingress {
    protocol        = "tcp"
    from_port       = 80
    to_port         = 80
    security_groups = [aws_security_group.alb_sg.id]
    description     = "Allow HTTP from ALB"
  }

  ingress {
    protocol    = "tcp"
    from_port   = 22
    to_port     = 22
    cidr_blocks = var.allowed_ssh_cidr
    description = "Allow SSH from allowed IPs"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.tags, { Name = "${local.name}-ec2-sg" })
}

# RDS Security Group: Allows inbound traffic from EC2 instances on the PostgreSQL port
resource "aws_security_group" "rds_sg" {
  name        = "${local.name}-rds-sg"
  description = "Allow inbound traffic from EC2 instances"
  vpc_id      = module.networking.vpc_id

  ingress {
    protocol        = "tcp"
    from_port       = 5432 # PostgreSQL port
    to_port         = 5432
    security_groups = [aws_security_group.ec2_sg.id]
    description     = "Allow PostgreSQL traffic from EC2"
  }

  tags = merge(local.tags, { Name = "${local.name}-rds-sg" })
}

# ------------------------------------------------------------------------------
# S3 BUCKET FOR STATIC ASSETS
# ------------------------------------------------------------------------------
module "s3_bucket" {
  source  = "terraform-aws-modules/s3-bucket/aws"
  version = "~> 3.15"

  bucket = "${local.name}-assets-${random_string.bucket_suffix.result}"
  tags   = local.tags

  # Security settings
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true

  # Versioning for recovery
  versioning = {
    enabled = true
  }

  # Server-side encryption
  server_side_encryption_configuration = {
    rule = {
      apply_server_side_encryption_by_default = {
        sse_algorithm = "AES256"
      }
    }
  }

  # Access logging
  control_object_ownership = true
  object_ownership         = "ObjectWriter"
  logging = {
    target_bucket = module.s3_logging_bucket.s3_bucket_id
    target_prefix = "log/"
  }
}

# Bucket for S3 access logs
module "s3_logging_bucket" {
  source  = "terraform-aws-modules/s3-bucket/aws"
  version = "~> 3.15"

  bucket = "${local.name}-access-logs-${random_string.bucket_suffix.result}"
  tags   = local.tags

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "random_string" "bucket_suffix" {
  length  = 8
  special = false
  upper   = false
}


# ------------------------------------------------------------------------------
# LOAD BALANCER (ALB)
# ------------------------------------------------------------------------------
# module "alb" {
#   source  = "terraform-aws-modules/alb/aws"
#   version = "~> 9.4"

#   name               = "${local.name}-alb"
#   load_balancer_type = "application"
#   vpc_id             = module.networking.vpc_id
#   subnets            = module.networking.public_subnets
#   security_groups    = [aws_security_group.alb_sg.id]

#   # -----------------------
#   # LISTENERS (v9.x syntax)
#   # -----------------------
#   listeners = [
#     {
#       port     = 80
#       protocol = "HTTP"

#       default_action = {
#         type             = "forward"
#         target_group_arn = module.alb.target_groups[0].arn
#       }
#     }
#   ]

#   # -----------------------
#   # TARGET GROUPS (v9.x syntax)
#   # -----------------------
#   # target_groups = [
#   #   {
#   #     name_prefix      = "app-"
#   #     backend_protocol = "HTTP"
#   #     backend_port     = 80
#   #     target_type      = "instance"

#   #     # ---- IMPORTANT ----
#   #     # TARGET MUST USE **id**, NOT target_id
#   #     # AND MUST BE A **LIST**, NOT A MAP
#   #     # ---------------------
#   #     targets = [
#   #       {
#   #         id   = aws_instance.app_server.id
#   #         port = 80
#   #       }
#   #     ]
#   #   }
#   # ]

#   tags = local.tags
# }


# ------------------------------------------------------------------------------
# DATABASE (RDS)
# ------------------------------------------------------------------------------
module "rds" {
  source  = "terraform-aws-modules/rds/aws"
  version = "~> 6.5"

  identifier = "${local.name}-db"

  engine               = "postgres"
  engine_version       = "15.5"
  family               = "postgres15"
  major_engine_version = "15"
  instance_class       = "db.t3.micro"
  allocated_storage    = 20

  db_name  = "${local.name}db"
  username = "dbadmin"
  password = var.db_password
  port     = 5432

  multi_az               = false # Set to true for production HA
  db_subnet_group_name   = module.networking.database_subnet_group_name
  vpc_security_group_ids = [aws_security_group.rds_sg.id]

  # Security
  publicly_accessible = false
  storage_encrypted   = true

  # Backups
  backup_retention_period = 7

  # Monitoring
  monitoring_interval = 60

  # Maintenance
  maintenance_window         = "Mon:00:00-Mon:03:00"
  backup_window              = "03:00-06:00"
  auto_minor_version_upgrade = true

  # Deletion protection
  deletion_protection = false # Set to true for production

  tags = local.tags
}