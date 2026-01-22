# ==================== Networking for Isolation ====================
data "aws_vpc" "default" {
  default = true
}
data "aws_subnets" "default" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }
}

resource "aws_security_group" "sagemaker" {
  name   = "${var.project_name}-sagemaker-sg"
  vpc_id = data.aws_vpc.default.id

  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"] # Your VPC CIDR
    description = "Allow HTTPS traffic to internal VPC endpoints only"
  }
  tags = local.common_tags

}
# SageMaker API & Runtime Interface Endpoints (PrivateLink) - this enforces private-only access
resource "aws_vpc_endpoint" "sagemaker_api" {
  vpc_id              = data.aws_vpc.default.id
  service_name        = "com.amazonaws.${var.region}.sagemaker.api"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = data.aws_subnets.default.ids
  security_group_ids  = [aws_security_group.sagemaker.id]
  private_dns_enabled = true
  tags                = local.common_tags
}


resource "aws_vpc_endpoint" "sagemaker_runtime" {
  vpc_id              = data.aws_vpc.default.id
  service_name        = "com.amazonaws.${var.region}.sagemaker.runtime"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = data.aws_subnets.default.ids
  security_group_ids  = [aws_security_group.sagemaker.id]
  private_dns_enabled = true
  tags                = local.common_tags
}

# S3 Gateway Endpoint (for private S3 access)
resource "aws_vpc_endpoint" "s3" {
  vpc_id            = data.aws_vpc.default.id
  service_name      = "com.amazonaws.${var.region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = data.aws_vpc.default.main_route_table_id != "" ? [data.aws_vpc.default.main_route_table_id] : null
  tags              = local.common_tags
}

# ==================== S3 Bucket (Data Residency) ====================
resource "aws_s3_bucket" "ml_data" {
  bucket = "${var.project_name}-ml-data-2025"
  tags   = local.common_tags
}

# ==================== IAM Role (Least Privilege) ====================
resource "aws_iam_role" "sagemaker_execution_role" {
  name = "${var.project_name}-sagemaker-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "sagemaker.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "sagemaker_full" {
  role       = aws_iam_role.sagemaker_execution_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"
}

resource "aws_iam_role_policy" "s3_access" {
  name = "S3Access"
  role = aws_iam_role.sagemaker_execution_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject", "s3:PutObject", "s3:ListBucket"]
      Resource = [aws_s3_bucket.ml_data.arn, "${aws_s3_bucket.ml_data.arn}/*"]
    }]
  })
}

# ==================== SageMaker Model (VPC config here is valid) ====================
resource "aws_sagemaker_model" "superman" {
  name                     = "${var.project_name}-model"
  execution_role_arn       = aws_iam_role.sagemaker_execution_role.arn
  enable_network_isolation = true

  primary_container {
    image          = "763104318107.dkr.ecr.${var.region}.amazonaws.com/tensorflow-training:2.13.1-cpu.py310-ubuntu20.04-v1"
    model_data_url = "s3://${aws_s3_bucket.ml_data.bucket}/model/placeholder.tar.gz" # dummy
  }

  # VPC config on the model controls training/job access to private resources
  vpc_config {
    security_group_ids = [aws_security_group.sagemaker.id]
    subnets            = data.aws_subnets.default.ids
  }

  tags = {
    signature = "sha256-abc123456789def"
    version   = "1.0.0"
  }
}

# ==================== SageMaker Endpoint Configuration (NO vpc_config, NO data_capture_config) ====================
resource "aws_sagemaker_endpoint_configuration" "superman" {
  name = "${var.project_name}-ep-config"

  production_variants {
    initial_instance_count = 1
    instance_type          = "ml.t2.medium"
    model_name             = aws_sagemaker_model.superman.name
    variant_name           = "AllTraffic"
  }
}

# ==================== SageMaker Endpoint (Private via VPC Endpoints) ====================
resource "aws_sagemaker_endpoint" "superman" {
  name                 = "${var.project_name}-endpoint"
  endpoint_config_name = aws_sagemaker_endpoint_configuration.superman.name
}

# ==================== Optional: Private Notebook Instance ====================
resource "aws_sagemaker_notebook_instance" "secure_notebook" {
  name                   = "${var.project_name}-notebook"
  instance_type          = "ml.t3.medium"
  role_arn               = aws_iam_role.sagemaker_execution_role.arn
  subnet_id              = data.aws_subnets.default.ids[0]
  security_groups        = [aws_security_group.sagemaker.id]
  direct_internet_access = "Disabled"
}