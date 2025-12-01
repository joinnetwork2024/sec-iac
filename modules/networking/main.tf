# This module is a wrapper around the official Terraform AWS VPC module.
# It simplifies VPC creation by exposing only necessary variables and enforcing conventions.

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.5"

  name = "${var.project_name}-vpc"
  cidr = var.vpc_cidr

  azs             = var.azs
  private_subnets = [for k, v in var.azs : cidrsubnet(var.vpc_cidr, 8, k)]
  public_subnets  = [for k, v in var.azs : cidrsubnet(var.vpc_cidr, 8, k + length(var.azs))]

  # NAT Gateway for outbound internet access from private subnets
  enable_nat_gateway = true
  single_nat_gateway = false # Use one NAT gateway per AZ for high availability

  # DNS settings
  enable_dns_hostnames = true
  enable_dns_support   = true

  # Database subnet group for RDS
  create_database_subnet_group = true
  database_subnet_group_name   = "${var.project_name}-db-sng"

  tags = var.tags

  public_subnet_tags = {
    "kubernetes.io/role/elb" = "1"
  }

  private_subnet_tags = {
    "kubernetes.io/role/internal-elb" = "1"
  }
}