variable "project_name" {
  description = "The name of the project, used to prefix resource names."
  type        = string
}

variable "aws_region" {
  description = "The AWS region where resources will be deployed."
  type        = string
}

variable "vpc_cidr" {
  description = "The CIDR block for the VPC."
  type        = string
  default     = "10.0.0.0/16"
}

variable "azs" {
  description = "A list of Availability Zones to deploy subnets into."
  type        = list(string)
  default     = ["us-east-1a", "us-east-1b"] # Default to 2 AZs for HA
}

variable "tags" {
  description = "A map of tags to apply to the network resources."
  type        = map(string)
  default     = {}
}