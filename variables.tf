variable "aws_region" {
  description = "The AWS region "
  type        = string
  default     = "eu-west-2"
}

variable "project_name" {
  description = "The name of the project, used for naming resources."
  type        = string
  default     = "test"
}

variable "tags" {
  description = "A map of tags to apply to all resources."
  type        = map(string)
  default = {
    env  = "prod"
    team = "devops"
  }
}

variable "db_password" {
  description = "The master password for the RDS database."
  type        = string
  sensitive   = true
  validation {
    condition     = length(var.db_password) >= 12
    error_message = "The database password must be at least 12 characters long."
  }
}

variable "allowed_ssh_cidr" {
  description = "A list of CIDR blocks allowed to SSH into the EC2 instances. Should be restricted to a Bastion host or VPN."
  type        = list(string)
  default     = ["0.0.0.0/0"] # WARNING: Not secure for production. Replace with your IP.
}