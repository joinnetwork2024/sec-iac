variable "aws_region" {
  description = "The AWS region"
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

variable "vault_addr" {
  description = "Vault address"
  type        = string
  default     = "http://192.168.1.125:30222"
}

variable "vaultroleid" {
  description = "vault role id"
  type        = string
  default     = "a74828d4-c31d-2c67-5cb4-9f127fb93f0f"
}

variable "vaultsecretid" {
  description = "vault secret id"
  type        = string
  default     = "c6c74c3d-a106-a1c0-e3af-d850c374eca3"
}



# variable "db_password" {
#   description = "The master password for the RDS database."
#   type        = string
#   sensitive   = true
#   validation {
#     condition     = length(var.db_password) >= 12
#     error_message = "The database password must be at least 12 characters long."
#   }
# }

# variable "allowed_ssh_cidr" {
#   description = "A list of CIDR blocks allowed to SSH into the EC2 instances. MUST be restricted to a Bastion host or VPN."
#   type        = list(string)
#   # REMOVED: default = ["0.0.0.0/0"]
#   # This change forces the user to provide a safe, specific IP range.
# }