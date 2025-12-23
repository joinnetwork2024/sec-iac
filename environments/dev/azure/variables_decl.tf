variable "location" {
  description = "Azure location - must be allowed by data residency policy"
  type        = string
  default     = "ukwest"
}

variable "project_name" {
  description = "Project name"
  type        = string
  default     = "sec-iac-azure"
}