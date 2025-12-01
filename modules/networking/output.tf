output "vpc_id" {
  description = "The ID of the VPC."
  value       = module.vpc.vpc_id
}

output "public_subnets" {
  description = "List of public subnet IDs."
  value       = module.vpc.public_subnets
}

output "private_subnets" {
  description = "List of private subnet IDs."
  value       = module.vpc.private_subnets
}

output "database_subnet_group_name" {
  description = "The name of the database subnet group created."
  value       = module.vpc.database_subnet_group_name
}
