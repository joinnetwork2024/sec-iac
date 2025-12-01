# output "alb_dns_name" {
#   description = "The public DNS name of the Application Load Balancer."
#   value       = module.alb.dns_name
# }

output "rds_endpoint" {
  description = "The connection endpoint for the RDS database instance."
  value       = module.rds.db_instance_address
  sensitive   = true
}

output "rds_db_name" {
  description = "The name of the database created in the RDS instance."
  value       = module.rds.db_instance_name
}

output "s3_bucket_id" {
  description = "The ID (name) of the S3 bucket for static assets."
  value       = module.s3_bucket.s3_bucket_id
}

# output "ec2_instance_id" {
#   description = "The ID of the EC2 application server instance."
#   value       = aws_instance.app_server.id
# }

output "vpc_id" {
  description = "The ID of the created VPC."
  value       = module.networking.vpc_id
}