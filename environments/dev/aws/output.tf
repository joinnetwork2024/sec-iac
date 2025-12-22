output "s3_bucket_name" {
  value = aws_s3_bucket.ml_data.bucket
}

output "sagemaker_endpoint_name" {
  value = aws_sagemaker_endpoint.superman.name
}