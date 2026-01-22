# Enable Security Hub
resource "aws_securityhub_account" "main" {}

# Subscribe to Foundational Security Best Practices
resource "aws_securityhub_standards_subscription" "foundational" {
  depends_on    = [aws_securityhub_account.main]
  standards_arn = "arn:aws:securityhub:${var.region}::standards/aws-foundational-security-best-practices/v/1.0.0"
}

# Subscribe to CIS AWS Foundations Benchmark
resource "aws_securityhub_standards_subscription" "cis" {
  depends_on    = [aws_securityhub_account.main]
  standards_arn = "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0"
}

# 1. Package the Python Code
data "archive_file" "lambda_zip" {
  type        = "zip"
  source_file = "remediate_s3.py" # Ensure this file exists in your directory
  output_path = "lambda_function_payload.zip"
}

# 2. IAM Role for Lambda
resource "aws_iam_role" "remediation_role" {
  name = "sec-iac-remediation-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
    }]
  })
}

# 3. Least Privilege Policy: Only allow S3 Public Access Block & Logging
resource "aws_iam_role_policy" "remediation_policy" {
  name = "s3-remediation-permissions"
  role = aws_iam_role.remediation_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action   = ["s3:PutBucketPublicAccessBlock"]
        Effect   = "Allow"
        Resource = "*" # In prod, restrict to specific AI data buckets
      },
      {
        Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Effect   = "Allow"
        Resource = "arn:aws:logs:*:*:*"
      }
    ]
  })
}

# 4. The Lambda Function
resource "aws_lambda_function" "s3_fixer" {
  filename         = data.archive_file.lambda_zip.output_path
  function_name    = "sec-iac-s3-public-remediator"
  role             = aws_iam_role.remediation_role.arn
  handler          = "remediate_s3.lambda_handler"
  runtime          = "python3.10"
  tags             = local.common_tags
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256

  environment {
    variables = {
      LOG_LEVEL = "INFO"
    }
  }

}

# 5. Allow EventBridge to trigger the Lambda
resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.s3_fixer.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.remediate_s3_public.arn
}

# 6. The Trigger: Define the EventBridge Rule
resource "aws_cloudwatch_event_rule" "remediate_s3_public" {
  name        = "remediate-s3-public-access"
  description = "Triggers Lambda when Security Hub finds a public S3 bucket"
  tags        = local.common_tags
  # Filters for "S3.1" failure (Block Public Access disabled)
  event_pattern = jsonencode({
    "source" : ["aws.securityhub"],
    "detail-type" : ["Security Hub Findings - Imported"],
    "detail" : {
      "findings" : {
        "Compliance" : {
          "Status" : ["FAILED"]
        },
        "GeneratorId" : ["aws-foundational-security-best-practices/v/1.0.0/S3.1"]
      }
    }
  })
}

# 7. The Target: Connect the Rule to the Lambda Function
resource "aws_cloudwatch_event_target" "lambda_target" {
  rule      = aws_cloudwatch_event_rule.remediate_s3_public.name
  target_id = "SendToLambda"
  arn       = aws_lambda_function.s3_fixer.arn
}