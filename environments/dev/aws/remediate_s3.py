import boto3
import json
import logging

# Set up logging for CloudWatch
logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    s3 = boto3.client('s3')
    
    # 1. Log the incoming event for audit purposes
    logger.info(f"Received Security Hub Finding: {json.dumps(event)}")
    
    try:
        # 2. Extract findings from the EventBridge event
        findings = event.get('detail', {}).get('findings', [])
        
        for finding in findings:
            # 3. Identify the non-compliant S3 resource
            resources = finding.get('Resources', [])
            for resource in resources:
                if resource.get('Type') == 'AwsS3Bucket':
                    # Extract bucket name from ARN (arn:aws:s3:::my-bucket-name)
                    bucket_arn = resource.get('Id')
                    bucket_name = bucket_arn.split(':::')[-1]
                    
                    logger.info(f"Attempting to remediate public access for: {bucket_name}")
                    
                    # 4. Apply the 'Block Public Access' configuration (The Remediation)
                    s3.put_public_access_block(
                        Bucket=bucket_name,
                        PublicAccessBlockConfiguration={
                            'BlockPublicAcls': True,
                            'IgnorePublicAcls': True,
                            'BlockPublicPolicy': True,
                            'RestrictPublicBuckets': True
                        }
                    )
                    
                    logger.info(f"Successfully applied Public Access Block to {bucket_name}")

        return {
            'statusCode': 200,
            'body': json.dumps('Remediation successful')
        }

    except Exception as e:
        logger.error(f"Error during remediation: {str(e)}")
        raise e