package sec_iac.ai_ml.security

import rego.v1

allowed_aws_regions := ["us-east-1", "eu-west-2"]
allowed_azure_locations := ["ukwest", "westus"]

# AWS
deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket"
    location := resource.change.after.region
    not array_contains(allowed_aws_regions, location)
    msg := sprintf("AWS S3 bucket '%s' in forbidden region '%s'", [resource.address, location])
}

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "aws_sagemaker_notebook_instance"
    location := resource.change.after.region
    not array_contains(allowed_aws_regions, location)
    msg := sprintf("SageMaker resource '%s' in forbidden region '%s'", [resource.address, location])
}

# Azure
deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "azurerm_storage_account"
    location := resource.change.after.location
    not array_contains(allowed_azure_locations, location)
    msg := sprintf("Azure Storage '%s' in forbidden location '%s'", [resource.address, location])
}

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "azurerm_machine_learning_workspace"
    location := resource.change.after.location
    not array_contains(allowed_azure_locations, location)
    msg := sprintf("Azure ML workspace '%s' in forbidden location '%s'", [resource.address, location])
}

array_contains(arr, elem) if arr[_] == elem