package sec_iac.ai_ml.security

import rego.v1

# AWS: Require SageMaker runtime VPC endpoint if any SageMaker resources exist
deny contains msg if {
    any_sagemaker_resources
    not any_sagemaker_runtime_endpoint
    msg := "AWS SageMaker real-time endpoints require private VPC endpoint (sagemaker.runtime)"
}

any_sagemaker_resources if {
    resource := input.resource_changes[_]
    startswith(resource.type, "aws_sagemaker_")
}

any_sagemaker_runtime_endpoint if {
    resource := input.resource_changes[_]
    resource.type == "aws_vpc_endpoint"
    contains(resource.change.after.service_name, "sagemaker.runtime")
}

# Azure: Public access must be disabled
deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "azurerm_machine_learning_workspace"
    resource.change.after.public_network_access_enabled == true
    msg := sprintf("Azure ML workspace '%s' must have public_network_access_enabled = false", [resource.address])
}

# Azure: Require private endpoints for dependencies
deny contains msg if {
    any_azure_ml_workspace
    not any_azure_private_endpoints
    msg := "Azure ML workspace requires private endpoints on dependencies (Key Vault, Storage, ACR)"
}

any_azure_ml_workspace if input.resource_changes[_].type == "azurerm_machine_learning_workspace"

any_azure_private_endpoints if {
    resource := input.resource_changes[_]
    resource.type == "azurerm_private_endpoint"
}