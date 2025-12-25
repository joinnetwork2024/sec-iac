package sec_iac.ai_ml.security

# --- AWS RULES ---

# AWS: Deny model deployment if model signature is missing
deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "aws_sagemaker_model"
    not resource.change.after.signature
    msg := sprintf("AWS SageMaker model '%s' must have a valid signature.", [resource.address])
}

# AWS: Deny deployment of models with an unapproved version
deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "aws_sagemaker_model"
    version := resource.change.after.version
    not approved_version(version)
    msg := sprintf("AWS SageMaker model '%s' version '%s' is not approved.", [resource.address, version])
}

# --- AZURE RULES ---

# Azure: Deny model deployment if model signature is missing
deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "azurerm_machine_learning_model"
    not resource.change.after.signature
    msg := sprintf("Azure ML model '%s' must have a valid signature.", [resource.address])
}

# Azure: Deny deployment of models with an unapproved version
deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "azurerm_machine_learning_model"
    version := resource.change.after.version
    not approved_version(version)
    msg := sprintf("Azure ML model '%s' version '%s' is not approved.", [resource.address, version])
}

# --- HELPER RULES ---

# Approved model versions
approved_version(version) if {
    valid_versions := {"1.0.0", "1.1.0", "2.0.0"}
    valid_versions[version]
}