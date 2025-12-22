package sec_iac.ai_ml.security

import rego.v1

# AWS: Deny wildcard SageMaker actions in IAM policies
deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "aws_iam_role_policy"
    statement := resource.change.after.policy.Statement[_]
    action := statement.Action[_]
    contains(action, "*")
    contains(statement.Resource[_], "sagemaker")
    msg := sprintf("AWS IAM policy '%s' contains forbidden wildcard for SageMaker", [resource.address])
}

# Azure: Deny broad Contributor role on ML scopes
deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "azurerm_role_assignment"
    resource.change.after.role_definition_name == "Contributor"
    contains(lower(resource.change.after.scope), "machinelearning")
    msg := sprintf("Azure role assignment '%s' uses forbidden broad 'Contributor' on ML scope", [resource.address])
}