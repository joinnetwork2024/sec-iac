package sec_iac.ai_ml.security

import rego.v1

# --- CONFIGURATION: Approved Identities ---
approved_aws_services := {"sagemaker.amazonaws.com"}
approved_azure_principals := {"ServicePrincipal", "UserAssigned"}

# ==========================================================
# 1. AWS IAM ROLE VALIDATION
# ==========================================================
deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "aws_iam_role"
    
    # Decode policy and find the service principal
    policy := json.unmarshal(resource.change.after.assume_role_policy)
    statement := policy.Statement[_]
    service := statement.Principal.Service
    
    not service in approved_aws_services
    msg := sprintf("AWS IAM ERROR [%s]: Unauthorized service '%s'. Must be: %v", [resource.name, service, approved_aws_services])
}

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "aws_iam_role"
    
    policy := json.unmarshal(resource.change.after.assume_role_policy)
    statement := policy.Statement[_]
    
    statement.Principal == "*"
    msg := sprintf("AWS CRITICAL RISK [%s]: Wildcard Principal (*) detected in Trust Policy!", [resource.name])
}

# ==========================================================
# 2. AZURE ROLE ASSIGNMENT VALIDATION
# ==========================================================
deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "azurerm_role_assignment"
    
    # Ensure identity type is a Managed Identity or Service Principal
    p_type := object.get(resource.change.after, "principal_type", "Unknown")
    not p_type in approved_azure_principals
    
    msg := sprintf("AZURE IAM ERROR [%s]: Invalid Principal Type '%s'. Use Managed Identity.", [resource.address, p_type])
}

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "azurerm_role_assignment"
    
    # Block Subscription-level assignments (Too broad for AI)
    scope := resource.change.after.scope
    regex.match("^/subscriptions/[^/]+$", scope)
    
    msg := sprintf("AZURE SCOPE RISK [%s]: AI roles must be scoped to Resource Groups, not the entire Subscription.", [resource.address])
}