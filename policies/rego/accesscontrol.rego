package sec_iac.ai_ml.security

import rego.v1

# --- AWS: Deny wildcard actions for AI services ---
deny contains msg if {
    resource := input.resource_changes[_]
    # Target both inline policies and managed policies
    resource_types := {"aws_iam_role_policy", "aws_iam_policy", "aws_iam_user_policy"}
    resource.type in resource_types
    
    # Terraform provides policy as a JSON string; we must unmarshal it to inspect it
    policy := json.unmarshal(resource.change.after.policy)
    statement := policy.Statement[_]
    
    # Check if Action is a single string or an array
    action := get_actions(statement.Action)[_]
    
    # Logic: Deny if Action contains '*' and Resource targets SageMaker or Bedrock
    contains(action, "*")
    some res in get_resources(statement.Resource)
    regex.match("(?i)(sagemaker|bedrock|kms)", res)

    msg := sprintf("AWS IAM LINT: Policy '%s' contains forbidden wildcard '%s' for sensitive AI/Security services.", [resource.address, action])
}

# --- Azure: Deny broad Roles on ML Scopes ---
deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "azurerm_role_assignment"
    
    # Azure Best Practice: Check both Name and ID (Contributor ID: b24988ac-6180-42a0-ab88-20f7382dd24c)
    role_name := object.get(resource.change.after, "role_definition_name", "")
    role_id := object.get(resource.change.after, "role_definition_id", "")
    
    is_privileged_role(role_name, role_id)
    
    # Logic: Deny if scoped to Machine Learning or Key Vault
    scope := lower(resource.change.after.scope)
    regex.match("(?i)(machinelearningservices|keyvaults)", scope)

    msg := sprintf("AZURE RBAC LINT: Assignment '%s' uses broad 'Contributor/Owner' on a sensitive AI scope.", [resource.address])
}

# --- Helpers ---

get_actions(a) = a if is_array(a)
get_actions(a) = [a] if is_string(a)

get_resources(r) = r if is_array(r)
get_resources(r) = [r] if is_string(r)

is_privileged_role(name, id) if {
    privileged_names := {"Contributor", "Owner"}
    name in privileged_names
}
is_privileged_role(name, id) if {
    # Match common GUIDs for Contributor/Owner
    regex.match("(b24988ac-6180-42a0-ab88-20f7382dd24c|8e3af657-a8ff-443c-a75c-2fe8c4bcb635)", id)
}