package sec_iac.ai_ml.security

import rego.v1

# Approved Internal CIDRs
whitelisted_internal_cidrs := {"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}

# --- AWS: Enforce SageMaker Network Isolation ---
deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "aws_sagemaker_model"
    
    # 1. Fetch the value, defaulting to 'null' if missing
    # 2. Check if the value is NOT exactly 'true'
    isolation := object.get(resource.change.after, "enable_network_isolation", null)
    isolation != true

    msg := sprintf("AWS SECURITY CRITICAL [%s]: SageMaker Model must have 'enable_network_isolation' set to true.", [resource.address])
}

# --- AZURE: Enforce AML Workspace Isolation ---
deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "azurerm_machine_learning_workspace"
    
    # Check if public access is enabled (should be false for sec-iac)
    public_access := object.get(resource.change.after, "public_network_access_enabled", true)
    public_access == true

    msg := sprintf("AZURE SECURITY CRITICAL [%s]: AML Workspace must have 'public_network_access_enabled' set to false.", [resource.address])
}

# --- AWS: Prevent Public Egress in SGs ---
deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "aws_security_group"
    
    # Check if tagged for AI (Your custom logic)
    tags := object.get(resource.change.after, "tags", {})
    tags["workload_type"] == "ai_inference"

    egress := resource.change.after.egress[_]
    cidr := object.get(egress, "cidr_blocks", [])[_]
    
    cidr == "0.0.0.0/0"
    msg := sprintf("AWS EXFILTRATION RISK [%s]: AI Security Group allows egress to 0.0.0.0/0.", [resource.address])
}

# --- AZURE: Prevent Public Outbound in NSGs ---
deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "azurerm_network_security_rule"
    
    resource.change.after.direction == "Outbound"
    resource.change.after.access == "Allow"

    dest := resource.change.after.destination_address_prefix
    
    # Block '0.0.0.0/0', '*', or 'Internet' tag
    is_public(dest)

    msg := sprintf("AZURE EXFILTRATION RISK [%s]: NSG rule allows outbound to '%s'. Only internal CIDRs permitted.", [resource.address, dest])
}

# --- AZURE: Enforce Key Vault Network ACLs ---
deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "azurerm_key_vault"
    
    # Check if default action is set to Allow
    network_acls := resource.change.after.network_acls[_]
    network_acls.default_action == "Allow"

    msg := sprintf("🛑 AZURE ACL RISK [%s]: Key Vault must have network_acls.default_action set to 'Deny'.", [resource.address])
}

# --- AZURE: Enforce Private AKS ---
deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "azurerm_kubernetes_cluster"
    
    # Ensure cluster is private
    is_private := object.get(resource.change.after, "private_cluster_enabled", false)
    not is_private

    msg := sprintf("🛑 AZURE AKS RISK [%s]: Inference clusters must be 'private_cluster_enabled = true'.", [resource.address])
}

# --- Helpers ---
is_public(dest) if dest == "0.0.0.0/0"
is_public(dest) if dest == "*"
is_public(dest) if lower(dest) == "internet"