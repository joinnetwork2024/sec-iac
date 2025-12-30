package sec_iac.ai_ml.security

import rego.v1

# Approved Internal CIDRs (Whitelisted destinations)
whitelisted_internal_cidrs := {"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}

# 1. Enforce SageMaker Network Isolation
deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "aws_sagemaker_model"
    
    # Check if network isolation is false or missing
    isolation := object.get(resource.change.after, "enable_network_isolation", false)
    not isolation

    msg := sprintf("SECURITY CRITICAL: SageMaker Model '%s' must have 'enable_network_isolation' set to true to prevent internet access.", [resource.address])
}

# 2. Prevent Public Egress in Security Groups
deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "aws_security_group"
    
    # Check if this SG is tagged for AI use
    tags := object.get(resource.change.after, "tags", {})
    tags["workload_type"] == "ai_inference"

    # Scrutinize Egress Rules
    egress := resource.change.after.egress[_]
    cidr := object.get(egress, "cidr_blocks", [])[_]
    
    cidr == "0.0.0.0/0"
    msg := sprintf("EXFILTRATION RISK: Security Group '%s' allows egress to 0.0.0.0/0. AI endpoints must use whitelisted internal CIDRs only.", [resource.address])
}