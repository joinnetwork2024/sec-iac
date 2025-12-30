package sec_iac.ai_ml.security

import rego.v1

# Approved internal destinations (RFC1918)
allowed_egress_cidrs := {"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}

# --- AWS: Deny Public Egress (0.0.0.0/0) ---
deny_public_egress contains msg if {
    some resource in input.resource_changes
    resource.type == "aws_security_group"
    
    # Check egress blocks
    some egress in resource.change.after.egress
    some cidr in egress.cidr_blocks
    
    # Check for the open internet
    cidr == "0.0.0.0/0"
    
    msg := sprintf("AWS EXFILTRATION RISK: Security Group '%s' allows egress to 0.0.0.0/0. AI workloads must be isolated.", [resource.address])
}

# --- AZURE: Deny Public Outbound (Internet tag or 0.0.0.0/0) ---
deny_public_egress contains msg if {
    some resource in input.resource_changes
    resource.type == "azurerm_network_security_rule"
    
    # Ensure it is an Outbound rule
    resource.change.after.direction == "Outbound"
    resource.change.after.access == "Allow"

    # Azure uses "destination_address_prefix"
    dest := resource.change.after.destination_address_prefix
    
    # Block if destination is 'Internet', '*' (Any), or '0.0.0.0/0'
    is_public_destination(dest)
    
    msg := sprintf("AZURE EXFILTRATION RISK: NSG Rule '%s' allows outbound to '%s'. Must use internal CIDRs or Service Tags.", [resource.address, dest])
}

# --- Helpers ---

is_public_destination(dest) if dest == "0.0.0.0/0"
is_public_destination(dest) if dest == "*"
is_public_destination(dest) if lower(dest) == "internet"