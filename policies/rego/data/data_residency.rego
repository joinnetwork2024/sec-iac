package sec_iac.ai_ml.security

import rego.v1

# Configuration: Approved regions by provider
approved_aws_regions := {"eu-west-2", "eu-west-1"}
approved_azure_regions := {"ukwest"}

# Configuration: Mandatory classification tags
required_classification_tag := "data_sensitivity"
valid_sensitivity_levels := {"public", "internal", "confidential", "pii"}

# Helper: Identify if a resource is an AI Data Store
is_ai_data_store(resource) if {
	# Check if it's a storage type
	resource_types := {"aws_s3_bucket", "azurerm_storage_account", "azurerm_storage_container"}
	resource.type in resource_types

	# Check if it's explicitly tagged or named for AI workloads
	tags := object.get(resource.change.after, "tags", {})
	tags.workload_type == "ai_training"
}

# Helper: Determine provider from resource type
is_aws_resource(resource) if {
	startswith(resource.type, "aws_")
}

is_azure_resource(resource) if {
	startswith(resource.type, "azurerm_")
}

# Helper: Get approved regions based on provider
get_approved_regions(resource) := approved_regions if {
	is_aws_resource(resource)
	approved_regions := approved_aws_regions
} else := approved_regions if {
	is_azure_resource(resource)
	approved_regions := approved_azure_regions
} # Default to empty set for unknown providers

else := {}

# RULE 1: Reject if outside approved regions for the provider
deny contains msg if {
	resource := input.resource_changes[_]
	is_ai_data_store(resource)

	# Extract region (handles both AWS and Azure providers)
	region := object.get(
		resource.change.after, "region",
		object.get(resource.change.after, "location", "unknown"),
	)

	# Get approved regions for this provider
	approved_regions := get_approved_regions(resource)

	not region in approved_regions

	msg := sprintf(
		"REGIONAL VIOLATION: AI Data Store '%s' (%s) is in '%s'. Must be in one of: %s for this provider.",
		[resource.address, resource.type, region, concat(", ", approved_regions)],
	)
}

# RULE 2: Reject if missing mandatory Data Classification tag
deny contains msg if {
	resource := input.resource_changes[_]
	is_ai_data_store(resource)

	tags := object.get(resource.change.after, "tags", {})
	classification := object.get(tags, required_classification_tag, "missing")

	not classification in valid_sensitivity_levels

	msg := sprintf(
		"TAGGING VIOLATION: AI Data Store '%s' is missing or has an invalid '%s' tag. Found: '%s'. Expected one of: %s.",
		[resource.address, required_classification_tag, classification, concat(", ", valid_sensitivity_levels)],
	)
}
