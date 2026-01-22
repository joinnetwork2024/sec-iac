package sec_iac.ai_ml.security

import rego.v1

# ── Config (stage 4: move to external data document for central governance) ──
required_tags := {"Environment", "Project", "CostCenter"}

allowed_environments := {"dev", "staging", "prod", "preprod"}

# Focus on billable/data-heavy resources — reduces noise while covering cost/ML risks
important_types := {
    "aws_s3_bucket",
    "aws_lambda_function",
    "aws_sagemaker_notebook_instance",
    "aws_sagemaker_model",
    "aws_sagemaker_endpoint",
    "aws_sagemaker_endpoint_configuration",
    "aws_security_group",
    "aws_vpc_endpoint",
    # Azure (common AI/ML + data resources)
    "azurerm_storage_account",
    "azurerm_machine_learning_workspace",
    "azurerm_virtual_machine",
    "azurerm_container_instance",
    "azurerm_kubernetes_cluster",
    "azurerm_sql_server",
    "azurerm_network_security_group",
}

# ── Decision API ──
deny contains msg if {
    res := input.resource_changes[_]
    res.mode == "managed"
    "create" in res.change.actions
    res.type in important_types

    # Correct coalescing: tags_all (includes provider defaults) → tags → empty
    tags := object.get(res.change.after, "tags_all", object.get(res.change.after, "tags", {}))

    some required_tag in required_tags
    not has_key(tags, required_tag)

    msg := sprintf(
        "Missing required tag '%s' on %s (%s) — critical for governance/chargeback",
        [required_tag, res.address, res.type]
    )
}

# Optional: Separate rule for value validation (keeps presence separate for granularity)
deny contains msg if {
    res := input.resource_changes[_]
    res.mode == "managed"
    "create" in res.change.actions
    res.type in important_types

    tags := object.get(res.change.after, "tags_all", object.get(res.change.after, "tags", {}))

    tags.Environment
    not tags.Environment in allowed_environments

    msg := sprintf(
        "Invalid Environment '%s' on %s (%s) — allowed: %v",
        [tags.Environment, res.address, res.type, allowed_environments]
    )
}

# ── Helper ──
has_key(obj, key) if _ = obj[key]