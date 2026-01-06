# 🛡️ sec-iac: Secure AI/ML Multi-Cloud Infrastructure

This repository implements a **Production-Ready, Multi-Cloud (AWS & Azure)** infrastructure baseline with a heavy focus on **AI/ML Security Governance**. It uses **Open Policy Agent (OPA)** and **Checkov** to enforce a "Shift-Left" security model.

## 🚀 AI/ML Governance PoC
The core of this project is a set of **Rego policies** that sit in the CI/CD pipeline, acting as a gatekeeper to prevent insecure AI workloads from reaching production.

### Key Security Guardrails
1. **Data Residency:** Training data is locked to the UK (`eu-west-2`) to meet sovereign data requirements.
2. **Network Isolation:** All AI model endpoints (SageMaker/Azure ML) are required to have Network Isolation enabled.
3. **Encryption at Rest:** Mandates AWS KMS / Azure Key Vault encryption for all model artifacts.
4. **Least Privilege:** Validates that AI execution roles do not possess broad administrative permissions.

## 🏗️ Architecture
The project follows the **C4 Model** for architectural clarity:
- **System Context:** High-level view of developer interaction with OPA.
- **Container View:** Integration of OPA CLI within GitHub Actions.
- **Component View:** Breakdown of specific Rego policy modules.

## 🛠️ Tech Stack
- **IaC:** Terraform (AWS & Azure)
- **Security Logic:** OPA (Rego)
- **Static Analysis:** Checkov
- **CI/CD:** GitHub Actions
- **Diagrams:** Structurizr (C4 DSL)

## 🚦 Getting Started
1. **Local Validation:**
   ```bash
   terraform plan -out=tfplan.binary
   terraform show -json tfplan.binary > tfplan.json
   opa exec --decision terraform/analysis/deny --bundle policies/ tfplan.json

# Secure IaC with AI/ML Focus (sec-iac)

## Project Evolution and Pivot
This repository evolved from foundational multi-cloud secure IaC practices (as seen in our [multi-cloud-secure-tf](https://github.com/joinnetwork2024/multi-cloud-secure-tf) repository) to an intentional focus on **AI/ML security governance**. The pivot addresses the growing need for robust security in AI/ML workloads, building on general security baselines to include specialized guardrails like policy-enforced data residency, isolated AI endpoints, encryption for ML datasets, and validation of execution roles. This ensures compliance and risk mitigation in production AI environments while maintaining the core principles of shift-left security.

For users starting with general multi-cloud setups, begin with `multi-cloud-secure-tf` and transition here for AI/ML-specific enhancements. This structure allows seamless navigation: use `multi-cloud-secure-tf` for broad infrastructure security, and `sec-iac` for targeted AI/ML governance.

The repository **sec-iac** implements a **Production-Ready, Multi-Cloud (AWS & Azure)** infrastructure baseline with a heavy focus on **AI/ML Security Governance**. It uses **Open Policy Agent (OPA)** and **Checkov** to enforce a "Shift-Left" security model through Rego policies in the CI/CD pipeline.

### Key Features:
- **AI/ML Governance PoC**: Rego policies act as gatekeepers to prevent insecure AI workloads from reaching production.
- **Security Guardrails**:
  - Data residency locked to the UK (eu-west-2).
  - Network isolation required for AI model endpoints (SageMaker/Azure ML).
  - Encryption at rest using AWS KMS / Azure Key Vault.
  - Least privilege validation for AI execution roles.

### Architecture:
Follows the **C4 Model** for clarity:
- System Context: Developer interaction with OPA.
- Container View: OPA CLI integration in GitHub Actions.
- Component View: Breakdown of Rego policy modules.

### Tech Stack:
- **IaC**: Terraform (AWS & Azure)
- **Security Logic**: OPA (Rego)
- **Static Analysis**: Checkov
- **CI/CD**: GitHub Actions
- **Diagrams**: Structurizr (C4 DSL)

### Getting Started:
1. Run `terraform plan` and export plan as JSON.
2. Execute OPA policy: `opa exec --decision terraform/analysis/deny --bundle policies/ tfplan.json`.

### Repository Structure:
Includes directories for:
- `.external_modules` (Terraform AWS modules)
- `.github/workflows` (CI/CD)
- `environments/dev` (Development environment)
- `modules/networking` (Networking modules)
- `policies/rego` (OPA policies)
- Configuration files: `main.tf`, `output.tf`, `vault.tf`, `readme.md`