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