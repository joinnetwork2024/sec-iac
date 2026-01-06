# 🛡️ sec-iac — AI-First Security Governance for Multi-Cloud AI/ML

---

## 🚀 Overview

**sec-iac** is a **production-ready, multi-cloud (AWS & Azure) security governance framework** purpose-built for **AI/ML workloads**. It applies **policy-as-code** and **shift-left security controls** to ensure AI infrastructure complies with strict security and regulatory requirements *before* it ever reaches production.

This repository represents an **intentional evolution** from general secure Infrastructure-as-Code toward **AI/ML-first security governance**, addressing risks unique to model training, inference, and data handling.

> **Architecture Philosophy**
>
> * 🧠 **sec-iac** — *The Brain*: AI/ML governance, compliance rules, and policy enforcement
> * 🧱 **multi-cloud-secure-tf** — *The Body*: secure infrastructure foundations
>
> 👉 Start with [multi-cloud-secure-tf](https://github.com/joinnetwork2024/multi-cloud-secure-tf) for baseline infrastructure, then layer **sec-iac** for AI/ML governance.

---

## 🎯 Why sec-iac Exists

Traditional cloud security baselines are not sufficient for AI/ML workloads. AI systems introduce new risks such as:

* Sensitive training data residency violations
* Public or weakly isolated inference endpoints
* Over-privileged execution roles
* Lack of enforceable governance before deployment

**sec-iac** solves these problems by embedding AI-aware security controls directly into the CI/CD pipeline.

---

## ✨ Core AI/ML Security Guardrails

### 🧠 Policy-as-Code Enforcement

Rego policies act as **gatekeepers** in CI/CD, preventing non-compliant AI infrastructure from being provisioned.

### 🔒 Key Guardrails Implemented

* **Data Residency Enforcement**
  Training and model data is restricted to approved regions (e.g. UK / `eu-west-2`).

* **Model & Endpoint Network Isolation**
  SageMaker and Azure ML endpoints must have network isolation enabled to mitigate data exfiltration risks.

* **Encryption at Rest**
  Mandatory use of AWS KMS and Azure Key Vault for datasets and model artifacts.

* **Least-Privilege AI Roles**
  Validation that AI execution roles do not include broad or administrative permissions.

---

## 🏗️ Architecture Approach

The project follows the **C4 Model** to clearly document how governance is enforced:

* **System Context** — Developer interaction with policy enforcement
* **Container View** — OPA CLI integrated into GitHub Actions
* **Component View** — Individual Rego policy modules

This structure ensures both **technical clarity** and **audit readiness**.

---

## 🛠️ Technology Stack

* **Infrastructure-as-Code**: Terraform (AWS & Azure)
* **Policy Engine**: Open Policy Agent (OPA / Rego)
* **Static Security Analysis**: Checkov
* **CI/CD**: GitHub Actions
* **Architecture Diagrams**: Structurizr (C4 DSL)

---

## 🚦 Getting Started

### Local Policy Validation

```bash
terraform plan -out=tfplan.binary
terraform show -json tfplan.binary > tfplan.json
opa exec --decision terraform/analysis/deny --bundle policies/ tfplan.json
```

This workflow simulates CI/CD enforcement locally, allowing developers to detect policy violations early.

---

## 📂 Repository Structure

```text
├── .github/workflows       # CI/CD pipelines (plan, validate, Checkov, OPA)
├── environments/dev        # Development environments (AWS & Azure)
├── modules/networking      # Secure networking modules
├── policies/rego           # AI/ML governance policies (OPA/Rego)
├── main.tf                 # Root Terraform configuration
├── vault.tf                # Secrets & encryption configuration
└── outputs.tf              # Terraform outputs
```

---

## 🔄 Project Evolution

This repository evolved from general **secure multi-cloud IaC practices** into a focused **AI/ML security governance layer**.

* **Then**: Secure-by-default cloud infrastructure
* **Now**: AI-aware compliance, data controls, and model governance

This evolution enables teams to progressively mature their security posture—from infrastructure security to **AI governance at scale**.

---

## 🧭 Navigation Guide

* Looking for **secure cloud foundations**? → Start with **multi-cloud-secure-tf**
* Need **AI/ML compliance, governance, and policy enforcement**? → You are in **sec-iac**

Together, these repositories provide an end-to-end path from **secure infrastructure** to **governed AI systems**.

---

## 📜 License

MIT License

---

**sec-iac enables teams to deploy AI faster—without sacrificing security, compliance, or control.**

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