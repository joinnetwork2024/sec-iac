package sec_iac.ai_ml.security

import rego.v1

# Approved container registries
approved_registries := {
  "public.ecr.aws",
  "715841360340.dkr.ecr.eu-west-1.amazonaws.com"
}

# Approved base images
approved_base_images := {
  "public.ecr.aws/official/python:3.10",
  "public.ecr.aws/official/ubuntu:22.04"
}

# Vulnerability thresholds
max_critical := 0
max_high := 5

############################################
# RULE 1: Block unapproved registries
############################################
deny contains msg if {
  image := input.image

  registry := split(image.name, "/")[0]
  not registry in approved_registries

  msg := sprintf(
    "IMAGE REGISTRY VIOLATION: Image '%s' is from unapproved registry '%s'. Allowed: %s",
    [image.name, registry, concat(", ", approved_registries)]
  )
}

############################################
# RULE 2: Block unapproved base images
############################################
deny contains msg if {
  image := input.image

  not image.base in approved_base_images

  msg := sprintf(
    "BASE IMAGE VIOLATION: Image '%s' uses unapproved base image '%s'. Allowed: %s",
    [image.name, image.base, concat(", ", approved_base_images)]
  )
}

############################################
# RULE 3: Vulnerability thresholds
############################################
deny contains msg if {
  vulns := input.vulnerabilities

  vulns.critical > max_critical

  msg := sprintf(
    "VULNERABILITY VIOLATION: %d critical vulnerabilities found (max allowed: %d)",
    [vulns.critical, max_critical]
  )
}

deny contains msg if {
  vulns := input.vulnerabilities

  vulns.high > max_high

  msg := sprintf(
    "VULNERABILITY VIOLATION: %d high vulnerabilities found (max allowed: %d)",
    [vulns.high, max_high]
  )
}