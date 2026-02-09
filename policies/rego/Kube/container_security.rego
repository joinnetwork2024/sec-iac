# Kubernetes admission policy for AI/ML container security baseline
# Targets Gatekeeper AdmissionReview input
# Enforces non-root, no privilege escalation, read-only root FS

package kubernetes.admission

import rego.v1  # Enables modern syntax (if/contains) - required in OPA ≥ v1.0

# Multi-value rule: collects all violation messages (partial set)
# Gatekeeper expects 'violation' to be a set of objects/maps with "msg"
violation contains msg if {
    input.review.kind.kind == "Pod"
    input.review.object.metadata.namespace == "ai-serving"
    input.review.object.metadata.labels["workload-type"] == "ai-model"

    container := input.review.object.spec.containers[_]

    # Rule 1: Must run as non-root (missing field → defaults vulnerable → deny)
    not container.securityContext.runAsNonRoot
    msg := sprintf(
        "Pod '%v' / Container '%v': must run as non-root (runAsNonRoot: true required)",
        [input.review.object.metadata.name, container.name]
    )
}

violation contains msg if {
    input.review.kind.kind == "Pod"
    input.review.object.metadata.namespace == "ai-serving"
    input.review.object.metadata.labels["workload-type"] == "ai-model"

    container := input.review.object.spec.containers[_]

    # Rule 2: Explicitly forbid privilege escalation
    container.securityContext.allowPrivilegeEscalation
    msg := sprintf(
        "Pod '%v' / Container '%v': privilege escalation is forbidden (allowPrivilegeEscalation: false required)",
        [input.review.object.metadata.name, container.name]
    )
}

violation contains msg if {
    input.review.kind.kind == "Pod"
    input.review.object.metadata.namespace == "ai-serving"
    input.review.object.metadata.labels["workload-type"] == "ai-model"

    container := input.review.object.spec.containers[_]

    # Rule 3: Enforce read-only root filesystem
    not container.securityContext.readOnlyRootFilesystem
    msg := sprintf(
        "Pod '%v' / Container '%v': readOnlyRootFilesystem must be true",
        [input.review.object.metadata.name, container.name]
    )
}