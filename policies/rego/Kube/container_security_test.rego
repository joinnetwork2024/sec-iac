package kubernetes.admission

import rego.v1

# Test 1: Deny when container runs as root (runAsUser: 0)
test_deny_root_run if {
    some violation_msg
    violation[violation_msg] with input.review as {
        "kind": {"kind": "Pod"},
        "object": {
            "metadata": {
                "name": "bad-pod",
                "namespace": "ai-serving",
                "labels": {"workload-type": "ai-model"}
            },
            "spec": {
                "containers": [{
                    "name": "app",
                    "securityContext": {"runAsUser": 0}
                }]
            }
        }
    }

    contains(violation_msg, "must run as non-root")
}

# Test 2: Allow when all required securityContext fields are set correctly
test_allow_non_root if {
    not any_violation with input.review as {
        "kind": {"kind": "Pod"},
        "object": {
            "metadata": {
                "name": "good-pod",
                "namespace": "ai-serving",
                "labels": {"workload-type": "ai-model"}
            },
            "spec": {
                "containers": [{
                    "name": "app",
                    "securityContext": {
                        "runAsNonRoot": true,
                        "allowPrivilegeEscalation": false,
                        "readOnlyRootFilesystem": true
                    }
                }]
            }
        }
    }
}

# Helper rule for test 2 (makes negation safe and readable)
any_violation if {
    violation[_]  # just check existence, no variable binding needed
}

# # Test 3: Deny when securityContext is missing (defaults are vulnerable)
# test_deny_missing_securitycontext if {
#     count(violation) > 0 with input.review as {
#         "kind": {"kind": "Pod"},
#         "object": {
#             "metadata": {
#                 "name": "no-secctx",
#                 "namespace": "ai-serving",
#                 "labels": {"workload-type": "ai-model"}
#             },
#             "spec": {"containers": [{"name": "app"}]}
#         }
#     }

#     # Optional: make it more precise by checking content of at least one msg
#     some violation_msg
#     violation[violation_msg]
#     contains(violation_msg, "must run as non-root")  # from Rule 1
# }