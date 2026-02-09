package sec_iac.ai_data_access

import future.keywords.if

# Mock external data
mock_ai_teams := {
    "approved_departments": {
        "training-data": "AI-Research",
        "inference-data": "AI-Research"
    }
}

# Test 1: Allowed read during business hours
test_allow_read_internal if {
    allow with input as {
        "user": {"department": "AI-Research", "clearance": "medium"},
        "resource": {"sensitivity": "internal", "type": "training-data"},
        "action": "read",
        "context": {"timestamp": "2026-02-09T10:30:00Z"}
    }
    with data.ai_teams as mock_ai_teams
}

# Test 2: Denied outside business hours
test_deny_outside_hours if {
    not allow with input as {
        "user": {"department": "AI-Research", "clearance": "high"},
        "resource": {"sensitivity": "internal", "type": "training-data"},
        "action": "read",
        "context": {"timestamp": "2026-02-09T18:15:00Z"}
    }
    with data.ai_teams as mock_ai_teams
}

# Test 3: Denied – wrong department for write
test_deny_wrong_department_write if {
    not allow with input as {
        "user": {"department": "Marketing", "clearance": "high"},
        "resource": {"sensitivity": "internal", "type": "training-data"},
        "action": "write",
        "context": {"timestamp": "2026-02-09T11:00:00Z"}
    }
    with data.ai_teams as mock_ai_teams
}

# Test 4: Denied – PII write access
test_deny_pii_access_write if {
    not allow with input as {
        "user": {"department": "AI-Research", "clearance": "high"},
        "resource": {"sensitivity": "PII", "type": "training-data"},
        "action": "write",
        "context": {"timestamp": "2026-02-09T10:00:00Z"}
    }
    with data.ai_teams as mock_ai_teams
}

# Test 5: Allowed write with correct department
test_allow_write_internal if {
    allow with input as {
        "user": {"department": "AI-Research", "clearance": "high"},
        "resource": {"sensitivity": "internal", "type": "training-data"},
        "action": "write",
        "context": {"timestamp": "2026-02-09T10:00:00Z"}
    }
    with data.ai_teams as mock_ai_teams
}