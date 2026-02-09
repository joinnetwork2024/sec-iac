# METADATA
# title: AI/ML Data Access ABAC Policy
# description: Enforces attribute-based access to sensitive AI datasets
package sec_iac.ai_data_access

import future.keywords.if
import future.keywords.in
import future.keywords.contains

default allow := false

# Helper: Business hours check
business_hours if {
    parsed_time := time.parse_rfc3339_ns(input.context.timestamp)
    day := time.weekday(parsed_time)
    day in {"Monday", "Tuesday", "Wednesday", "Thursday", "Friday"}
    [hour, _, _] := time.clock(parsed_time)
    hour >= 9
    hour < 17
}

allow if {
    business_hours
    input.action == "read"
    input.user.clearance in {"medium", "high"}
    input.resource.sensitivity == "internal"
}

allow if {
    business_hours
    input.action == "write"
    input.user.clearance == "high"
    input.resource.sensitivity != "PII"
    input.user.department == data.ai_teams.approved_departments[input.resource.type]
}

# Helper for reasons
has_specific_reason if {
    not business_hours
}

has_specific_reason if {
    input.action == "read"
    not (input.user.clearance in {"medium", "high"})
}

has_specific_reason if {
    input.action == "write"
    input.user.clearance != "high"
}

has_specific_reason if {
    input.action == "write"
    input.resource.sensitivity == "PII"
}

has_specific_reason if {
    input.action == "write"
    input.user.department != data.ai_teams.approved_departments[input.resource.type]
}

has_specific_reason if {
    input.action == "read"
    input.resource.sensitivity != "internal"
}

# Individual reason rules - CORRECT SYNTAX for v0.60.0+
reasons contains "Outside business hours" if {
    not allow
    not business_hours
}

reasons contains msg if {
    not allow
    input.action == "read"
    not (input.user.clearance in {"medium", "high"})
    msg := sprintf("Read action: insufficient clearance: got %v, need medium/high", [input.user.clearance])
}

reasons contains msg if {
    not allow
    input.action == "write"
    input.user.clearance != "high"
    msg := sprintf("Write action: requires high clearance only (got %v)", [input.user.clearance])
}

reasons contains "Write action: PII data write access forbidden" if {
    not allow
    input.action == "write"
    input.resource.sensitivity == "PII"
}

reasons contains msg if {
    not allow
    input.action == "write"
    input.user.department != data.ai_teams.approved_departments[input.resource.type]
    msg := sprintf("Write action: department mismatch: user=%v, required=%v", [
        input.user.department,
        data.ai_teams.approved_departments[input.resource.type]
    ])
}

reasons contains msg if {
    not allow
    input.action == "read"
    input.resource.sensitivity != "internal"
    msg := sprintf("Read action: resource sensitivity mismatch: got %v, need internal", [input.resource.sensitivity])
}

reasons contains "Access denied — policy violation" if {
    not allow
    not has_specific_reason
}