# METADATA
# title: AI/ML Data Access ABAC Policy
# description: Enforces attribute-based access to sensitive AI datasets (training, inference, PII)
# authors: [security-team]
# version: 1.0.0
# last_reviewed: 2026-02-09
# risk: high

package sec_iac.ai_data_access

import future.keywords.if
import future.keywords.in

# ────────────────────────────────────────────────────────────────────────────────
# Default deny — critical for auditability and zero-trust
# ────────────────────────────────────────────────────────────────────────────────
default allow := false

# Helper: Business hours check (UTC, Mon–Fri 09:00–17:00)
# Using time.weekday and time.clock for explicit, auditable logic
business_hours if {
    day := time.weekday(input.context.timestamp)
    day in {"Monday", "Tuesday", "Wednesday", "Thursday", "Friday"}

    [hour, _, _] := time.clock(input.context.timestamp)
    hour >= 9
    hour < 17
}

# Allowed: Read access to internal (non-PII) data during business hours
allow if {
    business_hours
    input.action == "read"
    input.user.clearance in {"medium", "high"}
    input.resource.sensitivity == "internal"
}

# Allowed: Write access — stricter rules
allow if {
    business_hours
    input.action == "write"
    input.user.clearance == "high"
    input.resource.sensitivity != "PII"
    input.user.department == data.ai_teams.approved_departments[input.resource.type]
}

# ────────────────────────────────────────────────────────────────────────────────
# Explainability: Collect denial reasons (very valuable for auditors & debugging)
# ────────────────────────────────────────────────────────────────────────────────
reasons contains msg if {
    not allow

    issues := [
        "Outside business hours" if not business_hours else "",
        sprintf("Insufficient clearance: got %v, need medium/high", [input.user.clearance]) if not (input.user.clearance in {"medium", "high"}) else "",
        sprintf("Write requires high clearance only (got %v)", [input.user.clearance]) if input.action == "write" and input.user.clearance != "high" else "",
        "PII data access forbidden" if input.resource.sensitivity == "PII" else "",
        sprintf("Department mismatch: user=%v, required=%v", [
            input.user.department,
            data.ai_teams.approved_departments[input.resource.type]
        ]) if input.user.department != data.ai_teams.approved_departments[input.resource.type] else ""
    ]

    msg := trim_space(concat("; ", [i | i := issues[_]; i != ""]))
    msg != ""
}

# Fallback generic reason if nothing specific matched (safety net)
reasons contains "Access denied — policy violation" if {
    not allow
    count(reasons) == 0
}