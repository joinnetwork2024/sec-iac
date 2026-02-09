# ai_data_access_compatible.rego
package sec_iac.ai_data_access

default allow = false

business_hours = true {
    parsed_time := time.parse_rfc3339_ns(input.context.timestamp)
    day := time.weekday(parsed_time)
    day = "Monday"
    [hour, _, _] := time.clock(parsed_time)
    hour >= 9
    hour < 17
}

business_hours = true {
    parsed_time := time.parse_rfc3339_ns(input.context.timestamp)
    day := time.weekday(parsed_time)
    day = "Tuesday"
    [hour, _, _] := time.clock(parsed_time)
    hour >= 9
    hour < 17
}

business_hours = true {
    parsed_time := time.parse_rfc3339_ns(input.context.timestamp)
    day := time.weekday(parsed_time)
    day = "Wednesday"
    [hour, _, _] := time.clock(parsed_time)
    hour >= 9
    hour < 17
}

business_hours = true {
    parsed_time := time.parse_rfc3339_ns(input.context.timestamp)
    day := time.weekday(parsed_time)
    day = "Thursday"
    [hour, _, _] := time.clock(parsed_time)
    hour >= 9
    hour < 17
}

business_hours = true {
    parsed_time := time.parse_rfc3339_ns(input.context.timestamp)
    day := time.weekday(parsed_time)
    day = "Friday"
    [hour, _, _] := time.clock(parsed_time)
    hour >= 9
    hour < 17
}

allow = true {
    business_hours
    input.action = "read"
    input.user.clearance = "medium"
    input.resource.sensitivity = "internal"
}

allow = true {
    business_hours
    input.action = "read"
    input.user.clearance = "high"
    input.resource.sensitivity = "internal"
}

allow = true {
    business_hours
    input.action = "write"
    input.user.clearance = "high"
    input.resource.sensitivity != "PII"
    input.user.department = data.ai_teams.approved_departments[input.resource.type]
}

# Reasons - compatible syntax
reasons["Outside business hours"] {
    not allow
    not business_hours
}

reasons[msg] {
    not allow
    input.action = "read"
    not input.user.clearance = "medium"
    not input.user.clearance = "high"
    msg := sprintf("Read action: insufficient clearance: got %v, need medium/high", [input.user.clearance])
}

reasons[msg] {
    not allow
    input.action = "write"
    input.user.clearance != "high"
    msg := sprintf("Write action: requires high clearance only (got %v)", [input.user.clearance])
}

reasons["Write action: PII data write access forbidden"] {
    not allow
    input.action = "write"
    input.resource.sensitivity = "PII"
}

reasons[msg] {
    not allow
    input.action = "write"
    input.user.department != data.ai_teams.approved_departments[input.resource.type]
    msg := sprintf("Write action: department mismatch: user=%v, required=%v", [
        input.user.department,
        data.ai_teams.approved_departments[input.resource.type]
    ])
}

reasons[msg] {
    not allow
    input.action = "read"
    input.resource.sensitivity != "internal"
    msg := sprintf("Read action: resource sensitivity mismatch: got %v, need internal", [input.resource.sensitivity])
}

reasons["Access denied — policy violation"] {
    not allow
    count(reasons) = 0
}