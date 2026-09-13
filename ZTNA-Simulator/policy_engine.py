from users import USERS, RESOURCES
from device_check import check_device_posture, is_device_healthy
from context_check import check_context

ROLE_HIERARCHY = {"employee": 1, "admin": 2}

def evaluate_access(username, password, resource, device_id, location):
    log = {"user": username, "resource": resource, "steps": []}

    # Step 1: Identity
    user = USERS.get(username)
    if not user or user["password"] != password:
        log["verdict"] = "DENY"
        log["reason"] = "Identity verification failed"
        return log
    log["steps"].append("Identity verified")

    # Step 2: Least privilege (role check)
    res = RESOURCES.get(resource)
    if not res or ROLE_HIERARCHY[user["role"]] < ROLE_HIERARCHY[res["min_role"]]:
        log["verdict"] = "DENY"
        log["reason"] = f"Role '{user['role']}' insufficient for {resource}"
        return log
    log["steps"].append("Role authorized")

    # Step 3: Device posture
    posture = check_device_posture(device_id)
    device_ok = is_device_healthy(posture)
    log["steps"].append(f"Device posture: {posture}")

    # Step 4: Context
    ctx = check_context(location)
    log["steps"].append(f"Context: {ctx}")

    # Decision logic
    if not device_ok:
        log["verdict"] = "DENY"
        log["reason"] = "Device posture check failed"
    elif not ctx["known_location"] or not ctx["business_hours"]:
        if user["mfa_enabled"]:
            log["verdict"] = "CHALLENGE (MFA required)"
            log["reason"] = "Unusual context, but MFA available"
        else:
            log["verdict"] = "DENY"
            log["reason"] = "Unusual context and no MFA enabled"
    else:
        log["verdict"] = "ALLOW"
        log["reason"] = "All checks passed"

    return log
