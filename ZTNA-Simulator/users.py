USERS = {
    "alice": {"password": "alice123", "role": "admin", "mfa_enabled": True},
    "bob": {"password": "bob123", "role": "employee", "mfa_enabled": False},
}

RESOURCES = {
    "finance_dashboard": {"min_role": "admin"},
    "company_wiki": {"min_role": "employee"},
    "server_console": {"min_role": "admin"},
}
