from policy_engine import evaluate_access
from report_generator import generate_report

test_cases = [
    ("alice", "alice123", "finance_dashboard", "dev-1", "India"),
    ("bob", "bob123", "finance_dashboard", "dev-2", "India"),
    ("bob", "bob123", "company_wiki", "dev-2", "Russia"),
    ("alice", "wrongpass", "server_console", "dev-1", "Germany"),
    ("alice", "alice123", "company_wiki", "dev-1", "Germany"),
]

results = []
for username, password, resource, device_id, location in test_cases:
    result = evaluate_access(username, password, resource, device_id, location)
    results.append(result)
    print(f"\n--- Request: {username} -> {resource} from {location} ---")
    for step in result["steps"]:
        print(f"  {step}")
    print(f"  VERDICT: {result['verdict']} ({result['reason']})")

generate_report(results)
