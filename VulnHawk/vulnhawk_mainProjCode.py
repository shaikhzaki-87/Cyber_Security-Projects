#!/usr/bin/env python3
"""
Author:Shaikh Zaki 2026
VulnHawk - Web Application Vulnerability Scanner
Checks for: SQL Injection, Reflected XSS, Missing Security Headers, CSRF

"""

import requests
import argparse
import json
import re
import os
from datetime import datetime
from urllib.parse import urljoin

SQLI_PAYLOADS = ["'", "' OR '1'='1", "\" OR \"1\"=\"1", "'--", "' OR 1=1--"]
SQLI_ERRORS = ["sql syntax", "mysql_fetch", "unclosed quotation", "sqlite3.OperationalError",
               "odbc drivers error", "pg_query", "syntax error"]

XSS_PAYLOADS = ["<script>alert(1)</script>", "\"><script>alert(1)</script>",
                "<img src=x onerror=alert(1)>"]

SECURITY_HEADERS = {
    "Content-Security-Policy": "high",
    "X-Frame-Options": "medium",
    "X-Content-Type-Options": "medium",
    "Strict-Transport-Security": "high",
    "Referrer-Policy": "low",
}

SEVERITY_CVSS = {"high": 7.5, "medium": 5.3, "low": 3.1}


def check_sql_injection(url, param="id"):
    findings = []
    for payload in SQLI_PAYLOADS:
        try:
            r = requests.get(url, params={param: payload}, timeout=5)
            body = r.text.lower()
            for err in SQLI_ERRORS:
                if err.lower() in body:
                    findings.append({
                        "type": "SQL Injection",
                        "owasp": "A03:2021-Injection",
                        "payload": payload,
                        "param": param,
                        "evidence": err,
                        "cvss": SEVERITY_CVSS["high"],
                        "severity": "High"
                    })
                    break
        except requests.RequestException as e:
            print(f"[!] Request failed for payload {payload}: {e}")
    return findings


def check_xss(url, param="q"):
    findings = []
    for payload in XSS_PAYLOADS:
        try:
            r = requests.get(url, params={param: payload}, timeout=5)
            if payload in r.text:
                findings.append({
                    "type": "Reflected XSS",
                    "owasp": "A03:2021-Injection (XSS)",
                    "payload": payload,
                    "param": param,
                    "evidence": "Payload reflected unescaped in response",
                    "cvss": SEVERITY_CVSS["high"],
                    "severity": "High"
                })
        except requests.RequestException as e:
            print(f"[!] Request failed for payload {payload}: {e}")
    return findings


def check_security_headers(url):
    findings = []
    try:
        r = requests.get(url, timeout=5)
        for header, sev in SECURITY_HEADERS.items():
            if header not in r.headers:
                findings.append({
                    "type": "Missing Security Header",
                    "owasp": "A05:2021-Security Misconfiguration",
                    "header": header,
                    "evidence": f"'{header}' not present in response headers",
                    "cvss": SEVERITY_CVSS[sev],
                    "severity": sev.capitalize()
                })
    except requests.RequestException as e:
        print(f"[!] Header check failed: {e}")
    return findings


CSRF_TOKEN_NAMES = ["csrf", "_token", "authenticity_token", "csrfmiddlewaretoken",
                     "csrf_token", "anti-csrf", "nonce"]


def check_csrf(url):
    """
    Checks each <form> on the page for a hidden anti-CSRF token field,
    and checks Set-Cookie headers for a missing/weak SameSite attribute.
    """
    findings = []
    try:
        r = requests.get(url, timeout=5)
    except requests.RequestException as e:
        print(f"[!] CSRF check failed: {e}")
        return findings

    # 1. Form-level check: look for POST forms lacking a CSRF token field
    forms = re.findall(r"<form\b[^>]*>(.*?)</form>", r.text, re.IGNORECASE | re.DOTALL)
    form_tags = re.findall(r"<form\b[^>]*>", r.text, re.IGNORECASE)

    for i, form_body in enumerate(forms):
        method_match = re.search(r'method=["\']?(\w+)', form_tags[i], re.IGNORECASE) if i < len(form_tags) else None
        method = method_match.group(1).lower() if method_match else "get"

        if method != "post":
            continue  # CSRF mainly matters for state-changing (POST) forms

        hidden_inputs = re.findall(r'<input[^>]+type=["\']hidden["\'][^>]*>', form_body, re.IGNORECASE)
        has_token = any(
            any(token_name in inp.lower() for token_name in CSRF_TOKEN_NAMES)
            for inp in hidden_inputs
        )
        if not has_token:
            findings.append({
                "type": "CSRF - Missing Anti-CSRF Token",
                "owasp": "A01:2021-Broken Access Control (CSRF)",
                "evidence": f"POST form #{i+1} has no hidden CSRF token field",
                "cvss": SEVERITY_CVSS["medium"],
                "severity": "Medium"
            })

    # 2. Cookie-level check: SameSite attribute missing/None on session-like cookies
    set_cookie_headers = r.raw.headers.get_all("Set-Cookie") if hasattr(r.raw.headers, "get_all") else r.headers.get("Set-Cookie")
    cookie_headers = set_cookie_headers if isinstance(set_cookie_headers, list) else ([set_cookie_headers] if set_cookie_headers else [])

    for ck in cookie_headers:
        if "session" in ck.lower() or "auth" in ck.lower() or "token" in ck.lower():
            if "samesite" not in ck.lower():
                findings.append({
                    "type": "CSRF - Missing SameSite Cookie Attribute",
                    "owasp": "A01:2021-Broken Access Control (CSRF)",
                    "evidence": f"Cookie missing SameSite attribute: {ck.split('=')[0]}",
                    "cvss": SEVERITY_CVSS["medium"],
                    "severity": "Medium"
                })
            elif "samesite=none" in ck.lower():
                findings.append({
                    "type": "CSRF - Weak SameSite Cookie Setting",
                    "owasp": "A01:2021-Broken Access Control (CSRF)",
                    "evidence": f"Cookie uses SameSite=None: {ck.split('=')[0]}",
                    "cvss": SEVERITY_CVSS["low"],
                    "severity": "Low"
                })

    return findings


def generate_report(target, all_findings, out_prefix="report"):
    output_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")
    os.makedirs(output_dir, exist_ok=True)

    report = {
        "target": target,
        "scan_date": datetime.now().isoformat(),
        "total_findings": len(all_findings),
        "findings": all_findings
    }
    json_path = os.path.join(output_dir, f"{out_prefix}.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    html_rows = ""
    for f_ in all_findings:
        html_rows += f"""
        <tr>
            <td>{f_['type']}</td>
            <td>{f_.get('owasp','-')}</td>
            <td>{f_['severity']}</td>
            <td>{f_['cvss']}</td>
            <td>{f_['evidence']}</td>
        </tr>"""

    html = f"""
    <html><head><title>VulnHawk Scan Report</title>
    <style>
    body {{ font-family: Arial, sans-serif; margin: 40px; }}
    table {{ border-collapse: collapse; width: 100%; }}
    th, td {{ border: 1px solid #ccc; padding: 8px; text-align: left; }}
    th {{ background: #222; color: #fff; }}
    tr:nth-child(even) {{ background: #f4f4f4; }}
    h1 {{ color: #b00; }}
    </style></head>
    <body>
    <h1>VulnHawk — Vulnerability Scan Report</h1>
    <p><b>Target:</b> {target}</p>
    <p><b>Scan Date:</b> {report['scan_date']}</p>
    <p><b>Total Findings:</b> {report['total_findings']}</p>
    <table>
    <tr><th>Type</th><th>OWASP Category</th><th>Severity</th><th>CVSS</th><th>Evidence</th></tr>
    {html_rows}
    </table>
    </body></html>
    """
    html_path = os.path.join(output_dir, f"{out_prefix}.html")
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html)

    return json_path, html_path


def main():
    parser = argparse.ArgumentParser(description="VulnHawk - Web App Vulnerability Scanner")
    parser.add_argument("url", help="Target URL, e.g. http://localhost/dvwa/vulnerabilities/sqli/")
    parser.add_argument("--param", default="id", help="Parameter name to inject (default: id)")
    parser.add_argument("--xss-param", default="q", help="Parameter name to test XSS on (default: q)")
    parser.add_argument("--out", default="report", help="Output filename prefix")
    args = parser.parse_args()

    print(f"[*] Scanning {args.url} ...")
    findings = []
    findings += check_sql_injection(args.url, args.param)
    findings += check_xss(args.url, args.xss_param)
    findings += check_security_headers(args.url)
    findings += check_csrf(args.url)

    if not findings:
        print("[*] No issues found (or target not vulnerable to tested payloads).")
    else:
        print(f"[+] {len(findings)} finding(s) detected.")

    json_path, html_path = generate_report(args.url, findings, args.out)
    print(f"[*] JSON report: {json_path}")
    print(f"[*] HTML report: {html_path}")


if __name__ == "__main__":
    main()


"""
Yeh ek Vulnerability Scanner hai jo web applications ke liye SQL Injection, Reflected XSS, Missing Security Headers, aur CSRF vulnerabilities check karta hai.
cd D:\CSF\CSP\Projects
python vulnapp.py

python vulnhawk.py http://127.0.0.1:5001/listproducts.php --param cat --xss-param artist
python vulnhawk.py http://127.0.0.1:5001/search --xss-param artist --out xss_test
python vulnhawk.py http://127.0.0.1:5001/change-password --out csrf_test

python secapp.py

python vulnhawk.py http://127.0.0.1:5002/listproducts.php --param cat --xss-param artist
python vulnhawk.py http://127.0.0.1:5002/search --xss-param artist --out secure_xss_test
python vulnhawk.py http://127.0.0.1:5002/change-password --out secure_csrf_test 

D:\CSF\CSP\Projects\reports\
"""