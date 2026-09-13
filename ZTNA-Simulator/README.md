# ZTNA Simulator — Zero Trust Access Policy Engine

A Python-based simulator demonstrating core Zero Trust Network Access (ZTNA) principles: never trust by default, verify continuously, and enforce least-privilege access — regardless of whether a request originates from inside or outside a "trusted" network.

## How it works
Every access request is evaluated through four independent checks, each of which can deny access on its own:
1. **Identity verification** — valid username/password
2. **Least-privilege authorization** — does the user's role meet the resource's minimum role requirement?
3. **Device posture check** — is the requesting device "healthy" (OS patched, antivirus active, disk encrypted)?
4. **Context/behavioral check** — is the request coming from a known location during expected business hours?

Based on these checks, a request is resolved to one of three verdicts:
- **ALLOW** — all checks passed
- **DENY** — a critical check failed
- **CHALLENGE (MFA required)** — context is unusual, but the user has MFA enabled as a fallback verification method

## Why this matters
Traditional network security assumes anything inside the perimeter is trustworthy. Zero Trust assumes the opposite — every request is verified on its own merits, every time, regardless of network location. This simulator demonstrates that logic in a minimal, explainable form.

## Tech Stack
Python, Jinja2 (for the HTML access-log report)

## Usage
```bash
python3 test_requests.py
```
Generates `ztna_report.html` with a full access log, including the verification steps and reasoning behind each decision.

## Disclaimer
A simplified educational simulation, not a production-grade ZTNA implementation.

Author: Shaikh Zaki shaikhzakiii34@gmail.com LinkedIn: https://www.linkedin.com/in/shaikh-zaki-55b493260/
