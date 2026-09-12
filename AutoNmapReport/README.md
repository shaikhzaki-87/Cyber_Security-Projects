# Automated Nmap Report Tool

A Python-based VAPT automation tool that performs network scanning, cross-references detected services against known CVEs (via NVD API), and generates a severity-tagged HTML report.

## Features
- Nmap-based service/version/OS detection scan
- Automated CVE lookup via NVD API
- CVSS-based severity tagging (Critical/High/Medium/Low)
- Clean, color-coded HTML report generation

## Tech Stack
Python, python-nmap, NVD REST API, Jinja2

## Usage
```bash
sudo venv/bin/python3 scanner.py
```
Enter target IP when prompted. Report generates as `report.html`.

## Disclaimer
For use only against systems you own or are authorized to test (e.g. Metasploitable2 lab environment).
