#  VulnHawk

**A lightweight Web Application Vulnerability Scanner** built to detect common security flaws in web applications — designed as a hands-on portfolio project demonstrating practical AppSec and offensive security skills.


>  **DISCLAIMER:** VulnHawk is built and shared **strictly for educational and learning purposes**. It is intended for use only on systems you own or have explicit written permission to test. Unauthorized scanning of websites/applications is illegal. The author holds no responsibility for any misuse of this tool.



##  Overview

VulnHawk automates the detection of some of the most common and dangerous web application vulnerabilities from the **OWASP Top 10**, helping identify security weaknesses before attackers do. It was built to strengthen practical, real-world offensive security skills beyond just tool usage — focusing on understanding *how* and *why* these vulnerabilities occur.



##  Features

-  **SQL Injection (SQLi) Detection** — Tests input fields and parameters for injectable SQL vulnerabilities
-  **Cross-Site Scripting (XSS) Detection** — Identifies reflected/stored XSS via payload injection and response analysis
-  **Missing Security Headers Check** — Flags missing headers like `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Strict-Transport-Security`
-  **CSRF Vulnerability Detection** — Checks for missing/weak anti-CSRF tokens on forms
-  **Automated Scan Reports** — Generates a clean, readable report of all findings per target



##  Tech Stack

- **Language:** Python 3
- **Core Libraries:** `requests`, `BeautifulSoup4`, `re` (regex-based payload matching)
- **Environment:** Tested on Kali Linux



##  Installation


# Clone the repository
git clone https://github.com/shaikhzaki-87/Cyber_Security-Projects.git
cd Cyber_Security-Projects/VulnHawk

# Install dependencies
pip install -r requirements.txt
 
Usage
python vulnhawk.py -u https://target-website.com


**Example:**
python vulnhawk.py -u http://testphp.vulnweb.com --full-scan
The scanner will crawl the target, run all checks, and output a summary report highlighting any vulnerabilities found.
 **Sample Output**
[+] Scanning target: http://testphp.vulnweb.com
[+] Checking for SQL Injection...        [VULNERABLE] /listproducts.php?cat=
[+] Checking for XSS...                  [VULNERABLE] /search.php?searchFor=
[+] Checking Security Headers...         [MISSING] Content-Security-Policy
[+] Checking CSRF Protection...          [SAFE]

  **Project Structure**
VulnHawk/
├── vulnhawk.py
├── modules/
│   ├── sqli_scanner.py
│   ├── xss_scanner.py
│   ├── header_checker.py
│   └── csrf_checker.py
├── requirements.txt
└── README.md


##  Roadmap / Future Improvements

- [/>] Add support for authenticated scans (session/cookie handling)
- [/>] Add report export (PDF/HTML)
- [/>] Integrate CVSS scoring for findings
- [/>] Add multithreading for faster scans
- [/>] Docker container support



##  Disclaimer

This tool is built strictly for **educational purposes and authorized security testing only**. Do not use VulnHawk against any system without explicit permission. The author is not responsible for any misuse.



## Author

**Shaikh Zaki**
📧 shaikhzakiii34@gmail.com
🔗 [LinkedIn](https://linkedin.com/in/shaikh-zaki-55b493260)
