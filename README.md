**Cyber Security Projetcs**
This repository is a personal collection of cybersecurity projects, organized into Beginner, Intermediate, and Advanced tiers as my skills progress. Each project is built purely for educational purposes — to strengthen practical, hands-on security knowledge across cryptography, web application security, system-level programming, and more.

 All tools and techniques shared here are intended strictly for learning and authorized testing. None of this content should be used against systems without explicit permission.

## Projects

### 1. Text Encryption / Decryption Tool
**File:** `Enrypt_2024.py`

A substitution cipher tool that encrypts and decrypts text using a randomly generated character mapping. Unlike Caesar cipher (which uses a fixed shift), this tool shuffles the entire character set — including letters, digits, punctuation, and spaces — to create a unique key every run.

**How it works:**
- Builds a character set of all printable characters
- Randomly shuffles it to generate a one-time substitution key
- Encrypts by mapping each character to its shuffled counterpart
- Decrypts by reversing the lookup

**Concepts covered:** Classical cryptography, substitution ciphers, character mapping, limitations of simple encryption (vulnerable to frequency analysis)

**Run:**

python Enrypt_2024.py

### 2. Password Strength Checker
**File:** `Password_Checker_2024.py`

A GUI-based password strength evaluator built with Tkinter. Analyzes a password against common security criteria and gives real-time color-coded feedback.

**How it works:**
- Checks 5 criteria using regex: length (8+), uppercase, lowercase, digits, special characters
- Assigns a score based on how many criteria are met
- Displays result as Weak / Moderate / Strong with color feedback (red / orange / green)

**Concepts covered:** GUI development with Tkinter, regex-based pattern matching, basic password policy design (aligned with NIST guidelines), user-facing security feedback

**Run:**

python Password_Checker_2024.py


### 3. Encoder / Decoder Tool
**File:** `encoder_decoder_2024.py`

A command-line tool that encodes and decodes text in three common formats: Base64, Hexadecimal, and URL encoding. Also includes a basic format auto-detection feature using regex pattern matching.

> **Note:** Encoding is NOT encryption. It's a different representation of the same data — anyone can decode it. This tool demonstrates why encoded strings in URLs, tokens, and cookies should always be inspected during security analysis.

**How it works:**
- Encode: converts plain text to Base64 / Hex / URL format simultaneously
- Decode: takes encoded input and reverses it back to plain text
- Detect: uses regex heuristics to guess which encoding format a string is in

**Concepts covered:** Data encoding standards (Base64, Hex, URL encoding), regex pattern matching, format detection, encoding vs encryption distinction, practical use in security testing (JWT tokens, cookies, web requests)

**Run:**
python encoder_decoder_2024.py


### 4. Keylogger (Educational / Research Purpose Only)
**File:** `keylogger_2025.py`

> **Disclaimer:** This project is strictly for educational purposes to understand how keyloggers work at a system level. Unauthorized use of keyloggers is illegal. Only run this on systems you own or have explicit permission to monitor.

A Python-based keylogger demonstrating keyboard event capture, structured logging, and system-level programming concepts. Built to understand how security tools monitor input at the OS level — knowledge essential for both offensive security research and defensive detection.

**How it works:**
- Uses `pynput` library to listen for keyboard events
- Tracks active window titles across Windows, macOS, and Linux
- Logs keystrokes with timestamps and window context to a local file
- Supports log rotation (new file when size exceeds limit)
- Optional webhook delivery for batched remote log transmission
- Toggle logging on/off with F9 key, exit with Ctrl+C

**Concepts covered:** Keyboard event capture, multi-threading with locks, cross-platform system interaction, structured logging with file rotation, dataclass-based configuration, ethical boundaries in security tooling

**Install dependencies:**
pip install pynput requests


**Run:**
python keylogger_2025.py

## Tech Stack

- Python 3.x
- Libraries: `tkinter`, `pynput`, `requests`, `re`, `base64`, `urllib`

  ### 5. VulnHawk — Web Application Vulnerability Scanner
**Folder:** `VulnHawk/`

A lightweight web application vulnerability scanner that automates detection of some of the most common OWASP Top 10 flaws. Built to strengthen practical offensive security skills beyond just tool usage — focusing on understanding how and why these vulnerabilities occur.

> **Disclaimer:** This tool is strictly for educational purposes and authorized security testing only. Do not use VulnHawk against any system without explicit permission.

**How it works:**
- Crawls the target and tests input fields/parameters for SQL Injection
- Injects payloads to detect Reflected/Stored XSS via response analysis
- Checks response headers for missing security headers (CSP, X-Frame-Options, HSTS, etc.)
- Inspects forms for missing/weak anti-CSRF tokens
- Generates a structured scan report mapped to OWASP categories with CVSS severity ratings

**Concepts covered:** OWASP Top 10, SQL Injection, Cross-Site Scripting (XSS), security misconfiguration, CSRF, CVSS scoring, automated vulnerability reporting

**Install dependencies:**
pip install -r VulnHawk/requirements.txt


**Run:**
python VulnHawk/vulnhawk.py -u https://target-website.com


**Full documentation:** [VulnHawk README →](./VulnHawk/README.md)




## Author
**Shaikh Zaki**
BCA — Savitribai Phule Pune University (2026)
Email: shaikhzakiii34@gmail.com
LinkedIn: https://linkedin.com/in/shaikh-zaki-55b493260


