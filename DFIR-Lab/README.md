# Digital Forensics Lab — Simulated Data Exfiltration Investigation

A hands-on DFIR (Digital Forensics & Incident Response) exercise using Autopsy and The Sleuth Kit to investigate a simulated insider-threat scenario.

## Scenario
A disk image was created and populated with sensitive files (`salary_data.txt`) and a suspicious script (`suspicious_script.sh`). A backup copy of the sensitive file was subsequently deleted, simulating an attempt to conceal evidence after unauthorized copying — a common indicator in insider-threat / data-exfiltration cases.

## Methodology
1. Created a 100MB disk image with an ext2 filesystem
2. Populated it with evidence files, then deleted a copy of the sensitive file
3. Loaded the image into Autopsy 2.24 as a case, with MD5 hash verification for data integrity
4. Performed file system analysis to identify existing files
5. Searched deleted/orphan files to locate the removed evidence
6. When the filesystem-level view showed an empty orphaned inode (data pointers cleared), performed a raw disk-level string search (`strings` + `grep`) to confirm the original file content was still physically present on disk

## Key Finding
Autopsy's file browser correctly identified a deleted file (`OrphanFile-14`) but could not display its content due to cleared inode pointers — a known ext2 behavior. A raw string search on the disk image (`strings evidence2.dd | grep -i confidential`) successfully recovered the original file content, demonstrating that file-system-level analysis alone is sometimes insufficient and that disk-level carving techniques are necessary for thorough forensic recovery.

## Evidence Integrity
MD5 hash of evidence image calculated and verified on import, per standard forensic chain-of-custody practice.

## Tools Used
Autopsy 2.24, The Sleuth Kit, Linux `strings`/`grep` (manual carving)

## Disclaimer
Conducted entirely on a self-created, simulated disk image for educational purposes. No real systems or data were involved.

Author: Shaikh Zaki 
shaikhzakiii34@gmail.com 
LinkedIn:
https://www.linkedin.com/in/shaikh-zaki-55b493260/
