# Network Audit Tool

A Python-based network security audit tool that scans a target host, identifies open ports and running services, assigns severity ratings, and automatically generates a professional PDF report — the kind you'd deliver to a real client.

Built as part of a penetration testing portfolio project.

---

## Features

- Scans ports 1–1024 using Nmap
- Detects service names and versions
- Assigns severity ratings: Critical / High / Medium / Low / Info
- Provides remediation recommendations per finding
- Generates a clean, color-coded PDF report automatically

---

## Requirements

- Python 3
- Nmap installed on your system
- python-nmap
- fpdf2

Install dependencies:
pip install python-nmap fpdf2

---

## Usage

python3 scanner.py <target>

Example:
python3 scanner.py scanme.nmap.org

---

## Sample Output

The tool generates a PDF report named:
report_<target>_<date>.pdf

Report includes:
- Executive summary
- Findings table with severity color coding
- Recommendations section per finding

---

## Tools and Technologies

- Python 3
- Nmap / python-nmap
- fpdf2
- Kali Linux

---

## Author

Rawan Rany
Computer and Information Sciences — Ain Shams University
Networking and Cybersecurity — WE for Applied Technology School

GitHub: github.com/rawanrany
