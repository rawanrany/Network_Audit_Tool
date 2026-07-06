import nmap
import sys
from fpdf import FPDF
from datetime import datetime

SEVERITY = {
    "ftp": ("High", "FTP transmits data in plaintext. Replace with SFTP."),
    "telnet": ("Critical", "Telnet is unencrypted. Disable immediately, use SSH."),
    "ssh": ("Low", "SSH is secure. Ensure strong passwords or key-based auth."),
    "http": ("Medium", "HTTP is unencrypted. Redirect all traffic to HTTPS."),
    "https": ("Low", "HTTPS is encrypted. Verify SSL certificate is valid."),
    "smtp": ("Medium", "Mail server exposed. Ensure authentication is required."),
    "smb": ("High", "SMB can be exploited. Ensure patched against EternalBlue."),
    "rdp": ("High", "RDP exposed to network. Restrict access via firewall."),
}
def get_severity(service):
    return SEVERITY.get(service.lower(), ("Info", "Review this service manually."))

def scan(target):
    scanner = nmap.PortScanner()
    print(f"\n[*] Scanning {target}...")
    scanner.scan(target, '1-1024', '-sV')
    results = []

    for host in scanner.all_hosts():
        print(f"[+] Host: {host} ({scanner[host].state()})")
        for proto in scanner[host].all_protocols():
            for port in sorted(scanner[host][proto].keys()):
                info = scanner[host][proto][port]
                service = info['name']
                state = info['state']
                version = info['version']
                severity, recommendation = get_severity(service)
                results.append({
                    "port": port,
                    "proto": proto,
                    "state": state,
                    "service": service,
                    "version": version,
                    "severity": severity,
                    "recommendation": recommendation
                })
                print(f"    {port}/{proto} - {state} - {service} {version} [{severity}]")
    return host, results

def generate_report(target, host, results):
    pdf = FPDF()
    pdf.add_page()

    # Title
    pdf.set_font("Arial", "B", 20)
    pdf.set_text_color(30, 30, 30)
    pdf.cell(0, 12, "Network Security Audit Report", ln=True, align="C")

    # Meta
    pdf.set_font("Arial", "", 11)
    pdf.set_text_color(100, 100, 100)
    pdf.cell(0, 8, f"Target: {target}   |   Date: {datetime.now().strftime('%Y-%m-%d %H:%M')}   |   Auditor: Rawan Rany", ln=True, align="C")
    pdf.ln(6)

    # Summary
    pdf.set_font("Arial", "B", 13)
    pdf.set_text_color(30, 30, 30)
    pdf.cell(0, 10, "Executive Summary", ln=True)
    pdf.set_font("Arial", "", 11)
    pdf.set_text_color(60, 60, 60)
    pdf.multi_cell(0, 7, f"This report presents the findings of an automated network security audit conducted against {target}. A total of {len(results)} open ports were identified. Each finding includes a severity rating and recommended remediation action.")
    pdf.ln(4)

    # Findings table
    pdf.set_font("Arial", "B", 13)
    pdf.set_text_color(30, 30, 30)
    pdf.cell(0, 10, "Findings", ln=True)

    # Table header
    pdf.set_fill_color(40, 40, 40)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Arial", "B", 10)
    pdf.cell(20, 8, "Port", border=1, fill=True, align="C")
    pdf.cell(20, 8, "Proto", border=1, fill=True, align="C")
    pdf.cell(25, 8, "State", border=1, fill=True, align="C")
    pdf.cell(30, 8, "Service", border=1, fill=True, align="C")
    pdf.cell(40, 8, "Version", border=1, fill=True, align="C")
    pdf.cell(25, 8, "Severity", border=1, fill=True, align="C")
    pdf.ln()

    # Severity colors
    colors = {
        "Critical": (200, 50, 50),
        "High": (220, 100, 40),
        "Medium": (200, 160, 0),
        "Low": (50, 150, 80),
        "Info": (100, 100, 200),
    }

    pdf.set_font("Arial", "", 9)
    for r in results:
        pdf.set_text_color(30, 30, 30)
        pdf.set_fill_color(245, 245, 245)
        pdf.cell(20, 7, str(r['port']), border=1, fill=True, align="C")
        pdf.cell(20, 7, r['proto'], border=1, fill=True, align="C")
        pdf.cell(25, 7, r['state'], border=1, fill=True, align="C")
        pdf.cell(30, 7, r['service'], border=1, fill=True, align="C")
        pdf.cell(40, 7, r['version'][:20], border=1, fill=True, align="C")
        c = colors.get(r['severity'], (100,100,100))
        pdf.set_text_color(c[0], c[1], c[2])
        pdf.cell(25, 7, r['severity'], border=1, fill=True, align="C")
        pdf.ln()

   # Recommendations
    pdf.ln(6)
    pdf.set_font("Arial", "B", 13)
    pdf.set_text_color(30, 30, 30)
    pdf.cell(0, 10, "Recommendations", ln=True)
    pdf.set_font("Arial", "", 11)
    for r in results:
        c = colors.get(r['severity'], (100,100,100))
        pdf.set_text_color(c[0], c[1], c[2])
        pdf.cell(0, 7, f"[{r['severity']}] Port {r['port']} - {r['service'].upper()}", ln=True)
        pdf.set_text_color(60, 60, 60)
        pdf.multi_cell(0, 6, f"  {r['recommendation']}")
        pdf.ln(1)

    filename = f"report_{target.replace('.','_')}_{datetime.now().strftime('%Y%m%d_%H%M')}.pdf"
    pdf.output(filename)
    print(f"\n[+] Report saved: {filename}")
if len(sys.argv) != 2:
    print("Usage: python3 scanner.py <target>")
    sys.exit(1)

target = sys.argv[1]
host, results = scan(target)
generate_report(target, host, results)
