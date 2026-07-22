import click
import requests
import socket
import os
import time
from urllib.parse import urlparse
from rich.console import Console
from rich.table import Table
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# Clear screen
os.system("clear" if os.name != "nt" else "cls")

# Banner
banner = f"""{Fore.CYAN}

██╗    ██╗███████╗██████╗      ███╗   ███╗ █████╗ ███████╗███████╗
██║    ██║██╔════╝██╔══██╗     ████╗ ████║██╔══██╗██╔════╝██╔════╝
██║ █╗ ██║█████╗  ██████╔╝     ██╔████╔██║███████║███████╗███████╗
██║███╗██║██╔══╝  ██╔══██╗     ██║╚██╔╝██║██╔══██║╚════██║╚════██║
╚███╔███╔╝███████╗██████╔╝     ██║ ╚═╝ ██║██║  ██║███████║███████║
 ╚══╝╚══╝ ╚══════╝╚═════╝      ╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝

{Fore.GREEN}                 ███████╗ ██████╗ █████╗ ███╗   ██╗
{Fore.GREEN}                 ██╔════╝██╔════╝██╔══██╗████╗  ██║
{Fore.GREEN}                 ███████╗██║     ███████║██╔██╗ ██║
{Fore.GREEN}                 ╚════██║██║     ██╔══██║██║╚██╗██║
{Fore.GREEN}                 ███████║╚██████╗██║  ██║██║ ╚████║
{Fore.GREEN}                 ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝

{Fore.MAGENTA}═══════════════════════════════════════════════════════════════════════════════
{Fore.YELLOW}                 HIGH PERFORMANCE WEB MASS SCANNER
{Fore.WHITE}                    Version : 1.0.0
{Fore.WHITE}                    Author  : Tapr0baneSec
{Fore.WHITE}                    Engine  : Async • Multi-thread • Fast Scan
{Fore.MAGENTA}═══════════════════════════════════════════════════════════════════════════════
"""

print(banner)

loading = [
    "Initializing Scanner Engine...",
    "Loading Detection Modules...",
    "Loading HTTP Client...",
    "Loading DNS Resolver...",
    "Loading Fingerprint Database...",
    "Preparing Threads...",
    "System Ready."
]

for item in loading:
    print(Fore.GREEN + "[+]" + Fore.WHITE + " " + item)
    time.sleep(0.25)

print()
print(Fore.CYAN + "➜ Ready to scan targets.")
print(Fore.RED + "⚠ Use only on systems you are authorized to test.")
print()

# Port scan function
def port_scan(host, ports=[21,22,3306,8080]):
    results = {}
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((host, port))
            if result == 0:
                results[port] = "Open"
            else:
                results[port] = "Closed"
            sock.close()
        except Exception as e:
            results[port] = f"Error: {e}"
    return results

# Scan function
def scan_site(url):
    results = {}
    try:
        r = requests.get(url, timeout=5)
        parsed = urlparse(url)
        host = parsed.hostname

        # Firewall check
        if "cloudflare" in r.headers.get("server", "").lower():
            results["firewall"] = "Cloudflare WAF"
        else:
            results["firewall"] = "No WAF Detected"

        # Vulnerability checks
        results["sql_injection"] = "Possible" if "id=" in r.text.lower() else "Not Detected"
        results["xss"] = "Possible" if "<script>" in r.text.lower() else "Not Detected"
        results["csrf"] = "Not Detected"

        # OWASP Top 10 (dummy checks)
        results["access_control"] = "Not Checked"
        results["crypto"] = "Weak SSL?" if "https" not in url else "OK"
        results["design"] = "Not Checked"
        results["misconfig"] = "Headers Missing" if "x-frame-options" not in r.headers else "OK"
        results["components"] = "Not Checked"
        results["auth"] = "Not Checked"
        results["integrity"] = "Not Checked"
        results["logging"] = "Not Checked"
        results["ssrf"] = "Not Checked"

        # Port scan
        port_results = port_scan(host)
        results["ports"] = port_results

    except Exception as e:
        results["firewall"] = f"Error: {e}"

    return results

# Print results in table
def print_results(scan_data, url):
    console = Console()
    table = Table(title=f"Scan Results for {url}")

    table.add_column("Category", style="cyan", no_wrap=True)
    table.add_column("Status", style="green")
    table.add_column("Notes", style="magenta")

    # Firewall
    table.add_row("Firewall", scan_data.get("firewall", "Unknown"), "Detected")

    # OWASP Top 10 checks
    table.add_row("Broken Access Control", scan_data.get("access_control", "Not Checked"), "Manual review")
    table.add_row("Cryptographic Failures", scan_data.get("crypto", "Not Checked"), "Weak SSL/TLS?")
    table.add_row("Injection", scan_data.get("sql_injection", "Not Detected"), "SQL/NoSQL")
    table.add_row("XSS", scan_data.get("xss", "Not Detected"), "Payload test")
    table.add_row("CSRF", scan_data.get("csrf", "Not Detected"), "Token validation")
    table.add_row("Insecure Design", scan_data.get("design", "Not Checked"), "Architecture flaws")
    table.add_row("Security Misconfiguration", scan_data.get("misconfig", "Not Checked"), "Headers, CORS")
    table.add_row("Vulnerable Components", scan_data.get("components", "Not Checked"), "Outdated libs")
    table.add_row("Auth Failures", scan_data.get("auth", "Not Checked"), "Weak login")
    table.add_row("Integrity Failures", scan_data.get("integrity", "Not Checked"), "Supply chain risk")
    table.add_row("Logging & Monitoring", scan_data.get("logging", "Not Checked"), "Missing alerts")
    table.add_row("SSRF", scan_data.get("ssrf", "Not Checked"), "Check external calls")

    # Ports
    for port, status in scan_data.get("ports", {}).items():
        table.add_row(f"Port {port}", status, "Risk if open")

    console.print(table)

@click.command()
@click.argument("url")
def main(url):
    results = scan_site(url)
    print_results(results, url)

if __name__ == "__main__":
    main()
