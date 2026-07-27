import os
import sys
import time
import socket
import requests
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor
from rich.console import Console
from rich.table import Table
from colorama import Fore, Style, init

# Initialize colorama & rich console
init(autoreset=True)
console = Console()

def clear_screen():
    os.system("clear" if os.name != "nt" else "cls")

def print_banner():
    banner = f"""{Fore.CYAN}
██╗    ██╗█]===[█╗██████╗      ███╗   ███╗█████╗ ███████╗█]===[█╗
██║    ██║██╔════╝██╔══██╗     ████╗ ████║██╔══██╗██╔════╝██╔════╝
██║ █╗ ██║█████╗  ██████╔╝     ██╔████╔██║███████║███████╗███████╗
██║███╗██║██╔══╝  ██╔══██╗     ██║╚██╔╝██║██╔══██║╚════██║╚════██║
╚███╔███╔╝█]===[█╗██████╔╝     ██║ ╚═╝ ██║██║  ██║███████║█]===[█╗
 ╚══╝╚══╝ ╚══════╝╚═════╝      ╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝

{Fore.GREEN}                 █]===[█╗ ██████╗ █████╗ ███╗   ██╗
{Fore.GREEN}                 ██╔════╝██╔════╝██╔══██╗████╗  ██║
{Fore.GREEN}                 ███████╗██║     ███████║██╔██╗ ██║
{Fore.GREEN}                 ╚════██║██║     ██╔══██║██║╚██╗██║
{Fore.GREEN}                 █]===[█║╚██████╗██║  ██║██║ ╚████║
{Fore.GREEN}                 ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝

{Fore.MAGENTA}═══════════════════════════════════════════════════════════════════════════════
{Fore.YELLOW}                 HIGH PERFORMANCE WEB MASS SCANNER  
{Fore.WHITE}                    Version : 2.0.0
{Fore.WHITE}                    Author  : Tapr0baneSec
{Fore.WHITE}                    Engine  : Async • Multi-thread • Fast Scan
{Fore.MAGENTA}═══════════════════════════════════════════════════════════════════════════════
"""
    print(banner)

def show_loading():
    loading = [
        "Initializing Scanner Engine...",
        "Loading Detection Modules...",
        "Loading HTTP Client...",
        "Loading DNS Resolver...",
        "Loading Fingerprint Database...",
        "Preparing Multi-threading Engine...",
        "System Ready."
    ]
    for item in loading:
        print(Fore.GREEN + "[+]" + Fore.WHITE + " " + item)
        time.sleep(0.12)
    print()
    print(Fore.CYAN + "➜ Ready to scan targets.")
    print(Fore.RED + "⚠ Use only on systems you are authorized to test.")
    print()

def format_url(url):
    url = url.strip()
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url
    return url

# Advanced WAF Detection Engine
def detect_waf(response):
    headers = {k.lower(): v.lower() for k, v in response.headers.items()}
    cookies = {k.lower(): v.lower() for k, v in response.cookies.items()}
    server = headers.get("server", "")

    wafs = []

    # Cloudflare
    if "cloudflare" in server or "cf-ray" in headers or "__cfduid" in cookies or "cf-cache-status" in headers:
        wafs.append("Cloudflare WAF")
    
    # AWS WAF / CloudFront
    if "aws" in server or "awselb" in server or "x-amz-cf-id" in headers or "amazon" in server:
        wafs.append("AWS WAF / CloudFront")

    # Akamai
    if "akamai" in server or "x-akamai-transformed" in headers or "akamaighost" in server:
        wafs.append("Akamai WAF")

    # Imperva / Incapsula
    if "incapsula" in server or "x-iinfo" in headers or "visid_incap" in cookies:
        wafs.append("Imperva Incapsula WAF")

    # Sucuri
    if "sucuri" in server or "x-sucuri-id" in headers or "x-sucuri-cache" in headers:
        wafs.append("Sucuri Firewall")

    # F5 BIG-IP
    if "big-ip" in server or "bigip" in server or "x-cnection" in headers:
        wafs.append("F5 BIG-IP ASM")

    # ModSecurity
    if "mod_security" in server or "modsecurity" in server:
        wafs.append("ModSecurity WAF")

    # DataDome
    if "datadome" in headers or "datadome" in cookies:
        wafs.append("DataDome WAF")

    if wafs:
        return ", ".join(wafs)
    return "No WAF Detected"

def check_single_port(host, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.8)
        result = sock.connect_ex((host, port))
        sock.close()
        if result == 0:
            return port, "Open"
        else:
            return port, "Closed"
    except Exception as e:
        return port, f"Error: {e}"

# High-Speed Multi-Threaded Port Scanner
def port_scan_fast(host, ports=[21, 22, 23, 25, 23, 80, 443, 445, 1433, 3306, 3389, 8080]):
    results = {}
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = [executor.submit(check_single_port, host, port) for port in ports]
        for future in futures:
            port, status = future.result()
            results[port] = status
    return results

# Main Target Scanner Logic
def scan_site(url):
    results = {
        "url": url,
        "host": "Unknown",
        "ip": "Unknown",
        "waf": "Not Checked",
        "owasp": {},
        "ports": {}
    }
    
    formatted_url = format_url(url)
    parsed = urlparse(formatted_url)
    host = parsed.hostname if parsed.hostname else url

    results["host"] = host

    # DNS Resolve IP
    try:
        ip = socket.gethostbyname(host)
        results["ip"] = ip
    except Exception:
        results["ip"] = "Resolution Failed"

    # HTTP Inspection
    try:
        r = requests.get(
            formatted_url, 
            timeout=5, 
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        )
        
        # Enhanced WAF Detection
        results["waf"] = detect_waf(r)

        # OWASP Security Checks
        owasp = {}
        owasp["A01: Broken Access Control"] = ("Manual Review Needed", "Verify endpoint & API access controls")
        owasp["A02: Cryptographic Failures"] = ("HTTPS Active" if formatted_url.startswith("https://") else "Weak SSL / HTTP Only", "Ensure HTTPS & strong TLS cipher suites")
        owasp["A03: Injection (SQLi)"] = ("Possible (id= parameter in body)" if "id=" in r.text.lower() else "Not Detected", "Check user inputs against SQL queries")
        owasp["A03: Cross-Site Scripting (XSS)"] = ("Possible (<script> payload present)" if "<script>" in r.text.lower() else "Not Detected", "Sanitize & encode output parameters")
        owasp["A04: Insecure Design"] = ("Manual Review Needed", "Architecture & business logic review required")
        owasp["A05: Security Misconfiguration"] = ("Missing X-Frame-Options Header" if "x-frame-options" not in r.headers.keys() else "X-Frame-Options Present", "Review clickjacking & HTTP headers")
        owasp["A06: Vulnerable Components"] = (f"Server Header Exposed: {r.headers.get('server')}" if "server" in r.headers else "Server Header Hidden", "Check version against known CVEs")
        owasp["A07: Identification & Auth Failures"] = ("Manual Review Needed", "Test authentication & session management")
        owasp["A08: Software & Data Integrity Failures"] = ("Not Checked", "Review supply chain & integrity controls")
        owasp["A09: Security Logging & Monitoring"] = ("Not Checked", "Verify audit logging mechanisms")
        owasp["A10: Server-Side Request Forgery (SSRF)"] = ("Not Checked", "Verify external resource URL handlers")

        results["owasp"] = owasp

    except Exception as e:
        results["waf"] = f"Request Error: {e}"
        results["owasp"] = {
            "Error": ("Failed to fetch HTTP content", str(e))
        }

    # Execute Multi-Threaded Port Scan
    results["ports"] = port_scan_fast(host)

    return results

# Function to Render Separate, Beautiful Rich Tables
def print_separated_results(scan_data):
    url = scan_data["url"]
    host = scan_data["host"]
    ip = scan_data["ip"]

    print()
    console.print(f"[bold cyan]██████]=======[████████ SCAN RESULTS FOR: {url} ███████]========[███████[/bold cyan]")
    print()

    # Table 1: Target & WAF Information Details
    table_waf = Table(title="Target & WAF Detection Details", title_style="bold cyan", expand=True)
    table_waf.add_column("Category / Parameter", style="cyan", no_wrap=True)
    table_waf.add_column("Value / Details", style="yellow")
    table_waf.add_column("Status / Detection Engine", style="green")

    table_waf.add_row("Target URL", url, "Input Target")
    table_waf.add_row("Hostname", host, "Parsed Host")
    table_waf.add_row("IP Address", ip, "DNS Resolved IP" if ip != "Resolution Failed" else "Unresolved")
    
    waf_status = scan_data.get("waf", "Unknown")
    waf_color = "bold green" if "No WAF" in waf_status else "bold red"
    table_waf.add_row("Firewall (WAF)", f"[{waf_color}]{waf_status}[/{waf_color}]", "Multi-Header / Cookie Inspector")

    console.print(table_waf)
    print()

    # Table 2: OWASP Top 10 Security Audit
    table_owasp = Table(title="OWASP Top 10 Vulnerability Audit", title_style="bold magenta", expand=True)
    table_owasp.add_column("OWASP Category", style="cyan", no_wrap=True)
    table_owasp.add_column("Status / Finding", style="bold yellow")
    table_owasp.add_column("Recommendation / Security Notes", style="white")

    for cat, val in scan_data.get("owasp", {}).items():
        status, notes = val
        status_color = "red" if any(w in status for w in ["Possible", "Weak", "Missing", "Exposed", "Error"]) else "green"
        table_owasp.add_row(cat, f"[{status_color}]{status}[/{status_color}]", notes)

    console.print(table_owasp)
    print()

    # Table 3: Port Scan Results
    table_ports = Table(title=f"Port Scan Results [{host} - {ip}]", title_style="bold green", expand=True)
    table_ports.add_column("Port Number", style="cyan", no_wrap=True)
    table_ports.add_column("State", style="bold")
    table_ports.add_column("Risk Assessment / Notes", style="magenta")

    for port, state in sorted(scan_data.get("ports", {}).items()):
        state_str = f"[bold green]{state}[/bold green]" if state == "Open" else f"[dim white]{state}[/dim white]"
        risk_str = "⚠ High Risk Service (Exposed)" if state == "Open" and port in [21, 22, 23, 445, 1433, 3306, 3389] else ("Standard Web Port" if port in [80, 443, 8080] else "Normal Port")
        table_ports.add_row(f"Port {port}", state_str, risk_str)

    console.print(table_ports)
    print()
    console.print("[bold yellow]" + "═"*90 + "[/bold yellow]")
    print()

def main():
    clear_screen()
    print_banner()
    show_loading()

    print(Fore.YELLOW + "Select Scan Mode:")
    print(Fore.CYAN + "  [01] Bulk Scan (Multi-Target Mass Scan - Max 10 URLs)")
    print(Fore.CYAN + "  [02] Single & Fast Scan (High Speed Single Target)")
    print()
    
    choice = input(Fore.GREEN + "Enter your choice (01 or 02): " + Fore.WHITE).strip()

    if choice in ["01", "1"]:
        try:
            count_str = input(Fore.GREEN + "Enter URL count (Max 10): " + Fore.WHITE).strip()
            count = int(count_str)
            if count < 1 or count > 10:
                print(Fore.RED + "[-] Invalid count! Please enter a number between 1 and 10.")
                sys.exit(1)
        except ValueError:
            print(Fore.RED + "[-] Please enter a valid integer!")
            sys.exit(1)

        urls = []
        print(Fore.CYAN + f"\nPlease enter {count} URLs below:")
        for i in range(1, count + 1):
            target_url = input(Fore.YELLOW + f"  URL {i}/{count}: " + Fore.WHITE).strip()
            if target_url:
                urls.append(target_url)

        if not urls:
            print(Fore.RED + "[-] No valid URLs provided!")
            sys.exit(1)

        print(Fore.GREEN + f"\n[+] Starting High-Speed Mass Scan for {len(urls)} target(s)...\n")

        # Multi-Threaded Mass Scan Execution
        with ThreadPoolExecutor(max_workers=min(len(urls), 10)) as executor:
            results = list(executor.map(scan_site, urls))

        print(Fore.MAGENTA + "\n" + "="*40 + " FINAL SCAN RESULTS " + "="*40 + "\n")
        for res in results:
            print_separated_results(res)

    elif choice in ["02", "2"]:
        target_url = input(Fore.GREEN + "\nEnter Target URL: " + Fore.WHITE).strip()
        if not target_url:
            print(Fore.RED + "[-] URL cannot be empty!")
            sys.exit(1)

        print(Fore.GREEN + "\n[+] Starting High-Speed Single Target Scan...\n")
        res = scan_site(target_url)
        
        print(Fore.MAGENTA + "\n" + "="*40 + " FINAL SCAN RESULTS " + "="*40 + "\n")
        print_separated_results(res)

    else:
        print(Fore.RED + "[-] Invalid option selected! Exiting.")

if __name__ == "__main__":
    main()