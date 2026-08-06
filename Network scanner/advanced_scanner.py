#!/usr/bin/env python3
"""
Advanced Network Vulnerability Scanner
Features: CVE lookup (NVD API + local DB), HTML report, GUI, multithreading, scheduling, NSE scripts
"""

import subprocess
import sys
import re
import json
import threading
import time
import os
from datetime import datetime
import socket

# Try to import optional libraries
try:
    import nmap
    HAS_NMAP = True
except ImportError:
    HAS_NMAP = False
    print("[!] python-nmap not found. Install: pip3 install python-nmap")

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False
    print("[!] requests not found. Install: pip3 install requests")


# ============================================================
# PART 1: CVE Lookup — Local DB + NVD API
# ============================================================

# Local fallback vulnerability database
LOCAL_VULN_DB = {
    "openssh": [
        {"cve": "CVE-2016-6210", "score": "7.5", "desc": "OpenSSH < 7.4 user enumeration via timing attack"},
        {"cve": "CVE-2018-15473", "score": "5.3", "desc": "OpenSSH < 7.7 user enumeration vulnerability"},
        {"cve": "CVE-2023-38408", "score": "9.8", "desc": "OpenSSH ssh-agent remote code execution"},
    ],
    "ssh": [
        {"cve": "CVE-2016-6210", "score": "7.5", "desc": "OpenSSH < 7.4 user enumeration"},
    ],
    "apache": [
        {"cve": "CVE-2021-41773", "score": "9.8", "desc": "Apache 2.4.49 path traversal and RCE"},
        {"cve": "CVE-2021-42013", "score": "9.8", "desc": "Apache 2.4.50 path traversal bypass"},
        {"cve": "CVE-2014-6271",  "score": "9.8", "desc": "Shellshock in CGI scripts (Apache/mod_cgi)"},
    ],
    "http": [
        {"cve": "CVE-2014-6271", "score": "9.8", "desc": "Shellshock in CGI scripts"},
    ],
    "smb": [
        {"cve": "CVE-2017-0144", "score": "8.5", "desc": "EternalBlue SMBv1 remote code execution"},
        {"cve": "CVE-2020-0796", "score": "10.0", "desc": "SMBGhost: SMBv3 buffer overflow (Win10)"},
    ],
    "ftp": [
        {"cve": "CVE-2015-3306", "score": "7.8", "desc": "ProFTPD 1.3.5 mod_copy arbitrary command execution"},
        {"cve": "CVE-2010-4221", "score": "10.0", "desc": "ProFTPD 1.3.2-1.3.3c remote code execution"},
    ],
    "mysql": [
        {"cve": "CVE-2012-2122", "score": "8.5", "desc": "MySQL authentication bypass via timing attack"},
        {"cve": "CVE-2016-6662", "score": "9.8", "desc": "MySQL remote root code execution"},
    ],
    "rdp": [
        {"cve": "CVE-2019-0708", "score": "9.8", "desc": "BlueKeep: RDP pre-auth remote code execution"},
        {"cve": "CVE-2012-0002", "score": "9.3", "desc": "MS12-020: RDP remote code execution"},
    ],
    "vnc": [
        {"cve": "CVE-2006-2369", "score": "7.5", "desc": "RealVNC authentication bypass"},
    ],
    "telnet": [
        {"cve": "CVE-2020-10188", "score": "9.8", "desc": "Telnet remote code execution via environment variables"},
    ],
    "smtp": [
        {"cve": "CVE-2020-28017", "score": "9.8", "desc": "Exim < 4.94.2 heap overflow (21Nails) - remote code execution"},
        {"cve": "CVE-2019-10149", "score": "9.8", "desc": "Exim < 4.92 remote command execution via MAIL FROM"},
        {"cve": "CVE-2021-27135", "score": "9.8", "desc": "Postfix SMTP smuggling allows spoofed emails"},
    ],
    "postfix": [
        {"cve": "CVE-2021-27135", "score": "9.8", "desc": "Postfix SMTP smuggling allows spoofed emails"},
        {"cve": "CVE-2011-1720", "score": "6.8", "desc": "Postfix SASL authentication memory corruption"},
    ],
    "exim": [
        {"cve": "CVE-2020-28017", "score": "9.8", "desc": "Exim < 4.94.2 heap overflow (21Nails)"},
        {"cve": "CVE-2019-10149", "score": "9.8", "desc": "Exim < 4.92 remote command execution"},
        {"cve": "CVE-2018-6789",  "score": "9.8", "desc": "Exim < 4.90.1 buffer overflow in base64 decoder"},
    ],
    "sendmail": [
        {"cve": "CVE-2014-3956", "score": "4.3", "desc": "Sendmail allows unintended open relay via IPv6"},
        {"cve": "CVE-2006-0058", "score": "9.3", "desc": "Sendmail signal handling race condition - remote exploit"},
    ],
    "pop3": [
        {"cve": "CVE-2003-0297", "score": "7.5", "desc": "Courier-IMAP POP3 server buffer overflow"},
    ],
    "imap": [
        {"cve": "CVE-2021-38370", "score": "7.4", "desc": "Alpine IMAP client STARTTLS plaintext injection"},
        {"cve": "CVE-2011-2813", "score": "7.5", "desc": "Dovecot IMAP server memory corruption"},
    ],
    "dns": [
        {"cve": "CVE-2020-1350", "score": "10.0", "desc": "SIGRed: Windows DNS Server wormable RCE"},
        {"cve": "CVE-2008-1447", "score": "6.8", "desc": "Kaminsky DNS cache poisoning attack"},
    ],
}

# ============================================================
# CPE (Common Platform Enumeration) mapping
# Maps nmap banner keywords → (vendor, product) for NVD CPE API
# Format used: cpe:2.3:a:<vendor>:<product>:<version>
# ============================================================
CPE_MAP = {
    "openssh":      ("openbsd",         "openssh"),
    "ssh":          ("openbsd",         "openssh"),
    "apache":       ("apache",          "http_server"),
    "httpd":        ("apache",          "http_server"),
    "http":         ("apache",          "http_server"),
    "nginx":        ("nginx",           "nginx"),
    "postfix":      ("postfix",         "postfix"),
    "smtp":         ("postfix",         "postfix"),
    "exim":         ("exim",            "exim"),
    "sendmail":     ("sendmail",        "sendmail"),
    "vsftpd":       ("beasts",          "vsftpd"),
    "proftpd":      ("proftpd",         "proftpd"),
    "ftp":          ("proftpd",         "proftpd"),
    "mysql":        ("mysql",           "mysql"),
    "mariadb":      ("mariadb",         "mariadb"),
    "openssh":      ("openbsd",         "openssh"),
    "microsoft-ds": ("microsoft",       "windows"),
    "smb":          ("samba",           "samba"),
    "rdp":          ("microsoft",       "remote_desktop_protocol"),
    "ms-wbt-server":("microsoft",       "remote_desktop_protocol"),
    "vnc":          ("realvnc",         "vnc"),
    "telnet":       ("mit",             "kerberos_5"),
    "pop3":         ("dovecot",         "dovecot"),
    "imap":         ("dovecot",         "dovecot"),
    "dovecot":      ("dovecot",         "dovecot"),
    "bind":         ("isc",             "bind"),
    "domain":       ("isc",             "bind"),
    "dns":          ("isc",             "bind"),
    "tomcat":       ("apache",          "tomcat"),
    "iis":          ("microsoft",       "internet_information_services"),
    "php":          ("php",             "php"),
    "openssl":      ("openssl",         "openssl"),
}


def parse_nmap_banner(raw_service):
    """
    Parse raw nmap banner string into (service_key, clean_version).

    Examples:
      'ssh OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13 (Ubuntu Linux; protocol 2.0)'
        → ('openssh', '6.6.1')

      'http Apache httpd 2.4.7 ((Ubuntu))'
        → ('apache', '2.4.7')

      'smtp?'
        → ('smtp', '')

      'mysql 5.5.62-0ubuntu0.14.04.1'
        → ('mysql', '5.5.62')
    """
    raw = raw_service.strip().rstrip("?").lower()

    # Detect service key from CPE_MAP
    detected_key = None
    for keyword in sorted(CPE_MAP.keys(), key=len, reverse=True):
        if keyword in raw:
            detected_key = keyword
            break

    if not detected_key:
        # Fallback: first word
        detected_key = raw.split()[0] if raw.split() else ""

    # Extract version number: first X.Y.Z or X.Y pattern in the string
    version_match = re.search(r'\b(\d+\.\d+[\.\d+p\d+]*)', raw)
    version = ""
    if version_match:
        # Clean version: keep only digits and dots (e.g. 6.6.1p1 → 6.6.1)
        raw_ver = version_match.group(1)
        version = re.sub(r'[^0-9.]', '', raw_ver).strip(".")

    return detected_key, version


def cpe_lookup(vendor, product, version):
    """
    Query NVD CPE Match API to get CVEs affecting exact product+version.
    Uses: /rest/json/cves/2.0?cpeName=cpe:2.3:a:<vendor>:<product>:<version>:*:*:*:*:*:*:*

    This is version-EXACT: only returns CVEs that actually affect this version.
    """
    cpe_string = f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        "cpeName": cpe_string,
        "resultsPerPage": 10,
    }
    try:
        resp = requests.get(url, params=params, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            results = []
            for item in data.get("vulnerabilities", []):
                cve_id = item["cve"]["id"]
                desc_list = item["cve"].get("descriptions", [])
                desc = next((d["value"] for d in desc_list if d["lang"] == "en"), "No description")
                score = "-"
                metrics = item["cve"].get("metrics", {})
                for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    if key in metrics and metrics[key]:
                        score = str(metrics[key][0]["cvssData"].get("baseScore", "-"))
                        break
                results.append({
                    "cve": cve_id,
                    "score": score,
                    "desc": desc[:150],
                    "source": "NVD-CPE"
                })
            return results
        elif resp.status_code == 403:
            print(f"  [!] NVD rate limited. Wait 30s or use --no-api flag.")
        return []
    except Exception as e:
        print(f"  [!] CPE API error: {e}")
        return []


def keyword_lookup(keyword):
    """
    Fallback: NVD keyword search (less accurate, no version filtering).
    Used when CPE lookup returns nothing.
    """
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {"keywordSearch": keyword, "resultsPerPage": 10}
    try:
        resp = requests.get(url, params=params, timeout=8)
        if resp.status_code == 200:
            data = resp.json()
            results = []
            for item in data.get("vulnerabilities", []):
                cve_id = item["cve"]["id"]
                # Skip ancient CVEs (before 2005) in keyword mode — too generic
                year = int(cve_id.split("-")[1]) if "-" in cve_id else 0
                if year < 2005:
                    continue
                desc_list = item["cve"].get("descriptions", [])
                desc = next((d["value"] for d in desc_list if d["lang"] == "en"), "No description")
                score = "-"
                metrics = item["cve"].get("metrics", {})
                for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    if key in metrics and metrics[key]:
                        score = str(metrics[key][0]["cvssData"].get("baseScore", "-"))
                        break
                results.append({
                    "cve": cve_id,
                    "score": score,
                    "desc": desc[:150],
                    "source": "NVD-keyword"
                })
            return results
    except Exception as e:
        print(f"  [!] Keyword API error: {e}")
    return []


def local_db_lookup(raw_service):
    """Fallback to local hardcoded DB."""
    service_lower = raw_service.lower().rstrip("?")
    for key, cve_list in LOCAL_VULN_DB.items():
        if key in service_lower:
            return [dict(c, source="local-db") for c in cve_list]
    return []


def searchCVE(raw_service):
    """
    3-tier CVE lookup:
      Tier 1 — NVD CPE API (version-exact, most accurate)
      Tier 2 — NVD keyword API (no version filter, filters pre-2005)
      Tier 3 — Local DB (offline fallback)
    """
    service_key, version = parse_nmap_banner(raw_service)

    # Tier 1: CPE exact version match
    if HAS_REQUESTS and version and service_key in CPE_MAP:
        vendor, product = CPE_MAP[service_key]
        print(f"         → CPE lookup: cpe:2.3:a:{vendor}:{product}:{version}")
        results = cpe_lookup(vendor, product, version)
        if results:
            return results, "CPE-exact"

    # Tier 2: Keyword search (with year filter)
    if HAS_REQUESTS and service_key:
        # Build a clean keyword from the key
        keyword_map = {k: v[1].replace("_", " ") for k, v in
                       {k: CPE_MAP[k] for k in CPE_MAP}.items()}
        keyword = keyword_map.get(service_key, service_key)
        print(f"         → Keyword fallback: '{keyword}'")
        results = keyword_lookup(keyword)
        if results:
            return results, "keyword"

    # Tier 3: Local DB
    results = local_db_lookup(raw_service)
    return results, "local-db"


def lookup_cve(raw_service):
    """
    Returns the single highest-severity CVE dict for this service, or None.
    Also prints what method was used so you can see accuracy level.
    """
    service_key, version = parse_nmap_banner(raw_service)
    print(f"  [*] {raw_service!r}")
    print(f"         → Detected: service='{service_key}'  version='{version or 'unknown'}'")

    cves, method = searchCVE(raw_service)

    if not cves:
        print(f"         → No CVEs found")
        return None

    def score_key(c):
        try:
            return float(c.get("score", 0))
        except (ValueError, TypeError):
            return 0

    best = max(cves, key=score_key)
    print(f"         → {len(cves)} CVE(s) found via [{method}] — best: {best['cve']} (score {best['score']})")
    return best


# ============================================================
# PART 2: NSE Scripts (safe vulnerability checks)
# ============================================================

def run_nse_scripts(ip, port, service):
    """Run Nmap NSE scripts for specific services."""
    scripts = []
    if "ssh" in service:
        scripts.append("ssh2-enum-algos")
    elif "smb" in service or str(port) == "445":
        scripts.append("smb-vuln-ms17-010")
    elif "http" in service or str(port) in ("80", "443"):
        scripts.append("http-shellshock")
        scripts.append("http-vuln-cve2014-2126")

    results = {}
    for script in scripts:
        cmd = f"nmap --script {script} -p {port} {ip} -oG -"
        try:
            output = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30).stdout
            if "VULNERABLE" in output or "vulnerable" in output.lower():
                results[script] = "⚠️  VULNERABLE"
            else:
                results[script] = "Not vulnerable"
        except subprocess.TimeoutExpired:
            results[script] = "Timeout"
    return results


# ============================================================
# PART 3: Version Detection via Nmap
# ============================================================

def get_service_version(ip, port):
    """Use nmap -sV to detect service name and version."""
    cmd = f"nmap -sV -p {port} {ip} --version-intensity 5 -oG -"
    try:
        output = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30).stdout
        # Parse line like: Ports: 22/open/tcp//ssh//OpenSSH 6.6.1p1 Ubuntu.../
        match = re.search(rf"{port}/open/tcp//(\S+)//([^/]+)/", output)
        if match:
            service = match.group(1)
            version = match.group(2).strip()
            return service, version
        # Simple fallback: look for service keyword
        service_map = {
            "ssh": "ssh", "http": "http", "ftp": "ftp",
            "mysql": "mysql", "microsoft-ds": "smb", "smb": "smb",
            "rdp": "rdp", "ms-wbt-server": "rdp", "vnc": "vnc", "telnet": "telnet"
        }
        for kw, svc in service_map.items():
            if kw in output.lower():
                return svc, ""
    except subprocess.TimeoutExpired:
        pass
    return "unknown", ""


# ============================================================
# PART 4: HTML Report Generator
# ============================================================

def generate_html_report(scan_results, filename="scan_report.html"):
    """Creates a professional colour-coded HTML report."""
    total_vulns = sum(
        1 for data in scan_results.values()
        for info in data.get("ports", {}).values()
        if info.get("cve")
    )

    html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Network Vulnerability Scan Report</title>
    <meta charset="UTF-8">
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background: #f9f9f9; }}
        h1 {{ color: #2c3e50; }}
        .summary {{ background: #ecf0f1; padding: 15px; border-radius: 8px; margin-bottom: 20px; }}
        .summary p {{ margin: 4px 0; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 10px; background: white; }}
        th, td {{ border: 1px solid #ddd; padding: 10px; text-align: left; font-size: 13px; }}
        th {{ background-color: #2c3e50; color: white; }}
        tr:hover {{ filter: brightness(0.95); }}
        .critical {{ background-color: #ffcccc; }}
        .high     {{ background-color: #ffebcc; }}
        .medium   {{ background-color: #ffffcc; }}
        .low      {{ background-color: #e8f8e8; }}
        .none     {{ background-color: #f0f0f0; }}
        .badge {{ display:inline-block; padding:2px 8px; border-radius:4px;
                  font-weight:bold; font-size:11px; }}
        .badge-critical {{ background:#c0392b; color:white; }}
        .badge-high     {{ background:#e67e22; color:white; }}
        .badge-medium   {{ background:#f1c40f; color:#333; }}
        .badge-low      {{ background:#27ae60; color:white; }}
        .badge-none     {{ background:#95a5a6; color:white; }}
        footer {{ margin-top: 30px; color: #999; font-size: 12px; }}
    </style>
</head>
<body>
    <h1>🔍 Network Vulnerability Scan Report</h1>
    <div class="summary">
        <p><strong>Scan Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p><strong>Total Hosts Scanned:</strong> {len(scan_results)}</p>
        <p><strong>Total Vulnerabilities Found:</strong> {total_vulns}</p>
    </div>
    <table>
        <tr>
            <th>IP Address</th><th>Port</th><th>Service</th><th>Version</th>
            <th>CVE ID</th><th>Severity</th><th>Description</th><th>NSE Result</th>
        </tr>
"""

    for ip, data in scan_results.items():
        if not data.get("ports"):
            html += f"""
        <tr class="none">
            <td>{ip}</td>
            <td colspan="7"><em>No open ports found</em></td>
        </tr>"""
            continue
        for port, info in data["ports"].items():
            cve_info = info.get("cve") or {}
            score_str = cve_info.get("score", "-")
            try:
                score = float(score_str)
            except (ValueError, TypeError):
                score = 0

            if score >= 9:
                cls, badge = "critical", "badge-critical"
                label = f"Critical ({score_str})"
            elif score >= 7:
                cls, badge = "high", "badge-high"
                label = f"High ({score_str})"
            elif score >= 4:
                cls, badge = "medium", "badge-medium"
                label = f"Medium ({score_str})"
            elif score > 0:
                cls, badge = "low", "badge-low"
                label = f"Low ({score_str})"
            else:
                cls, badge = "none", "badge-none"
                label = "None"

            nse = info.get("nse", {})
            nse_text = "; ".join(f"{s}: {r}" for s, r in nse.items()) if nse else "-"
            method = info.get("cve_method", "-")
            all_cves = info.get("all_cves", [])

            # Build CVE cell: show best CVE + count of others
            if cve_info:
                cve_cell = f"{cve_info.get('cve', 'None')}"
                if len(all_cves) > 1:
                    cve_cell += f" (+{len(all_cves)-1} more)"
                cve_cell += f"<br><small style='color:#666'>[{method}]</small>"
            else:
                cve_cell = "None"

            html += f"""
        <tr class="{cls}">
            <td>{ip}</td>
            <td>{port}</td>
            <td>{info.get('service', 'unknown')}</td>
            <td>{info.get('version', '-')}</td>
            <td>{cve_cell}</td>
            <td><span class="badge {badge}">{label}</span></td>
            <td>{cve_info.get('desc', 'No known vulnerability') if cve_info else 'No CVEs found'}</td>
            <td>{nse_text}</td>
        </tr>"""

    html += """
    </table>
    <footer><i>Generated by Advanced Network Vulnerability Scanner</i></footer>
</body>
</html>"""

    with open(filename, "w") as f:
        f.write(html)
    print(f"✅ HTML report saved as {filename}")
    return filename


# ============================================================
# PART 5: Multithreaded Scanner
# ============================================================

DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5900, 8080, 8443]


class ThreadedScanner:
    def __init__(self, ips, ports=None, threads=10, run_nse=False):
        self.ips = ips
        self.ports = ports or DEFAULT_PORTS
        self.threads = threads
        self.run_nse = run_nse
        self.results = {}
        self.lock = threading.Lock()

    def scan_ip(self, ip):
        """Scan a single IP: port check → version detect → CVE lookup → NSE."""
        ip_results = {"ports": {}}

        # Build nmap command for all ports at once (faster)
        port_str = ",".join(map(str, self.ports))
        cmd = f"nmap -sV --version-intensity 5 -p {port_str} {ip} -oG -"
        try:
            output = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=120).stdout
        except subprocess.TimeoutExpired:
            output = ""

        for port in self.ports:
            if f"{port}/open" in output:
                # Extract service + version from grepable output
                # Example line: Ports: 22/open/tcp//ssh//OpenSSH 6.6.1p1/
                match = re.search(rf"{port}/open/tcp//([^/]*)//([^/]*)/", output)
                if match:
                    service = match.group(1).strip() or "unknown"
                    version = match.group(2).strip()
                else:
                    service, version = "unknown", ""
                    # Best-effort keyword detection
                    for kw in ("ssh", "http", "ftp", "mysql", "smb", "rdp", "vnc", "telnet", "smtp", "pop3", "imap"):
                        if kw in output.lower():
                            service = kw
                            break

                # Build full banner for CVE lookup
                banner = f"{service} {version}".strip() if version else service

                # CVE lookup — version-exact via CPE API
                cve_info = lookup_cve(banner)

                # Get all CVEs for the HTML report
                all_cves, method = searchCVE(banner)

                # Optional NSE scripts
                nse_results = {}
                if self.run_nse:
                    nse_results = run_nse_scripts(ip, port, service)

                ip_results["ports"][str(port)] = {
                    "service": service,
                    "version": version,
                    "banner": banner,
                    "cve": cve_info,
                    "all_cves": all_cves,
                    "cve_method": method,
                    "nse": nse_results,
                }

        with self.lock:
            self.results[ip] = ip_results

    def run(self):
        threads = []
        for ip in self.ips:
            t = threading.Thread(target=self.scan_ip, args=(ip,), daemon=True)
            threads.append(t)
            t.start()
            if len(threads) >= self.threads:
                for t in threads:
                    t.join()
                threads = []
        for t in threads:
            t.join()
        return self.results


# ============================================================
# PART 6: Host Discovery
# ============================================================

def discover_hosts(network):
    """Ping sweep to find live IPs."""
    cmd = f"nmap -sn {network} -oG -"
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)
        live_ips = []
        for line in result.stdout.split('\n'):
            if 'Status: Up' in line:
                parts = line.split()
                for part in parts:
                    if part.count('.') == 3 and part[0].isdigit():
                        live_ips.append(part)
                        break
                # Also handle hostnames
                if not live_ips or live_ips[-1].count('.') != 3:
                    match = re.search(r'Host: (\S+)', line)
                    if match:
                        live_ips.append(match.group(1))
        return live_ips
    except subprocess.TimeoutExpired:
        return []


def resolve_target(target):
    """Resolve hostname to IP if needed."""
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return target


# ============================================================
# PART 7: GUI (Tkinter)
# ============================================================

def launch_gui():
    try:
        import tkinter as tk
        from tkinter import scrolledtext, messagebox, ttk
    except ImportError:
        print("[!] Tkinter not available. Install: sudo apt install python3-tk")
        return

    def log(msg):
        text_output.insert(tk.END, msg + "\n")
        text_output.see(tk.END)
        root.update_idletasks()

    def start_scan():
        network = entry_network.get().strip()
        if not network:
            messagebox.showerror("Error", "Please enter a network range or hostname")
            return

        btn_scan.config(state=tk.DISABLED, text="Scanning…")
        text_output.delete(1.0, tk.END)
        progress_bar.start(10)

        def scan_thread():
            log(f"[1] Discovering hosts on {network}…")
            live_ips = discover_hosts(network)

            if not live_ips:
                ip = resolve_target(network)
                live_ips = [ip]
                log(f"    No sweep results. Treating as single target: {ip}")
            else:
                log(f"✅ Found {len(live_ips)} live IP(s): {', '.join(live_ips)}")

            log("\n[2] Starting vulnerability scan…")
            use_nse = var_nse.get()
            scanner = ThreadedScanner(live_ips, run_nse=use_nse)
            results = scanner.run()

            log(f"\n[3] Results ({len(results)} host(s)):")
            for ip, data in results.items():
                if data["ports"]:
                    log(f"\n  {ip}:")
                    for port, info in data["ports"].items():
                        svc = info.get("service", "unknown")
                        ver = info.get("version", "")
                        cve = info.get("cve")
                        line = f"    Port {port}: {svc} {ver}"
                        if cve:
                            line += f" → {cve['cve']} (Score: {cve['score']})"
                        else:
                            line += " → No CVE found"
                        log(line)
                        for script, res in info.get("nse", {}).items():
                            log(f"      NSE [{script}]: {res}")
                else:
                    log(f"\n  {ip}: No open ports found")

            log("\n[4] Generating HTML report…")
            report_file = generate_html_report(results)
            log(f"✅ Report saved: {report_file}")
            log("\nDone! Open the report in your browser.")

            progress_bar.stop()
            btn_scan.config(state=tk.NORMAL, text="Start Scan")

        threading.Thread(target=scan_thread, daemon=True).start()

    # --- Build GUI ---
    root = tk.Tk()
    root.title("Advanced Network Vulnerability Scanner")
    root.geometry("800x580")
    root.configure(bg="#2c3e50")

    header = tk.Frame(root, bg="#2c3e50", pady=10)
    header.pack(fill=tk.X)
    tk.Label(header, text="🔍 Network Vulnerability Scanner",
             font=("Arial", 16, "bold"), bg="#2c3e50", fg="white").pack()

    form = tk.Frame(root, bg="#ecf0f1", pady=10, padx=20)
    form.pack(fill=tk.X, padx=20)

    tk.Label(form, text="Target (IP, hostname, or CIDR range):",
             font=("Arial", 11), bg="#ecf0f1").grid(row=0, column=0, sticky="w", pady=5)
    entry_network = tk.Entry(form, width=40, font=("Arial", 11))
    entry_network.grid(row=0, column=1, padx=10, pady=5)
    entry_network.insert(0, "scanme.nmap.org")

    var_nse = tk.BooleanVar(value=False)
    tk.Checkbutton(form, text="Run NSE vulnerability scripts (slower)",
                   variable=var_nse, bg="#ecf0f1", font=("Arial", 10)).grid(
        row=1, column=0, columnspan=2, sticky="w", pady=2)

    btn_scan = tk.Button(form, text="Start Scan", command=start_scan,
                         bg="#27ae60", fg="white", font=("Arial", 12, "bold"),
                         padx=20, pady=5, relief=tk.FLAT, cursor="hand2")
    btn_scan.grid(row=2, column=0, columnspan=2, pady=10)

    progress_bar = ttk.Progressbar(root, mode="indeterminate", length=760)
    progress_bar.pack(pady=(0, 5), padx=20)

    text_output = scrolledtext.ScrolledText(root, width=95, height=22,
                                            font=("Courier", 10), bg="#1e1e1e", fg="#d4d4d4")
    text_output.pack(pady=5, padx=20)

    root.mainloop()


# ============================================================
# PART 8: Scheduling (cron)
# ============================================================

def setup_scheduling(network="10.0.3.0/24"):
    script_path = os.path.abspath(__file__)
    cron_line = (
        f"0 9 * * * /usr/bin/python3 {script_path} --auto --network {network} "
        f">> /tmp/auto_scan.log 2>&1"
    )
    with open("/tmp/my_cron", "w") as f:
        f.write(cron_line + "\n")
    subprocess.run("crontab /tmp/my_cron", shell=True)
    print(f"✅ Scheduled daily scan of {network} at 9 AM.")
    print("   Check with: crontab -l")
    print("   Logs at: /tmp/auto_scan.log")


# ============================================================
# PART 9: Main entry point
# ============================================================

def main():
    args = sys.argv[1:]

    if "--gui" in args:
        launch_gui()
        return

    if "--schedule" in args:
        # Allow --network flag
        net = "10.0.3.0/24"
        if "--network" in args:
            idx = args.index("--network")
            if idx + 1 < len(args):
                net = args[idx + 1]
        setup_scheduling(net)
        return

    # Determine network (auto or interactive)
    if "--auto" in args:
        network = "10.0.3.0/24"
        if "--network" in args:
            idx = args.index("--network")
            if idx + 1 < len(args):
                network = args[idx + 1]
        report_file = "scan_report.html"
        if "--report" in args:
            idx = args.index("--report")
            if idx + 1 < len(args):
                report_file = args[idx + 1]
        auto_mode = True
    else:
        network = input("Enter target or network (e.g., scanme.nmap.org or 10.0.3.0/24): ").strip()
        report_file = "scan_report.html"
        auto_mode = False

    # ---- Step 1: Discover hosts ----
    print(f"\n[1] Discovering live hosts on {network}…")
    live_ips = discover_hosts(network)

    if not live_ips:
        ip = resolve_target(network)
        if ip:
            print(f"    Treating as single target: {ip}")
            live_ips = [ip]
        else:
            print("[!] No targets found. Exiting.")
            return

    print(f"✅ Found {len(live_ips)} IP(s): {live_ips}")

    # ---- Step 2: Scan ----
    print("\n[2] Starting threaded vulnerability scan with version detection…")
    run_nse = "--nse" in args
    scanner = ThreadedScanner(live_ips, run_nse=run_nse)
    results = scanner.run()

    # ---- Step 3: Print results ----
    print("\n[3] Results:")
    for ip, data in results.items():
        if data["ports"]:
            print(f"\n{ip}:")
            for port, info in data["ports"].items():
                svc = info.get("service", "unknown")
                ver = info.get("version", "")
                cve = info.get("cve")
                line = f"   Port {port}: {svc} {ver}"
                if cve:
                    line += f" - {cve['cve']} (Severity: {cve['score']})"
                else:
                    line += " - No CVE found"
                print(line)
                for script, res in info.get("nse", {}).items():
                    print(f"      NSE [{script}]: {res}")
        else:
            print(f"\n{ip}: No open ports found")

    # ---- Step 4: Report ----
    print("\n[4] Generating HTML report…")
    generate_html_report(results, filename=report_file)
    print(f"Report saved: {report_file}")

    if not auto_mode:
        print("\nTo view report:       firefox scan_report.html")
        print("To launch GUI:        python3 advanced_scanner.py --gui")
        print("To schedule daily:    python3 advanced_scanner.py --schedule")
        print("To run NSE scripts:   python3 advanced_scanner.py --nse")


if __name__ == "__main__":
    main()
