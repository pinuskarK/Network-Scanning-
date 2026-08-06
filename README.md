# 🔍 Advanced Network Vulnerability Scanner
<img width="735" height="602" alt="Screenshot_2026-02-26_21_33_51" src="https://github.com/user-attachments/assets/03d1df14-734b-4748-922c-e3239a5da86b" />


<img width="1920" height="974" alt="Screenshot_2026-06-13_00_56_09" src="https://github.com/user-attachments/assets/bee429f4-f111-4958-853e-fd0b65adde6a" />


<img width="776" height="577" alt="Screenshot_2026-06-13_01-00-56" src="https://github.com/user-attachments/assets/f0c5c0a1-90d7-4723-998c-24c89658592c" />

<img width="1476" height="564" alt="Screenshot_2026-06-13_01-01-33" src="https://github.com/user-attachments/assets/37a5d1b2-0361-4d5d-858b-69be4e636de9" />

<img width="731" height="99" alt="Screenshot_2026-06-13_01-26-06" src="https://github.com/user-attachments/assets/71fe04c0-b05a-4e0a-a624-303536fdc175" />

<img width="675" height="132" alt="Screenshot_2026-06-13_01-26-26" src="https://github.com/user-attachments/assets/7ef9700b-1529-41cc-ad03-2c0ffb01da6b" />


> A Python-based network vulnerability scanner that discovers live hosts, detects exact service versions, and performs **real-time CVE lookups** using the US Government National Vulnerability Database (NVD) API with version-exact CPE matching.

**Built by Pinuskar Kamalanathan — BSc (Hons) Cybersecurity, SLIIT Sri Lanka**

---

## 📸 Screenshots

### 🖥️ Terminal Scan — Live CVE Lookup
<img width="1920" height="974" alt="Screenshot_2026-06-13_00_56_09" src="https://github.com/user-attachments/assets/f7091895-8f03-4ebe-bf8c-ee3d1489917d" />


### 📊 HTML Vulnerability Report
<img width="1476" height="564" alt="Screenshot_2026-06-13_01-01-33" src="https://github.com/user-attachments/assets/2789d889-84cb-43c3-bfcd-d9b5ab81165e" />


### 🖱️ GUI Mode
<img width="776" height="577" alt="Screenshot_2026-06-13_01-00-56" src="https://github.com/user-attachments/assets/f87a89a7-4c60-475c-b006-87fd2a134a7f" />


### ⏰ Scheduled Auto-Scan (Cron)
<img width="731" height="99" alt="Screenshot_2026-06-13_01-26-06" src="https://github.com/user-attachments/assets/43f9cfd6-2a41-480e-be1f-1e0002b54655" />


---

## 🚀 What Makes This Different

Most basic port scanners just tell you **which ports are open**. This tool goes 3 steps further:

```
Basic Scanner      →   Port 22 is open
This Tool          →   Port 22: OpenSSH 6.6.1 → CVE-2016-6210 (Score: 5.3) — user enumeration vulnerability
```

1. **Detects exact software version** running on each open port
2. **Matches that version** against real CVEs in the NVD database using CPE version-exact lookup
3. **Generates a colour-coded HTML report** showing severity for every vulnerability found

---

## ✅ Features

| Feature | Description |
|---------|-------------|
| 🔍 **Host Discovery** | Ping sweep to find all live hosts on any network range |
| 🔢 **Version Detection** | Identifies exact software and version on every open port |
| 🛡️ **CVE Lookup — CPE Exact** | Queries NVD with CPE string for version-exact matches — no false positives |
| 🔄 **3-Tier Fallback System** | CPE API → Keyword API → Local DB — works even offline |
| ⚡ **Multithreaded Scanning** | Scans multiple hosts simultaneously — much faster than sequential |
| 📊 **HTML Report** | Colour-coded by severity: Critical 🔴 High 🟠 Medium 🟡 Low 🟢 |
| 🖥️ **GUI Mode** | Native Tkinter GUI with live output, progress bar, NSE toggle |
| 📜 **NSE Script Support** | Runs EternalBlue (MS17-010), Shellshock, SSH algorithm checks |
| ⏰ **Auto Scheduling** | Sets up daily cron job for automatic scanning at 9AM |
| 🔑 **NVD API Key Support** | Supports API key for higher NVD rate limits |
| 📁 **Offline Fallback DB** | Local vulnerability database for 15+ services — no internet needed |

---

## 🛠️ Tech Stack

| Technology | Purpose |
|------------|---------|
| **Python 3** | Core language |
| **Nmap** | Port scanning and service/version detection |
| **NVD API v2.0** | Live CVE data from US Government database |
| **CPE 2.3 Standard** | Version-exact vulnerability matching |
| **threading + Lock()** | Parallel scanning, race condition prevention |
| **tkinter** | Native Python GUI — no extra install needed |
| **requests** | HTTP calls to NVD REST API |
| **subprocess** | Running nmap commands from Python |
| **re (regex)** | Extracting version numbers from nmap banners |

---

## ⚙️ Installation

### Prerequisites
- Kali Linux (or any Linux)
- Python 3.8+
- Nmap

```bash
# Install nmap if not already installed
sudo apt install nmap

# Clone this repository
git clone https://github.com/pinuskar/network-vulnerability-scanner.git
cd network-vulnerability-scanner

# Create virtual environment
python3 -m venv myenv
source myenv/bin/activate

# Install Python dependencies
pip install -r requirements.txt
```

### Optional — NVD API Key
Get a free API key from [nvd.nist.gov](https://nvd.nist.gov/developers/request-an-api-key) for higher rate limits:
```bash
export NVD_API_KEY="your-api-key-here"
```

---

## 🚀 Usage

```bash
# Activate virtual environment first
source myenv/bin/activate

# Interactive terminal mode
python3 advanced_scanner.py

# GUI mode (Tkinter window)
python3 advanced_scanner.py --gui

# With NSE vulnerability scripts (EternalBlue, Shellshock)
python3 advanced_scanner.py --nse

# Set up daily auto-scan at 9AM via cron
python3 advanced_scanner.py --schedule

# Automated mode (used by cron)
python3 advanced_scanner.py --auto --network 10.0.3.0/24
```

---

## 📋 Example Output

```
Enter target or network (e.g., scanme.nmap.org or 10.0.3.0/24): scanme.nmap.org

[1] Discovering live hosts on scanme.nmap.org…
✅ Found 1 IP(s): ['45.33.32.156']

[2] Starting threaded vulnerability scan with version detection…
  [*] 'ssh OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13 (Ubuntu Linux; protocol 2.0)'
         → Detected: service='openssh'  version='6.6.1'
         → CPE lookup: cpe:2.3:a:openbsd:openssh:6.6.1
         → 4 CVE(s) found via [CPE-exact] — best: CVE-2016-6210 (score 5.3)

  [*] 'http Apache httpd 2.4.7 ((Ubuntu))'
         → Detected: service='apache'  version='2.4.7'
         → CPE lookup: cpe:2.3:a:apache:http_server:2.4.7
         → 3 CVE(s) found via [CPE-exact] — best: CVE-2014-0226 (score 6.8)

[3] Results:
45.33.32.156:
   Port 22: ssh OpenSSH 6.6.1 — CVE-2016-6210 (Severity: 5.3)
   Port 80: http Apache httpd 2.4.7 — CVE-2014-0226 (Severity: 6.8)

[4] Generating HTML report…
✅ HTML report saved as scan_report.html
```

---

## 🔐 CVE Lookup — 3-Tier System

The scanner uses a 3-tier system to ensure accurate CVE results:

```
┌─────────────────────────────────────────────────────────────────┐
│  Tier 1 — NVD CPE API (Most Accurate)                          │
│  cpe:2.3:a:openbsd:openssh:6.6.1:*:*:*:*:*:*:*               │
│  ✅ Only returns CVEs that affect this exact version            │
├─────────────────────────────────────────────────────────────────┤
│  Tier 2 — NVD Keyword Search (Fallback)                        │
│  keyword="OpenSSH" + filter: year >= 2005                      │
│  ⚠️  Less precise — used when version not detected             │
├─────────────────────────────────────────────────────────────────┤
│  Tier 3 — Local Database (Offline)                             │
│  LOCAL_VULN_DB["openssh"] — hardcoded CVEs for 15+ services   │
│  ❌ Static data — used when no internet available              │
└─────────────────────────────────────────────────────────────────┘
```

**Why CPE matters:** Early versions searched by keyword only and returned CVE-1999-0661 (a 1999 generic SSH CVE) for OpenSSH 6.6.1 — completely wrong. CPE exact matching fixed this by querying NVD with the full version string.

---

## 📁 Project Structure

```
network-vulnerability-scanner/
│
├── advanced_scanner.py          ← Main scanner — all features
├── scanner.py                   ← Lightweight version
├── test_cve.py                  ← CVE API test script
├── requirements.txt             ← Python dependencies
│
├── docs/
│   └── Network_Vulnerability_Scanner_Documentation.docx
│
└── screenshots/
    ├── 01_setup.png             ← Project environment setup
    ├── 02_terminal_scan.png     ← Live terminal scan output
    ├── 03_gui_mode.png          ← Tkinter GUI window
    ├── 04_html_report.png       ← Generated HTML report in Firefox
    ├── 05_cron_job.png          ← Cron job verification
    └── 06_project_files.png     ← Project file listing
```

---

## 🎯 Supported Services & CVE Coverage

| Service | Port | Example CVEs Detected |
|---------|------|-----------------------|
| OpenSSH | 22 | CVE-2016-6210, CVE-2018-15473, CVE-2023-38408 |
| Apache HTTP | 80/443 | CVE-2021-41773, CVE-2014-6271 (Shellshock) |
| SMB | 445 | CVE-2017-0144 (EternalBlue), CVE-2020-0796 (SMBGhost) |
| FTP | 21 | CVE-2015-3306, CVE-2010-4221 |
| MySQL | 3306 | CVE-2012-2122, CVE-2016-6662 |
| RDP | 3389 | CVE-2019-0708 (BlueKeep) |
| SMTP | 25 | CVE-2019-10149, CVE-2020-28017 |
| Telnet | 23 | CVE-2020-10188 |
| VNC | 5900 | CVE-2006-2369 |
| + more | — | Via live NVD API lookup |

---

## ⚠️ Legal & Ethical Notice

```
This tool is built strictly for:
  ✅ Educational purposes
  ✅ Authorized penetration testing
  ✅ Scanning networks you own
  ✅ CTF (Capture The Flag) challenges

  ❌ DO NOT scan networks without explicit written permission
  ❌ Unauthorized scanning is illegal in most countries

The author takes no responsibility for misuse of this tool.
Always get written permission before scanning any network.
```

---

## 📚 What I Learned Building This

- **CPE & CVE standards** — how NIST structures vulnerability data
- **NVD REST API** — querying and parsing live government security data
- **Python threading** — parallel scanning with race condition prevention using `Lock()`
- **Regex** — extracting version numbers from messy nmap banner strings
- **Subprocess** — running external programs (nmap) from Python
- **Tkinter GUI** — building responsive native Python interfaces with daemon threads
- **Graceful degradation** — building systems that work even when parts fail
- **Cron scheduling** — automating security tasks on Linux

---





## 📄 License

MIT License — feel free to use, modify, and distribute with attribution.

---

