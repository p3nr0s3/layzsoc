# 🦥 LazySOC 
## Threat Intelligence Triage & Security Operations Workbench

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg?logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110%2B-009688.svg?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![TailwindCSS](https://img.shields.io/badge/TailwindCSS-v3-38bdf8.svg?logo=tailwindcss&logoColor=white)](https://tailwindcss.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Creator](https://img.shields.io/badge/Author-@p3nr0s3-00f2fe.svg?logo=github&logoColor=white)](https://github.com/p3nr0s3)

**LazySOC** is a high-performance, dark-mode cybersecurity workbench built for SOC analysts, incident responders, and threat hunters. It eliminates repetitive manual triage by combining automated threat intelligence enrichment, live network reconnaissance, deep email forensics, real-time cyber news feeds, and live online vulnerability lookup into a single zero-friction dashboard.

---

## ⚡ Core Capabilities

### 🎯 1. Multi-IoC Triage & Risk Scoring
- **Smart Defanger & Parser**: Paste unstructured threat bulletins, firewall logs, or defanged indicators (`1[.]1[.]1[.]1`, `hxxps://evil[.]com`, hashes). Automatically extracts, normalizes, deduplicates, and classifies IPv4/IPv6, domains, URLs, and MD5/SHA1/SHA256 hashes.
- **Multi-Key API Rotation Pool**: Add multiple free-tier API keys for **VirusTotal (v3)** and **AbuseIPDB (v2)**. LazySOC load-balances requests across keys and automatically fails over on HTTP 429 rate limits.
- **Smart Cooldown & Countdown**: Smoothly pauses with a live countdown timer when quotas are reached, resuming execution automatically without dropping jobs.
- **Threat Hunting Query Generator**: One-click generation of ready-to-run queries for **Splunk SPL**, **Microsoft Sentinel KQL**, **CrowdStrike Falcon**, **OpenSearch**, **Sigma YAML**, and **Firewall CLI** (iptables/Palo Alto).
- **Clean Incident Escalation Note**: Generates clean, standardized SOC incident handover documentation (Executive Summary, Technical Findings, and Immediate Recommendations).

### 📡 2. Active & Passive Network Recon
- Query any IP or domain for live infrastructure intelligence:
  - Reverse DNS (PTR) records & geolocation
  - ASN & ISP network routing telemetry
  - Passive Shodan exposure (open ports, protocols, HTTP headers, TLS certificate details, and active host vulnerabilities).

### 🎣 3. Deep Phishing & EML Forensics
- Upload `.eml` or `.msg` files or paste raw RFC 822 email headers.
- Visual **Hop-by-Hop Transmission Delay Analyzer** with geolocation and delay timing.
- Cryptographic authentication posture audit (**SPF, DKIM, DMARC**).
- Automated attachment hash extraction (MD5/SHA256) and defanged hyperlink harvester.

### 🛡️ 4. Domain Mail Health & Spoofing Posture
- Audit any domain's email security configuration.
- Checks MX records, SPF syntax, DMARC policy enforcement (`reject`, `quarantine`, `none`), and flags domain spoofing vulnerability risks.

### 📰 5. Paginated Live Cyber Threat Feeds (RSS)
- Real-time aggregations from top cybersecurity publishers:
  - **The Hacker News**
  - **BleepingComputer**
  - **CISA Security Advisories**
  - **Krebs on Security**
- **Interactive Pagination**: Browse articles with page controls, adjustable page sizes (6, 9, 12, 18, 30), and category/source filters.
- **One-Click Triage**: Transfer extracted article contents directly into the triage scanner.

### 🚨 6. Live Online CVE & NIST NVD Intelligence (Zero Local Database)
- **100% Real-Time & Online**: Directly queries the official **NIST NVD 2.0 API** and **CISA Known Exploited Vulnerabilities (KEV)** catalog.
- Zero local database bloat — search by CVE ID (e.g. `CVE-2024-3400`) or vendor keywords (Ivanti, Palo Alto, Microsoft, Linux).
- Live CVSS v3.1 impact scores, severity levels, CWE weakness types, and CVSS vector metrics.

### 🎨 7. Analyst Themes & Split-Screen Responsive UI
- 5 Cyberpunk-inspired themes: **Cyberpunk Cyan**, **Matrix Green**, **Dracula Violet**, **Crimson Alert**, and **Nordic Frost**.
- Responsive split-screen navbar that adapts seamlessly when browser windows are tiled side-by-side.

### 📋 8. Interactive SOC Playbooks & Incident Checklist
- **NIST SP 800-61r2 & MITRE ATT&CK Aligned**: Structured standard operating procedures for the 5 most common enterprise threats:
  - **Phishing & Business Email Compromise (BEC)** (`T1566`, `T1586`)
  - **Ransomware & Destructive Malware** (`T1486`, `T1489`)
  - **Compromised Account & Credential Access / ATO** (`T1078`, `T1110`)
  - **C2 Beaconing & Data Exfiltration** (`T1071`, `T1041`)
  - **Web Exploit & Webshell Outbreak** (`T1190`, `T1505.003`)
- **Phase-by-Phase Interactive Checklist**: Track tasks across **Identification**, **Containment**, **Eradication**, and **Recovery** with real-time percentage progress bar.
- **Ready-to-Run Remediation Snippets**: 1-click copy remediation CLI commands for PowerShell, M365 Exchange, iptables, Azure AD, and EDR agents.
- **Audit Handover Report**: One-click generation of Markdown incident handover notes containing completed checklist tasks, triage IoCs, and timestamps ready for Jira, ServiceNow, Slack, or TheHive.

### 🔗 9. Safe URL Redirect Tracer & Domain Age Inspector
- **Safe & Passive**: Uses lightweight HTTP header inspection (`stream=True`, zero executable downloads) to trace complex URL redirection hops (301, 302, 307, 308).
- **Unshorten Tracking Links**: Automatically resolves bit.ly, tinyurl, t.co, and custom URL shorteners.
- **Domain Age Detection via RDAP**: Calculates domain age and flags **Newly Registered Domains (NRDs <= 14 days)** as critical phishing/C2 indicators.
- **TLS / SSL Inspection**: Verifies certificate validity, issuer, subject, and expiration without risky browser rendering.

### 🧪 10. SOC De-obfuscator & CyberChef-Lite Studio
- **PowerShell -enc Decoder**: Extracts and decodes Base64 UTF-16LE commands, strips backtick obfuscation, flags dangerous cmdlets (`DownloadString`, `IEX`, `Net.WebClient`), and harvests embedded URLs.
- **Multi-Scheme Decoders**: Standard Base64, Hex / byte arrays (`\x41`, `0x41`, raw hex), multi-pass URL percent-encoding, ROT13, and string reversal.
- **Single-Byte XOR Brute-Force Scanner**: Tests keys `0x01`–`0xFF` against ascii/hex streams to uncover XOR-encrypted shellcode and C2 domains.
- **1-Click Defang & Refang**: Safely neutralizes or normalizes URLs, IPs, and hostnames for reporting.

---

## 🚀 Quickstart Guide

### 1. Clone & Setup Environment

```bash
git clone https://github.com/p3nr0s3/layzsoc.git
cd layzsoc

# Create virtual environment
python -m venv .venv

# Activate on Windows:
.venv\Scripts\activate
# Activate on Linux/macOS:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Configure Environment (Optional)

Create a `.env` file in the root directory:

```env
# VirusTotal Free API Keys (comma-separated for key rotation)
VIRUSTOTAL_API_KEYS=your_vt_key_1,your_vt_key_2

# AbuseIPDB Free API Keys (comma-separated for key rotation)
ABUSEIPDB_API_KEYS=your_abuse_key_1,your_abuse_key_2

# Security lock: set to false in production to prevent web UI modification of API keys
ALLOW_KEY_MANAGEMENT=false

# Cache TTL (hours)
CACHE_TTL_HOURS=24
```

### 3. Launch LazySOC

```bash
python server.py
```

Open your browser at **`http://localhost:8000`**.

---

## 🌐 Deploying to Render.com / Cloud Platforms

LazySOC is optimized for zero-configuration cloud deployment:

1. Connect your GitHub repository (`p3nr0s3/layzsoc`) to **Render.com** (Web Service).
2. Set the build and start commands:
   - **Environment**: `Python 3`
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `python server.py`
3. Add environment variables under **Environment**:
   - `VIRUSTOTAL_API_KEYS`: your API key(s)
   - `ABUSEIPDB_API_KEYS`: your API key(s)
   - `ALLOW_KEY_MANAGEMENT`: `false` (locks sensitive key endpoints)
   - `PORT`: `8000` (or leave default assigned by host)

---

## 🧪 Testing

LazySOC includes a comprehensive test suite covering parser regexes, key rotation algorithms, cooldown mechanics, database cache transactions, and API endpoints:

```bash
pytest -v
```

---

## 📁 Repository Structure

```
lazysoc/
├── server.py              # FastAPI application server & REST endpoints
├── requirements.txt       # Python dependencies
├── .env.example           # Environment variable template
├── web/
│   └── index.html         # Responsive Cyberpunk SPA dashboard
├── core/
│   ├── config.py          # Application configuration & constants
│   ├── parser.py          # Unified defanger & regex extractor
│   ├── key_manager.py     # Rate-limit tracker & API key rotation pool
│   ├── database.py        # Local SQLite cache & audit history
│   ├── engine.py          # Scan orchestrator, verdicts & SIEM logic
│   ├── feed.py            # Real-time RSS cyber threat news aggregator
│   ├── cve.py             # Live online NIST NVD & CISA KEV client
│   ├── recon.py           # Shodan, DNS & network recon module
│   ├── containment.py     # Firewall & EDR blocklist script generator
│   ├── url_tracer.py      # Passive redirect tracer, RDAP domain age & SSL
│   ├── deobfuscator.py    # PowerShell -enc, Base64, Hex & XOR decoder
│   ├── email_analyzer.py  # RFC 822 / EML header & phishing analyzer
│   ├── mail_checker.py    # DNS MX, SPF & DMARC posture auditor
│   ├── exporter.py        # CSV and JSON report generation
│   └── clients/
│       ├── virustotal.py  # VirusTotal v3 API client
│       └── abuseipdb.py   # AbuseIPDB v2 API client
└── tests/                 # Unit & integration test suite
```

---

## 👤 Author & Credits

Developed by **[@p3nr0s3](https://github.com/p3nr0s3)**.

Designed for analysts who want clean, fast security triage without vendor lock-in or manual spreadsheet fatigue.
