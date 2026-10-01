# 🦥 Slothery // IoC Threat Intelligence & Triage

A high-resilience **Indicator of Compromise (IoC)** security triage and threat intelligence dashboard. Built for analysts who need fast, structured enrichment of **IP addresses** and **file hashes** without hitting rate-limit brick walls.

---

## ✨ Features

- **Multi-Key Rotation Pool**: Add multiple free-tier API keys for **VirusTotal (v3)** and **AbuseIPDB (v2)**. Slothery load-balances requests across keys and automatically rotates to the next healthy key on HTTP 429 rate limits.
- **Smart Throttling**: When all configured keys hit per-minute quotas (e.g. VirusTotal 4 req/min limit), Slothery smoothly pauses with a real-time countdown timer until the earliest reset window, then seamlessly resumes execution.
- **Unified Smart Input**: Paste raw logs, threat bulletins, or defanged indicators (`1[.]1[.]1[.]1`, `hxxps://...`, hashes). Automatically extracts, normalizes, deduplicates, and flags private/RFC1918 IPs. Supports drag-and-drop `.txt` and `.csv` files.
- **Local SQLite Caching**: Automatically caches results with configurable TTL (default 24h) to prevent burning API quota on repeat lookups.
- **Minimalist Cyber Aesthetic**: Dark-themed, high-contrast dashboard with custom monospace telemetry badges, live progress bars, summary metric cards, and expandable vendor breakdowns.
- **Defanged Export**: Export triage findings directly to **CSV** or **JSON**, with an option to keep indicators defanged for safe sharing.

---

## 🚀 Quickstart

### 1. Prerequisites
- Python 3.10+ (tested on Python 3.14)

### 2. Setup Virtual Environment
```powershell
# Create virtual environment
python -m venv .venv

# Activate virtual environment
# On Windows:
.venv\Scripts\activate
# On Linux/macOS:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 3. Configure API Keys (Optional)
You can configure keys directly in the web UI sidebar, or create a `.env` file:
```env
# VirusTotal Free API Keys (comma-separated for key rotation)
VIRUSTOTAL_API_KEYS=your_vt_key_1,your_vt_key_2

# AbuseIPDB Free API Keys (comma-separated for key rotation)
ABUSEIPDB_API_KEYS=your_abuse_key_1,your_abuse_key_2

# Cache TTL (hours)
CACHE_TTL_HOURS=24
```

### 4. Launch Dashboard

You have **two UI experiences** available:

#### Option A: Bespoke Modern Web App (Recommended)
A dedicated, custom-styled single-page application with real-time reactive indicator pills, telemetry inspection drawer, glowing cybersecurity metrics, and zero generic framework chrome:
```powershell
python server.py
```
Open your browser at **`http://localhost:8000`**.

#### Option B: Revamped Streamlit Dashboard
The Streamlit dashboard with all Streamlit chrome (Deploy button, hamburger menu, banners) stripped and restyled with custom segmented control tabs and glowing dark themes:
```powershell
streamlit run app.py
```
Open your browser at **`http://localhost:8501`**.

---

## 🧪 Running Tests

Slothery includes a pytest test suite verifying defanging, regex extraction, key rotation, cooldown math, and SQLite cache roundtrips:

```powershell
.venv\Scripts\python.exe -m pytest -v
```

---

## 📁 Project Architecture

```
d:/Projects/slothery/
├── app.py                   # Streamlit web application & analyst UI
├── requirements.txt         # Project dependencies
├── .env.example             # Configuration template
├── static/
│   └── styles.css           # Minimalist cyber CSS styles
├── core/
│   ├── config.py            # Global settings & constants
│   ├── parser.py            # Unified defanger & regex parser
│   ├── key_manager.py       # Key rotation pool & rate-limit tracker
│   ├── database.py          # SQLite cache & scan audit log
│   ├── clients/
│   │   ├── virustotal.py    # VirusTotal v3 client
│   │   └── abuseipdb.py     # AbuseIPDB v2 client
│   ├── engine.py            # Batch lookup orchestrator & verdicts
│   └── exporter.py          # CSV and JSON export utilities
└── tests/
    ├── test_parser.py       # Defanging & extraction tests
    ├── test_key_manager.py  # Rotation & cooldown tests
    ├── test_database.py     # SQLite cache tests
    └── test_engine.py       # Verdicts & export tests
```
