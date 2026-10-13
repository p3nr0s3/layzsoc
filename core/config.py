"""Configuration and environment settings for LazySOC."""

import os
import shutil
from pathlib import Path
from dotenv import load_dotenv

# Base paths
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
STATIC_DIR = BASE_DIR / "static"
KEYS_FILE = DATA_DIR / "keys.json"
CACHE_DB_FILE = DATA_DIR / "lazysoc_cache.db"

# Ensure directories exist
DATA_DIR.mkdir(parents=True, exist_ok=True)
STATIC_DIR.mkdir(parents=True, exist_ok=True)

# Auto-migrate legacy slothery_cache.db if present
legacy_cache = DATA_DIR / "slothery_cache.db"
if legacy_cache.exists() and not CACHE_DB_FILE.exists():
    try:
        shutil.move(str(legacy_cache), str(CACHE_DB_FILE))
    except Exception:
        pass

# Load .env if present
load_dotenv(BASE_DIR / ".env")

# Settings
CACHE_TTL_HOURS = int(os.getenv("CACHE_TTL_HOURS", "24"))
RATE_LIMIT_COOLDOWN_SECONDS = int(os.getenv("RATE_LIMIT_COOLDOWN_SECONDS", "65"))

# API Base URLs
VIRUSTOTAL_API_URL = "https://www.virustotal.com/api/v3"
ABUSEIPDB_API_URL = "https://api.abuseipdb.com/api/v2"
SHODAN_INTERNETDB_URL = "https://internetdb.shodan.io"

# NIST NVD Configuration
NVD_API_KEY = os.getenv("NVD_API_KEY", "")

# Free tier limits (reference)
# VirusTotal: 4 requests / minute, 500 requests / day
# AbuseIPDB: 1000 requests / day
VT_MINUTE_RATE_LIMIT = 4
VT_MINUTE_WINDOW_SECONDS = 60
