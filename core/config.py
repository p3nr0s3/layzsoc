"""Configuration and environment settings for Slothery."""

import os
from pathlib import Path
from dotenv import load_dotenv

# Base paths
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
STATIC_DIR = BASE_DIR / "static"
KEYS_FILE = DATA_DIR / "keys.json"
CACHE_DB_FILE = DATA_DIR / "slothery_cache.db"

# Ensure directories exist
DATA_DIR.mkdir(parents=True, exist_ok=True)
STATIC_DIR.mkdir(parents=True, exist_ok=True)

# Load .env if present
load_dotenv(BASE_DIR / ".env")

# Settings
CACHE_TTL_HOURS = int(os.getenv("CACHE_TTL_HOURS", "24"))
RATE_LIMIT_COOLDOWN_SECONDS = int(os.getenv("RATE_LIMIT_COOLDOWN_SECONDS", "65"))

# API Base URLs
VIRUSTOTAL_API_URL = "https://www.virustotal.com/api/v3"
ABUSEIPDB_API_URL = "https://api.abuseipdb.com/api/v2"

# Free tier limits (reference)
# VirusTotal: 4 requests / minute, 500 requests / day
# AbuseIPDB: 1000 requests / day
VT_MINUTE_RATE_LIMIT = 4
VT_MINUTE_WINDOW_SECONDS = 60
