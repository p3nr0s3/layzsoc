"""AbuseIPDB v2 API client with automatic key rotation."""

import time
import requests
from typing import Dict, Any, Optional, Tuple
from core.config import ABUSEIPDB_API_URL, RATE_LIMIT_COOLDOWN_SECONDS
from core.key_manager import (
    KeyManager,
    SERVICE_ABUSE,
)


class AbuseIPDBClient:
    """Client for interacting with AbuseIPDB with key rotation."""

    def __init__(self, key_manager: Optional[KeyManager] = None):
        self.km = key_manager or KeyManager()
        self.session = requests.Session()
        self.session.headers.update({"Accept": "application/json"})

    def check_ip(self, ip: str, max_retries: int = 3) -> Dict[str, Any]:
        """
        Queries AbuseIPDB for an IP address.
        Handles key rotation automatically if a key hits rate limits (429).
        """
        retries = 0
        while retries < max_retries:
            key, wait_time = self.km.get_next_key(SERVICE_ABUSE)

            if not key:
                if wait_time is not None and wait_time > 0:
                    return {
                        "success": False,
                        "error_type": "THROTTLED",
                        "wait_seconds": wait_time,
                        "error": f"All AbuseIPDB keys are temporarily rate-limited. Wait {int(wait_time)}s.",
                    }
                return {
                    "success": False,
                    "error_type": "NO_KEYS",
                    "error": "No active AbuseIPDB API keys available. Please add a key in the sidebar.",
                }

            headers = {
                "Key": key,
                "Accept": "application/json",
            }
            params = {
                "ipAddress": ip,
                "maxAgeInDays": "90",
                "verbose": "true",
            }

            try:
                resp = self.session.get(
                    f"{ABUSEIPDB_API_URL}/check",
                    headers=headers,
                    params=params,
                    timeout=10,
                )

                if resp.status_code == 200:
                    self.km.mark_success(SERVICE_ABUSE, key)
                    data = resp.json().get("data", {})
                    return {
                        "success": True,
                        "data": {
                            "ip": data.get("ipAddress", ip),
                            "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                            "total_reports": data.get("totalReports", 0),
                            "country_code": data.get("countryCode", "??"),
                            "country_name": data.get("countryName", "Unknown"),
                            "isp": data.get("isp", "Unknown"),
                            "domain": data.get("domain", ""),
                            "usage_type": data.get("usageType", ""),
                            "is_whitelisted": data.get("isWhitelisted", False),
                            "is_tor": data.get("isTor", False),
                            "last_reported_at": data.get("lastReportedAt", ""),
                        },
                    }

                elif resp.status_code == 429:
                    # Rate limit or daily limit hit
                    err_msg = resp.text
                    is_daily = "daily" in err_msg.lower() or "limit" in err_msg.lower()
                    self.km.mark_rate_limited(
                        SERVICE_ABUSE,
                        key,
                        cooldown_seconds=RATE_LIMIT_COOLDOWN_SECONDS,
                        is_daily=is_daily,
                    )
                    retries += 1
                    continue

                elif resp.status_code in (401, 403):
                    self.km.mark_invalid(SERVICE_ABUSE, key, f"Auth error ({resp.status_code})")
                    retries += 1
                    continue

                else:
                    return {
                        "success": False,
                        "error_type": "API_ERROR",
                        "error": f"AbuseIPDB error {resp.status_code}: {resp.text[:100]}",
                    }

            except requests.RequestException as e:
                retries += 1
                if retries >= max_retries:
                    return {
                        "success": False,
                        "error_type": "NETWORK_ERROR",
                        "error": f"Network exception: {str(e)}",
                    }
                time.sleep(1)

        return {
            "success": False,
            "error_type": "RETRIES_EXCEEDED",
            "error": "Exceeded maximum retry attempts across AbuseIPDB keys.",
        }

    def test_key(self, key: str) -> Tuple[bool, str]:
        """Validates a key using a benign lookup (e.g. Cloudflare DNS 1.1.1.1)."""
        headers = {"Key": key, "Accept": "application/json"}
        params = {"ipAddress": "1.1.1.1", "maxAgeInDays": "1"}
        try:
            resp = self.session.get(
                f"{ABUSEIPDB_API_URL}/check",
                headers=headers,
                params=params,
                timeout=8,
            )
            if resp.status_code == 200:
                return True, "API Key is valid and active."
            elif resp.status_code == 429:
                return False, "Rate limit reached for this key."
            elif resp.status_code in (401, 403):
                return False, f"Invalid API key (Status {resp.status_code})."
            else:
                return False, f"Error {resp.status_code}: {resp.text[:80]}"
        except Exception as e:
            return False, f"Connection failed: {str(e)}"
