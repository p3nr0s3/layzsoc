"""VirusTotal v3 API client with automatic key rotation and rate-limit handling."""

import time
import base64
import requests
from typing import Dict, Any, Optional, Tuple
from core.config import VIRUSTOTAL_API_URL, RATE_LIMIT_COOLDOWN_SECONDS
from core.key_manager import (
    KeyManager,
    SERVICE_VT,
)


class VirusTotalClient:
    """Client for interacting with VirusTotal v3 API with key rotation."""

    def __init__(self, key_manager: Optional[KeyManager] = None):
        self.km = key_manager or KeyManager()
        self.session = requests.Session()
        self.session.headers.update({"Accept": "application/json"})

    def _execute_request(self, endpoint: str, max_retries: int = 3) -> Dict[str, Any]:
        """Executes a request to VT v3 with key rotation and error handling."""
        retries = 0
        while retries < max_retries:
            key, wait_time = self.km.get_next_key(SERVICE_VT)

            if not key:
                if wait_time is not None and wait_time > 0:
                    return {
                        "success": False,
                        "error_type": "THROTTLED",
                        "wait_seconds": wait_time,
                        "error": f"All VirusTotal keys are temporarily throttled (rate limit 4/min). Wait {int(wait_time)}s.",
                    }
                return {
                    "success": False,
                    "error_type": "NO_KEYS",
                    "error": "No active VirusTotal API keys available. Please add a key in the sidebar.",
                }

            headers = {"x-apikey": key}

            try:
                resp = self.session.get(
                    f"{VIRUSTOTAL_API_URL}/{endpoint}",
                    headers=headers,
                    timeout=12,
                )

                if resp.status_code == 200:
                    self.km.mark_success(SERVICE_VT, key)
                    return {"success": True, "data": resp.json().get("data", {})}

                elif resp.status_code == 404:
                    # Not found in VT database (valid query, zero detections / not indexed)
                    self.km.mark_success(SERVICE_VT, key)
                    return {
                        "success": True,
                        "data": None,
                        "not_found": True,
                        "message": "Indicator not indexed in VirusTotal database.",
                    }

                elif resp.status_code == 429:
                    # Rate limit or quota exceeded
                    err_json = {}
                    try:
                        err_json = resp.json().get("error", {})
                    except Exception:
                        pass
                    msg = err_json.get("message", resp.text)
                    is_daily = "daily" in msg.lower() or "month" in msg.lower()
                    self.km.mark_rate_limited(
                        SERVICE_VT,
                        key,
                        cooldown_seconds=RATE_LIMIT_COOLDOWN_SECONDS,
                        is_daily=is_daily,
                    )
                    retries += 1
                    continue

                elif resp.status_code in (401, 403):
                    self.km.mark_invalid(SERVICE_VT, key, f"Auth error ({resp.status_code})")
                    retries += 1
                    continue

                else:
                    return {
                        "success": False,
                        "error_type": "API_ERROR",
                        "error": f"VirusTotal error {resp.status_code}: {resp.text[:100]}",
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
            "error": "Exceeded maximum retry attempts across VirusTotal keys.",
        }

    def check_ip(self, ip: str) -> Dict[str, Any]:
        """Queries VirusTotal for an IP address report."""
        res = self._execute_request(f"ip_addresses/{ip}")
        if not res.get("success"):
            return res

        data = res.get("data")
        if not data:
            return {
                "success": True,
                "not_found": True,
                "stats": {"malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0},
                "as_owner": "Unknown",
                "country": "Unknown",
                "reputation": 0,
            }

        attrs = data.get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        results = attrs.get("last_analysis_results", {})

        # Extract top malicious vendor hits
        flagged_vendors = []
        for engine, report in results.items():
            cat = report.get("category", "")
            if cat in ("malicious", "suspicious"):
                flagged_vendors.append({
                    "engine": engine,
                    "category": cat,
                    "result": report.get("result", "flagged"),
                })

        return {
            "success": True,
            "not_found": False,
            "stats": stats,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "as_owner": attrs.get("as_owner", "Unknown"),
            "country": attrs.get("country", "Unknown"),
            "reputation": attrs.get("reputation", 0),
            "flagged_vendors": flagged_vendors[:10],
            "last_analysis_date": attrs.get("last_analysis_date"),
        }

    def check_hash(self, file_hash: str) -> Dict[str, Any]:
        """Queries VirusTotal for a file hash (MD5, SHA1, or SHA256)."""
        res = self._execute_request(f"files/{file_hash}")
        if not res.get("success"):
            return res

        data = res.get("data")
        if not data:
            return {
                "success": True,
                "not_found": True,
                "stats": {"malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0},
                "threat_label": "Not Found in VT",
                "meaningful_name": "Unknown",
                "file_type": "Unknown",
                "size": 0,
            }

        attrs = data.get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        results = attrs.get("last_analysis_results", {})

        threat_class = attrs.get("popular_threat_classification", {})
        threat_label = threat_class.get("suggested_threat_label", "")
        if not threat_label:
            # Fallback to meaningful name or tags
            tags = attrs.get("tags", [])
            threat_label = tags[0] if tags else "Clean / Unclassified"

        flagged_vendors = []
        for engine, report in results.items():
            cat = report.get("category", "")
            if cat in ("malicious", "suspicious"):
                flagged_vendors.append({
                    "engine": engine,
                    "category": cat,
                    "result": report.get("result", "flagged"),
                })

        return {
            "success": True,
            "not_found": False,
            "stats": stats,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "threat_label": threat_label,
            "meaningful_name": attrs.get("meaningful_name", "Unknown"),
            "file_type": attrs.get("type_description", attrs.get("magic", "Unknown")),
            "size": attrs.get("size", 0),
            "flagged_vendors": flagged_vendors[:10],
            "first_submission_date": attrs.get("first_submission_date"),
            "last_analysis_date": attrs.get("last_analysis_date"),
        }

    def check_domain(self, domain: str) -> Dict[str, Any]:
        """Queries VirusTotal for a domain report."""
        res = self._execute_request(f"domains/{domain}")
        if not res.get("success"):
            return res

        data = res.get("data")
        if not data:
            return {
                "success": True,
                "not_found": True,
                "stats": {"malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0},
                "categories": {},
                "registrar": "Unknown",
                "reputation": 0,
            }

        attrs = data.get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        results = attrs.get("last_analysis_results", {})

        flagged_vendors = []
        for engine, report in results.items():
            cat = report.get("category", "")
            if cat in ("malicious", "suspicious"):
                flagged_vendors.append({
                    "engine": engine,
                    "category": cat,
                    "result": report.get("result", "flagged"),
                })

        return {
            "success": True,
            "not_found": False,
            "stats": stats,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "categories": attrs.get("categories", {}),
            "registrar": attrs.get("registrar", "Unknown"),
            "reputation": attrs.get("reputation", 0),
            "flagged_vendors": flagged_vendors[:10],
            "last_analysis_date": attrs.get("last_analysis_date"),
        }

    def check_url(self, url: str) -> Dict[str, Any]:
        """Queries VirusTotal for a URL report using base64 URL ID."""
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        res = self._execute_request(f"urls/{url_id}")
        if not res.get("success"):
            return res

        data = res.get("data")
        if not data:
            return {
                "success": True,
                "not_found": True,
                "stats": {"malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0},
                "categories": {},
                "reputation": 0,
            }

        attrs = data.get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        results = attrs.get("last_analysis_results", {})

        flagged_vendors = []
        for engine, report in results.items():
            cat = report.get("category", "")
            if cat in ("malicious", "suspicious"):
                flagged_vendors.append({
                    "engine": engine,
                    "category": cat,
                    "result": report.get("result", "flagged"),
                })

        return {
            "success": True,
            "not_found": False,
            "stats": stats,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "categories": attrs.get("categories", {}),
            "reputation": attrs.get("reputation", 0),
            "flagged_vendors": flagged_vendors[:10],
            "last_analysis_date": attrs.get("last_analysis_date"),
        }

    def test_key(self, key: str) -> Tuple[bool, str]:
        """Validates a key using a benign VT file/IP lookup."""
        headers = {"x-apikey": key}
        try:
            # 8.8.8.8 is a permanent well-known record in VT
            resp = self.session.get(
                f"{VIRUSTOTAL_API_URL}/ip_addresses/8.8.8.8",
                headers=headers,
                timeout=8,
            )
            if resp.status_code == 200:
                return True, "API Key is valid and active."
            elif resp.status_code == 429:
                return False, "Rate limit reached for this key."
            elif resp.status_code in (401, 403):
                return False, f"Invalid API key (Status {resp.status_code})."
            else:
                return False, f"Status {resp.status_code}: {resp.text[:80]}"
        except Exception as e:
            return False, f"Connection error: {str(e)}"
