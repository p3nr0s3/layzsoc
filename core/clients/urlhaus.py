"""abuse.ch URLhaus API Client (Free, Keyless Threat Intelligence)."""

import requests
from typing import Dict, Any, Optional

URLHAUS_API_BASE = "https://urlhaus-api.abuse.ch/v1"


class URLhausClient:
    """Client for querying abuse.ch URLhaus database without needing an API key."""

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            "Accept": "application/json",
            "User-Agent": "Slothery-Threat-Triage/2.0",
        })

    def check_url(self, url: str) -> Dict[str, Any]:
        """Queries URLhaus for a specific URL."""
        try:
            resp = self.session.post(
                f"{URLHAUS_API_BASE}/url/",
                data={"url": url},
                timeout=8,
            )
            if resp.status_code == 200:
                data = resp.json()
                query_status = data.get("query_status", "")
                if query_status == "ok":
                    return {
                        "success": True,
                        "found": True,
                        "id": data.get("id"),
                        "url_status": data.get("url_status", "unknown"),
                        "threat": data.get("threat", "malware_download"),
                        "tags": data.get("tags") or [],
                        "reporter": data.get("reporter", ""),
                        "date_added": data.get("date_added", ""),
                    }
                elif query_status == "no_results":
                    return {
                        "success": True,
                        "found": False,
                        "message": "URL not found in URLhaus malicious dataset.",
                    }
            return {
                "success": False,
                "error": f"URLhaus returned status {resp.status_code}",
            }
        except Exception as e:
            return {"success": False, "error": f"URLhaus connection error: {str(e)}"}

    def check_host(self, host: str) -> Dict[str, Any]:
        """Queries URLhaus for a domain or IP host."""
        try:
            resp = self.session.post(
                f"{URLHAUS_API_BASE}/host/",
                data={"host": host},
                timeout=8,
            )
            if resp.status_code == 200:
                data = resp.json()
                query_status = data.get("query_status", "")
                if query_status == "ok":
                    urls = data.get("urls") or []
                    return {
                        "success": True,
                        "found": True,
                        "host": host,
                        "url_count": len(urls),
                        "firstseen": data.get("firstseen", ""),
                        "urls_sample": urls[:5],
                    }
                elif query_status == "no_results":
                    return {
                        "success": True,
                        "found": False,
                        "message": "Host not flagged in URLhaus.",
                    }
            return {
                "success": False,
                "error": f"URLhaus returned status {resp.status_code}",
            }
        except Exception as e:
            return {"success": False, "error": f"URLhaus connection error: {str(e)}"}
