"""GreyNoise Community API Client (Noise Reduction & RIOT Service Checker)."""

import os
import requests
from typing import Dict, Any, Optional

GREYNOISE_COMMUNITY_URL = "https://api.greynoise.io/v3/community"


class GreyNoiseClient:
    """
    Client for querying the GreyNoise Community API.
    Identifies internet background scanners and RIOT (Rule It Out) benign enterprise services.
    """

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("GREYNOISE_API_KEY", "")
        self.session = requests.Session()
        headers = {
            "Accept": "application/json",
            "User-Agent": "LazySOC-CyberSec/3.0",
        }
        if self.api_key:
            headers["key"] = self.api_key
        self.session.headers.update(headers)

    def check_ip(self, ip: str) -> Dict[str, Any]:
        """
        Queries GreyNoise for an IP address.
        Returns noise flag, RIOT (Rule It Out) status, classification, and actor name.
        """
        clean_ip = ip.strip()
        if not clean_ip:
            return {"success": False, "error": "IP is empty"}

        try:
            resp = self.session.get(
                f"{GREYNOISE_COMMUNITY_URL}/{clean_ip}",
                timeout=6,
            )
            if resp.status_code == 200:
                data = resp.json()
                is_noise = bool(data.get("noise", False))
                is_riot = bool(data.get("riot", False))
                classification = data.get("classification", "unknown")
                name = data.get("name") or ("Benign Service" if is_riot else "Unknown Scanner")
                
                return {
                    "success": True,
                    "found": True,
                    "ip": clean_ip,
                    "noise": is_noise,
                    "riot": is_riot,
                    "classification": classification,
                    "name": name,
                    "link": data.get("link") or f"https://viz.greynoise.io/ip/{clean_ip}",
                    "last_seen": data.get("last_seen"),
                    "message": data.get("message", ""),
                }
            elif resp.status_code == 404:
                return {
                    "success": True,
                    "found": False,
                    "ip": clean_ip,
                    "noise": False,
                    "riot": False,
                    "classification": "unknown",
                    "message": "IP has not been observed by GreyNoise internet sensors.",
                }
            elif resp.status_code == 429:
                return {
                    "success": False,
                    "error": "GreyNoise Community rate limit reached.",
                }
            else:
                return {
                    "success": False,
                    "error": f"GreyNoise returned status code {resp.status_code}",
                }
        except Exception as e:
            return {"success": False, "error": f"GreyNoise request error: {str(e)}"}
