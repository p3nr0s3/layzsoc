"""abuse.ch ThreatFox API Client (Keyless Indicator of Compromise Database)."""

import requests
from typing import Dict, Any, Optional

THREATFOX_API_URL = "https://threatfox-api.abuse.ch/api/v1/"


class ThreatFoxClient:
    """
    Client for querying the abuse.ch ThreatFox database.
    Correlates IoCs (IP, domain, URL, hash) with active malware families and C2 campaigns.
    """

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            "Accept": "application/json",
            "User-Agent": "LazySOC-CyberSec/3.0",
        })

    def search_ioc(self, ioc: str) -> Dict[str, Any]:
        """
        Searches ThreatFox for any indicator (IP:Port, domain, URL, or hash).
        """
        clean_ioc = ioc.strip()
        if not clean_ioc:
            return {"success": False, "error": "IoC is empty"}

        try:
            resp = self.session.post(
                THREATFOX_API_URL,
                json={"query": "search_ioc", "search_term": clean_ioc},
                timeout=8,
            )
            if resp.status_code == 200:
                data = resp.json()
                status = data.get("query_status", "")
                if status == "ok":
                    records = data.get("data") or []
                    if records:
                        primary = records[0]
                        return {
                            "success": True,
                            "found": True,
                            "id": primary.get("id"),
                            "ioc": primary.get("ioc"),
                            "threat_type": primary.get("threat_type_desc") or primary.get("threat_type", "Malicious IoC"),
                            "malware": primary.get("malware_printable") or primary.get("malware", "Unknown Malware"),
                            "malware_alias": primary.get("malware_alias"),
                            "confidence_level": primary.get("confidence_level", 100),
                            "tags": primary.get("tags") or [],
                            "reporter": primary.get("reporter", ""),
                            "first_seen": primary.get("first_seen", ""),
                            "reference": primary.get("reference", ""),
                            "total_matches": len(records),
                        }
                elif status == "no_result":
                    return {
                        "success": True,
                        "found": False,
                        "message": "Indicator not found in ThreatFox database.",
                    }
            return {
                "success": False,
                "error": f"ThreatFox returned status code {resp.status_code}",
            }
        except Exception as e:
            return {"success": False, "error": f"ThreatFox connection error: {str(e)}"}
