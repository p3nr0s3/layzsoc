"""
Real-time CVE & NVD Vulnerability Intelligence Module for LazySOC.
Fetches, caches, and aggregates live vulnerability data from CISA KEV and NIST NVD APIs.
"""

import time
import requests
from typing import List, Dict, Any, Optional

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

CACHE_TTL = 300  # 5 minutes in-memory cache
_CVE_CACHE: Dict[str, Any] = {}
_KEV_CACHE: Dict[str, Any] = {"timestamp": 0.0, "items": []}


def fetch_cisa_kev_recent(limit: int = 15) -> List[Dict[str, Any]]:
    """Fetches real-time latest known exploited vulnerabilities from CISA KEV catalog."""
    global _KEV_CACHE
    now = time.time()

    if now - _KEV_CACHE["timestamp"] < CACHE_TTL and _KEV_CACHE["items"]:
        items = _KEV_CACHE["items"]
    else:
        try:
            resp = requests.get(CISA_KEV_URL, headers={"User-Agent": "LazySOC-CyberSec/3.0"}, timeout=8)
            if resp.status_code == 200:
                raw_vulns = resp.json().get("vulnerabilities", [])
                # Sort newest by dateAdded descending
                sorted_vulns = sorted(raw_vulns, key=lambda x: x.get("dateAdded", ""), reverse=True)
                formatted = []
                for v in sorted_vulns[:40]:
                    cve_id = v.get("cveID", "")
                    vendor = v.get("vendorProject", "Vendor")
                    prod = v.get("product", "Product")
                    desc = v.get("shortDescription") or v.get("vulnerabilityName", "")
                    date_added = v.get("dateAdded", "")
                    ransomware = v.get("knownRansomwareCampaignUse", "Unknown") == "Known"

                    formatted.append({
                        "id": cve_id,
                        "cvss": 9.8 if ransomware else 8.8,  # High/Critical default for active zero-days in KEV
                        "severity": "CRITICAL" if ransomware else "HIGH",
                        "cwe": f"{vendor} {prod}",
                        "vector": f"Active Exploit | Ransomware Use: {'YES' if ransomware else 'Investigating'}",
                        "description": desc,
                        "published": date_added,
                        "source": "CISA KEV (Real-Time)",
                        "link": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                        "known_exploited": True,
                    })
                _KEV_CACHE["timestamp"] = now
                _KEV_CACHE["items"] = formatted
                items = formatted
            else:
                items = _KEV_CACHE.get("items", [])
        except Exception:
            items = _KEV_CACHE.get("items", [])

    return items[:limit]


def _parse_nvd_item(item: Dict[str, Any]) -> Dict[str, Any]:
    """Extracts structured vulnerability record from an NVD CVE object."""
    cve = item.get("cve", {})
    cve_id = cve.get("id", "UNKNOWN")

    metrics = cve.get("metrics", {})
    cvss_score = 0.0
    severity = "UNKNOWN"
    vector = ""

    v31 = metrics.get("cvssMetricV31", [])
    v30 = metrics.get("cvssMetricV30", [])
    primary_metric = v31[0] if v31 else (v30[0] if v30 else None)

    if primary_metric:
        data = primary_metric.get("cvssData", {})
        cvss_score = float(data.get("baseScore", 0.0))
        severity = data.get("baseSeverity", primary_metric.get("baseSeverity", "UNKNOWN")).upper()
        vector = data.get("vectorString", "")
    else:
        v2 = metrics.get("cvssMetricV2", [])
        if v2:
            data = v2[0].get("cvssData", {})
            cvss_score = float(data.get("baseScore", 0.0))
            vector = data.get("vectorString", "")
            if cvss_score >= 9.0:
                severity = "CRITICAL"
            elif cvss_score >= 7.0:
                severity = "HIGH"
            elif cvss_score >= 4.0:
                severity = "MEDIUM"
            else:
                severity = "LOW"

    descriptions = cve.get("descriptions", [])
    en_desc = next((d.get("value", "") for d in descriptions if d.get("lang") == "en"), "")
    if not en_desc and descriptions:
        en_desc = descriptions[0].get("value", "")

    weaknesses = cve.get("weaknesses", [])
    cwe_str = ""
    if weaknesses:
        cwes = []
        for w in weaknesses:
            for desc in w.get("description", []):
                cwes.append(desc.get("value", ""))
        cwe_str = ", ".join(cwes[:2])

    published = (cve.get("published", "") or "")[:10]

    return {
        "id": cve_id,
        "cvss": cvss_score,
        "severity": severity,
        "cwe": cwe_str or "Not Specified",
        "vector": vector,
        "description": en_desc,
        "published": published,
        "source": "NIST NVD",
        "link": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        "known_exploited": False,
    }


def query_cve(search: Optional[str] = None, limit: int = 15) -> Dict[str, Any]:
    """Queries real-time live CVEs from CISA KEV and NIST NVD."""
    now = time.time()
    query = (search or "").strip()

    # 1. Default view: Return real-time latest known exploited vulnerabilities added to CISA KEV
    if not query:
        realtime_items = fetch_cisa_kev_recent(limit=limit)
        return {
            "total": len(realtime_items),
            "query": "",
            "realtime": True,
            "items": realtime_items,
            "cached": True,
        }

    cache_key = f"cve_{query.lower()}_{limit}"
    if cache_key in _CVE_CACHE:
        entry = _CVE_CACHE[cache_key]
        if now - entry["timestamp"] < CACHE_TTL:
            return entry["data"]

    # 2. Query NIST NVD for specific CVE or keyword
    headers = {"User-Agent": "LazySOC-CyberSec/3.0"}
    params: Dict[str, Any] = {"resultsPerPage": min(limit, 20)}

    is_cve_id = query.upper().startswith("CVE-")
    if is_cve_id:
        params["cveId"] = query.upper()
    else:
        params["keywordSearch"] = query

    try:
        resp = requests.get(NVD_API_URL, headers=headers, params=params, timeout=8)
        if resp.status_code == 200:
            data = resp.json()
            vulns = data.get("vulnerabilities", [])
            items = [_parse_nvd_item(v) for v in vulns]

            result = {
                "total": len(items),
                "query": query,
                "realtime": True,
                "items": items,
                "cached": False,
            }
            _CVE_CACHE[cache_key] = {"timestamp": now, "data": result}
            return result
    except Exception:
        pass

    # 3. Fallback: Search in CISA KEV items
    kev_items = fetch_cisa_kev_recent(limit=50)
    q_low = query.lower()
    fallback_items = [
        item for item in kev_items
        if q_low in item["id"].lower() or q_low in item["description"].lower() or q_low in item["cwe"].lower()
    ]

    return {
        "total": len(fallback_items),
        "query": query,
        "items": fallback_items,
        "cached": True,
        "fallback": True,
    }
