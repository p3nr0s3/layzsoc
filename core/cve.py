"""
CVE & NVD Vulnerability Intelligence Module for LazySOC.
Fetches, caches, and aggregates vulnerability data from NIST NVD and CIRCL CVE APIs.
"""

import time
import requests
from typing import List, Dict, Any, Optional

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CIRCL_API_URL = "https://cve.circl.lu/api/cve"

CACHE_TTL = 300  # 5 minutes in-memory cache
_CVE_CACHE: Dict[str, Any] = {}

# Curated high-impact / notable recent CVEs for instant showcase
CURATED_CVES = [
    {
        "id": "CVE-2024-3400",
        "cvss": 10.0,
        "severity": "CRITICAL",
        "cwe": "CWE-77 (Command Injection)",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "description": "Arbitrary command injection in the GlobalProtect feature of Palo Alto Networks PAN-OS software allows an unauthenticated attacker to execute arbitrary code with root privileges on the firewall.",
        "published": "2024-04-12",
        "source": "NIST NVD",
        "link": "https://nvd.nist.gov/vuln/detail/CVE-2024-3400",
        "known_exploited": True,
    },
    {
        "id": "CVE-2024-21887",
        "cvss": 9.1,
        "severity": "CRITICAL",
        "cwe": "CWE-78 (OS Command Injection)",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H",
        "description": "Command injection vulnerability in web components of Ivanti Connect Secure (9.x, 22.x) and Ivanti Policy Secure allows an authenticated administrator to execute arbitrary commands.",
        "published": "2024-01-12",
        "source": "NIST NVD",
        "link": "https://nvd.nist.gov/vuln/detail/CVE-2024-21887",
        "known_exploited": True,
    },
    {
        "id": "CVE-2023-46805",
        "cvss": 8.2,
        "severity": "HIGH",
        "cwe": "CWE-287 (Authentication Bypass)",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
        "description": "Authentication bypass vulnerability in the web server of Ivanti Connect Secure and Ivanti Policy Secure allows a remote attacker to access restricted resources by bypassing control checks.",
        "published": "2024-01-12",
        "source": "NIST NVD",
        "link": "https://nvd.nist.gov/vuln/detail/CVE-2023-46805",
        "known_exploited": True,
    },
    {
        "id": "CVE-2023-4966",
        "cvss": 9.4,
        "severity": "CRITICAL",
        "cwe": "CWE-119 (Buffer Overflow - Citrix Bleed)",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "description": "Citrix Bleed: Sensitive information disclosure in NetScaler ADC and NetScaler Gateway when configured as an appliance allows unauthorized session takeover.",
        "published": "2023-10-10",
        "source": "NIST NVD",
        "link": "https://nvd.nist.gov/vuln/detail/CVE-2023-4966",
        "known_exploited": True,
    },
    {
        "id": "CVE-2021-44228",
        "cvss": 10.0,
        "severity": "CRITICAL",
        "cwe": "CWE-502 (Deserialization - Log4Shell)",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "description": "Apache Log4j2 JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints (Log4Shell).",
        "published": "2021-12-10",
        "source": "NIST NVD",
        "link": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
        "known_exploited": True,
    },
]


def _parse_nvd_item(item: Dict[str, Any]) -> Dict[str, Any]:
    """Extracts structured vulnerability record from an NVD CVE object."""
    cve = item.get("cve", {})
    cve_id = cve.get("id", "UNKNOWN")

    # Extract CVSS v3.1 or v3.0 score & severity
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
        # Fallback to CVSS v2
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

    # Extract Description
    descriptions = cve.get("descriptions", [])
    en_desc = next((d.get("value", "") for d in descriptions if d.get("lang") == "en"), "")
    if not en_desc and descriptions:
        en_desc = descriptions[0].get("value", "")

    # Extract CWE Weakness
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
    """Queries NIST NVD for specific CVE or keyword, with caching and fallback."""
    now = time.time()
    query = (search or "").strip()

    # 1. Default view if empty search
    if not query:
        return {
            "total": len(CURATED_CVES),
            "query": "",
            "items": CURATED_CVES,
            "cached": True,
        }

    cache_key = f"cve_{query.lower()}_{limit}"
    if cache_key in _CVE_CACHE:
        entry = _CVE_CACHE[cache_key]
        if now - entry["timestamp"] < CACHE_TTL:
            return entry["data"]

    # 2. Query NIST NVD
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
                "items": items,
                "cached": False,
            }
            _CVE_CACHE[cache_key] = {"timestamp": now, "data": result}
            return result
    except Exception as e:
        pass

    # 3. Fallback: Filter curated list by query
    q_low = query.lower()
    fallback_items = [
        item for item in CURATED_CVES
        if q_low in item["id"].lower() or q_low in item["description"].lower() or q_low in item["cwe"].lower()
    ]

    return {
        "total": len(fallback_items),
        "query": query,
        "items": fallback_items,
        "cached": True,
        "fallback": True,
    }
