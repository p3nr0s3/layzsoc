"""Orchestration engine for IoC enrichment and threat triage."""

import time
from typing import List, Dict, Any, Generator, Optional
from core.parser import IoCItem
from core.key_manager import KeyManager
from core.clients.virustotal import VirusTotalClient
from core.clients.abuseipdb import AbuseIPDBClient
from core.clients.urlhaus import URLhausClient
from core.mail_health import MailHealthChecker
from core.database import get_cached_ioc, save_cached_ioc, log_scan
from core.config import CACHE_TTL_HOURS


VERDICT_MALICIOUS = "Malicious"
VERDICT_SUSPICIOUS = "Suspicious"
VERDICT_CLEAN = "Clean"
VERDICT_UNKNOWN = "Unknown"


def determine_verdict(
    ioc_type: str,
    vt_res: Optional[Dict[str, Any]],
    abuse_res: Optional[Dict[str, Any]],
    urlhaus_res: Optional[Dict[str, Any]] = None,
    is_private: bool = False,
) -> str:
    """Calculates overall risk verdict across integrated threat providers."""
    if is_private:
        return VERDICT_UNKNOWN

    # URLhaus check (immediate malicious trigger if positive threat)
    if urlhaus_res and urlhaus_res.get("found"):
        return VERDICT_MALICIOUS

    vt_mal = 0
    vt_susp = 0
    vt_success = False

    if vt_res and vt_res.get("success"):
        vt_success = True
        vt_mal = vt_res.get("malicious", 0)
        vt_susp = vt_res.get("suspicious", 0)

    abuse_score = 0
    abuse_success = False
    if abuse_res and abuse_res.get("success"):
        abuse_success = True
        abuse_data = abuse_res.get("data", {})
        abuse_score = abuse_data.get("abuse_confidence_score", 0)

    # 1. Malicious rules
    if abuse_score >= 50 or vt_mal >= 2:
        return VERDICT_MALICIOUS
    if vt_mal == 1 and abuse_score >= 20:
        return VERDICT_MALICIOUS

    # 2. Suspicious rules
    if abuse_score > 0 or vt_susp >= 1 or vt_mal == 1:
        return VERDICT_SUSPICIOUS

    # 3. Clean rules
    if vt_success or abuse_success:
        if vt_mal == 0 and vt_susp == 0 and abuse_score == 0:
            return VERDICT_CLEAN

    return VERDICT_UNKNOWN


class EnrichmentEngine:
    """Coordinates threat intelligence lookup with rate-limit pacing and caching."""

    def __init__(self, key_manager: Optional[KeyManager] = None):
        self.km = key_manager or KeyManager()
        self.vt_client = VirusTotalClient(self.km)
        self.abuse_client = AbuseIPDBClient(self.km)
        self.urlhaus_client = URLhausClient()
        self.mail_checker = MailHealthChecker()

    def scan_items(
        self,
        items: List[IoCItem],
        use_cache: bool = True,
        ttl_hours: int = CACHE_TTL_HOURS,
        skip_private_ips: bool = True,
        auto_throttle: bool = True,
    ) -> Generator[Dict[str, Any], None, None]:
        """
        Processes a list of IoCItem objects.
        Yields real-time events:
        - {"type": "progress", "index": i, "total": total, "current": val}
        - {"type": "item_result", "data": {...}}
        - {"type": "complete", "summary": {...}}
        """
        total = len(items)
        results: List[Dict[str, Any]] = []

        malicious_count = 0
        suspicious_count = 0
        clean_count = 0
        unknown_count = 0

        for i, item in enumerate(items):
            val = item.value
            ioc_type = item.ioc_type

            yield {
                "type": "progress",
                "index": i + 1,
                "total": total,
                "current_ioc": val,
                "current_type": ioc_type,
            }

            # 1. Check if Private / Local IP
            if item.is_private and skip_private_ips:
                item_dict = {
                    "ioc": val,
                    "type": ioc_type,
                    "verdict": VERDICT_UNKNOWN,
                    "notes": "Private / Loopback / Bogon IP (RFC 1918)",
                    "vt_stats": "N/A",
                    "abuse_score": "N/A",
                    "details": {
                        "is_private": True,
                        "description": "Private address spaces are not routable on the public internet.",
                    },
                    "is_cached": False,
                }
                unknown_count += 1
                results.append(item_dict)
                yield {"type": "item_result", "data": item_dict}
                continue

            # 2. Check local SQLite Cache
            if use_cache:
                cached = get_cached_ioc(val)
                if cached:
                    verdict = cached["verdict"]
                    if verdict == VERDICT_MALICIOUS:
                        malicious_count += 1
                    elif verdict == VERDICT_SUSPICIOUS:
                        suspicious_count += 1
                    elif verdict == VERDICT_CLEAN:
                        clean_count += 1
                    else:
                        unknown_count += 1

                    vt_data = cached.get("vt_data")
                    abuse_data = cached.get("abuse_data")

                    item_dict = {
                        "ioc": val,
                        "type": ioc_type,
                        "verdict": verdict,
                        "notes": "Retrieved from local cache",
                        "vt_stats": self._format_vt_summary(vt_data),
                        "abuse_score": self._format_abuse_summary(abuse_data),
                        "vt_data": vt_data,
                        "abuse_data": abuse_data,
                        "mail_health": vt_data.get("mail_health") if isinstance(vt_data, dict) else None,
                        "urlhaus_data": vt_data.get("urlhaus_data") if isinstance(vt_data, dict) else None,
                        "is_cached": True,
                        "updated_at": cached.get("updated_at"),
                    }
                    results.append(item_dict)
                    yield {"type": "item_result", "data": item_dict}
                    continue

            # 3. Live External Queries
            vt_res = None
            abuse_res = None
            urlhaus_res = None
            mail_res = None

            # For IPs
            if ioc_type in ("ipv4", "ipv6"):
                abuse_res = self._query_with_throttle(
                    lambda: self.abuse_client.check_ip(val),
                    service_name="AbuseIPDB",
                    auto_throttle=auto_throttle,
                )
                vt_res = self._query_with_throttle(
                    lambda: self.vt_client.check_ip(val),
                    service_name="VirusTotal",
                    auto_throttle=auto_throttle,
                )

            # For Hashes
            elif ioc_type in ("md5", "sha1", "sha256"):
                vt_res = self._query_with_throttle(
                    lambda: self.vt_client.check_hash(val),
                    service_name="VirusTotal",
                    auto_throttle=auto_throttle,
                )

            # For Domains
            elif ioc_type == "domain":
                vt_res = self._query_with_throttle(
                    lambda: self.vt_client.check_domain(val),
                    service_name="VirusTotal",
                    auto_throttle=auto_throttle,
                )
                # URLhaus host lookup
                urlhaus_res = self.urlhaus_client.check_host(val)
                # Mail health audit
                mail_res = self.mail_checker.check_domain(val)

            # For URLs
            elif ioc_type == "url":
                vt_res = self._query_with_throttle(
                    lambda: self.vt_client.check_url(val),
                    service_name="VirusTotal",
                    auto_throttle=auto_throttle,
                )
                urlhaus_res = self.urlhaus_client.check_url(val)

            # Calculate verdict
            verdict = determine_verdict(ioc_type, vt_res, abuse_res, urlhaus_res, item.is_private)
            if verdict == VERDICT_MALICIOUS:
                malicious_count += 1
            elif verdict == VERDICT_SUSPICIOUS:
                suspicious_count += 1
            elif verdict == VERDICT_CLEAN:
                clean_count += 1
            else:
                unknown_count += 1

            # Embed extra data in vt_res container for caching
            cache_vt = dict(vt_res) if vt_res else {}
            if mail_res:
                cache_vt["mail_health"] = mail_res
            if urlhaus_res:
                cache_vt["urlhaus_data"] = urlhaus_res

            # Prepare detail item
            item_dict = {
                "ioc": val,
                "type": ioc_type,
                "verdict": verdict,
                "notes": self._generate_notes(ioc_type, vt_res, abuse_res, urlhaus_res, mail_res),
                "vt_stats": self._format_vt_summary(vt_res),
                "abuse_score": self._format_abuse_summary(abuse_res),
                "vt_data": vt_res,
                "abuse_data": abuse_res,
                "urlhaus_data": urlhaus_res,
                "mail_health": mail_res,
                "is_cached": False,
            }

            # Save to SQLite Cache
            if use_cache:
                save_cached_ioc(
                    ioc_value=val,
                    ioc_type=ioc_type,
                    verdict=verdict,
                    vt_data=cache_vt,
                    abuse_data=abuse_res,
                    ttl_hours=ttl_hours,
                )

            results.append(item_dict)
            yield {"type": "item_result", "data": item_dict}

        # Log batch to scan history
        log_scan(
            total=total,
            mal=malicious_count,
            susp=suspicious_count,
            clean=clean_count,
            unk=unknown_count,
        )

        yield {
            "type": "complete",
            "summary": {
                "total": total,
                "malicious": malicious_count,
                "suspicious": suspicious_count,
                "clean": clean_count,
                "unknown": unknown_count,
            },
            "results": results,
        }

    def _query_with_throttle(
        self,
        query_fn,
        service_name: str,
        auto_throttle: bool = True,
        max_waits: int = 5,
    ) -> Dict[str, Any]:
        """Executes a query function, handling temporary rate-limit waits if enabled."""
        waits = 0
        while waits < max_waits:
            res = query_fn()
            if not res:
                return {"success": False, "error": "Empty response"}

            if res.get("error_type") == "THROTTLED" and auto_throttle:
                wait_sec = res.get("wait_seconds", 60)
                time.sleep(min(wait_sec, 65))
                waits += 1
                continue

            return res

        return res

    def _format_vt_summary(self, vt_data: Optional[Dict[str, Any]]) -> str:
        if not vt_data:
            return "N/A"
        if not vt_data.get("success"):
            return vt_data.get("error_type", "Error")
        if vt_data.get("not_found"):
            return "Not indexed (0/0)"

        stats = vt_data.get("stats", {})
        mal = stats.get("malicious", 0)
        susp = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        total_engines = mal + susp + harmless + undetected

        label = vt_data.get("threat_label", "")
        if label and label not in ("Clean / Unclassified", "Not Found in VT"):
            return f"{mal}/{total_engines} ({label})"
        return f"{mal}/{total_engines}"

    def _format_abuse_summary(self, abuse_data: Optional[Dict[str, Any]]) -> str:
        if not abuse_data:
            return "N/A"
        if not abuse_data.get("success"):
            return abuse_data.get("error_type", "Error")
        data = abuse_data.get("data", {})
        score = data.get("abuse_confidence_score", 0)
        reports = data.get("total_reports", 0)
        return f"{score}% ({reports} reports)"

    def _generate_notes(
        self,
        ioc_type: str,
        vt_res: Optional[Dict[str, Any]],
        abuse_res: Optional[Dict[str, Any]],
        urlhaus_res: Optional[Dict[str, Any]] = None,
        mail_res: Optional[Dict[str, Any]] = None,
    ) -> str:
        notes = []

        # URLhaus notes
        if urlhaus_res and urlhaus_res.get("found"):
            if ioc_type == "url":
                notes.append(f"URLhaus: {urlhaus_res.get('threat')} ({urlhaus_res.get('url_status')})")
            else:
                notes.append(f"URLhaus: {urlhaus_res.get('url_count')} malicious URLs on host")

        # VT notes
        if vt_res and vt_res.get("success"):
            if vt_res.get("malicious", 0) > 0:
                notes.append(f"VT flagged: {vt_res.get('malicious')} engines")
            if vt_res.get("threat_label") and vt_res.get("threat_label") != "Clean / Unclassified":
                notes.append(f"Threat: {vt_res.get('threat_label')}")
            if vt_res.get("registrar") and vt_res.get("registrar") != "Unknown":
                notes.append(f"Registrar: {vt_res.get('registrar')}")
            if vt_res.get("as_owner") and vt_res.get("as_owner") != "Unknown":
                notes.append(f"ASN: {vt_res.get('as_owner')}")

        # AbuseIPDB notes
        if abuse_res and abuse_res.get("success"):
            data = abuse_res.get("data", {})
            isp = data.get("isp")
            country = data.get("country_name")
            if isp and isp != "Unknown":
                notes.append(f"ISP: {isp} ({country})")

        # Mail health notes for domains
        if mail_res:
            m_rating = mail_res.get("rating")
            d_pol = mail_res.get("dmarc", {}).get("policy", "none")
            mx_prov = mail_res.get("mx", {}).get("provider", "No MX")
            notes.append(f"Mail: {mx_prov} | DMARC: {d_pol} ({m_rating})")

        return "; ".join(notes) if notes else "No threat activity reported"
