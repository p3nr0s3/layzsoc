"""Network Recon, RDAP/WHOIS, and IP Geolocation module for Slothery."""

import socket
import requests
from typing import Dict, Any, Optional
from core.parser import is_valid_ipv4, is_valid_ipv6


def resolve_ptr(ip: str) -> Optional[str]:
    """Resolves IP address to reverse DNS hostname (PTR record)."""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except Exception:
        return None


def get_ip_geo(ip: str) -> Dict[str, Any]:
    """Retrieves Geolocation, ASN, and ISP for an IP address via IP-API."""
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,query"
        resp = requests.get(url, timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "success":
                return {
                    "success": True,
                    "ip": data.get("query", ip),
                    "country": data.get("country", "Unknown"),
                    "country_code": data.get("countryCode", "??"),
                    "city": data.get("city", "Unknown"),
                    "region": data.get("regionName", "Unknown"),
                    "lat": data.get("lat"),
                    "lon": data.get("lon"),
                    "timezone": data.get("timezone", ""),
                    "isp": data.get("isp", "Unknown"),
                    "org": data.get("org", ""),
                    "asn": data.get("as", "Unknown"),
                }
        return {"success": False, "error": f"Lookup failed: {resp.text[:80]}"}
    except Exception as e:
        return {"success": False, "error": f"Network error: {str(e)}"}


def get_rdap_whois(domain: str) -> Dict[str, Any]:
    """Queries ICANN's standardized RDAP service for domain registration data."""
    clean_domain = domain.lower().strip()
    if "://" in clean_domain:
        clean_domain = clean_domain.split("://")[1].split("/")[0]
    clean_domain = clean_domain.split("/")[0].split(":")[0]

    try:
        url = f"https://rdap.org/domain/{clean_domain}"
        resp = requests.get(url, timeout=6, headers={"Accept": "application/json"})
        if resp.status_code == 200:
            data = resp.json()

            # Extract registrar entity
            registrar = "Unknown"
            entities = data.get("entities", [])
            for ent in entities:
                roles = ent.get("roles", [])
                if "registrar" in roles:
                    vcard = ent.get("vcardArray", [])
                    if len(vcard) > 1:
                        for item in vcard[1]:
                            if item[0] == "fn":
                                registrar = item[3]
                                break

            # Extract creation and expiration dates
            created = "Unknown"
            expires = "Unknown"
            updated = "Unknown"
            for ev in data.get("events", []):
                action = ev.get("eventAction", "")
                date = ev.get("eventDate", "")
                if action == "registration":
                    created = date[:10]
                elif action == "expiration":
                    expires = date[:10]
                elif action == "last changed":
                    updated = date[:10]

            # Nameservers
            nameservers = [ns.get("ldhName", "") for ns in data.get("nameservers", [])]

            # Status codes
            status = data.get("status", [])

            return {
                "success": True,
                "domain": clean_domain,
                "registrar": registrar,
                "created": created,
                "expires": expires,
                "updated": updated,
                "nameservers": nameservers,
                "status": status,
            }
        elif resp.status_code == 404:
            return {"success": False, "error": "Domain registration record not found in RDAP."}
        else:
            return {"success": False, "error": f"RDAP server responded with status {resp.status_code}"}
    except Exception as e:
        return {"success": False, "error": f"RDAP query failed: {str(e)}"}


def perform_recon(target: str) -> Dict[str, Any]:
    """Unified network recon orchestrator for an IP address or Domain."""
    tgt = target.strip()
    is_ip = is_valid_ipv4(tgt) or is_valid_ipv6(tgt)

    if is_ip:
        ptr = resolve_ptr(tgt)
        geo = get_ip_geo(tgt)
        return {
            "target": tgt,
            "type": "ip",
            "ptr": ptr or "No PTR hostname configured",
            "geo": geo,
        }
    else:
        # Domain target
        rdap = get_rdap_whois(tgt)
        # Also resolve domain IP
        resolved_ip = None
        try:
            resolved_ip = socket.gethostbyname(tgt)
        except Exception:
            pass

        geo = get_ip_geo(resolved_ip) if resolved_ip else None

        return {
            "target": tgt,
            "type": "domain",
            "resolved_ip": resolved_ip,
            "whois": rdap,
            "geo": geo,
        }
