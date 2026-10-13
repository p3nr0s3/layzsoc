"""Network Recon, RDAP/WHOIS, Shodan Exposure, and IP Geolocation module for LazySOC."""

import socket
import ipaddress
import requests
from typing import Dict, Any, Optional
from core.parser import is_valid_ipv4, is_valid_ipv6
from core.config import SHODAN_INTERNETDB_URL


def is_private_ip(ip: str) -> bool:
    """Checks if an IP string is private, loopback, or non-routable."""
    try:
        ip_obj = ipaddress.ip_address(ip.strip())
        return (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_reserved
            or ip_obj.is_unspecified
        )
    except Exception:
        return False


def resolve_ptr(ip: str) -> Optional[str]:
    """Resolves IP address to reverse DNS hostname (PTR record)."""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except Exception:
        return None


def get_ip_geo(ip: str) -> Dict[str, Any]:
    """Retrieves Geolocation, ASN, and ISP for an IP address via IP-API."""
    if is_private_ip(ip):
        return {
            "success": False,
            "ip": ip,
            "error": "Private / RFC 1918 address (not routable on public internet)",
        }

    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,query"
        resp = requests.get(url, timeout=5, headers={"User-Agent": "LazySOC-CyberSec/3.0"})
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


def get_shodan_exposure(ip: str) -> Dict[str, Any]:
    """
    Queries Shodan's free, zero-key InternetDB API for open ports, CPEs,
    tags, hostnames, and known CVE vulnerabilities.
    """
    if is_private_ip(ip):
        return {
            "success": True,
            "found": False,
            "message": "Private / Internal IP range not indexed in Shodan InternetDB.",
            "ports": [],
            "vulns": [],
            "cpes": [],
            "tags": [],
        }

    try:
        url = f"{SHODAN_INTERNETDB_URL}/{ip}"
        resp = requests.get(url, timeout=5, headers={"User-Agent": "LazySOC-CyberSec/3.0"})
        if resp.status_code == 200:
            data = resp.json()
            return {
                "success": True,
                "found": True,
                "ip": data.get("ip", ip),
                "ports": data.get("ports", []),
                "vulns": data.get("vulns", []),
                "cpes": data.get("cpes", []),
                "tags": data.get("tags", []),
                "hostnames": data.get("hostnames", []),
            }
        elif resp.status_code == 404:
            return {
                "success": True,
                "found": False,
                "message": "No open ports or active CVEs indexed in Shodan InternetDB.",
                "ports": [],
                "vulns": [],
                "cpes": [],
                "tags": [],
            }
        return {"success": False, "found": False, "error": f"Shodan returned status {resp.status_code}"}
    except Exception as e:
        return {"success": False, "found": False, "error": f"Shodan InternetDB error: {str(e)}"}


def get_rdap_whois(domain: str) -> Dict[str, Any]:
    """Queries ICANN's standardized RDAP service for domain registration data."""
    clean_domain = domain.lower().strip()
    if "://" in clean_domain:
        clean_domain = clean_domain.split("://")[1].split("/")[0]
    clean_domain = clean_domain.split("/")[0].split(":")[0]

    try:
        url = f"https://rdap.org/domain/{clean_domain}"
        resp = requests.get(url, timeout=6, headers={"Accept": "application/json", "User-Agent": "LazySOC-CyberSec/3.0"})
        if resp.status_code == 200:
            data = resp.json()

            # Extract registrar entity
            registrar = "Unknown"
            entities = data.get("entities", [])
            for ent in entities:
                roles = ent.get("roles", [])
                if "registrar" in roles:
                    vcard = ent.get("vcardArray", [])
                    if len(vcard) > 1 and isinstance(vcard[1], list):
                        for item in vcard[1]:
                            if isinstance(item, list) and len(item) > 3 and item[0] == "fn":
                                registrar = item[3]
                                break
                    if registrar == "Unknown" and ent.get("handle"):
                        registrar = ent.get("handle")

            # Extract creation and expiration dates
            created = "Unknown"
            expires = "Unknown"
            updated = "Unknown"
            for ev in data.get("events", []):
                action = ev.get("eventAction", "")
                date = ev.get("eventDate", "")
                if action in ("registration", "registered"):
                    created = date[:10]
                elif action in ("expiration", "expired"):
                    expires = date[:10]
                elif action in ("last changed", "last update"):
                    updated = date[:10]

            # Nameservers
            nameservers = [ns.get("ldhName", "") for ns in data.get("nameservers", []) if isinstance(ns, dict)]

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
        shodan = get_shodan_exposure(tgt)
        return {
            "target": tgt,
            "type": "ip",
            "ptr": ptr or "No PTR hostname configured",
            "geo": geo,
            "shodan": shodan,
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
        shodan = get_shodan_exposure(resolved_ip) if resolved_ip else None

        return {
            "target": tgt,
            "type": "domain",
            "resolved_ip": resolved_ip,
            "whois": rdap,
            "geo": geo,
            "shodan": shodan,
        }
