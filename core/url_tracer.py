"""
Safe URL Redirect Tracer & Domain Age Inspector for LazySOC.
Passively inspects URL redirection chains, status codes, destination servers,
SSL certificates, and computes domain age from RDAP to flag Newly Registered Domains (NRDs).
"""

import socket
import ssl
import datetime
from urllib.parse import urlparse
import requests
from typing import Dict, Any, List, Optional


def _get_ssl_info(hostname: str, port: int = 443) -> Optional[Dict[str, Any]]:
    """Retrieves SSL certificate metadata safely without downloading body content."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # Safe inspection even if cert is self-signed/expired

        with socket.create_connection((hostname, port), timeout=4) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert(binary_form=False)
                if not cert:
                    # binary_form fallback when CERT_NONE
                    der_cert = ssock.getpeercert(binary_form=True)
                    if der_cert:
                        return {"has_ssl": True, "note": "Valid TLS Handshake (Peer cert presented)"}
                    return None

                issuer_dict = dict(x[0] for x in cert.get("issuer", []))
                not_after_str = cert.get("notAfter", "")
                expires_days = None

                if not_after_str:
                    try:
                        exp_dt = datetime.datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                        now_dt = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
                        expires_days = (exp_dt - now_dt).days
                    except Exception:
                        pass

                return {
                    "has_ssl": True,
                    "issuer": issuer_dict.get("organizationName") or issuer_dict.get("commonName") or "Unknown Issuer",
                    "subject": dict(x[0] for x in cert.get("subject", [])).get("commonName", hostname),
                    "expires_in_days": expires_days,
                }
    except Exception as e:
        return {"has_ssl": False, "error": str(e)[:100]}


def _get_domain_age(domain: str) -> Dict[str, Any]:
    """Queries RDAP protocol (RFC 7480) for domain creation date and calculates age."""
    clean_domain = domain.lower().strip()
    if clean_domain.startswith("www."):
        clean_domain = clean_domain[4:]

    # Remove port if present
    if ":" in clean_domain:
        clean_domain = clean_domain.split(":")[0]

    # Skip IP addresses
    is_ip = False
    try:
        socket.inet_aton(clean_domain)
        is_ip = True
    except Exception:
        pass

    if is_ip or not clean_domain or "." not in clean_domain:
        return {"domain": clean_domain, "age_days": None, "risk": "UNKNOWN", "note": "IP or Local Domain"}

    try:
        resp = requests.get(
            f"https://rdap.org/domain/{clean_domain}",
            headers={"User-Agent": "LazySOC-CyberSec/3.0", "Accept": "application/json"},
            timeout=4
        )
        if resp.status_code == 200:
            data = resp.json()
            events = data.get("events", [])
            reg_date_str = None
            for ev in events:
                if ev.get("eventAction") in ("registration", "registered"):
                    reg_date_str = ev.get("eventDate", "")
                    break

            registrar = None
            for ent in data.get("entities", []):
                if "registrar" in ent.get("roles", []):
                    registrar = ent.get("vcardArray", [None, [None, None, None, [""]]])[1][3][3] or ent.get("handle")
                    break

            if reg_date_str:
                clean_date = reg_date_str[:10]
                dt = datetime.datetime.strptime(clean_date, "%Y-%m-%d")
                now = datetime.datetime.now()
                age_days = (now - dt).days

                risk = "LOW_ESTABLISHED"
                risk_label = "Established Domain (> 90 days)"
                if age_days <= 14:
                    risk = "CRITICAL_NEW_DOMAIN"
                    risk_label = "Newly Registered Domain (<= 14 days) - High Risk Phishing/C2 Indicator!"
                elif age_days <= 30:
                    risk = "HIGH_RECENT_DOMAIN"
                    risk_label = "Recently Registered Domain (<= 30 days)"
                elif age_days <= 90:
                    risk = "MEDIUM_YOUNG_DOMAIN"
                    risk_label = "Young Domain (<= 90 days)"

                return {
                    "domain": clean_domain,
                    "registered_date": clean_date,
                    "age_days": age_days,
                    "risk": risk,
                    "risk_label": risk_label,
                    "registrar": registrar or "Standard Accredited Registrar",
                }
    except Exception:
        pass

    return {
        "domain": clean_domain,
        "age_days": None,
        "risk": "UNKNOWN",
        "risk_label": "Domain Age Unavailable via RDAP",
        "registrar": "Not Disclosed",
    }


def trace_url_redirects(target_url: str, max_hops: int = 8) -> Dict[str, Any]:
    """
    Traces URL redirect chain safely and passively (headers only, stream=True).
    Returns list of hops, final landing URL, domain age, and SSL metadata.
    """
    raw_url = target_url.strip()
    if not raw_url.startswith("http://") and not raw_url.startswith("https://"):
        raw_url = "https://" + raw_url

    hops: List[Dict[str, Any]] = []
    current_url = raw_url
    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 LazySOC/3.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    })

    try:
        for step in range(1, max_hops + 1):
            parsed = urlparse(current_url)
            hostname = parsed.hostname or ""

            try:
                # Do NOT follow redirects automatically to capture every step
                resp = session.get(current_url, allow_redirects=False, timeout=6, stream=True)
                status_code = resp.status_code
                headers = dict(resp.headers)
                location = headers.get("Location") or headers.get("location")
                server = headers.get("Server") or headers.get("server") or "Not Disclosed"
                content_type = headers.get("Content-Type") or headers.get("content-type") or "Unknown"

                # Immediately close stream to avoid downloading malware binaries
                resp.close()

                hop_info = {
                    "hop": step,
                    "url": current_url,
                    "domain": hostname,
                    "status_code": status_code,
                    "server": server,
                    "content_type": content_type[:40],
                    "redirect_to": location,
                }
                hops.append(hop_info)

                # Check if this status code represents a redirection
                if status_code in (301, 302, 303, 307, 308) and location:
                    if location.startswith("/"):
                        # Relative redirect
                        current_url = f"{parsed.scheme}://{parsed.netloc}{location}"
                    elif not location.startswith("http://") and not location.startswith("https://"):
                        current_url = f"{parsed.scheme}://{parsed.netloc}/{location.lstrip('/')}"
                    else:
                        current_url = location
                else:
                    # Final landing destination reached
                    break
            except Exception as hop_err:
                hops.append({
                    "hop": step,
                    "url": current_url,
                    "domain": hostname,
                    "status_code": "ERROR",
                    "error": str(hop_err)[:100],
                })
                break
    except Exception as e:
        pass

    final_url = hops[-1]["url"] if hops else raw_url
    final_domain = urlparse(final_url).hostname or urlparse(raw_url).hostname or ""

    domain_age_info = _get_domain_age(final_domain)
    ssl_info = _get_ssl_info(final_domain) if final_url.startswith("https://") else None

    is_shortener = False
    KNOWN_SHORTENERS = {
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
        "adf.ly", "bit.do", "cutt.ly", "rb.gy", "shorturl.at", "rebrand.ly"
    }
    first_domain = urlparse(raw_url).hostname or ""
    if any(s in first_domain.lower() for s in KNOWN_SHORTENERS):
        is_shortener = True

    return {
        "initial_url": raw_url,
        "final_url": final_url,
        "total_hops": len(hops),
        "is_shortener": is_shortener,
        "has_redirects": len(hops) > 1,
        "hops": hops,
        "domain_info": domain_age_info,
        "ssl_info": ssl_info,
    }
