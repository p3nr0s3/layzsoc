"""Unified IoC Parser and Defanger for Slothery."""

import re
import ipaddress
import csv
import io
from urllib.parse import urlparse
from typing import List, Dict, Set, Optional, Tuple

# Regex patterns
RE_IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
)

# Hex hash patterns (strict word boundaries to avoid matching random words or longer strings)
RE_MD5 = re.compile(r"\b[a-fA-F0-9]{32}\b")
RE_SHA1 = re.compile(r"\b[a-fA-F0-9]{40}\b")
RE_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")

# URL pattern
RE_URL = re.compile(r"\b(?:https?://|ftp://)[^\s<>\"'{}|\\^`\[\]]+\b", re.IGNORECASE)

# Domain pattern (excluding common non-domain file extensions)
COMMON_EXTENSIONS = {
    "exe", "dll", "zip", "rar", "tar", "gz", "7z", "pdf", "txt", "docx",
    "xlsx", "pptx", "png", "jpg", "jpeg", "gif", "svg", "bin", "sh", "bat",
    "py", "js", "html", "css", "json", "xml", "csv", "log", "iso", "apk"
}

RE_DOMAIN = re.compile(
    r"\b(?!(?:https?://))([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"([a-zA-Z]{2,24})\b",
    re.IGNORECASE
)

# Defang replacements
DEFANG_REPLACEMENTS = [
    (re.compile(r"hxxps?://", re.IGNORECASE), lambda m: "https://" if "s" in m.group(0).lower() else "http://"),
    (re.compile(r"\[\.\]|\(\.\)|\{\.\}|\\\.|\s*\[dot\]\s*", re.IGNORECASE), "."),
    (re.compile(r"\[:\]|\(:\)|\{:\}|\\:|\\\/\\\/", re.IGNORECASE), ":"),
    (re.compile(r"\[at\]|\(at\)", re.IGNORECASE), "@"),
]


def defang_string(text: str) -> str:
    """Normalize and defang an input string."""
    if not text:
        return ""
    result = text
    for pattern, repl in DEFANG_REPLACEMENTS:
        if callable(repl):
            result = pattern.sub(repl, result)
        else:
            result = pattern.sub(repl, result)
    return result.strip()


def refang_string(ioc: str, ioc_type: str) -> str:
    """Intentionally defang an IoC for safe display / export if desired."""
    if ioc_type in ("ipv4", "ipv6", "domain"):
        return ioc.replace(".", "[.]").replace(":", "[:]")
    elif ioc_type == "url":
        return ioc.replace("http://", "hxxp://").replace("https://", "hxxps://").replace(".", "[.]")
    return ioc


def is_valid_ipv4(ip: str) -> bool:
    """Check if string is a valid IPv4 address."""
    try:
        obj = ipaddress.IPv4Address(ip)
        return True
    except (ipaddress.AddressValueError, ValueError):
        return False


def is_valid_ipv6(ip: str) -> bool:
    """Check if string is a valid IPv6 address."""
    try:
        obj = ipaddress.IPv6Address(ip)
        return True
    except (ipaddress.AddressValueError, ValueError):
        return False


def is_private_ip(ip: str) -> bool:
    """Check if IP is private, loopback, link-local, multicast, or reserved."""
    try:
        obj = ipaddress.ip_address(ip)
        return (
            obj.is_private
            or obj.is_loopback
            or obj.is_link_local
            or obj.is_multicast
            or obj.is_reserved
        )
    except ValueError:
        return False


class IoCItem:
    """Represents an extracted Indicator of Compromise."""
    def __init__(self, raw: str, value: str, ioc_type: str, is_private: bool = False):
        self.raw = raw
        self.value = value
        self.ioc_type = ioc_type  # 'ipv4', 'ipv6', 'md5', 'sha1', 'sha256', 'domain', 'url'
        self.is_private = is_private

    def to_dict(self) -> Dict[str, any]:
        return {
            "raw": self.raw,
            "value": self.value,
            "type": self.ioc_type,
            "is_private": self.is_private,
        }

    def __repr__(self) -> str:
        return f"IoCItem({self.ioc_type}: {self.value})"

    def __eq__(self, other) -> bool:
        if isinstance(other, IoCItem):
            return self.value.lower() == other.value.lower() and self.ioc_type == other.ioc_type
        return False

    def __hash__(self) -> int:
        return hash((self.value.lower(), self.ioc_type))


def parse_raw_text(text: str) -> List[IoCItem]:
    """
    Extracts all supported IoCs (IPs, Hashes, Domains, URLs) from raw text.
    Handles defanging, deduplication, and classification.
    """
    if not text:
        return []

    cleaned_text = defang_string(text)

    found_items: List[IoCItem] = []
    seen: Set[Tuple[str, str]] = set()

    # 1. Extract URLs first
    url_matches = RE_URL.findall(cleaned_text)
    for u in url_matches:
        u_clean = u.rstrip(".,;)\"'>]")
        key = (u_clean.lower(), "url")
        if key not in seen:
            seen.add(key)
            found_items.append(IoCItem(raw=u, value=u_clean, ioc_type="url"))

    # Mask out extracted URLs to avoid double-matching their hosts as separate domains
    masked_urls = RE_URL.sub(" ", cleaned_text)

    # 2. Extract Hashes (longest to shortest)
    sha256_matches = RE_SHA256.findall(masked_urls)
    for h in sha256_matches:
        val = h.lower()
        key = (val, "sha256")
        if key not in seen:
            seen.add(key)
            found_items.append(IoCItem(raw=h, value=val, ioc_type="sha256"))

    masked_hashes = RE_SHA256.sub(" " * 64, masked_urls)

    sha1_matches = RE_SHA1.findall(masked_hashes)
    for h in sha1_matches:
        val = h.lower()
        key = (val, "sha1")
        if key not in seen:
            seen.add(key)
            found_items.append(IoCItem(raw=h, value=val, ioc_type="sha1"))

    masked_hashes = RE_SHA1.sub(" " * 40, masked_hashes)

    md5_matches = RE_MD5.findall(masked_hashes)
    for h in md5_matches:
        val = h.lower()
        key = (val, "md5")
        if key not in seen:
            seen.add(key)
            found_items.append(IoCItem(raw=h, value=val, ioc_type="md5"))

    # 3. Extract IPv4
    ipv4_matches = RE_IPV4.findall(cleaned_text)
    for ip in ipv4_matches:
        if is_valid_ipv4(ip):
            key = (ip, "ipv4")
            if key not in seen:
                seen.add(key)
                found_items.append(
                    IoCItem(
                        raw=ip,
                        value=ip,
                        ioc_type="ipv4",
                        is_private=is_private_ip(ip),
                    )
                )

    # 4. Extract Domains
    domain_matches = RE_DOMAIN.finditer(masked_urls)
    for match in domain_matches:
        dom = match.group(0).lower().rstrip(".,;)\"'>]")
        tld = match.group(2).lower()
        
        # Skip if ends with a common file extension or looks like an IP
        if tld in COMMON_EXTENSIONS or is_valid_ipv4(dom):
            continue

        key = (dom, "domain")
        if key not in seen:
            seen.add(key)
            found_items.append(IoCItem(raw=match.group(0), value=dom, ioc_type="domain"))

    # 5. Extract IPv6 candidates
    tokens = re.split(r"[\s,;\"\']+", cleaned_text)
    for tok in tokens:
        tok_clean = tok.strip("[](){}<>\"':")
        if ":" in tok_clean and is_valid_ipv6(tok_clean):
            try:
                norm_ipv6 = str(ipaddress.IPv6Address(tok_clean))
                key = (norm_ipv6, "ipv6")
                if key not in seen:
                    seen.add(key)
                    found_items.append(
                        IoCItem(
                            raw=tok_clean,
                            value=norm_ipv6,
                            ioc_type="ipv6",
                            is_private=is_private_ip(norm_ipv6),
                        )
                    )
            except ValueError:
                pass

    return found_items


def parse_uploaded_file(file_bytes: bytes, filename: str) -> List[IoCItem]:
    """Parse IoCs from uploaded TXT or CSV file bytes."""
    try:
        content = file_bytes.decode("utf-8", errors="ignore")
    except Exception:
        content = file_bytes.decode("latin-1", errors="ignore")

    lower_name = filename.lower()
    if lower_name.endswith(".csv"):
        extracted_text = []
        try:
            reader = csv.reader(io.StringIO(content))
            for row in reader:
                extracted_text.extend(row)
            content = " \n ".join(extracted_text)
        except Exception:
            pass

    return parse_raw_text(content)
