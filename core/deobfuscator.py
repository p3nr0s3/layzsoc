"""
SOC De-obfuscation & CyberChef-Lite Utility for LazySOC.
Decodes and inspects obfuscated attack commands:
- PowerShell Encoded Commands (UTF-16LE Base64)
- Standard Base64 (ASCII / UTF-8)
- Hex / Byte arrays (\\x.., 0x.., continuous hex)
- URL / Percent-encoding (multi-pass)
- ROT13 Substitution
- Reverse strings
- Single-byte XOR brute-force scanner
- Defang / Refang converter
"""

import re
import base64
import urllib.parse
from typing import Dict, Any, List, Optional


def _clean_backticks(text: str) -> str:
    """Removes PowerShell tick obfuscation (e.g. d`o`w`n`l`o`a`d)."""
    return text.replace("`", "")


def _extract_powershell_encoded(text: str) -> List[Dict[str, Any]]:
    """Detects and decodes PowerShell -enc / -EncodedCommand arguments."""
    results = []
    # Pattern to match powershell -enc / -encodedcommand followed by base64
    patterns = [
        r"(?:-e|-ec|-enc|-encodedcommand)\s+([A-Za-z0-9+/=]{12,})",
        r"(?:\[Convert\]::FromBase64String\(['\"]([A-Za-z0-9+/=]{12,})['\"]\)\]?)",
    ]

    for pat in patterns:
        for match in re.finditer(pat, text, re.IGNORECASE):
            b64_str = match.group(1).strip()
            try:
                # Add padding if needed
                pad = len(b64_str) % 4
                if pad:
                    b64_str += "=" * (4 - pad)
                decoded_bytes = base64.b64decode(b64_str)
                # PowerShell uses UTF-16LE
                decoded_text = decoded_bytes.decode("utf-16le", errors="replace")
                cleaned_text = _clean_backticks(decoded_text)

                # Look for suspicious IOCs / cmdlets
                suspicious_patterns = [
                    "downloadstring", "downloadfile", "invoke-expression", "iex", "start-process",
                    "bypass", "hidden", "windowstyle", "net.webclient", "curl", "bitsadmin",
                    "certutil", "regsvr32", "rundll32", "mshta", "wscript", "cscript"
                ]
                detected_cmdlets = [c for c in suspicious_patterns if c in cleaned_text.lower()]

                # Find any nested URLs
                urls = re.findall(r"https?://[^\s'\"`]+", cleaned_text, re.IGNORECASE)

                results.append({
                    "raw_encoded": match.group(0),
                    "base64_payload": match.group(1),
                    "decoded_command": cleaned_text,
                    "suspicious_cmdlets": detected_cmdlets,
                    "extracted_urls": urls,
                })
            except Exception:
                pass

    return results


def _decode_standard_base64(text: str) -> Optional[str]:
    """Tries decoding text as standard ASCII/UTF-8 base64."""
    clean = text.strip()
    # Check if looks like pure base64
    if re.fullmatch(r"[A-Za-z0-9+/=]{8,}", clean):
        try:
            pad = len(clean) % 4
            if pad:
                clean += "=" * (4 - pad)
            dec = base64.b64decode(clean).decode("utf-8", errors="ignore")
            if len(dec) >= 4 and sum(c.isprintable() or c.isspace() for c in dec) / len(dec) > 0.8:
                return dec
        except Exception:
            pass
    return None


def _decode_hex_string(text: str) -> Optional[str]:
    """Decodes hex formats: continuous hex, \\x41\\x42, or 0x41, 0x42."""
    clean = text.strip()
    # Continuous hex (e.g. 48656c6c6f)
    if re.fullmatch(r"[0-9a-fA-F]{6,}", clean) and len(clean) % 2 == 0:
        try:
            dec = bytes.fromhex(clean).decode("utf-8", errors="ignore")
            if sum(c.isprintable() or c.isspace() for c in dec) / len(dec) > 0.8:
                return dec
        except Exception:
            pass

    # \x48\x65 or 0x48 formats
    hex_tokens = re.findall(r"(?:\\x|0x)([0-9a-fA-F]{2})", clean)
    if len(hex_tokens) >= 3:
        try:
            b = bytes(int(t, 16) for t in hex_tokens)
            dec = b.decode("utf-8", errors="ignore")
            if sum(c.isprintable() or c.isspace() for c in dec) / len(dec) > 0.8:
                return dec
        except Exception:
            pass

    return None


def _decode_rot13(text: str) -> str:
    """Rot13 Caesar substitution."""
    res = []
    for c in text:
        if 'a' <= c <= 'z':
            res.append(chr((ord(c) - ord('a') + 13) % 26 + ord('a')))
        elif 'A' <= c <= 'Z':
            res.append(chr((ord(c) - ord('A') + 13) % 26 + ord('A')))
        else:
            res.append(c)
    return "".join(res)


def _decode_url_multi(text: str) -> str:
    """Unquotes URL encoding, repeating up to 3 times for double/triple encoded strings."""
    curr = text
    for _ in range(3):
        unq = urllib.parse.unquote(curr)
        if unq == curr:
            break
        curr = unq
    return curr


def _xor_bruteforce(raw_bytes: bytes) -> List[Dict[str, Any]]:
    """Tests single-byte XOR keys (1..255) looking for high-confidence English/command strings."""
    candidates = []
    interesting_keywords = [
        b"http", b"https", b"cmd", b"powershell", b"program", b"system32",
        b"kernel", b"user32", b"getprocaddress", b"loadlibrary", b"socket"
    ]

    for k in range(1, 256):
        xored = bytes(b ^ k for b in raw_bytes)
        try:
            text = xored.decode("ascii", errors="ignore")
            if len(text) < 4:
                continue
            printable_ratio = sum(c.isprintable() for c in text) / len(text)
            if printable_ratio > 0.85:
                # Check for keywords
                matched = [kw.decode() for kw in interesting_keywords if kw in xored.lower()]
                if matched:
                    candidates.append({
                        "key": f"0x{k:02X} ({k})",
                        "matches": matched,
                        "preview": text[:200],
                    })
        except Exception:
            pass

    return candidates[:3]


def defang_text(text: str) -> str:
    """Safely defangs URLs, IPs, and protocols."""
    s = text.replace("http://", "hxxp://").replace("https://", "hxxps://")
    s = s.replace("ftp://", "fxp://")
    # Defang dots in IPs and domains
    s = re.sub(r"(?<=\w)\.(?=\w)", "[.]", s)
    return s


def refang_text(text: str) -> str:
    """Refangs defanged text back to standard format."""
    s = text.replace("[.]", ".").replace("(.)", ".")
    s = s.replace("hxxps://", "https://").replace("hxxp://", "http://").replace("fxp://", "ftp://")
    return s


def deobfuscate_payload(raw_text: str) -> Dict[str, Any]:
    """
    Main entry point for de-obfuscation studio.
    Runs multiple decoders and returns structured analysis.
    """
    text = raw_text.strip()
    if not text:
        return {"error": "Input text is empty."}

    results: Dict[str, Any] = {
        "input_length": len(text),
        "powershell": _extract_powershell_encoded(text),
        "base64_standard": _decode_standard_base64(text),
        "hex_decoded": _decode_hex_string(text),
        "url_decoded": _decode_url_multi(text) if "%" in text else None,
        "rot13": _decode_rot13(text),
        "reversed": text[::-1] if len(text) > 4 else None,
        "defanged_version": defang_text(text),
        "refanged_version": refang_text(text),
        "xor_candidates": [],
    }

    # If input is hex or ascii bytes, try XOR
    clean_hex = re.sub(r"[\s,\\x0x]", "", text)
    if re.fullmatch(r"[0-9a-fA-F]{8,}", clean_hex) and len(clean_hex) % 2 == 0:
        try:
            raw_bytes = bytes.fromhex(clean_hex)
            results["xor_candidates"] = _xor_bruteforce(raw_bytes)
        except Exception:
            pass

    return results
