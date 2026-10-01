"""Tests for the IoC parser and defanging logic."""

import pytest
from core.parser import (
    defang_string,
    refang_string,
    parse_raw_text,
    is_valid_ipv4,
    is_valid_ipv6,
    is_private_ip,
)


def test_defang_string():
    assert defang_string("1[.]1[.]1[.]1") == "1.1.1.1"
    assert defang_string("8(.)8(.)8(.)8") == "8.8.8.8"
    assert defang_string("hxxps://malware[.]com/bad") == "https://malware.com/bad"
    assert defang_string("hxxp://evil[:]8080") == "http://evil:8080"


def test_refang_string():
    assert refang_string("1.1.1.1", "ipv4") == "1[.]1[.]1[.]1"
    assert refang_string("2001:db8::1", "ipv6") == "2001[:]db8[:][:]1"


def test_is_private_ip():
    assert is_private_ip("192.168.1.1") is True
    assert is_private_ip("10.0.0.1") is True
    assert is_private_ip("127.0.0.1") is True
    assert is_private_ip("8.8.8.8") is False
    assert is_private_ip("1.1.1.1") is False


def test_parse_raw_text_mixed():
    sample = """
    Incident Report #4102:
    Attacker IP was 118[.]25[.]6[.]39 communicating with C2 server at 185.220.101.5.
    Internal host 192.168.1.100 was infected.
    Dropped payload MD5: 84c82835a5d21bbcf75a61706d8ab549
    Dropped payload SHA256: ed01ebf83434a16f6003bc90ab3a145b81db813363f49e64bc87da54a07a1222
    Also duplicate IP: 118.25.6.39
    """
    items = parse_raw_text(sample)
    values = [item.value for item in items]

    # Verify extracted indicators
    assert "118.25.6.39" in values
    assert "185.220.101.5" in values
    assert "192.168.1.100" in values
    assert "84c82835a5d21bbcf75a61706d8ab549" in values
    assert "ed01ebf83434a16f6003bc90ab3a145b81db813363f49e64bc87da54a07a1222" in values

    # Verify deduplication
    assert values.count("118.25.6.39") == 1

    # Verify classifications
    item_map = {item.value: item for item in items}
    assert item_map["118.25.6.39"].ioc_type == "ipv4"
    assert item_map["192.168.1.100"].is_private is True
    assert item_map["118.25.6.39"].is_private is False
    assert item_map["84c82835a5d21bbcf75a61706d8ab549"].ioc_type == "md5"
    assert item_map["ed01ebf83434a16f6003bc90ab3a145b81db813363f49e64bc87da54a07a1222"].ioc_type == "sha256"
