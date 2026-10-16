"""Unit tests for SIEM & EDR Threat Hunting Query Generator."""

import pytest
from core.hunting import generate_single_ioc_hunt_queries, _sanitize_val


def test_sanitize_val():
    malicious_input = '1.1.1.1" OR index=* | script evil\n'
    sanitized = _sanitize_val(malicious_input)
    assert "\n" not in sanitized
    assert '\\"' in sanitized


def test_generate_ip_hunt_queries():
    res = generate_single_ioc_hunt_queries("185.220.101.5", "ipv4", "Malicious")
    assert "queries" in res
    q = res["queries"]
    assert "splunk" in q
    assert "sentinel" in q
    assert "crowdstrike" in q
    assert "185.220.101.5" in q["splunk"]
    assert "185.220.101.5" in q["sentinel"]


def test_generate_hash_hunt_queries():
    sha = "84c82835a5d21bbcf75a61706d8ab549"
    res = generate_single_ioc_hunt_queries(sha, "md5", "Malicious")
    q = res["queries"]
    assert sha in q["splunk"]
    assert sha in q["sentinel"]


def test_generate_domain_hunt_queries():
    domain = "evil-phishing-domain.com"
    res = generate_single_ioc_hunt_queries(domain, "domain", "Suspicious")
    q = res["queries"]
    assert domain in q["splunk"]
    assert domain in q["sentinel"]
