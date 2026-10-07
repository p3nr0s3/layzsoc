"""Tests for FastAPI backend API endpoints."""

import pytest
from fastapi.testclient import TestClient
from server import app

client = TestClient(app)


def test_status_endpoint():
    res = client.get("/api/status")
    assert res.status_code == 200
    data = res.json()
    assert "pools" in data
    assert "cache" in data
    assert "services" in data


def test_parse_endpoint():
    res = client.post("/api/parse", json={"raw_text": "Check IP 1[.]1[.]1[.]1 and hash 84c82835a5d21bbcf75a61706d8ab549"})
    assert res.status_code == 200
    data = res.json()
    assert data["total"] == 2
    types = [i["type"] for i in data["items"]]
    assert "ipv4" in types
    assert "md5" in types


def test_index_html_served():
    res = client.get("/")
    assert res.status_code == 200
    assert "LazySOC" in res.text
    assert "IoC Triage" in res.text
    assert "Network Recon" in res.text
    assert "Phishing EML" in res.text
    assert "Threat Intel Auto-Detection Pipeline" in res.text
    assert "SIEM Hunting Queries" in res.text
    assert "SOC Incident Note" in res.text
    assert "OpenSearch" in res.text


def test_scan_with_selected_providers():
    res = client.post("/api/scan", json={
        "raw_text": "1.1.1.1",
        "providers": ["dns", "urlhaus"],
        "use_cache": False
    })
    assert res.status_code == 200
    data = res.json()
    assert "results" in data
    assert len(data["results"]) == 1
    assert data["results"][0]["ioc"] == "1.1.1.1"



def test_mail_health_endpoint():
    res = client.get("/api/mail-health?domain=google.com")
    assert res.status_code == 200
    data = res.json()
    assert "score" in data
    assert "rating" in data
    assert "dmarc" in data


def test_recon_endpoint():
    res = client.get("/api/recon?target=8.8.8.8")
    assert res.status_code == 200
    data = res.json()
    assert data["target"] == "8.8.8.8"
    assert data["type"] == "ip"
    assert "ptr" in data


def test_analyze_eml_endpoint():
    sample_raw = "From: PayPal Support <phish@scam.org>\nReply-To: bad@evil.com\nSubject: Account Locked\nAuthentication-Results: spf=fail; dmarc=fail\n\nClick http://1.2.3.4/login"
    res = client.post("/api/analyze-eml", data={"raw_text": sample_raw})
    assert res.status_code == 200
    data = res.json()
    assert data["risk_verdict"] == "PHISHING / MALICIOUS"
    assert data["risk_score"] >= 60
    assert len(data["alerts"]) > 0


def test_key_endpoints_locked_by_default():
    # Attempting to add key via API should be blocked (403)
    res_add = client.post("/api/keys", json={"service": "virustotal", "key": "malicious_attempt"})
    assert res_add.status_code == 403

    # Attempting to delete key via API should be blocked (403)
    res_del = client.delete("/api/keys?service=virustotal&key=somekey")
    assert res_del.status_code == 403


def test_status_endpoint_never_leaks_raw_keys():
    res = client.get("/api/status")
    assert res.status_code == 200
    data = res.json()
    for service, key_list in data.get("services", {}).items():
        for k in key_list:
            assert "key_raw" not in k, f"Raw API key was leaked in status for service {service}!"
            assert "key_masked" in k


def test_index_html_hides_key_management():
    res = client.get("/")
    assert res.status_code == 200
    assert 'id="tab-btn-keys"' not in res.text
    assert 'id="view-keys"' not in res.text
    assert "removeKey(" not in res.text
    # Verify theme picker, feed tab, cve tab & footer watermark exist
    assert 'id="theme-btn"' in res.text
    assert 'id="tab-btn-feed"' in res.text
    assert 'id="tab-btn-cve"' in res.text
    assert 'id="view-cve"' in res.text
    assert '@p3nr0s3' in res.text


def test_cyber_feed_endpoint():
    res = client.get("/api/feed?source=all&limit=5")
    assert res.status_code == 200
    data = res.json()
    assert "total" in data
    assert "sources" in data
    assert "items" in data
    assert isinstance(data["items"], list)


def test_cve_endpoint():
    res = client.get("/api/cve")
    assert res.status_code == 200
    data = res.json()
    assert "items" in data
    assert len(data["items"]) > 0
    first = data["items"][0]
    assert "id" in first
    assert "cvss" in first
    assert "severity" in first


def test_cve_vendor_search_and_pagination():
    res = client.get("/api/cve?query=Fortinet&limit=5&page=1")
    assert res.status_code == 200
    data = res.json()
    assert "items" in data
    assert len(data["items"]) > 0
    # Verify latest items are returned and sorted descending
    dates = [item.get("published", "") for item in data["items"] if item.get("published")]
    if len(dates) >= 2:
        assert dates == sorted(dates, reverse=True)

    # Test page 2
    res2 = client.get("/api/cve?query=Fortinet&limit=5&page=2")
    assert res2.status_code == 200
    data2 = res2.json()
    assert "items" in data2
    assert "has_more" in data2



