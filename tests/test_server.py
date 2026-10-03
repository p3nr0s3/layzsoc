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
    assert "SLOTHERY" in res.text
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
