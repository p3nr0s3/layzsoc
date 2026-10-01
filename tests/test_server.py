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
