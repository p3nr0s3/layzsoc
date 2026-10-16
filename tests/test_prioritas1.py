"""Tests for Prioritas 1 SOC enhancements: GreyNoise, ThreatFox, MalwareBazaar, Containment, and MITRE Navigator Layer."""

import pytest
from unittest.mock import MagicMock, patch
from fastapi.testclient import TestClient

from server import app
from core.containment import generate_containment_scripts
from core.mitre import export_mitre_navigator_layer
from core.engine import determine_verdict, VERDICT_MALICIOUS, VERDICT_CLEAN, VERDICT_SUSPICIOUS
from core.clients.greynoise import GreyNoiseClient
from core.clients.threatfox import ThreatFoxClient
from core.clients.malwarebazaar import MalwareBazaarClient


client = TestClient(app)


def test_containment_script_generation():
    iocs = [
        {"ioc": "198.51.100.42", "type": "ipv4", "verdict": "Malicious"},
        {"ioc": "evil-c2.xyz", "type": "domain", "verdict": "Malicious"},
        {"ioc": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "type": "sha256", "verdict": "Malicious"},
    ]
    res = generate_containment_scripts(iocs, rule_name="TEST_BLOCK", zone="untrust")
    
    # Check Palo Alto
    assert "set address" in res["palo_alto"]
    assert "198.51.100.42" in res["palo_alto"]
    assert "evil-c2.xyz" in res["palo_alto"]
    assert "TEST_BLOCK_GRP" in res["palo_alto"]

    # Check Fortinet
    assert "config firewall address" in res["fortinet"]
    assert "198.51.100.42" in res["fortinet"]

    # Check Cisco ASA
    assert "object network" in res["cisco_asa"]
    assert "access-list" in res["cisco_asa"]

    # Check Linux iptables
    assert "iptables -I INPUT -s 198.51.100.42 -j DROP" in res["iptables"]

    # Check Windows Firewall
    assert "New-NetFirewallRule" in res["windows_firewall"]
    assert "198.51.100.42" in res["windows_firewall"]

    # Check EDR & Hashes
    assert "route add 198.51.100.42" in res["edr_isolation"]
    assert "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" in res["hash_blocklist"]


def test_mitre_navigator_layer_export():
    iocs = [
        {"ioc": "https://malicious-login.com", "type": "url", "verdict": "Malicious"},
        {"ioc": "1.2.3.4", "type": "ipv4", "verdict": "Malicious"},
    ]
    layer = export_mitre_navigator_layer(iocs, active_playbook_id="phishing")
    
    assert layer["name"] == "LazySOC Incident TTP Heatmap"
    assert layer["versions"]["navigator"] == "4.5"
    assert layer["domain"] == "enterprise-attack"
    assert len(layer["techniques"]) > 0

    # Ensure T1566 (Phishing) is present
    technique_ids = [t["techniqueID"] for t in layer["techniques"]]
    assert "T1566" in technique_ids


def test_determine_verdict_with_new_cti():
    # 1. ThreatFox found -> Malicious
    v1 = determine_verdict(
        "ipv4",
        vt_res=None,
        abuse_res=None,
        threatfox_res={"found": True, "malware": "RedLine Stealer"},
    )
    assert v1 == VERDICT_MALICIOUS

    # 2. MalwareBazaar found -> Malicious
    v2 = determine_verdict(
        "sha256",
        vt_res=None,
        abuse_res=None,
        malwarebazaar_res={"found": True, "signature": "AgentTesla"},
    )
    assert v2 == VERDICT_MALICIOUS

    # 3. GreyNoise RIOT / Benign scanner -> Clean (unless VT/Abuse high)
    v3 = determine_verdict(
        "ipv4",
        vt_res={"success": True, "malicious": 0, "suspicious": 0},
        abuse_res={"success": True, "data": {"abuse_confidence_score": 0}},
        greynoise_res={"found": True, "riot": True, "name": "Google DNS", "classification": "benign"},
    )
    assert v3 == VERDICT_CLEAN

    # 4. GreyNoise Malicious scanner -> Malicious
    v4 = determine_verdict(
        "ipv4",
        vt_res=None,
        abuse_res=None,
        greynoise_res={"found": True, "noise": True, "classification": "malicious"},
    )
    assert v4 == VERDICT_MALICIOUS


def test_api_endpoints_prioritas1():
    # Test Containment Endpoint
    resp = client.post("/api/containment/generate", json={
        "iocs": [{"ioc": "192.0.2.1", "type": "ipv4", "verdict": "Malicious"}],
        "rule_name": "API_TEST",
    })
    assert resp.status_code == 200
    data = resp.json()
    assert "palo_alto" in data
    assert "192.0.2.1" in data["iptables"]

    # Test MITRE Navigator Export Endpoint
    resp_layer = client.post("/api/mitre/export-layer", json={
        "iocs": [{"ioc": "evil.com", "type": "domain", "verdict": "Malicious"}],
        "playbook_id": "c2_exfil",
    })
    assert resp_layer.status_code == 200
    layer_data = resp_layer.json()
    assert layer_data["versions"]["navigator"] == "4.5"

    # Test Mocked GreyNoise Endpoint
    with patch.object(GreyNoiseClient, "check_ip", return_value={"success": True, "found": True, "riot": True}):
        resp_gn = client.post("/api/soc/greynoise", json={"ip": "8.8.8.8"})
        assert resp_gn.status_code == 200
        assert resp_gn.json()["riot"] is True

    # Test Mocked ThreatFox Endpoint
    with patch.object(ThreatFoxClient, "search_ioc", return_value={"success": True, "found": True, "malware": "Cobalt Strike"}):
        resp_tf = client.post("/api/soc/threatfox", json={"ioc": "1.1.1.1"})
        assert resp_tf.status_code == 200
        assert resp_tf.json()["malware"] == "Cobalt Strike"

    # Test Mocked MalwareBazaar Endpoint
    with patch.object(MalwareBazaarClient, "check_hash", return_value={"success": True, "found": True, "signature": "Lokibot"}):
        resp_mb = client.post("/api/soc/malwarebazaar", json={"hash": "d41d8cd98f00b204e9800998ecf8427e"})
        assert resp_mb.status_code == 200
        assert resp_mb.json()["signature"] == "Lokibot"
