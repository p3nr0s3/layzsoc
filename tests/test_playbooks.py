"""Unit tests for SOC Incident Response Playbooks."""

import pytest
from core.playbooks import get_all_playbooks, get_playbook, generate_playbook_report


def test_get_all_playbooks():
    pbs = get_all_playbooks()
    assert len(pbs) >= 5
    ids = [p["id"] for p in pbs]
    assert "phishing" in ids
    assert "ransomware" in ids
    assert "credential_theft" in ids


def test_get_specific_playbook():
    pb = get_playbook("phishing")
    assert pb is not None
    assert pb["title"] == "Phishing & Business Email Compromise (BEC)"
    assert len(pb["tasks"]) > 0
    assert any(t["phase"] == "Identification" for t in pb["tasks"])
    assert any(t["phase"] == "Containment" for t in pb["tasks"])


def test_generate_playbook_report():
    report = generate_playbook_report(
        playbook_id="phishing",
        completed_task_ids=["phish_1", "phish_2"],
        analyst_name="Test Analyst",
        incident_id="INC-2026-001",
        notes="Containment in progress.",
        iocs=["185.220.101.5", "bad-login.xyz"],
    )
    assert "report_markdown" in report
    md = report["report_markdown"]
    assert "INC-2026-001" in md
    assert "Test Analyst" in md
    assert "185.220.101.5" in md
    assert report["completed_count"] == 2
    assert report["progress_pct"] > 0
