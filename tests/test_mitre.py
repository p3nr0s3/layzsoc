"""Unit tests for MITRE ATT&CK Matrix and Heatmap Engine."""

import pytest
from core.mitre import get_mitre_matrix_data, analyze_mitre_coverage


def test_get_mitre_matrix_data():
    data = get_mitre_matrix_data()
    assert "tactics" in data
    assert "matrix" in data
    assert len(data["tactics"]) == 12
    assert data["techniques_count"] > 0
    tactic_ids = [t["id"] for t in data["tactics"]]
    assert "TA0001" in tactic_ids  # Initial Access
    assert "TA0002" in tactic_ids  # Execution


def test_analyze_mitre_coverage_with_playbook():
    res = analyze_mitre_coverage(
        iocs=[{"ioc": "evil-c2.com", "type": "domain", "verdict": "Malicious"}],
        active_playbook_id="phishing",
    )
    assert "active_techniques" in res
    assert "T1566" in res["active_techniques"]  # Phishing technique
    assert res["total_active"] > 0
