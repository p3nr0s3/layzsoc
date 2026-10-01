"""Tests for the orchestration engine and export functionality."""

import pytest
from core.parser import IoCItem
from core.engine import (
    determine_verdict,
    EnrichmentEngine,
    VERDICT_MALICIOUS,
    VERDICT_SUSPICIOUS,
    VERDICT_CLEAN,
    VERDICT_UNKNOWN,
)
from core.exporter import export_to_csv, export_to_json


def test_determine_verdict():
    # 1. High abuse score -> Malicious
    v1 = determine_verdict(
        "ipv4",
        vt_res={"success": True, "malicious": 0, "suspicious": 0},
        abuse_res={"success": True, "data": {"abuse_confidence_score": 85}},
    )
    assert v1 == VERDICT_MALICIOUS

    # 2. VT Malicious >= 2 -> Malicious
    v2 = determine_verdict(
        "sha256",
        vt_res={"success": True, "malicious": 15, "suspicious": 1},
        abuse_res=None,
    )
    assert v2 == VERDICT_MALICIOUS

    # 3. Suspicious score
    v3 = determine_verdict(
        "ipv4",
        vt_res={"success": True, "malicious": 0, "suspicious": 1},
        abuse_res={"success": True, "data": {"abuse_confidence_score": 10}},
    )
    assert v3 == VERDICT_SUSPICIOUS

    # 4. Clean
    v4 = determine_verdict(
        "ipv4",
        vt_res={"success": True, "malicious": 0, "suspicious": 0},
        abuse_res={"success": True, "data": {"abuse_confidence_score": 0}},
    )
    assert v4 == VERDICT_CLEAN

    # 5. Private IP
    v5 = determine_verdict("ipv4", vt_res=None, abuse_res=None, is_private=True)
    assert v5 == VERDICT_UNKNOWN


def test_export_utilities():
    sample_results = [
        {
            "ioc": "1.1.1.1",
            "type": "ipv4",
            "verdict": "Clean",
            "vt_stats": "0/70",
            "abuse_score": "0%",
            "notes": "Cloudflare DNS",
            "is_cached": False,
        },
        {
            "ioc": "185.220.101.5",
            "type": "ipv4",
            "verdict": "Malicious",
            "vt_stats": "12/70",
            "abuse_score": "100%",
            "notes": "Tor Exit Node",
            "is_cached": True,
        },
    ]

    # Test CSV with defang
    csv_str = export_to_csv(sample_results, defang_output=True)
    assert "1[.]1[.]1[.]1" in csv_str
    assert "185[.]220[.]101[.]5" in csv_str
    assert "MALICIOUS" in csv_str.upper()

    # Test JSON
    json_str = export_to_json(sample_results, defang_output=False)
    assert '"ioc": "1.1.1.1"' in json_str
    assert '"verdict": "Malicious"' in json_str
