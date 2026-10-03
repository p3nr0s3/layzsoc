"""Tests for the MailHealthChecker module."""

import pytest
from core.mail_health import MailHealthChecker


def test_mail_health_mock_scoring():
    checker = MailHealthChecker()

    # 1. Perfectly protected domain
    mx_good = {"has_mx": True, "provider": "Google Workspace", "records": [{"priority": 1, "host": "smtp.google.com"}]}
    spf_good = {"has_spf": True, "record": "v=spf1 include:_spf.google.com -all", "status": "STRICT", "is_multiple": False}
    dmarc_good = {"has_dmarc": True, "record": "v=DMARC1; p=reject; pct=100", "policy": "reject"}

    score, rating, verdict, issues = checker._calculate_health_score(mx_good, spf_good, dmarc_good)
    assert score >= 80
    assert rating == "PROTECTED"
    assert "Strong" in verdict

    # 2. Highly vulnerable / spoofable domain
    mx_none = {"has_mx": False, "provider": "None", "records": []}
    spf_none = {"has_spf": False, "record": None, "status": "MISSING"}
    dmarc_none = {"has_dmarc": False, "record": None, "policy": "none"}

    score_vuln, rating_vuln, verdict_vuln, issues_vuln = checker._calculate_health_score(mx_none, spf_none, dmarc_none)
    assert score_vuln < 30
    assert rating_vuln == "VULNERABLE"
    assert len(issues_vuln) > 0
