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


# ---------------------------------------------------------------------------
# DNS behaviour tests (offline: the resolver is replaced by a fake)
# ---------------------------------------------------------------------------
import dns.exception
import dns.resolver

from core.mail_health import MailHealthChecker as _Checker


class _Txt:
    def __init__(self, text):
        self.strings = [text.encode()]


class _Mx:
    def __init__(self, pref, host):
        self.preference, self.exchange = pref, host


class FakeResolver:
    """Maps (name, rdtype) -> list of rdata | Exception instance. Unknown -> NXDOMAIN."""

    def __init__(self, table):
        self.table = table
        self.calls = []

    def resolve(self, name, rdtype):
        self.calls.append((name, rdtype))
        value = self.table.get((name, rdtype), dns.resolver.NXDOMAIN())
        if isinstance(value, Exception):
            raise value
        return value


def _checker(table):
    return _Checker(resolver=FakeResolver(table))


def test_default_resolver_uses_edns():
    # Large TXT answers (google.com, github.com) are truncated over plain UDP
    assert _Checker().resolver.edns >= 0


def test_spf_matches_all_mechanism_token_not_substring():
    c = _checker({
        ("a.test", "MX"): [_Mx(10, "mx.a.test.")],
        ("a.test", "TXT"): [_Txt("v=spf1 include:mail-all.example.com ~all")],
        ("_dmarc.a.test", "TXT"): [_Txt("v=DMARC1; p=reject")],
    })
    assert c.check_domain("a.test")["spf"]["status"] == "MODERATE"  # not STRICT


def test_dns_timeout_is_inconclusive_not_missing():
    c = _checker({
        ("a.test", "MX"): [_Mx(10, "mx.a.test.")],
        ("a.test", "TXT"): dns.exception.Timeout(),
        ("_dmarc.a.test", "TXT"): [_Txt("v=DMARC1; p=reject")],
    })
    res = c.check_domain("a.test")
    assert res["rating"] == "INCONCLUSIVE"
    assert res["score"] is None
    assert res["dns_errors"] == ["SPF"]
    assert res["spf"]["status"] == "ERROR"


def test_nxdomain_is_not_found():
    res = _checker({}).check_domain("nope.test")
    assert res["rating"] == "NOT_FOUND"
    assert res["exists"] is False


def test_subdomain_inherits_parent_dmarc_and_uses_sp():
    c = _checker({
        ("login.a.test", "MX"): dns.resolver.NoAnswer(),
        ("login.a.test", "TXT"): dns.resolver.NoAnswer(),
        ("_dmarc.a.test", "TXT"): [_Txt("v=DMARC1; p=none; sp=reject")],
    })
    d = c.check_domain("login.a.test")["dmarc"]
    assert d["has_dmarc"] and d["inherited_from"] == "_dmarc.a.test"
    assert d["policy"] == "reject"       # sp applies to sub-domains
    assert d["domain_policy"] == "none"


def test_url_input_is_normalised():
    c = _checker({("a.test", "MX"): [_Mx(10, "mx.a.test.")]})
    assert c.check_domain("https://A.test/path?x=1")["domain"] == "a.test"
